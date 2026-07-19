//! Integration tests for the node-native **JMAP** listener (spec §8.1).
//!
//! These drive the real surface end-to-end over a real TCP socket: a client authenticates with an
//! app-password (spec §8.2) and runs `Session` / `Mailbox/get` / `Email/query` + `Email/get` against
//! a node whose INBOX holds a **genuinely delivered MOTE** (Alice → Bob over the in-memory mesh, Bob
//! validates + decrypts + stores it, §2.7). The client therefore sees the node's *live* mail, not a
//! fresh empty store. A bad app-password is rejected fail-closed with a Basic challenge.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::jmap_api::{run_loop_with_apis, JmapApi};
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_mail::jmap::{CAP_CORE, CAP_MAIL};
use dmtap_mail::util::base64_encode;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ACCOUNT: &str = "bob@dmtap.local";
const APP_PW: &str = "device-app-password";

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    let transport = net.endpoint(ik_pub.clone());
    (Node::with_identity(ik, seal, transport), ik_pub, seal_pub)
}

/// Basic auth header value for `user:pass`.
fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", base64_encode(format!("{user}:{pass}").as_bytes()))
}

/// Like [`roundtrip`] but returns the raw response text (status line + headers + body) so tests can
/// assert on headers (CORS, Retry-After) too.
async fn roundtrip_raw(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

/// One HTTP/1.1 request→response round trip over a fresh `Connection: close` socket. Returns the
/// status code and the response body bytes.
async fn roundtrip(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();

    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
    let head = String::from_utf8_lossy(&buf[..split]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status line");
    (status, buf[split + 4..].to_vec())
}

#[tokio::test]
async fn client_authenticates_and_reads_genuinely_delivered_mail_over_tcp() {
    // --- 1. Deliver a REAL end-to-end-encrypted MOTE from Alice to Bob over the mesh. -----------
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    let secret = b"the JMAP client must see this exact delivered plaintext";
    alice.send_mail(&bob_ik, "Delivered over the mesh", secret).expect("send");
    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "Bob stored the MOTE");
    assert_eq!(bob.inbox().exists(), 1, "the live store holds the delivered MOTE");

    // --- 2. Bind the node-native JMAP listener over Bob's LIVE store. ---------------------------
    let jmap = JmapApi::new(
        ACCOUNT,
        "http://127.0.0.1", // base URL is cosmetic for this test
        bob_ik.clone(),
        &[(ACCOUNT.to_string(), APP_PW.to_string())],
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // --- 3. A client task: bad password rejected, then a full Session + Mailbox + Email flow. ---
    // (A plain atomic flag drives shutdown — the node crate's tokio has no `sync` feature.)
    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let client = tokio::spawn(async move {
        let mut out = Vec::new();

        // Bad app-password → 401 fail-closed.
        let (st, _b) = roundtrip(addr, "GET", "/jmap/session", Some(&basic(ACCOUNT, "WRONG")), b"").await;
        out.push(("bad_pw".to_string(), st, Vec::new()));

        // No credential at all → 401.
        let (st, _b) = roundtrip(addr, "GET", "/jmap/session", None, b"").await;
        out.push(("no_pw".to_string(), st, Vec::new()));

        let auth = basic(ACCOUNT, APP_PW);

        // Session/get.
        let (st, body) = roundtrip(addr, "GET", "/jmap/session", Some(&auth), b"").await;
        out.push(("session".to_string(), st, body));

        // Mailbox/get.
        let req = json!({
            "using": [CAP_CORE, CAP_MAIL],
            "methodCalls": [["Mailbox/get", { "accountId": ACCOUNT, "ids": null }, "m"]]
        });
        let (st, body) = roundtrip(addr, "POST", "/jmap/api/", Some(&auth), &serde_json::to_vec(&req).unwrap()).await;
        out.push(("mailbox".to_string(), st, body));

        // Email/query → Email/get (chained via back-reference).
        let req = json!({
            "using": [CAP_MAIL],
            "methodCalls": [
                ["Email/query", { "accountId": ACCOUNT, "filter": { "inMailbox": "INBOX" } }, "q"],
                ["Email/get", { "accountId": ACCOUNT, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" } }, "g"]
            ]
        });
        let (st, body) = roundtrip(addr, "POST", "/jmap/api/", Some(&auth), &serde_json::to_vec(&req).unwrap()).await;
        out.push(("email".to_string(), st, body));

        done_client.store(true, Ordering::SeqCst);
        out
    });

    // --- 4. Run the daemon serve loop (JMAP only) until the client is done. ---------------------
    run_loop_with_apis(
        &mut bob,
        None,
        None,
        Some(&jmap),
        Some(listener),
        None,
        None,
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;
    let results = client.await.unwrap();

    // --- 5. Assertions. ------------------------------------------------------------------------
    let get = |name: &str| results.iter().find(|(n, _, _)| n == name).unwrap();

    assert_eq!(get("bad_pw").1, 401, "a bad app-password is rejected fail-closed");
    assert_eq!(get("no_pw").1, 401, "a missing credential is rejected fail-closed");

    let (_, st, body) = get("session");
    assert_eq!(*st, 200);
    let session: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(session["primaryAccounts"][CAP_MAIL], json!(ACCOUNT));
    assert!(session["apiUrl"].as_str().unwrap().ends_with("/jmap/api/"));

    let (_, st, body) = get("mailbox");
    assert_eq!(*st, 200);
    let mailbox: Value = serde_json::from_slice(body).unwrap();
    let inbox = mailbox["methodResponses"][0][1]["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == json!("INBOX"))
        .expect("INBOX present");
    assert_eq!(inbox["totalEmails"], json!(1), "the live INBOX shows the delivered MOTE");

    let (_, st, body) = get("email");
    assert_eq!(*st, 200);
    let email: Value = serde_json::from_slice(body).unwrap();
    let msg = &email["methodResponses"][1][1]["list"][0];
    assert_eq!(msg["subject"], json!("Delivered over the mesh"));
    // The exact delivered plaintext is visible to the JMAP client — proof it is the live store.
    let preview = msg["preview"].as_str().unwrap_or("");
    let body_val = msg["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    let secret_str = std::str::from_utf8(secret).unwrap();
    assert!(
        preview.contains(secret_str) || body_val.contains(secret_str),
        "the JMAP client sees the exact delivered plaintext; preview={preview:?} body={body_val:?}"
    );
}

/// The flagship browser-send path, end-to-end over a real TCP socket: the client holds ONE base URL
/// — the JMAP listener's — and drives the real browser sequence against it: (1) a credential-less
/// CORS preflight for `/v1/send` (answered 204 + the CORS grant, never a fail-closed 401), (2) the
/// real `POST /v1/send` with a capability **Bearer** token (NOT a Basic app-password — the request
/// must reach the Send API's own gate, not die at the JMAP Basic gate: the exact bug this guards
/// against), and (3) an unauthenticated send, still refused fail-closed by the Send API. The
/// authorized send routes a real MOTE into the node's §20.1 outbound path and onto the mesh.
#[tokio::test]
async fn browser_client_sends_through_the_jmap_listener_with_a_bearer_token() {
    use dmtap::send_api::SendApi;
    use dmtap::transport::{Frame, Transport};
    use dmtap_send::{Environment, SendScope};

    // The live listener stamps requests with the REAL wall clock (`daemon::now_ms`), so the key must
    // be issued against that same clock — a fixed test epoch would (rightly) read as expired.
    let now = dmtap::daemon::now_ms();

    // A node whose identity the Send API shares (as the daemon builds them from one keystore).
    let net = InMemoryNetwork::new();
    let node_ik = IdentityKey::from_seed(&[21u8; 32]);
    let node_ik_pub = node_ik.public();
    let node_t = net.endpoint(node_ik_pub.clone());
    let mut node = Node::with_identity(node_ik, SealKeypair::generate(), node_t);

    // A native recipient the node knows, registered on the fabric so the dispatched MOTE lands.
    let rik = IdentityKey::generate();
    let rseal = SealKeypair::generate();
    let rt = net.endpoint(rik.public());
    node.add_contact(&rik.public(), *rseal.public());
    let to = dmtap::names::base64url::encode(&rik.public());

    let mut send_api = SendApi::new(IdentityKey::from_seed(&[21u8; 32]), None);
    let key = send_api.service_mut().issue_key(
        SendScope::account(Environment::Prod),
        now,
        365 * 24 * 60 * 60 * 1000,
    );
    let secret = key.secret().to_string();

    let jmap = JmapApi::new(
        ACCOUNT,
        "http://127.0.0.1",
        node_ik_pub,
        &[(ACCOUNT.to_string(), APP_PW.to_string())],
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let bearer = format!("Bearer {secret}");
    let client = tokio::spawn(async move {
        // 1. The browser's preflight: OPTIONS, no credentials.
        let preflight = roundtrip_raw(addr, "OPTIONS", "/v1/send", None, b"").await;

        // 2. The real send: Bearer capability token against the JMAP listener's /v1/send.
        let body = serde_json::to_vec(&json!({
            "from": "hello@example.com", "to": to, "subject": "hi", "body": "sent from the browser"
        }))
        .unwrap();
        let sent = roundtrip_raw(addr, "POST", "/v1/send", Some(&bearer), &body).await;

        // 3. No token at all: the Send API's own gate refuses, fail-closed.
        let body = serde_json::to_vec(&json!({
            "from": "hello@example.com", "to": "whoever", "subject": "x", "body": "y"
        }))
        .unwrap();
        let unauthed = roundtrip_raw(addr, "POST", "/v1/send", None, &body).await;

        done_client.store(true, Ordering::SeqCst);
        (preflight, sent, unauthed)
    });

    run_loop_with_apis(
        &mut node,
        Some(&mut send_api),
        None, // the standalone :4610 listener is not needed for the one-base-URL path
        Some(&jmap),
        Some(listener),
        None,
        None,
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;
    let (preflight, sent, unauthed) = client.await.unwrap();

    assert!(preflight.starts_with("HTTP/1.1 204"), "preflight is 204, was: {preflight}");
    assert!(preflight.contains("Access-Control-Allow-Origin: *"), "preflight grants CORS: {preflight}");
    assert!(
        preflight.to_ascii_lowercase().contains("access-control-allow-headers: authorization"),
        "preflight advertises the Authorization header: {preflight}"
    );

    assert!(sent.starts_with("HTTP/1.1 200"), "the Bearer-authed send succeeded, was: {sent}");
    assert!(sent.contains("Access-Control-Allow-Origin: *"), "the browser can read the result: {sent}");
    let sent_body: Value =
        serde_json::from_str(sent.split("\r\n\r\n").nth(1).unwrap_or("")).expect("JSON send receipt");
    assert_eq!(sent_body["native"], json!(true));

    assert!(unauthed.starts_with("HTTP/1.1 401"), "no token ⇒ the Send API refuses: {unauthed}");

    // The MOTE genuinely traversed the node's outbound path onto the mesh to the recipient.
    assert_eq!(node.outbound_len(), 1, "the send entered the node's real §20.1 outbound queue");
    let got_mote = rt.drain().iter().any(|(_, f)| matches!(f, Frame::Mote(_)));
    assert!(got_mote, "the recipient's endpoint received the dispatched MOTE frame");
}
