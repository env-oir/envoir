//! Integration tests for the node's **Envoir Send** HTTP API (spec §13.5.1).
//!
//! These drive the real surface end-to-end: a capability API key authorizes a `POST /v1/send`, the
//! request enters the node's real §20.1 outbound path (retry queue + mesh dispatch), and the object
//! the recipient receives is a real, decryptable MOTE. Fail-closed rejection is asserted for
//! revoked / expired / out-of-scope / unknown keys, and the admin-guarded key-management routes are
//! exercised. One test proves the whole thing over a real TCP socket.

use dmtap::identity::IdentityKey;
use dmtap::mote::{validate, Envelope, Hpke, Outcome, RecipientCtx, SealKeypair};
use dmtap::names::base64url;
use dmtap::node::Node;
use dmtap::send_api::SendApi;
use dmtap::transport::{Frame, InMemoryNetwork, InMemoryTransport, Transport};

use dmtap_send::http::{HttpRequest, HttpResponse};
use dmtap_send::{Environment, SendScope};

use serde_json::{json, Value};

const NOW: u64 = 1_700_000_000_000;
const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;
const ADMIN: &str = "admin-secret-token";

/// A running node + a Send API owned by the same identity, a resolvable native recipient, and the
/// recipient's transport endpoint (to drain what the mesh actually delivered).
struct Fixture {
    node: Node<InMemoryTransport>,
    api: SendApi,
    rt: InMemoryTransport,
    rik_public: Vec<u8>,
    rseal: SealKeypair,
    to: String,
}

fn fixture() -> Fixture {
    let net = InMemoryNetwork::new();
    // The node and the Send API share ONE identity (from a fixed seed), so a capability-authorized
    // send seals a MOTE authenticated as from this node.
    let node_ik = IdentityKey::from_seed(&[7u8; 32]);
    let node_t = net.endpoint(node_ik.public());
    let mut node = Node::with_identity(IdentityKey::from_seed(&[7u8; 32]), SealKeypair::generate(), node_t);

    // A native recipient this node already knows (so the resolver can seal to it). Its endpoint must
    // be registered before any send, or the in-memory transport reports it unreachable.
    let rik = IdentityKey::generate();
    let rseal = SealKeypair::generate();
    let rt = net.endpoint(rik.public());
    node.add_contact(&rik.public(), *rseal.public());
    let to = base64url::encode(&rik.public());

    let api = SendApi::new(IdentityKey::from_seed(&[7u8; 32]), Some(ADMIN.to_string()));
    Fixture { node, api, rt, rik_public: rik.public(), rseal, to }
}

fn post(path: &str, bearer: Option<&str>, body: Value) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        path: path.into(),
        authorization: bearer.map(|b| format!("Bearer {b}")),
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn parse(resp: &HttpResponse) -> Value {
    serde_json::from_slice(&resp.body).unwrap()
}

fn send_body(from: &str, to: &str) -> Value {
    json!({ "from": from, "to": to, "subject": "hi", "body": "hello over http" })
}

#[test]
fn valid_key_sends_and_message_enters_delivery_as_real_mote() {
    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();

    let resp = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("hello@example.com", &f.to)), NOW);
    assert_eq!(resp.status, 200);
    let v = parse(&resp);
    assert_eq!(v["id"].as_str().unwrap().len(), 66, "33-byte content id in hex");
    assert_eq!(v["native"], true);
    assert_eq!(v["transport"], "native-mesh");

    // It entered the node's real §20.1 outbound retry queue.
    assert_eq!(f.node.outbound_len(), 1);

    // The mesh transport actually carried a real MOTE the recipient can open + validate.
    let frames = f.rt.drain();
    assert_eq!(frames.len(), 1, "exactly one MOTE was dispatched over the mesh");
    let bytes = match &frames[0].1 {
        Frame::Mote(b) => b.clone(),
        _ => panic!("expected a MOTE frame"),
    };
    let env = Envelope::from_det_cbor(&bytes).unwrap();
    let ctx = RecipientCtx { our_ik: &f.rik_public, seal_secret: f.rseal.secret(), sender_is_known: true };
    match validate(&Hpke, &env, &ctx).unwrap() {
        Outcome::Accepted(p) => {
            assert_eq!(p.body, b"hello over http");
            assert_eq!(p.headers.subject.as_deref(), Some("hi"));
        }
        Outcome::Deferred => panic!("a known-contact MOTE must be accepted"),
    }
}

#[test]
fn missing_bearer_is_rejected_fail_closed() {
    let mut f = fixture();
    let resp = f.api.handle(&mut f.node, &post("/v1/send", None, send_body("hello@example.com", &f.to)), NOW);
    assert_eq!(resp.status, 401);
    assert_eq!(f.node.outbound_len(), 0, "no MOTE built for an unauthenticated request");
}

#[test]
fn unknown_key_is_rejected_fail_closed() {
    let mut f = fixture();
    let resp =
        f.api.handle(&mut f.node, &post("/v1/send", Some("envoir_live_deadbeef"), send_body("hello@example.com", &f.to)), NOW);
    assert_eq!(resp.status, 401);
    assert_eq!(parse(&resp)["error"], "unauthorized");
    assert_eq!(f.node.outbound_len(), 0);
}

#[test]
fn revoked_key_is_rejected_fail_closed() {
    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();
    f.api.service_mut().revoke_key(&secret, NOW).unwrap();

    let resp = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("hello@example.com", &f.to)), NOW + 1);
    assert_eq!(resp.status, 401);
    assert_eq!(parse(&resp)["error"], "revoked");
    assert_eq!(f.node.outbound_len(), 0);
}

#[test]
fn expired_key_is_rejected_fail_closed() {
    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, 60_000);
    let secret = key.secret().to_string();

    // One minute later the key is expired.
    let resp = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("hello@example.com", &f.to)), NOW + 60_000);
    assert_eq!(resp.status, 401);
    assert_eq!(parse(&resp)["error"], "expired");
    assert_eq!(f.node.outbound_len(), 0);
}

#[test]
fn out_of_scope_from_is_rejected_fail_closed() {
    let mut f = fixture();
    // Key scoped to example.com only.
    let key = f.api.service_mut().issue_key(SendScope::domain("example.com", Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();

    // Sending FROM a different domain is out of scope.
    let resp = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("evil@other.com", &f.to)), NOW);
    assert_eq!(resp.status, 403);
    assert_eq!(parse(&resp)["error"], "out_of_scope");
    assert_eq!(f.node.outbound_len(), 0, "an out-of-scope request never seals or delivers");
}

#[test]
fn unresolvable_recipient_fails_closed() {
    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();

    // A well-formed DMTAP address this node has never learned.
    let ghost = base64url::encode(&IdentityKey::generate().public());
    let resp = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("hello@example.com", &ghost)), NOW);
    assert_eq!(resp.status, 422);
    assert_eq!(parse(&resp)["error"], "unresolvable_recipient");
    assert_eq!(f.node.outbound_len(), 0);
}

#[test]
fn key_management_is_disabled_without_an_admin_token() {
    let mut f = fixture();
    // A service with NO admin token configured refuses all key management (fail-closed).
    f.api = SendApi::new(IdentityKey::from_seed(&[7u8; 32]), None);

    let resp = f.api.handle(&mut f.node, &post("/v1/keys", Some(ADMIN), json!({ "env": "prod" })), NOW);
    assert_eq!(resp.status, 403);
    assert_eq!(parse(&resp)["error"], "forbidden");
}

#[test]
fn key_management_requires_the_admin_bearer() {
    let mut f = fixture();
    // Missing token.
    let r1 = f.api.handle(&mut f.node, &post("/v1/keys", None, json!({ "env": "prod" })), NOW);
    assert_eq!(r1.status, 401);
    // Wrong token.
    let r2 = f.api.handle(&mut f.node, &post("/v1/keys", Some("not-the-admin-token"), json!({ "env": "prod" })), NOW);
    assert_eq!(r2.status, 401);
}

#[test]
fn admin_can_issue_a_key_that_then_sends() {
    let mut f = fixture();
    // Issue via the admin-guarded route.
    let issued = f.api.handle(&mut f.node, &post("/v1/keys", Some(ADMIN), json!({ "env": "prod" })), NOW);
    assert_eq!(issued.status, 200);
    let v = parse(&issued);
    let secret = v["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("envoir_live_"));
    assert_eq!(v["environment"], "prod");

    // The freshly-issued key sends successfully.
    let sent = f.api.handle(&mut f.node, &post("/v1/send", Some(&secret), send_body("hello@example.com", &f.to)), NOW);
    assert_eq!(sent.status, 200);
    assert_eq!(f.node.outbound_len(), 1);
}

#[test]
fn admin_can_rotate_and_revoke_keys() {
    let mut f = fixture();
    let issued = f.api.handle(&mut f.node, &post("/v1/keys", Some(ADMIN), json!({ "env": "prod" })), NOW);
    let old_secret = parse(&issued)["secret"].as_str().unwrap().to_string();

    // Rotate: mints a new secret, revokes the old.
    let rotated = f.api.handle(&mut f.node, &post("/v1/keys/rotate", Some(ADMIN), json!({ "secret": old_secret })), NOW + 1);
    assert_eq!(rotated.status, 200);
    let new_secret = parse(&rotated)["secret"].as_str().unwrap().to_string();
    assert_ne!(new_secret, old_secret);

    // Old secret no longer sends; new one does.
    let old_try = f.api.handle(&mut f.node, &post("/v1/send", Some(&old_secret), send_body("hello@example.com", &f.to)), NOW + 2);
    assert_eq!(old_try.status, 401);
    let new_try = f.api.handle(&mut f.node, &post("/v1/send", Some(&new_secret), send_body("hello@example.com", &f.to)), NOW + 2);
    assert_eq!(new_try.status, 200);

    // Revoke the new one; it stops sending.
    let revoked = f.api.handle(&mut f.node, &post("/v1/keys/revoke", Some(ADMIN), json!({ "secret": new_secret })), NOW + 3);
    assert_eq!(revoked.status, 200);
    assert_eq!(parse(&revoked)["revoked"], true);
    let after = f.api.handle(&mut f.node, &post("/v1/send", Some(&new_secret), send_body("hello@example.com", &f.to)), NOW + 4);
    assert_eq!(after.status, 401);
}

#[test]
fn unknown_route_is_404() {
    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();
    let resp = f.api.handle(&mut f.node, &post("/v1/nope", Some(&secret), json!({})), NOW);
    assert_eq!(resp.status, 404);
}

/// The full path over a real TCP socket: bind a listener, drive the request from a client task, and
/// serve the connection inline against the live node — proving the wire framing + delivery are real.
#[tokio::test]
async fn live_tcp_round_trip_delivers_a_real_mote() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut f = fixture();
    let key = f.api.service_mut().issue_key(SendScope::account(Environment::Prod), NOW, YEAR);
    let secret = key.secret().to_string();
    let to = f.to.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Client task: send a raw HTTP/1.1 request and read the whole response back.
    let client = tokio::spawn(async move {
        let body = serde_json::to_vec(&send_body("hello@example.com", &to)).unwrap();
        let head = format!(
            "POST /v1/send HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    });

    // Server: accept one connection and serve it against the live node.
    let (stream, _peer) = listener.accept().await.unwrap();
    f.api.handle_connection(&mut f.node, stream, NOW).await.unwrap();

    let resp = client.await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "response was: {text}");

    // The MOTE entered the node's real outbound path and reached the recipient over the mesh.
    assert_eq!(f.node.outbound_len(), 1);
    let frames = f.rt.drain();
    assert_eq!(frames.len(), 1);
    let bytes = match &frames[0].1 {
        Frame::Mote(b) => b.clone(),
        _ => panic!("expected a MOTE frame"),
    };
    let env = Envelope::from_det_cbor(&bytes).unwrap();
    let ctx = RecipientCtx { our_ik: &f.rik_public, seal_secret: f.rseal.secret(), sender_is_known: true };
    assert!(matches!(validate(&Hpke, &env, &ctx).unwrap(), Outcome::Accepted(_)));
}
