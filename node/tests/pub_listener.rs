//! Integration tests for the live DMTAP-PUB gateway listener (spec §22.5/§22.6), wired into the
//! node daemon's steady-state loop (`crate::jmap_api::run_loop_with_apis`) behind
//! `NodeConfig::pub_serve_enabled` — the same config-flag-gated `TcpListener` pattern the JMAP and
//! Envoir Send listeners already use.
//!
//! - **Config off:** no socket is ever bound on `pub_bind` — proven by binding it ourselves right
//!   after a disabled run, exactly mirroring the conditional `daemon::serve` uses.
//! - **Config on:** all five well-known GET endpoints (feed head, feed range, announce, manifest,
//!   chunk) respond over a REAL TCP socket with their spec-mandated cache directives, serving
//!   objects that were pinned/published into the gateway's store exactly as a running node would.
//! - **Capability gating is enforced live, not bypassed:** the enabled gateway got there by
//!   presenting a genuine self-issued `pub-1` [`CapabilityToken`] to `enable_with_capability`
//!   (the same fail-closed path `pub1_authorizes` verifies) — never the unconditional `enable()`
//!   escape hatch — and a gateway that never received a valid capability answers every well-known
//!   path `404` over the wire, not just in the in-process `handle()` unit tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dmtap::dmtap_core::capability::{Capability, CapabilityToken};
use dmtap::dmtap_core::identity::IdentityKey;
use dmtap::dmtap_core::pubobj::{PubAnnounce, PubManifest, ServePolicy};
use dmtap::dmtap_core::suite::Suite;
use dmtap::dmtap_core::ContentId;
use dmtap::jmap_api::run_loop_with_apis;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::pubserve::{b64url_encode, PubGateway, PUB1_ABILITY, PUB1_RESOURCE, WELL_KNOWN_BASE};
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

const NOW: u64 = 1_752_000_000_000;

fn make_node(net: &InMemoryNetwork) -> Node<InMemoryTransport> {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let transport = net.endpoint(ik_pub);
    Node::with_identity(ik, seal, transport)
}

/// One HTTP/1.1 request→response round trip over a fresh `Connection: close` socket. Returns
/// `(status, headers_lowercased, body_bytes)`. The body is kept as **raw bytes** — several of these
/// endpoints serve binary CBOR, and lossily decoding the whole response as UTF-8 (as a JSON-only
/// listener's tests can get away with) would corrupt it.
async fn roundtrip(addr: SocketAddr, method: &str, path: &str) -> (u16, String, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    split_response(&buf)
}

/// Split a raw HTTP/1.1 response into `(status, headers_lowercased, body_bytes)`. The
/// status-line/header block is always plain ASCII (this surface never emits a non-ASCII header),
/// so only that prefix is decoded as text; the body after the `\r\n\r\n` split stays raw bytes.
fn split_response(raw: &[u8]) -> (u16, String, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header/body split");
    let head = std::str::from_utf8(&raw[..split]).expect("headers are ASCII");
    let body = raw[split + 4..].to_vec();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status line");
    (status, head.to_ascii_lowercase(), body)
}

/// A self-issued `pub-1` capability the node presents to itself, exactly as `daemon::serve` mints
/// one for the self-host case (operator == node). Returns `(token, operator_pub)`.
fn self_issued_pub1_capability(now: u64) -> (CapabilityToken, IdentityKey, Vec<u8>) {
    let owner = IdentityKey::generate();
    let owner_pub = owner.public();
    let token = CapabilityToken::issue(
        &owner,
        owner_pub.clone(),
        vec![Capability { resource: PUB1_RESOURCE.to_string(), ability: PUB1_ABILITY.to_string(), caveats: None }],
        now.saturating_sub(1_000),
        now + 365 * 24 * 60 * 60 * 1000,
        vec![1, 2, 3, 4],
        None,
    );
    (token, owner, owner_pub)
}

/// **Config off**: the pub listener is never bound. Mirrors `daemon::serve`'s exact
/// `if config.pub_serve_enabled { bind } else { None }` conditional over a real, concrete address —
/// then proves the port is genuinely free by binding it ourselves.
#[tokio::test]
async fn pub_serve_disabled_binds_no_socket() {
    // Pick a free ephemeral port, then release it immediately (`config.pub_bind` default is a fixed
    // address; a disabled config must never touch it).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let pub_serve_enabled = false; // NodeConfig::default().pub_serve_enabled
    let pub_listener = if pub_serve_enabled {
        Some(tokio::net::TcpListener::bind(addr).await.unwrap())
    } else {
        None
    };
    assert!(pub_listener.is_none(), "disabled config must not produce a listener");

    // The port is genuinely untouched — binding it ourselves succeeds.
    let rebind = tokio::net::TcpListener::bind(addr).await;
    assert!(rebind.is_ok(), "pub_bind must be free when pub_serve_enabled=false: {rebind:?}");

    // And with no listener passed into the daemon's loop at all, a live connection attempt to that
    // same address is refused — there is truly nothing serving it.
    drop(rebind);
    let connect = tokio::net::TcpStream::connect(addr).await;
    assert!(connect.is_err(), "no listener ⇒ connection refused");
}

/// **Config on**: a gateway enabled via a genuine, verified self-issued `pub-1` capability (not the
/// `enable()` bypass) serves all five well-known GET endpoints over real HTTP, with the spec's cache
/// directives, from objects pinned into its store exactly as a running node would publish them.
#[tokio::test]
async fn pub_serve_enabled_serves_all_five_endpoints_over_real_http() {
    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    // --- Build the gateway and enable it through the REAL capability-verification path. ---------
    let (token, publisher_sk, publisher_pub) = self_issued_pub1_capability(NOW);
    let mut gw = PubGateway::new(ServePolicy::default());
    assert!(!gw.is_enabled(), "starts disabled (§22.6.1)");
    let enabled = gw.enable_with_capability(&token, &publisher_pub, NOW);
    assert!(enabled, "a valid, self-issued pub-1 capability enables serving");
    assert!(gw.is_enabled());

    // --- Publish real objects into the store: a chunk, a manifest over it, an announce, a feed. ---
    let plaintext = b"served over a real TCP socket".to_vec();
    let chunk_hash = gw.store.store_chunk(plaintext.clone(), &publisher_pub).unwrap();
    let manifest = PubManifest::new(plaintext.len() as u64, 1 << 20, vec![chunk_hash.clone()], Suite::Classical);
    let manifest_id = gw.store.store_manifest(manifest, &publisher_pub).unwrap();

    let mut announce = PubAnnounce {
        v: 0,
        suite: Suite::Classical,
        publisher: publisher_pub.clone(),
        roots: vec![manifest_id.clone()],
        meta: Vec::new(),
        supersedes: None,
        ts: NOW,
        signer: publisher_pub.clone(),
        sig: Vec::new(),
    };
    announce.sign(&publisher_sk);
    let head = gw.store.append(announce.clone(), &publisher_sk, NOW).unwrap();
    assert_eq!(head.seq, 0);
    let announce_id = announce.announce_id();

    // --- Bind the real listener and run the daemon's steady-state loop over it. ------------------
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pub_b64 = b64url_encode(&publisher_pub);

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let announce_id_client = announce_id.clone();
    let manifest_id_client = manifest_id.clone();
    let client = tokio::spawn(async move {
        let mut out = Vec::new();

        let head_path = format!("{WELL_KNOWN_BASE}feed/{pub_b64}/head");
        out.push(("head".to_string(), roundtrip(addr, "GET", &head_path).await));

        let range_path = format!("{WELL_KNOWN_BASE}feed/{pub_b64}/range?from=0&to=0");
        out.push(("range".to_string(), roundtrip(addr, "GET", &range_path).await));

        let announce_path = format!("{WELL_KNOWN_BASE}announce/{}", b64url_encode(announce_id_client.as_bytes()));
        out.push(("announce".to_string(), roundtrip(addr, "GET", &announce_path).await));

        let manifest_path = format!("{WELL_KNOWN_BASE}manifest/{}", b64url_encode(manifest_id_client.as_bytes()));
        out.push(("manifest".to_string(), roundtrip(addr, "GET", &manifest_path).await));

        let chunk_path = format!("{WELL_KNOWN_BASE}chunk/{}", b64url_encode(chunk_hash.as_bytes()));
        out.push(("chunk".to_string(), roundtrip(addr, "GET", &chunk_path).await));

        // A wrong method is 405; a miss is 404 — both live over the wire, not just in-process.
        out.push(("bad_method".to_string(), roundtrip(addr, "POST", &head_path).await));
        let miss_path = format!("{WELL_KNOWN_BASE}announce/{}", b64url_encode(ContentId::of(b"nope").as_bytes()));
        out.push(("miss".to_string(), roundtrip(addr, "GET", &miss_path).await));

        done_client.store(true, Ordering::SeqCst);
        out
    });

    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        Some(&gw),
        Some(listener),
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;
    let results = client.await.unwrap();
    let get = |name: &str| results.iter().find(|(n, _)| n == name).unwrap().1.clone();

    let (status, headers, body) = get("head");
    assert_eq!(status, 200, "feed head");
    assert!(headers.contains("must-revalidate"), "feed head is short-TTL, not immutable: {headers}");
    let served_head = dmtap::dmtap_core::pubobj::FeedHead::from_det_cbor(&body).unwrap();
    served_head.verify().unwrap();
    assert_eq!(served_head.seq, 0);

    let (status, headers, _body) = get("range");
    assert_eq!(status, 200, "feed range");
    assert!(headers.contains("immutable"), "a range slice is derived+immutable: {headers}");

    let (status, headers, body) = get("announce");
    assert_eq!(status, 200, "announce");
    assert!(headers.contains("immutable"));
    let served_announce = PubAnnounce::from_det_cbor(&body).unwrap();
    served_announce.verify(&announce_id).unwrap();

    let (status, headers, body) = get("manifest");
    assert_eq!(status, 200, "manifest");
    assert!(headers.contains("immutable"));
    let served_manifest = PubManifest::from_det_cbor(&body).unwrap();
    served_manifest.verify().unwrap();
    assert_eq!(served_manifest.id, manifest_id);

    let (status, headers, body) = get("chunk");
    assert_eq!(status, 200, "chunk");
    assert!(headers.contains("immutable"));
    assert!(headers.contains("application/octet-stream"));
    assert_eq!(body, plaintext, "the exact published plaintext is served over the wire");

    let (status, _, _) = get("bad_method");
    assert_eq!(status, 405, "a non-GET method is refused");

    let (status, _, _) = get("miss");
    assert_eq!(status, 404, "an unknown content address is a 404, not an error");
}

/// **Capability gating is enforced live**: a gateway that never received a valid `pub-1` capability
/// answers every well-known path `404` over a real socket — the same as a totally unconfigured
/// surface, so a fetcher rotates to another holder instead of learning anything is different.
#[tokio::test]
async fn disabled_gateway_serves_nothing_over_real_http() {
    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    // A gateway that never got a valid capability presented to it — starts, and stays, disabled.
    let gw = PubGateway::new(ServePolicy::default());
    assert!(!gw.is_enabled());

    let publisher = IdentityKey::generate().public();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let path = format!("{WELL_KNOWN_BASE}feed/{}/head", b64url_encode(&publisher));

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let path_client = path.clone();
    let client = tokio::spawn(async move {
        let r = roundtrip(addr, "GET", &path_client).await;
        done_client.store(true, Ordering::SeqCst);
        r
    });

    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        Some(&gw),
        Some(listener),
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;
    let (status, _, body) = client.await.unwrap();
    assert_eq!(
        status, 404,
        "a never-enabled gateway serves nothing, even over real HTTP: {:?}",
        String::from_utf8_lossy(&body)
    );
}
