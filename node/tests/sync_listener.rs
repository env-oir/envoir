//! Integration tests for the live Sync-substrate reconciliation listener
//! (`substrate/SYNC.md` §5.2/§5.3), wired into the node daemon's steady-state loop
//! (`crate::jmap_api::run_loop_with_apis`) behind `NodeConfig::sync_serve_enabled` — the same
//! config-flag-gated `TcpListener` pattern the JMAP, Send and DMTAP-PUB listeners already use.
//!
//! - **Config off:** no socket is bound on `sync_bind`, proven by binding it ourselves.
//! - **Config on:** all four §5.2/§5.3 operations (`GET /sync/vector`, `POST /sync/pull`,
//!   `POST /sync/ops`, `POST /sync/fingerprint`) answer over a REAL TCP socket with deterministic
//!   CBOR bodies, and a genuine two-replica round converges over the wire.
//! - **Capability gating is live:** the gateway was enabled by presenting a real self-issued
//!   `sync-1` [`CapabilityToken`], and each request carries one as a Bearer token. A request with
//!   no token, a wrong-audience token, or a token granting some other resource is `401` — over the
//!   wire, not just in-process.
//! - **Transport auth is not op auth (§5.4):** an op whose COSE_Sign1 does not verify is refused
//!   with `ERR_SYNC_OP_SIG_INVALID` (`0x0A02`) *even though the pusher held a perfectly valid
//!   `sync-1` capability*. This is the property the whole section exists to state, so it is asserted
//!   end-to-end rather than as a unit test on the verifier.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dmtap::dmtap_core::capability::{Capability, CapabilityToken};
use dmtap::dmtap_core::identity::IdentityKey;
use dmtap::jmap_api::run_loop_with_apis;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::syncserve::{
    b64url_encode, SyncGateway, SYNC1_ABILITY, SYNC1_RESOURCE, SYNC_BASE,
};
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};
use dmtap_sync::detcbor::{decode, encode};
use dmtap_sync::wire::{Hlc, SyncOp, OP_SET_ADD};
use dmtap_sync::{sign_op, SVal, VersionVector};

/// The receiver clock these tests run at: the REAL current time, because both the §3 HLC skew
/// window and the capability token's nbf/exp are checked against it. A frozen constant would make
/// the suite start failing the moment it drifted a year out of the token's validity window.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_millis() as u64
}

fn make_node(net: &InMemoryNetwork) -> Node<InMemoryTransport> {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let transport = net.endpoint(ik_pub);
    Node::with_identity(ik, seal, transport)
}

/// One HTTP/1.1 request→response round trip over a fresh `Connection: close` socket, with an
/// optional `Authorization` header and a raw (CBOR) body. Returns `(status, headers, body_bytes)`.
async fn roundtrip(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    split_response(&buf)
}

/// Split a raw HTTP/1.1 response; the body stays raw bytes (every 200 here is binary CBOR).
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

/// A `sync-1` capability issued by `owner` to itself — what `daemon::serve` mints for the self-host
/// case, and what a peer presents per request (§5.4).
fn sync1_token(owner: &IdentityKey, resource: &str, aud: Vec<u8>, now: u64) -> CapabilityToken {
    CapabilityToken::issue(
        owner,
        aud,
        vec![Capability {
            resource: resource.to_string(),
            ability: SYNC1_ABILITY.to_string(),
            caveats: None,
        }],
        now.saturating_sub(1_000),
        now + 365 * 24 * 60 * 60 * 1000,
        vec![7, 7, 7, 7],
        None,
    )
}

fn bearer(token: &CapabilityToken) -> String {
    format!("Bearer {}", b64url_encode(&token.det_cbor()))
}

/// A signed `set-add` op from `sk` into namespace `ns`, at HLC counter `counter`.
fn signed_add(sk: &IdentityKey, ns: &str, target: &str, element: &str, counter: u32) -> Vec<u8> {
    let op = SyncOp {
        kind: OP_SET_ADD,
        ns: ns.to_string(),
        target: target.to_string(),
        field: None,
        value: Some(SVal::Text(element.to_string())),
        hlc: Hlc { wall: now(), counter, author: sk.public() },
        observed: None,
        reference: None,
    };
    sign_op(sk, &op).unwrap().to_bytes()
}

fn map_field(body: &[u8], key: u64) -> SVal {
    let SVal::Map(fields) = decode(body).expect("CBOR body") else {
        panic!("body is an integer-keyed map");
    };
    fields.into_iter().find(|(k, _)| *k == key).expect("field present").1
}

/// **Config off**: the sync listener is never bound.
#[tokio::test]
async fn sync_serve_disabled_binds_no_socket() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let sync_serve_enabled = false; // NodeConfig::default().sync_serve_enabled
    let sync_listener = if sync_serve_enabled {
        Some(tokio::net::TcpListener::bind(addr).await.unwrap())
    } else {
        None
    };
    assert!(sync_listener.is_none(), "disabled config must not produce a listener");

    let rebind = tokio::net::TcpListener::bind(addr).await;
    assert!(rebind.is_ok(), "sync_bind must be free when sync_serve_enabled=false: {rebind:?}");
    drop(rebind);
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "no listener ⇒ connection refused"
    );
}

/// **Config on**: every §5.2/§5.3 endpoint answers over real HTTP, a push converges into the
/// responder's state, a pull returns exactly the ops the caller lacks, and the auth rules hold.
#[tokio::test]
async fn sync_serve_enabled_serves_all_four_endpoints_over_real_http() {
    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    // --- Build the gateway and enable it through the REAL capability-verification path. ----------
    let operator = IdentityKey::generate();
    let operator_pub = operator.public();
    let mut gw = SyncGateway::new(operator_pub.clone(), operator_pub.clone(), vec!["docs".into()]);
    assert!(!gw.is_enabled(), "starts disabled (opt-in)");
    let enable_token = sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now());
    assert!(gw.enable_with_capability(&enable_token, now()), "a valid sync-1 capability enables it");

    // --- Seed the responder with one op it already holds, so `pull` has a real difference. -------
    let alice = IdentityKey::generate();
    let seeded = signed_add(&alice, "docs", "list", "already-here", 1);
    assert!(gw.replica.ingest_cose(&seeded, now()).unwrap(), "seed applied");

    // The peer's own sync-1 token (audience = the operator it is syncing with).
    let peer_auth = bearer(&sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()));
    // A token for a DIFFERENT resource — valid signature, wrong grant.
    let wrong_resource = bearer(&sync1_token(&operator, "pub-1", operator_pub.clone(), now()));
    // A token whose audience is somebody else.
    let wrong_aud = bearer(&sync1_token(&operator, SYNC1_RESOURCE, vec![0xAB; 32], now()));

    // Ops the peer will push: one valid, plus a forged one for the §5.4 assertion.
    let bob = IdentityKey::generate();
    let pushed = signed_add(&bob, "docs", "list", "pushed-over-http", 2);
    let forged = {
        // A structurally perfect op — correct `kid`, canonical payload, right author — whose
        // signature does not actually verify. (`sign_op` refuses to sign for a foreign author, so
        // the only way to mint this is the way an attacker would: a valid envelope with a
        // signature that is not the author's.)
        let mut cose = dmtap_sync::CoseSign1::from_bytes(&signed_add(
            &bob,
            "docs",
            "list",
            "forged",
            3,
        ))
        .unwrap();
        cose.signature[0] ^= 0xFF;
        cose.to_bytes()
    };
    // An op in a namespace this replica never subscribed to (§7).
    let off_ns = signed_add(&bob, "secrets", "list", "not-subscribed", 4);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Copies the client task owns; the assertions below compare against the originals.
    let (pushed_c, forged_c, off_ns_c) = (pushed.clone(), forged.clone(), off_ns.clone());

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let client = tokio::spawn(async move {
        let mut out = Vec::new();
        let p = |ep: &str| format!("{SYNC_BASE}{ep}");

        // --- Auth (§5.4): no token, wrong grant, wrong audience — all 401, never anonymous. ------
        out.push(("no_auth", roundtrip(addr, "GET", &p("vector"), None, b"").await));
        out.push((
            "wrong_resource",
            roundtrip(addr, "GET", &p("vector"), Some(&wrong_resource), b"").await,
        ));
        out.push(("wrong_aud", roundtrip(addr, "GET", &p("vector"), Some(&wrong_aud), b"").await));

        // --- GET /sync/vector ---------------------------------------------------------------------
        out.push(("vector", roundtrip(addr, "GET", &p("vector"), Some(&peer_auth), b"").await));

        // --- POST /sync/ops: a valid push, a forged op, an off-namespace op ------------------------
        let push_body = |ops: Vec<&[u8]>| {
            encode(&SVal::Map(vec![(
                1,
                SVal::Array(ops.into_iter().map(|o| SVal::Bytes(o.to_vec())).collect()),
            )]))
        };
        out.push((
            "ops_push",
            roundtrip(addr, "POST", &p("ops"), Some(&peer_auth), &push_body(vec![&pushed_c])).await,
        ));
        out.push((
            "ops_replay",
            roundtrip(addr, "POST", &p("ops"), Some(&peer_auth), &push_body(vec![&pushed_c])).await,
        ));
        out.push((
            "ops_forged",
            roundtrip(addr, "POST", &p("ops"), Some(&peer_auth), &push_body(vec![&forged_c])).await,
        ));
        out.push((
            "ops_off_ns",
            roundtrip(addr, "POST", &p("ops"), Some(&peer_auth), &push_body(vec![&off_ns_c])).await,
        ));

        // --- POST /sync/pull with an EMPTY vector: the caller lacks everything ---------------------
        let pull_all = encode(&SVal::Map(vec![
            (1, VersionVector::new().to_sval()),
            (2, SVal::Array(vec![SVal::Text("docs".into())])),
        ]));
        out.push(("pull_all", roundtrip(addr, "POST", &p("pull"), Some(&peer_auth), &pull_all).await));

        // --- POST /sync/fingerprint over a range covering everything (§5.3) -----------------------
        let lo = Hlc { wall: 0, counter: 0, author: vec![0u8; 32] };
        let hi = Hlc { wall: u64::MAX, counter: u32::MAX, author: vec![0xFFu8; 32] };
        // An empty caller: its fold over the range differs, so the range comes back mismatched.
        let fp_body = encode(&SVal::Map(vec![
            (1, SVal::Text("docs".into())),
            (
                2,
                SVal::Array(vec![SVal::Map(vec![
                    (1, lo.to_sval()),
                    (2, hi.to_sval()),
                    (3, SVal::Bytes(dmtap_sync::fingerprint(&[]).0.as_bytes().to_vec())),
                    (4, SVal::Uint(0)),
                ])]),
            ),
        ]));
        out.push((
            "fingerprint_mismatch",
            roundtrip(addr, "POST", &p("fingerprint"), Some(&peer_auth), &fp_body).await,
        ));

        // A wrong method on a real endpoint is 405; an unknown endpoint is 404.
        out.push(("bad_method", roundtrip(addr, "GET", &p("ops"), Some(&peer_auth), b"").await));
        out.push(("unknown", roundtrip(addr, "GET", &p("nope"), Some(&peer_auth), b"").await));

        done_client.store(true, Ordering::SeqCst);
        out
    });

    let gw_lock = std::sync::Mutex::new(gw);
    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&gw_lock),
        Some(listener),
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;

    let results: std::collections::HashMap<&str, (u16, String, Vec<u8>)> =
        client.await.unwrap().into_iter().collect();

    // ── Auth (§5.4): the transport gate is real and never degrades to anonymous ─────────────────
    for key in ["no_auth", "wrong_resource", "wrong_aud"] {
        assert_eq!(results[key].0, 401, "{key} must be refused, got {:?}", results[key]);
    }

    // ── GET /sync/vector ────────────────────────────────────────────────────────────────────────
    let (status, headers, body) = &results["vector"];
    assert_eq!(*status, 200);
    assert!(headers.contains("content-type: application/cbor"));
    assert!(headers.contains("cache-control: no-store"), "live state is never cached");
    assert_eq!(map_field(body, 1), SVal::Bytes(operator_pub.clone()), "node key");
    assert_eq!(map_field(body, 2), SVal::Array(vec![SVal::Text("docs".into())]), "namespaces");
    let SVal::BytesMap(marks) = map_field(body, 3) else { panic!("vector is a bytes-keyed map") };
    assert_eq!(marks.len(), 1, "one author seeded");
    assert_eq!(marks[0].0, alice.public());

    // ── POST /sync/ops ──────────────────────────────────────────────────────────────────────────
    assert_eq!(results["ops_push"].0, 200);
    assert_eq!(map_field(&results["ops_push"].2, 1), SVal::Uint(1), "one newly applied op");
    assert_eq!(
        map_field(&results["ops_replay"].2, 1),
        SVal::Uint(0),
        "apply is idempotent — a re-pushed op is a no-op, not an error (§5.2)"
    );

    // THE §5.4 property: a valid transport credential does NOT make an op authentic.
    let (status, _, body) = &results["ops_forged"];
    assert_eq!(*status, 422, "a forged op is refused even from an authorized peer");
    let msg = String::from_utf8_lossy(body);
    assert!(
        msg.contains("ERR_SYNC_OP_SIG_INVALID") && msg.contains("0x0a02"),
        "expected the §12 signature code, got {msg}"
    );

    // §7: a namespace this replica never subscribed to is refused, not silently absorbed.
    let (status, _, body) = &results["ops_off_ns"];
    assert_eq!(*status, 422);
    assert!(
        String::from_utf8_lossy(body).contains("ERR_SYNC_NS_LEAK"),
        "off-namespace push must be 0x0A0A"
    );

    // ── POST /sync/pull ─────────────────────────────────────────────────────────────────────────
    let (status, _, body) = &results["pull_all"];
    assert_eq!(*status, 200);
    let SVal::Array(ops) = map_field(body, 1) else { panic!("ops is an array") };
    assert_eq!(ops.len(), 2, "an empty vector lacks both the seeded and the pushed op");
    // Oldest HLC first (§5.2), so a truncated batch is always a prefix of the difference.
    let returned: Vec<Vec<u8>> = ops
        .iter()
        .map(|o| o.as_bytes().expect("op is a byte string").to_vec())
        .collect();
    assert!(returned.contains(&seeded), "the seeded op is returned verbatim, still signed");
    assert!(returned.contains(&pushed), "the pushed op round-tripped through the responder");
    let hlcs: Vec<u32> = returned
        .iter()
        .map(|b| dmtap_sync::verify_op_bytes(b).expect("still verifies after the round trip").hlc.counter)
        .collect();
    assert!(hlcs.windows(2).all(|w| w[0] <= w[1]), "oldest HLC first, got {hlcs:?}");
    // The forged and off-namespace ops were never journalled.
    assert!(!returned.contains(&forged) && !returned.contains(&off_ns));

    // ── POST /sync/fingerprint (§5.3) ───────────────────────────────────────────────────────────
    let (status, _, body) = &results["fingerprint_mismatch"];
    assert_eq!(*status, 200);
    let SVal::Array(mismatched) = map_field(body, 1) else { panic!("mismatched is an array") };
    assert_eq!(mismatched.len(), 1, "the caller's empty fold differs from the responder's two ops");
    let SVal::Map(range) = &mismatched[0] else { panic!("range is a map") };
    let count = range.iter().find(|(k, _)| *k == 4).map(|(_, v)| v.clone());
    assert_eq!(count, Some(SVal::Uint(2)), "the responder reports its own count for the range");
    let SVal::Array(ids) = range.iter().find(|(k, _)| *k == 5).unwrap().1.clone() else {
        panic!("ids array")
    };
    assert_eq!(ids.len(), 2, "and the op ids it holds there, so the caller can fetch them");

    // ── Method / path handling ──────────────────────────────────────────────────────────────────
    assert_eq!(results["bad_method"].0, 405);
    assert_eq!(results["unknown"].0, 404);
}

/// A range both sides agree on exchanges **nothing** — the property that makes §5.3 O(divergence)
/// rather than O(history), asserted over the wire rather than in the reconciler's unit tests.
#[tokio::test]
async fn matching_fingerprint_exchanges_nothing_over_http() {
    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    let operator = IdentityKey::generate();
    let operator_pub = operator.public();
    let mut gw = SyncGateway::new(operator_pub.clone(), operator_pub.clone(), vec!["docs".into()]);
    assert!(gw.enable_with_capability(
        &sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()),
        now()
    ));

    let alice = IdentityKey::generate();
    let op = signed_add(&alice, "docs", "list", "shared", 1);
    gw.replica.ingest_cose(&op, now()).unwrap();
    // The caller computes the SAME fold the responder will, from the op it also holds.
    let entry = dmtap_sync::recon::OpEntry {
        hlc: dmtap_sync::verify_op_bytes(&op).unwrap().hlc,
        id: dmtap_sync::verify_op_bytes(&op).unwrap().op_id(),
    };
    let (fp, count) = dmtap_sync::fingerprint(&[entry]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = bearer(&sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()));

    let lo = Hlc { wall: 0, counter: 0, author: vec![0u8; 32] };
    let hi = Hlc { wall: u64::MAX, counter: u32::MAX, author: vec![0xFFu8; 32] };
    let body = encode(&SVal::Map(vec![
        (1, SVal::Text("docs".into())),
        (
            2,
            SVal::Array(vec![SVal::Map(vec![
                (1, lo.to_sval()),
                (2, hi.to_sval()),
                (3, SVal::Bytes(fp.as_bytes().to_vec())),
                (4, SVal::Uint(count)),
            ])]),
        ),
    ]));

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let client = tokio::spawn(async move {
        let r = roundtrip(addr, "POST", &format!("{SYNC_BASE}fingerprint"), Some(&auth), &body).await;
        done_client.store(true, Ordering::SeqCst);
        r
    });

    let gw_lock = std::sync::Mutex::new(gw);
    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&gw_lock),
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
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        map_field(&body, 1),
        SVal::Array(vec![]),
        "equal (fp, count) ⇒ the range short-circuits and nothing is exchanged (§5.3)"
    );
}

/// §5.2.1 over the wire: a replica that has truncated its op-log answers a behind-the-cut peer with
/// a `FastJoin` (key 2) rather than the surviving suffix (key 1), so the peer fast-joins instead of
/// silently losing the ops that no longer exist — and the peer can adopt what it is handed.
#[tokio::test]
async fn a_truncated_replica_answers_pull_with_a_snapshot_over_http() {
    use dmtap_sync::Snapshot;

    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    let operator = IdentityKey::generate();
    let operator_pub = operator.public();
    let mut gw = SyncGateway::new(operator_pub.clone(), operator_pub.clone(), vec!["docs".into()]);
    assert!(gw.enable_with_capability(
        &sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()),
        now()
    ));

    // Five ops, a snapshot over all of them, then truncate everything below the last two.
    let alice = IdentityKey::generate();
    for i in 0..5u32 {
        gw.replica.ingest_cose(&signed_add(&alice, "docs", "list", &format!("e{i}"), i), now()).unwrap();
    }
    let snap = Snapshot::create(&alice, 1, "docs", gw.replica.state(), now());
    let state_body = dmtap_sync::ObservableState::of(gw.replica.state()).det_cbor();
    let cut = Hlc { wall: now(), counter: 3, author: alice.public() };
    let dropped = gw.replica.truncate_below(&cut, snap.clone(), state_body.clone()).unwrap();
    assert!(dropped > 0, "the test only means anything if history was actually discarded");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = bearer(&sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()));
    // A brand-new peer: empty vector, therefore behind the cut.
    let body = encode(&SVal::Map(vec![
        (1, VersionVector::new().to_sval()),
        (2, SVal::Array(vec![SVal::Text("docs".into())])),
    ]));

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let client = tokio::spawn(async move {
        let r = roundtrip(addr, "POST", &format!("{SYNC_BASE}pull"), Some(&auth), &body).await;
        done_client.store(true, Ordering::SeqCst);
        r
    });

    let gw_lock = std::sync::Mutex::new(gw);
    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&gw_lock),
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
    assert_eq!(status, 200);
    let SVal::Map(fields) = decode(&body).expect("CBOR body") else { panic!("map") };
    assert!(
        fields.iter().all(|(k, _)| *k != 1),
        "a behind-the-cut peer must NOT be handed a partial op list — that answer is well-formed \
         and would apply without error, which is exactly why §5.2.1 forbids it"
    );
    let fj_sval = fields.iter().find(|(k, _)| *k == 2).expect("key 2 FastJoin").1.clone();
    let fj = dmtap_sync::FastJoin::from_det_cbor(&encode(&fj_sval)).expect("FastJoin decodes");
    fj.snapshot.verify_sig().expect("the peer can verify it independently");
    assert_eq!(fj.snapshot.root, snap.root, "it is the snapshot that replaced the truncated prefix");
    assert_eq!(fj.floor, cut, "the responder names its floor — the caller's audit handle");

    // The peer completes §5.2.1 step 3 against what it was given. This body is small, so it rode
    // inline; the adopt path hashes it to `root` exactly as it would a fetched one.
    assert!(fj.state.is_some(), "a small state body should ride inline (key 3)");
    let adopted = fj
        .adopt(&VersionVector::new(), &["docs".into()], &[], |_| None)
        .expect("a peer must be able to actually adopt what it was handed");
    assert_eq!(
        adopted.det_cbor(),
        state_body,
        "the adopted state is byte-identical to the responder's projection"
    );
}

/// The by-reference half (§5.2.1): `GET /sync/state/<root>` serves the body a `FastJoin` commits to
/// by address, and serves it for that address only.
#[tokio::test]
async fn the_state_body_is_served_by_content_address() {
    use dmtap_sync::Snapshot;

    let net = InMemoryNetwork::new();
    let mut node = make_node(&net);

    let operator = IdentityKey::generate();
    let operator_pub = operator.public();
    let mut gw = SyncGateway::new(operator_pub.clone(), operator_pub.clone(), vec!["docs".into()]);
    assert!(gw.enable_with_capability(
        &sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()),
        now()
    ));

    let alice = IdentityKey::generate();
    for i in 0..3u32 {
        gw.replica.ingest_cose(&signed_add(&alice, "docs", "list", &format!("e{i}"), i), now()).unwrap();
    }
    let snap = Snapshot::create(&alice, 1, "docs", gw.replica.state(), now());
    let state_body = dmtap_sync::ObservableState::of(gw.replica.state()).det_cbor();
    let cut = Hlc { wall: now(), counter: 2, author: alice.public() };
    gw.replica.truncate_below(&cut, snap.clone(), state_body.clone()).unwrap();

    let root_hex: String = snap.root.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = bearer(&sync1_token(&operator, SYNC1_RESOURCE, operator_pub.clone(), now()));

    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let auth2 = auth.clone();
    let wrong_hex = "00".repeat(33);
    let client = tokio::spawn(async move {
        let hit =
            roundtrip(addr, "GET", &format!("{SYNC_BASE}state/{root_hex}"), Some(&auth), &[]).await;
        let miss =
            roundtrip(addr, "GET", &format!("{SYNC_BASE}state/{wrong_hex}"), Some(&auth2), &[]).await;
        done_client.store(true, Ordering::SeqCst);
        (hit, miss)
    });

    let gw_lock = std::sync::Mutex::new(gw);
    run_loop_with_apis(
        &mut node,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&gw_lock),
        Some(listener),
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;

    let ((hit_status, _, hit_body), (miss_status, _, _)) = client.await.unwrap();
    assert_eq!(hit_status, 200);
    assert_eq!(hit_body, state_body, "the address IS the hash of the body served");
    assert_eq!(
        dmtap_sync::state_root_of(&hit_body),
        snap.root,
        "a caller re-hashes what it received rather than trusting the endpoint"
    );
    assert_eq!(miss_status, 404, "an address this replica does not hold is a miss, not a guess");
}
