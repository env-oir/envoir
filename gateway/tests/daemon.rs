//! End-to-end daemon tests (spec §7): the real recipient directory ([`FileDirectory`], §3) and the
//! real mesh-delivery adapter ([`HttpMeshDelivery`], §4) wired into the inbound pipeline, plus the
//! graceful-shutdown accept loop ([`MxListener::serve_until`]).
//!
//! The flagship test drives an inbound RFC 5322 message for a **configured** recipient through the
//! full bridge — SPF + DKIM + DMARC evaluated, converted to a signed, recipient-sealed MOTE,
//! provenance-stamped — and hands it to the HTTP mesh adapter, which POSTs it to a loopback node
//! ingest server. It asserts the directory hit, the delivered MOTE, and the provenance chain.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{validate, Envelope, Hpke, Kind, Outcome, RecipientCtx, SealKeypair};

use envoir_gateway::attestation::{AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::b64;
use envoir_gateway::dkim::{self, DkimKey, DkimVerdict, StaticDkimKeys};
use envoir_gateway::dmarc::{DmarcVerdict, InMemoryDmarcResolver};
use envoir_gateway::inbound::{
    AllowAllAbuse, DeliveryOutcome, DkimPolicy, DmarcHandling, InboundGateway, KeyDirectory,
    MeshDelivery, MxSession, RecipientKey, SpfPolicy,
};
use envoir_gateway::provenance::Origin;
use envoir_gateway::spf::{InMemorySpfResolver, SpfResult};
use envoir_gateway::{FileDirectory, HttpMeshDelivery, MxListener, NullMesh};

const NOW: u64 = 1_752_600_000_000;
const GW_DOMAIN: &str = "example.org";
const GW_SELECTOR: &str = "gw1";
const SENDER_DOMAIN: &str = "acme.example";
const PEER_IP: &str = "203.0.113.9";

// ---------------------------------------------------------------------------------------------
// A loopback "node ingest" HTTP server: accepts one POST, captures the body + selected headers,
// answers `200 OK` (a durable-custody ack). This stands in for a co-located `envoir-node`.
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Captured {
    body: Vec<u8>,
    mote_id_hdr: Option<String>,
    att_domain_hdr: Option<String>,
    smtp_rcpt_hdr: Option<String>,
}

/// Spawn a one-shot ingest server. `ack` chooses the HTTP status (200 → durable ack, 503 → not).
fn spawn_ingest(ack: bool) -> (SocketAddr, Arc<Mutex<Option<Captured>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ingest bind");
    let addr = listener.local_addr().expect("ingest addr");
    let slot: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let slot2 = slot.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(_) => return,
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut w = stream.try_clone().expect("clone");
        let mut r = BufReader::new(stream);

        // Read the request head (headers up to the blank line), pulling out what we assert on.
        let mut content_length = 0usize;
        let mut cap = Captured::default();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break; // end of headers
            }
            if let Some((name, val)) = trimmed.split_once(':') {
                let (name, val) = (name.trim().to_ascii_lowercase(), val.trim().to_string());
                match name.as_str() {
                    "content-length" => content_length = val.parse().unwrap_or(0),
                    "x-dmtap-mote-id" => cap.mote_id_hdr = Some(val),
                    "x-dmtap-gateway-domain" => cap.att_domain_hdr = Some(val),
                    "x-dmtap-smtp-rcpt" => cap.smtp_rcpt_hdr = Some(val),
                    _ => {}
                }
            }
        }
        // Read exactly Content-Length body bytes (the MOTE det-CBOR).
        let mut body = vec![0u8; content_length];
        if r.read_exact(&mut body).is_ok() {
            cap.body = body;
        }
        *slot2.lock().unwrap() = Some(cap);

        let status = if ack { "200 OK" } else { "503 Service Unavailable" };
        let _ = w.write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        let _ = w.flush();
    });
    (addr, slot, handle)
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

struct TestRecipient {
    email: String,
    ik: IdentityKey,
    seal: SealKeypair,
}
impl TestRecipient {
    fn new(email: &str) -> Self {
        TestRecipient { email: email.into(), ik: IdentityKey::generate(), seal: SealKeypair::generate() }
    }
}

/// Write a reference directory file mapping `recip` and return a loaded [`FileDirectory`].
fn directory_file_for(recip: &TestRecipient, tag: &str) -> (FileDirectory, std::path::PathBuf) {
    let mut path = std::env::temp_dir();
    path.push(format!("envoir-gw-e2e-{}-{tag}.txt", std::process::id()));
    let line = format!(
        "# e2e directory\n{}  {}  {}\n",
        recip.email,
        b64::encode(&recip.ik.public()),
        b64::encode(recip.seal.public()),
    );
    std::fs::write(&path, line).expect("write directory");
    let dir = FileDirectory::load(&path).expect("load directory");
    (dir, path)
}

/// A DKIM-signed legacy message from `alice@SENDER_DOMAIN` to `to`, returning `(bytes, pubkey)`.
fn dkim_signed_message(to: &str) -> (Vec<u8>, [u8; 32]) {
    let mut seed = [0u8; 32];
    for (i, b) in SENDER_DOMAIN.bytes().chain(b"s1".iter().copied()).enumerate().take(32) {
        seed[i] = b;
    }
    let key = DkimKey::from_seed(SENDER_DOMAIN, "s1", &seed);
    let pubk = key.public_bytes();
    let msg = format!(
        "From: alice@{SENDER_DOMAIN}\r\nTo: {to}\r\nSubject: hello over the bridge\r\n\
         Date: Tue, 15 Jul 2026 00:00:00 +0000\r\n\r\nGreetings across the bridge.\r\n"
    )
    .into_bytes();
    let header = dkim::sign(&key, &msg, NOW / 1000);
    let mut out = header.into_bytes();
    out.extend_from_slice(&msg);
    (out, pubk)
}

// ---------------------------------------------------------------------------------------------
// 1. Full inbound bridge: directory hit → SPF/DKIM/DMARC evaluated → signed MOTE → provenance →
//    HTTP mesh delivery to a loopback node → durable ack → 250. Asserts all three artefacts.
// ---------------------------------------------------------------------------------------------

#[test]
fn e2e_inbound_bridge_directory_mesh_and_provenance() {
    let recip = TestRecipient::new("bob@example.org");
    let (directory, dir_path) = directory_file_for(&recip, "bridge");

    // The node ingest server (durable-acks the MOTE).
    let (ingest_addr, captured, ingest) = spawn_ingest(true);
    let mesh = HttpMeshDelivery::new(&format!("http://{ingest_addr}/dmtap/ingest"))
        .expect("mesh endpoint")
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(5));

    // Real SPF / DKIM / DMARC resolvers so all three checks are genuinely evaluated (annotate mode).
    let (signed, dkim_pub) = dkim_signed_message(&recip.email);
    let spf = InMemorySpfResolver::new()
        .with_txt(SENDER_DOMAIN, &["v=spf1 ip4:203.0.113.0/24 -all"]);
    let dkim = StaticDkimKeys::new().publish(SENDER_DOMAIN, "s1", dkim_pub.to_vec());
    let dmarc = InMemoryDmarcResolver::new()
        .with_txt(&format!("_dmarc.{SENDER_DOMAIN}"), &["v=DMARC1; p=none"]);

    let att_key = AttestationKey::generate(GW_DOMAIN, GW_SELECTOR);
    let att_pub = att_key.public();
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![att_key],
        Box::new(directory),
        Box::new(mesh),
        Box::new(AllowAllAbuse),
    )
    .with_spf(Box::new(spf), SpfPolicy::Annotate)
    .with_dkim(Box::new(dkim), DkimPolicy::Annotate)
    .with_dmarc(Box::new(dmarc), DmarcHandling::Annotate);

    // The three legacy-auth checks are really evaluated (not fabricated / skipped).
    let mail_from = format!("alice@{SENDER_DOMAIN}");
    let spf_outcome = gw.evaluate_spf(PEER_IP, &mail_from, Some(SENDER_DOMAIN));
    assert_eq!(spf_outcome.result, SpfResult::Pass, "SPF genuinely passes for the authorized IP");
    assert!(matches!(gw.verify_inbound_dkim(&signed), DkimVerdict::Pass { .. }), "DKIM genuinely verifies");
    assert!(
        matches!(gw.evaluate_dmarc(&signed, Some(&spf_outcome), &mail_from), DmarcVerdict::Pass),
        "DMARC aligns (SPF + DKIM) for the header-from domain"
    );

    // Provenance chain (§7.8 / §18.8.1): stamp the same bytes and verify the gateway hop.
    let bridged = gw.wrap_attest_and_stamp(&mail_from, &recip.email, &signed, NOW).expect("stamp");
    let published = StaticGwKeys::new().publish(GW_DOMAIN, GW_SELECTOR, att_pub.clone());
    let gw_key = published.resolve_gw_key(GW_DOMAIN, GW_SELECTOR);
    bridged
        .gateway_attestation
        .verify(gw_key.as_deref(), &signed)
        .expect("gateway attestation verifies over the exact legacy bytes");
    assert_eq!(bridged.provenance.origin, Origin::GatewayTouched);
    assert_eq!(bridged.provenance.gateway_hops(), 1, "exactly one gateway hop in the provenance chain");
    assert!(!bridged.provenance.is_pure_mesh());

    // Drive the full inbound SMTP transaction; the terminating '.' converts + POSTs to the node.
    let mut s = MxSession::new(&gw, PEER_IP, NOW);
    assert_eq!(s.greeting().code, 220);
    assert_eq!(s.feed_line(&format!("EHLO {SENDER_DOMAIN}")).code, 250);
    assert_eq!(s.feed_line(&format!("MAIL FROM:<{mail_from}>")).code, 250);
    assert_eq!(s.feed_line(&format!("RCPT TO:<{}>", recip.email)).code, 250, "directory RESOLVED the recipient");
    assert_eq!(s.feed_line("DATA").code, 354);
    for line in String::from_utf8(signed.clone()).unwrap().split("\r\n") {
        // dot-stuffing not needed for this content; feed each line as-is.
        assert_eq!(s.feed_line(line).code, 0);
    }
    let final_reply = s.feed_line(".");
    assert_eq!(final_reply.code, 250, "node durably acked the POSTed MOTE → 250");

    ingest.join().expect("ingest thread");
    let cap = captured.lock().unwrap().take().expect("the node received a POST");

    // The node received the SMTP recipient in the header and the MOTE id matches the delivered MOTE.
    assert_eq!(cap.att_domain_hdr.as_deref(), Some(GW_DOMAIN), "gateway attestation domain header");
    assert_eq!(cap.smtp_rcpt_hdr.as_deref(), Some(recip.email.as_str()), "SMTP recipient header");

    // The POST body is the canonical MOTE, sealed to the DIRECTORY-resolved recipient key, and it
    // decrypts to the original legacy body — the whole bridge, over the real mesh adapter.
    let env = Envelope::from_det_cbor(&cap.body).expect("body is a valid MOTE envelope");
    assert_eq!(cap.mote_id_hdr.as_deref(), Some(b64::encode(env.id.as_bytes()).as_str()), "mote-id header binds the body");
    assert_eq!(env.kind, Kind::Mail);
    assert!(env.to.resolves_to_key(&recip.ik.public()), "MOTE sealed to the directory recipient key");

    let ctx = RecipientCtx { our_ik: &recip.ik.public(), seal_secret: recip.seal.secret(), sender_is_known: true };
    let payload = match validate(&Hpke, &env, &ctx).expect("validate") {
        Outcome::Accepted(p) => *p,
        Outcome::Deferred => panic!("known-contact MOTE must be accepted"),
    };
    assert!(
        String::from_utf8_lossy(&payload.body).contains("Greetings across the bridge"),
        "the original legacy body crossed the bridge into the delivered MOTE"
    );

    let _ = std::fs::remove_file(&dir_path);
}

// ---------------------------------------------------------------------------------------------
// 2. A node that does NOT ack (non-2xx) → no durable custody → 451, never a false 250.
// ---------------------------------------------------------------------------------------------

#[test]
fn e2e_node_that_refuses_yields_451_not_a_false_ack() {
    let recip = TestRecipient::new("bob@example.org");
    let (directory, dir_path) = directory_file_for(&recip, "noack");
    let (ingest_addr, _cap, ingest) = spawn_ingest(false); // 503 → not a durable ack
    let mesh = HttpMeshDelivery::new(&format!("http://{ingest_addr}/ingest"))
        .expect("mesh")
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(5));
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(GW_DOMAIN, GW_SELECTOR)],
        Box::new(directory),
        Box::new(mesh),
        Box::new(AllowAllAbuse),
    );

    let msg = format!(
        "From: alice@{SENDER_DOMAIN}\r\nTo: {}\r\nSubject: hi\r\n\r\nbody\r\n",
        recip.email
    )
    .into_bytes();
    let reply = gw.accept_message(&format!("alice@{SENDER_DOMAIN}"), &recip.email, &msg, NOW);
    assert_eq!(reply.code, 451, "a node that returns non-2xx is a NoAck → 451, never a false 250");
    ingest.join().ok();
    let _ = std::fs::remove_file(&dir_path);
}

// ---------------------------------------------------------------------------------------------
// 3. Graceful shutdown: `serve_until` stops accepting and returns cleanly when the flag flips.
// ---------------------------------------------------------------------------------------------

#[test]
fn serve_until_shuts_down_gracefully_on_the_flag() {
    // A minimal gateway (empty directory, NullMesh) — this test is about the daemon loop lifecycle,
    // not delivery. It must bind, stay up, then return promptly once the shutdown flag is set.
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(GW_DOMAIN, GW_SELECTOR)],
        Box::new(envoir_gateway::InMemoryDirectory::new()),
        Box::new(NullMesh),
        Box::new(AllowAllAbuse),
    );
    let listener = MxListener::bind("127.0.0.1:0", None).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let shutdown = Arc::new(AtomicBool::new(false));

    // `InboundGateway` is not `Send`, so the daemon loop runs on THIS thread; a helper thread probes
    // that it is up, then flips the shutdown flag. The helper returns whether the probe saw a 220.
    let shutdown2 = shutdown.clone();
    let control = thread::spawn(move || -> bool {
        // Give serve_until a moment to enter its accept loop.
        thread::sleep(Duration::from_millis(150));
        let greeted = match TcpStream::connect(addr) {
            Ok(mut probe) => {
                probe.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut greeting = [0u8; 3];
                let ok = probe.read_exact(&mut greeting).is_ok() && &greeting == b"220";
                probe.write_all(b"QUIT\r\n").ok();
                ok
            }
            Err(_) => false,
        };
        // Signal graceful shutdown; serve_until must observe it and return.
        thread::sleep(Duration::from_millis(50));
        shutdown2.store(true, Ordering::SeqCst);
        greeted
    });

    // Blocks until the helper flips the flag; a hang here (never returning) fails the test via the
    // harness timeout — proving the loop actually terminates on the flag rather than running forever.
    let start = Instant::now();
    listener.serve_until(&gw, &shutdown).expect("serve_until returns cleanly on shutdown");
    assert!(start.elapsed() < Duration::from_secs(30), "shutdown was prompt, not a timeout");

    let greeted = control.join().expect("control thread joined cleanly");
    assert!(greeted, "daemon was up and greeted a new connection with 220 before shutdown");
}

// Touch DeliveryOutcome + KeyDirectory + MeshDelivery + NullMesh so an unused-import regression in
// this file's public-surface imports is caught at compile time rather than drifting silently.
#[test]
fn public_surface_types_are_constructible() {
    let dir = envoir_gateway::InMemoryDirectory::new()
        .with_recipient("x@y.z", RecipientKey { ik: vec![1], seal_pub: vec![2] });
    assert!(dir.resolve("x@y.z").is_some());
    let _ = DeliveryOutcome::Acked;
    fn _accepts_mesh(_m: &dyn MeshDelivery) {}
    fn _accepts_dir(_d: &dyn KeyDirectory) {}
    _accepts_mesh(&NullMesh);
    _accepts_dir(&dir);
}
