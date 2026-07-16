//! Full round trip (spec §3.3, §2.4, §4.1, §2.7, §8): the entire naming → seal → mesh → mail
//! composition in **one** path — KT-resolve a recipient's identity (`dmtap-naming`), build and
//! HPKE-seal a real MOTE to the resolved key (`dmtap-core`, driven through the node's own
//! `resolve_and_pin`/`send_mail` seam), carry it over the **real libp2p mesh** (`dmtap-p2p`), and
//! read it back through a real `dmtap-mail` JMAP view.
//!
//! Each stage already has its own narrower test elsewhere: `kt_resolution_and_delegation.rs` proves
//! `dmtap-naming`'s resolution algorithm directly against a KT log (no node, no mesh, no mail);
//! `p2p_delivery.rs` proves the real libp2p wire carries a MOTE into a JMAP view (no naming — the
//! recipient is `add_contact`-pinned by hand, bypassing resolution entirely). What's missing — and
//! what this file adds — is the node's own [`dmtap::node::Node::resolve_and_pin`] seam actually
//! driving a KT-verified binding into a real mesh send, so the whole `name@domain` →
//! delivered-and-readable-mail path is proven as one composition: exactly what
//! [`send_mail_to_name`](dmtap::node::Node::send_mail_to_name) exists to let a real client do in a
//! single call (here split into its two calls, `resolve_and_pin` then `send_mail`, so each stage's
//! result is independently assertable).
//!
//! This whole delivery never invokes any `envoir-gateway` component — it is provably pure-mesh
//! (§7.8.1(b)) simply because no gateway ever touched it. `gateway_provenance.rs` is the companion
//! test that makes gateway-touched vs. pure-mesh explicitly distinguishable and provable within one
//! recipient's inbox.

use std::time::{Duration, Instant};

use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::naming::seal_key_bundle;
use dmtap::node::Node;
use dmtap::outbound::OutState;

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, KeyPackageBundleRef};
use dmtap_core::TimestampMs;

use dmtap_mail::jmap::{self, Request};
use dmtap_naming::kt::InMemoryKtLog;
use dmtap_naming::{DmtapTxtRecord, InMemoryKeyPackages, InMemoryResolver};

use dmtap_p2p::Libp2pTransport;

use serde_json::json;

const NOW: TimestampMs = 1_752_600_000_000;
const NAME: &str = "bob@mesh.example";

/// Generous loopback bound: real dialing + Noise handshake + Yamux + request-response, occasionally
/// slow under CI load (same bound `p2p_delivery.rs` uses).
const SPIN: Duration = Duration::from_secs(15);

fn tcp_listener(t: &Libp2pTransport) -> libp2p::Multiaddr {
    t.wait_for_listener(SPIN)
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

/// Pump **both** real swarms while waiting on a predicate. Each side's libp2p transport drives its
/// own socket on a background task, but the node's `poll()` is what drains that transport's inbox
/// channel and advances the §2.7 pipeline (delivery) / §20.1 sender machine (ack). Waiting on
/// delivery therefore has to keep *Bob* polled (to drain + accept the inbound MOTE) **and** *Alice*
/// polled (so her sender machine keeps servicing retries and, later, drains the returning ack) —
/// polling only one side stalls the half whose channel never gets read. This mirrors the two
/// separate `poll_until` waits `p2p_delivery.rs` runs, collapsed into one loop that pumps both.
fn poll_both_until(
    a: &mut Node<Libp2pTransport>,
    b: &mut Node<Libp2pTransport>,
    mut pred: impl FnMut(&Node<Libp2pTransport>, &Node<Libp2pTransport>) -> bool,
) -> bool {
    let deadline = Instant::now() + SPIN;
    loop {
        a.poll();
        b.poll();
        if pred(a, b) {
            return true;
        }
        if Instant::now() >= deadline {
            return pred(a, b);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run a JMAP `Email/query` → `Email/get` chain against the node's live store (same helper shape as
/// `legacy_to_dmtap.rs` / `p2p_delivery.rs`) and return the first email object.
fn jmap_first_email(node: &mut Node<Libp2pTransport>, account: &str) -> serde_json::Value {
    let req: Request = serde_json::from_value(json!({
        "using": [jmap::CAP_CORE, jmap::CAP_MAIL],
        "methodCalls": [
            ["Email/query", { "accountId": account }, "0"],
            ["Email/get", {
                "accountId": account,
                "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                "properties": ["subject", "from", "bodyValues"]
            }, "1"]
        ]
    }))
    .unwrap();
    let resp = jmap::process(node.store_mut(), account, &req);
    let get = &resp.method_responses[1].1;
    get["list"][0].clone()
}

#[test]
fn kt_resolved_name_seals_and_delivers_over_real_libp2p_into_a_jmap_readable_inbox() {
    // Bob's real DMTAP identity + sealing key, published exactly as spec §3.2/§3.3 model it: a
    // content-addressed KeyPackage bundle carrying his real X25519 sealing key, a signed `Identity`
    // naming him, and a DNS `_dmtap` TXT record cross-checked against that Identity.
    let bob_ik = IdentityKey::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();

    let bundle_bytes = seal_key_bundle(&bob_seal_pub);
    let bundle_ref = KeyPackageBundleRef::new("/mesh/kp/bob", ContentId::of(&bundle_bytes));

    let identity = Identity::create_classical(
        &bob_ik,
        0,
        vec![],
        bundle_ref,
        ContentId::of(b"bob-recovery-policy"),
        vec![NAME.to_owned()],
        None,
        NOW,
    );
    let txt = DmtapTxtRecord {
        version: "dmtap1".into(),
        suite: 1,
        ik: bob_ik_pub.clone(),
        id: identity.content_id(),
        kt: vec!["https://kt.mesh.example/log".into()],
        keypkgs: "/mesh/kp/bob".into(),
    }
    .to_txt();

    let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[0x77; 32]));
    log.append_identity(NAME, &identity).expect("classical ik present");

    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("bob._dmtap.mesh.example", &txt);
    resolver.publish_identity(identity);
    resolver.pin_log(log);

    let mut kps = InMemoryKeyPackages::new();
    kps.publish("/mesh/kp/bob", bundle_bytes);

    // Two real libp2p swarms — the actual §4.1 wire — plus the transport-level route Alice needs to
    // dial Bob. Naming resolves IDENTITY keys (§3.3); the dialable network location is a separate
    // §4.2 concern, seeded here exactly as `p2p_delivery.rs` seeds it.
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();
    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .expect("alice swarm starts");
    let bob_tp = Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .expect("bob swarm starts");
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.peer_id(), bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    // Bob already knows Alice as a warm contact (§2.7 step 5): her inbound MOTE classifies as a
    // *known* sender, so it lands in the INBOX and is acked — the ordinary two-way path this test
    // asserts. (`p2p_delivery.rs` pins the same way; the companion cold-sender test below omits this
    // pin precisely to exercise the §2.7a deferred path instead.) Alice, in turn, learned Bob's real
    // sealing key + identity through the KT `resolve_and_pin` above — this is the reverse pin.
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // 1. KT-resolve "bob@mesh.example" (dmtap-naming): DNS parse, Identity fetch/verify, DNS⇄Identity
    //    cross-check, KT inclusion vs the pinned log's signed tree head — fail-closed the whole way.
    //    Only on success is Bob's sealing key fetched (content-verified) and pinned into Alice's
    //    contact/directory cache.
    let resolved_ik = alice
        .resolve_and_pin(NAME, &resolver, &kps)
        .expect("KT-verified resolution succeeds and pins Bob");
    assert_eq!(resolved_ik, bob_ik_pub, "resolution pins the real, KT-attested identity key");

    // 2. Build + HPKE-seal a real MOTE (dmtap-core) to the resolved key and hand it to the real
    //    libp2p swarm (dmtap-p2p).
    let secret = "the whole chain: KT resolution, real HPKE seal, real libp2p wire, JMAP view";
    let id = alice
        .send_mail(&resolved_ik, "resolved over the real mesh", secret.as_bytes())
        .expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the real swarm");

    // 3. Deliver over the real libp2p mesh; Bob runs the real §2.7 validation pipeline, decrypts,
    //    stores it.
    assert!(
        poll_both_until(&mut alice, &mut bob, |_, b| b.inbox().exists() == 1),
        "the KT-resolved, HPKE-sealed MOTE should arrive over the real libp2p swarm"
    );

    // 4. Read via a real dmtap-mail JMAP view.
    let email = jmap_first_email(&mut bob, NAME);
    assert_eq!(email["subject"], "resolved over the real mesh", "subject projected to JMAP");
    let body = email["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    assert!(
        body.contains(secret),
        "content round-tripped end to end: KT resolve → seal → real mesh → JMAP; got {body:?}"
    );

    // The ack travels back over the same real connection until Alice's sender queue reaches ACKED —
    // the full loop the naming resolution kicked off is provably complete.
    assert!(
        poll_both_until(&mut alice, &mut bob, |a, _| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over real libp2p and the sender queue reaches ACKED"
    );
}

/// Companion to the warm path above: the same real libp2p wire, but Bob has **not** pinned Alice, so
/// her MOTE is an unproven **cold sender** (§2.7 step 5 / §2.7a / §19.3.1 step 9). The negative
/// dispositions this asserts are precisely what keeps the warm test above honest — it proves the
/// INBOX-landing + ACK it sees are earned by the contact pin, not granted to any sender who can reach
/// the socket. Over the real mesh the sealed MOTE must therefore:
///   * arrive and decrypt (Bob holds the sealing secret), yet be filed in the **requests** area,
///     never the INBOX (§2.7a: a cold sender does not get inbox placement); and
///   * never be acked — acking a cold sender would falsely signal *delivered* and confirm existence
///     (§19.3.2), so Alice's sender queue stays un-`ACKED` (it retries, then EXPIREs).
/// This is the real-libp2p analogue of the in-process cold-sender assertion in `adversarial.rs`.
#[test]
fn cold_sender_mote_over_real_libp2p_is_deferred_to_requests_never_inbox_and_never_acked() {
    // Real identities + sealing keys for both nodes (spec §1, §2.4).
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    // Two real libp2p swarms on ephemeral loopback ports; Alice learns Bob's dialable route (§4.2).
    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .expect("alice swarm starts");
    let bob_tp = Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .expect("bob swarm starts");
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.peer_id(), bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);

    // Alice learns Bob's sealing key so she can seal to him, but does *not* pin him and — crucially —
    // Bob never pins Alice. `learn_key` (vs. `add_contact`) is exactly the "knows the recipient key,
    // is not yet a mutual contact" cold-sender shape (§2.7a).
    alice.learn_key(&bob_ik_pub, bob_seal_pub);

    // Alice seals a real MOTE and hands it to the real swarm.
    let secret = "a cold sender still reaches the socket — but earns neither inbox nor ack";
    let id = alice
        .send_mail(&bob_ik_pub, "cold over the real mesh", secret.as_bytes())
        .expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the real swarm");

    // It arrives + decrypts over the real wire, but is deferred to the requests area, not the INBOX.
    assert!(
        poll_both_until(&mut alice, &mut bob, |_, b| b.requests().exists() == 1),
        "the cold-sender MOTE should arrive and be filed in the requests area over the real swarm"
    );
    assert_eq!(bob.inbox().exists(), 0, "a cold sender must never land in the INBOX (§2.7a)");

    // And it is never acked: keep pumping both swarms across the full window — the sender queue must
    // NOT reach ACKED (a cold sender is owed no receipt, §19.3.2). It legitimately stays IN_FLIGHT /
    // RETRY or EXPIREs; the one state it must never reach is ACKED.
    let acked = poll_both_until(&mut alice, &mut bob, |a, _| {
        a.outbound_state(&id) == Some(OutState::Acked)
    });
    assert!(!acked, "a cold sender must never be acked");
    assert_ne!(alice.outbound_state(&id), Some(OutState::Acked), "sender queue never reaches ACKED");
    assert_eq!(bob.inbox().exists(), 0, "still nothing in the INBOX after the full wait");
    assert_eq!(bob.requests().exists(), 1, "the deferred MOTE remains held in the requests area");
}
