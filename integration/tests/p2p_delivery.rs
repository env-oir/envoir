//! DMTAP → DMTAP over the **real libp2p mesh** (spec §4, §4.1) — the highest-value cross-component
//! path this crate proves: two real `envoir-node` nodes, wired over a real `dmtap-p2p`
//! (TCP + Noise + Yamux + request-response) swarm on `127.0.0.1`, exchange a real HPKE-sealed MOTE
//! + ack, and the delivered message is then visible through a **real** `dmtap-mail` JMAP view.
//!
//! `dmtap_to_dmtap.rs` (this crate) already proves the same delivery shape over the node's own
//! in-tree `TcpTransport`; `dmtap-p2p`'s own crate tests already prove its swarm mechanics in
//! isolation (Kademlia PUT/GET, retry-then-route-learned). What's missing — and what this file
//! adds — is the three-crate composition: the *real* libp2p transport carrying the MOTE all the
//! way into a JMAP projection, exactly the seam a real deployment would exercise end-to-end.

use std::time::Duration;

use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;

use dmtap_mail::jmap::{self, Request};
use dmtap_p2p::Libp2pTransport;

use serde_json::json;

/// Generous loopback bound: real dialing + Noise handshake + Yamux + request-response, occasionally
/// slow under CI load.
const SPIN: Duration = Duration::from_secs(15);

fn tcp_listener(t: &Libp2pTransport) -> libp2p::Multiaddr {
    t.wait_for_listener(SPIN)
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

fn poll_until(node: &mut Node<Libp2pTransport>, mut pred: impl FnMut(&Node<Libp2pTransport>) -> bool) -> bool {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        node.poll();
        if pred(node) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return pred(node);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run a JMAP `Email/query` → `Email/get` chain against the node's live store (same helper shape
/// as `legacy_to_dmtap.rs`) and return the first email object.
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
fn two_real_nodes_exchange_a_real_mote_over_real_libp2p_and_it_is_visible_over_jmap() {
    // Real DMTAP identities + sealing keys for both nodes (spec §1, §2.4).
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    // Two real libp2p swarms on ephemeral loopback ports (the actual §4.1 stack: TCP/Noise/Yamux).
    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .expect("alice swarm starts");
    let bob_tp =
        Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .expect("bob swarm starts");

    // Alice learns Bob's route (peer id + dialable multiaddr) — a stand-in for the §4.2 signed
    // location record a real resolver would hand her. Bob auto-learns Alice's route from her
    // inbound frame (§19.3.2 "back over the same channel"), so no reverse route is seeded here.
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.peer_id(), bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // Alice seals a real MOTE (HPKE, §2.4) and hands it to the real swarm.
    let secret = "the whole stack: libp2p wire, node validation, JMAP projection";
    let id = alice
        .send_mail(&bob_ik_pub, "hello over the real mesh", secret.as_bytes())
        .expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the real swarm");

    // Bob receives it off the real socket, runs §2.7 validation, decrypts, stores it.
    assert!(
        poll_until(&mut bob, |b| b.inbox().exists() == 1),
        "the sealed MOTE should arrive and decrypt over the real libp2p swarm"
    );
    // The JMAP `accountId` is echoed, not used to filter the (single-mailbox, per-node) store —
    // any stable label works; a human-readable one keeps the assertions legible.
    let email = jmap_first_email(&mut bob, "bob@mesh.local");
    assert_eq!(email["subject"], "hello over the real mesh", "subject projected to JMAP");
    let body = email["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    assert!(
        body.contains(secret),
        "the decrypted plaintext round-tripped: real libp2p wire → node store → JMAP view; got {body:?}"
    );

    // The ack travels back over the same real connection until Alice's sender queue reaches ACKED.
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over real libp2p and the sender queue reaches ACKED"
    );
}
