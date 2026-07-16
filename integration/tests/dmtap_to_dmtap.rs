//! DMTAP → DMTAP: two real `envoir-node` nodes exchange an encrypted MOTE + ack over the TCP
//! transport (spec §2, §4, §19.3). This is the pure-mesh path — no gateway, no legacy — proving
//! the node crate's seal → validate → decrypt → ack loop works over real `127.0.0.1` sockets.

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::TcpTransport;

fn poll_until_outcome(node: &mut Node<TcpTransport>) -> Vec<InboundOutcome> {
    for _ in 0..1000 {
        let outcomes = node.poll();
        if !outcomes.is_empty() {
            return outcomes;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    node.poll()
}

fn poll_until(node: &mut Node<TcpTransport>, mut pred: impl FnMut(&Node<TcpTransport>) -> bool) -> bool {
    for _ in 0..1000 {
        node.poll();
        if pred(node) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    pred(node)
}

#[test]
fn two_real_nodes_exchange_encrypted_mote_and_ack_over_tcp() {
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    let alice_tp = TcpTransport::bind(alice_ik_pub.clone(), "127.0.0.1:0").unwrap();
    let bob_tp = TcpTransport::bind(bob_ik_pub.clone(), "127.0.0.1:0").unwrap();
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.local_socket_addr());
    bob_tp.add_peer(alice_ik_pub.clone(), alice_tp.local_socket_addr());

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    let secret = b"end-to-end encrypted across two processes";
    let id = alice.send_mail(&bob_ik_pub, "hello over the mesh", secret).expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    let outcomes = poll_until_outcome(&mut bob);
    match &outcomes[0] {
        InboundOutcome::Stored { id: got, .. } => assert_eq!(got, &id, "stored the exact MOTE"),
        other => panic!("expected Stored, got {other:?}"),
    }
    assert_eq!(bob.inbox().exists(), 1);
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the decrypted plaintext round-trips over the socket"
    );

    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over TCP and the sender queue reaches ACKED"
    );
}
