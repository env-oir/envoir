//! Two nodes exchange a real encrypted MOTE over the TCP/loopback transport (spec §2, §4, §19.3).
//!
//! The same seal → validate → decrypt → ack path as the in-memory E2E test, but driven over real
//! `127.0.0.1` sockets via [`TcpTransport`] — proving a MOTE (and its ack) survives the
//! length-prefixed wire framing between what could be two separate OS processes.

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::TcpTransport;

/// Poll `node` repeatedly (bridging the async socket gap) until it yields at least one inbound
/// outcome or the budget runs out.
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

/// Poll `node` until `pred` holds (e.g. an ack advances the outbound state) or the budget runs out.
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
fn two_nodes_exchange_a_real_mote_over_tcp_and_ack() {
    // Identities double as logical transport addresses.
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    // Bind both listeners on ephemeral loopback ports.
    let alice_tp = TcpTransport::bind(alice_ik_pub.clone(), "127.0.0.1:0").unwrap();
    let bob_tp = TcpTransport::bind(bob_ik_pub.clone(), "127.0.0.1:0").unwrap();
    // Cross-register sockets (the peer book stands in for §4.2 mesh discovery).
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.local_socket_addr());
    bob_tp.add_peer(alice_ik_pub.clone(), alice_tp.local_socket_addr());

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);

    // Mutual pinning.
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    let secret = b"a MOTE crossing a real socket";
    let id = alice.send_mail(&bob_ik_pub, "over tcp", secret).expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "dispatched over the socket");

    // Bob receives, validates (§2.7), decrypts, stores, and acks.
    let outcomes = poll_until_outcome(&mut bob);
    match &outcomes[0] {
        InboundOutcome::Stored { id: got, .. } => assert_eq!(got, &id),
        other => panic!("expected Stored over TCP, got {other:?}"),
    }
    assert_eq!(bob.inbox().exists(), 1);
    let raw = &bob.inbox().messages[0].raw;
    assert!(raw.windows(secret.len()).any(|w| w == secret), "exact plaintext survived the wire");

    // Bob's ack travels back over TCP; Alice's queue reaches ACKED.
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "sender reaches ACKED after the ack returns over the socket"
    );
}
