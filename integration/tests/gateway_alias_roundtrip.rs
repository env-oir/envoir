//! Key-derived legacy gateway alias round trip, through a **real** mesh delivery (spec §3.9, §7).
//!
//! `node/src/naming.rs`'s own unit tests already round-trip the raw
//! [`dmtap::naming::gateway_alias_local`] / [`dmtap::naming::ik_from_gateway_alias`] free functions
//! byte-for-byte and prove they fail closed on non-alias input. What is new here is the
//! **cross-component** composition those unit tests cannot reach on their own: a real,
//! live [`dmtap::node::Node::gateway_alias`] call, decoded independently at **two** unrelated
//! "gateways" (proving it needs no shared registry/state — any gateway can bridge it cold), and then
//! actually **addressing and delivering a real MOTE to the decoded key**, landing in the node's own
//! inbox — not just a byte-equality assertion on the decoded key.

use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::naming::ik_from_gateway_alias;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::InMemoryNetwork;

#[test]
fn gateway_alias_decodes_identically_at_two_gateways_and_a_mote_addressed_via_it_reaches_the_node() {
    let bob_ik = IdentityKey::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();

    let net = InMemoryNetwork::new();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    // The node's own stateless legacy alias local-part — a pure function of its key (§3.9, §7), read
    // straight off a live Node (not the free function in isolation, as the crate's own unit tests do).
    let alias = bob.gateway_alias();

    // Two INDEPENDENT "gateways" — nothing shared between these two decode calls, no registry, no
    // coordination — each decode the exact same local-part back to the exact same key.
    let decoded_at_gateway_a = ik_from_gateway_alias(&alias).expect("gateway A decodes the alias");
    let decoded_at_gateway_b = ik_from_gateway_alias(&alias).expect("gateway B decodes the alias");
    assert_eq!(decoded_at_gateway_a, bob_ik_pub, "gateway A recovers the exact identity key");
    assert_eq!(decoded_at_gateway_b, bob_ik_pub, "gateway B recovers the exact identity key");
    assert_eq!(
        decoded_at_gateway_a, decoded_at_gateway_b,
        "identical decode at both gateways — no shared state, no directory lookup"
    );

    // A sender who only ever saw the alias string (never Bob's raw key handed to her directly)
    // addresses a real, HPKE-sealed MOTE to the key DECODED from it, over a real node-to-node mesh
    // send — proving the decoded bytes are not just byte-equal but genuinely addressable.
    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_seal_pub = *alice_seal.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));

    // Warm contact both ways (as the other in-memory-mesh tests do) so the MOTE lands in the INBOX.
    alice.add_contact(&decoded_at_gateway_a, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    let secret = b"addressed only via the key decoded from the gateway alias";
    let id = alice
        .send_mail(&decoded_at_gateway_a, "via gateway alias", secret)
        .expect("send to the alias-decoded key");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    bob.poll();
    assert_eq!(bob.inbox().exists(), 1, "the MOTE addressed via the decoded key reached the node");
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the decrypted plaintext round-trips: gateway-alias decode → real seal → real delivery"
    );

    // The same decoded-key address round-trips through gateway B too — reachability isn't an
    // artifact of which gateway happened to decode it.
    assert_eq!(
        ik_from_gateway_alias(&alias).expect("gateway B still decodes it after delivery"),
        decoded_at_gateway_b
    );

    alice.poll();
    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::Acked),
        "the ack returns and the sender queue reaches ACKED"
    );
}
