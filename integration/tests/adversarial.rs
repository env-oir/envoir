//! Adversarial cross-component paths (spec §2.7, §2.7a, §19.3.1).
//!
//! Real crates, hostile inputs. A tampered or forged MOTE fed to a real `envoir-node` is rejected
//! **before** any decryption and is never acked; a well-formed MOTE from an unpinned (cold) sender
//! is *held but not acked* — matching the reconciled rule that the ack axis is binary (ack iff
//! delivered to the inbox; a merely-deferred cold MOTE is UNacked, §2.7a / §19.3.1 step 9 / §20.2).

use dmtap::identity::IdentityKey;
use dmtap::inbound::{DropReason, InboundOutcome};
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_core::mote::{build_mote, Envelope, Hpke, Kind, MoteDraft};

/// A recipient node whose transport address equals its identity key, plus its key material.
fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    (Node::with_identity(ik, seal, net.endpoint(ik_pub.clone())), ik_pub, seal_pub)
}

/// Seal a real MOTE (via dmtap-core `build_mote`) from a fresh sender to `to_ik`/`to_seal`, returning
/// the wire bytes and the sender's identity (its transport return path).
fn sealed_to(net: &InMemoryNetwork, to_ik: &[u8], to_seal: &[u8; 32], body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, body.to_vec());
    let env = build_mote(&Hpke, &sender, &eph, to_ik, to_seal, draft).unwrap();
    net.endpoint(sender.public()); // register the sender so an ack (if any) has somewhere to go.
    (env.det_cbor(), sender.public())
}

#[test]
fn tampered_ciphertext_is_rejected_before_decryption_and_not_acked() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    let (bytes, sender) = sealed_to(&net, &bob_ik, &bob_seal, b"tamper me");
    bob.add_contact(&sender, [7u8; 32]); // pinned, so only the tamper — not cold-sender defer — stops it.

    // Flip a ciphertext byte: the content address (§2.7 step 2) no longer matches, so the MOTE is
    // dropped before any HPKE open is attempted.
    let mut env = Envelope::from_det_cbor(&bytes).unwrap();
    env.ciphertext[0] ^= 0xff;
    let outcome = bob.receive_mote(&sender, &env.det_cbor());

    assert_eq!(outcome, InboundOutcome::Dropped(DropReason::BadContentAddress));
    assert!(!outcome.acked(), "a forged MOTE is never acked (§2.7a)");
    assert_eq!(bob.inbox().exists(), 0, "nothing stored");
    assert_eq!(net.in_flight(), 0, "no ack emitted");
}

#[test]
fn forged_sender_signature_is_rejected_and_not_acked() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    let (bytes, sender) = sealed_to(&net, &bob_ik, &bob_seal, b"forge me");
    bob.add_contact(&sender, [7u8; 32]);

    // Corrupt the envelope sender_sig but keep `id` matching the ciphertext, so the specific failure
    // is the signature check (§2.7 step 3), not the address check.
    let mut env = Envelope::from_det_cbor(&bytes).unwrap();
    if let Some(sig) = env.sender_sig.as_mut() {
        sig[0] ^= 0xff;
    }
    let outcome = bob.receive_mote(&sender, &env.det_cbor());

    assert_eq!(outcome, InboundOutcome::Dropped(DropReason::BadPayloadSig));
    assert!(!outcome.acked());
    assert_eq!(bob.inbox().exists(), 0);
    assert_eq!(net.in_flight(), 0, "no ack emitted for a forgery");
}

#[test]
fn deferred_cold_mote_is_held_but_unacked_and_sender_never_sees_acked() {
    let net = InMemoryNetwork::new();
    // Two real nodes: Alice knows Bob's key but Bob has NOT pinned Alice ⇒ she is a cold sender.
    let (mut alice, _alice_ik, _alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.learn_key(&bob_ik, bob_seal);

    let id = alice.send_mail(&bob_ik, "cold", b"do you know me?").unwrap();
    let outcomes = bob.poll();

    // Held in the requests area, NOT the inbox, and NOT acked.
    assert_eq!(outcomes[0], InboundOutcome::Deferred { id: id.clone() });
    assert!(!outcomes[0].acked(), "a deferred cold MOTE is not acked (§2.7a / §19.3.1 step 9)");
    assert_eq!(bob.inbox().exists(), 0, "never the inbox");
    assert_eq!(bob.requests().exists(), 1, "held in the requests area (30-day retention)");

    // Because Bob sent no ack, Alice's queue never reaches ACKED — her own retry would EXPIRE.
    alice.poll();
    assert_ne!(
        alice.outbound_state(&id),
        Some(OutState::Acked),
        "no ack ⇒ the sender never sees ACKED for a merely-deferred cold MOTE"
    );
}
