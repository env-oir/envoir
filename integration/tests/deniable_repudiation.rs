//! Deniable 1:1 exchange (spec §5.2.1) proving the repudiation property holds all the way to the
//! **wire**, not just as an in-memory struct comparison.
//!
//! `dmtap-deniable`'s own crate tests already prove `DeniableSession::forge_peer_message` produces
//! a struct a fresh copy of the receiving session accepts as genuine
//! (`repudiation_receiver_can_forge_a_sender_message`). What's missing — and the cross-crate value
//! this integration test adds — is carrying that forged message through the REAL `dmtap-core` wire
//! encoding (`DeniableFrame::det_cbor` / `from_det_cbor`, the exact bytes a real transport would
//! carry, §18.3.9) and back, then decrypting the round-tripped bytes. That closes the gap between
//! "the forgery works as a Rust value" and "the forgery works as the bytes that actually cross the
//! network" — the only form of the deniability guarantee that matters to a real observer of a
//! transcript.

use dmtap_core::deniable::{DeniableFrame, DeniableMessage, DeniablePayload};
use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{Headers, Kind};

use dmtap_deniable::{initiate, DeniableIdentity, DeniableResponder};

fn ik(seed: u8) -> IdentityKey {
    IdentityKey::from_seed(&[seed; 32])
}

fn payload(from: &[u8], body: &str) -> DeniablePayload {
    DeniablePayload {
        from: from.to_vec(),
        kind: Kind::Chat,
        headers: Headers::default(),
        body: body.as_bytes().to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}

/// Serialize a `DeniableMessage` through the real `dmtap-core` wire object and parse it back,
/// panicking (real test failure, not a swallowed error) if either step fails or yields a different
/// discriminator — the honest "this really crossed the wire format" check.
fn wire_round_trip(msg: DeniableMessage) -> DeniableMessage {
    let bytes = DeniableFrame::Message(msg).det_cbor();
    match DeniableFrame::from_det_cbor(&bytes).expect("wire bytes decode") {
        DeniableFrame::Message(m) => m,
        DeniableFrame::Init(_) => panic!("expected a Message frame back"),
    }
}

#[test]
fn forged_message_is_indistinguishable_and_authenticates_after_a_real_wire_round_trip() {
    let alice = DeniableIdentity::new(ik(0xA1));
    let mut bob = DeniableResponder::new(DeniableIdentity::new(ik(0xB0)), 2, 1, 1_700_000_000_000);

    // Real X3DH handshake (§5.2.1(a)) over the actual dmtap-deniable session crate.
    let (mut a_session, init) =
        initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "genuine hello")).unwrap();
    let (b_session, first) = bob.accept(&init).expect("bob completes the handshake");
    assert_eq!(first.body, b"genuine hello");

    // Bob (the RECEIVER, holding only the shared ratchet state — no access to Alice's keys) forges
    // a message that claims to be from Alice.
    let confession = "I, Alice, confess";
    let forged = b_session
        .forge_peer_message(&payload(&alice.ik_public(), confession))
        .expect("receiver can forge from the shared receiving chain");

    // A genuine message from Alice at the same logical position, for shape comparison.
    let genuine = a_session.encrypt(&payload(&alice.ik_public(), confession));

    // Structural indistinguishability BEFORE the wire round-trip (the property under test).
    assert_eq!(forged.dh, genuine.dh);
    assert_eq!(forged.n, genuine.n);
    assert_eq!(forged.pn, genuine.pn);
    assert_eq!(forged.ct.len(), genuine.ct.len());

    // Now push both through the REAL dmtap-core wire encoding (`DeniableFrame`, §18.3.9) and back —
    // proving the forgery is not just a same-shaped Rust struct but genuinely the same bytes a real
    // transport would carry, still structurally indistinguishable after the round trip.
    let forged_wire = wire_round_trip(forged);
    let genuine_wire = wire_round_trip(genuine);
    assert_eq!(forged_wire.dh, genuine_wire.dh, "wire round-trip preserves indistinguishability");
    assert_eq!(forged_wire.n, genuine_wire.n);
    assert_eq!(forged_wire.ct.len(), genuine_wire.ct.len());

    // The wire-round-tripped FORGERY authenticates: a fresh copy of Bob's receiving state accepts
    // it as a valid "from Alice" message and recovers the exact forged content. The MAC is
    // symmetric (a shared-key MAC, not a signature), so Bob could always have produced these bytes
    // himself — a transcript proves nothing about who actually typed "I, Alice, confess".
    let mut judge = b_session.snapshot();
    let opened = judge.decrypt(&forged_wire).expect("the forged wire bytes authenticate as genuine");
    assert_eq!(opened.body, confession.as_bytes());
    assert_eq!(opened.from, alice.ik_public(), "the forgery even claims Alice as the sender");

    // And the SAME judge state equally accepts Alice's real wire-round-tripped message — the two
    // are interchangeable both as structs and as bytes, which is exactly the repudiation guarantee.
    let mut judge2 = b_session.snapshot();
    let opened_genuine = judge2.decrypt(&genuine_wire).expect("genuine wire bytes also authenticate");
    assert_eq!(opened_genuine.body, confession.as_bytes());
}

#[test]
fn tampered_wire_bytes_still_fail_the_mac() {
    // Sanity companion: the repudiation property is about WHO could have authored a message, not
    // an "anything goes" channel — a bit-flipped wire ciphertext must still fail closed after a
    // real wire round trip, exactly as the in-memory tamper tests already prove.
    let alice = DeniableIdentity::new(ik(0xC1));
    let mut bob = DeniableResponder::new(DeniableIdentity::new(ik(0xD0)), 1, 1, 1);
    let (mut a_session, init) =
        initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "hi")).unwrap();
    let (mut b_session, _) = bob.accept(&init).unwrap();

    let mut msg = a_session.encrypt(&payload(&alice.ik_public(), "secret over the wire"));
    let last = msg.ct.len() - 1;
    msg.ct[last] ^= 0x01;
    let tampered_wire = wire_round_trip(msg);

    assert!(
        b_session.decrypt(&tampered_wire).is_err(),
        "a tampered ciphertext must fail the MAC even after a real wire round trip"
    );
}
