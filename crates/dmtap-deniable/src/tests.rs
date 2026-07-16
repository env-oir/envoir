//! Property tests for the deniable 1:1 mode (spec §5.2.1), including the deniability-relevant
//! properties expressed as executable assertions: bidirectional messaging, MAC tamper-detection,
//! forward secrecy, **constructive repudiation** (the receiver forges a sender message), and the
//! last-resort replay defense.

use dmtap_core::deniable::{DeniableInit, DeniableMessage, DeniablePayload};
use dmtap_core::id::ContentId;
use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{Headers, Kind};
use dmtap_core::suite::Suite;

use crate::{initiate, DeniableError, DeniableIdentity, DeniableResponder};

fn ik(seed: u8) -> IdentityKey {
    IdentityKey::from_seed(&[seed; 32])
}

/// A minimal chat payload with a chosen body.
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

/// Alice (initiator) + Bob (responder) with a bundle carrying `num_opks` one-time prekeys.
fn setup(num_opks: usize) -> (DeniableIdentity, DeniableResponder) {
    let alice = DeniableIdentity::new(ik(0xA1));
    let bob = DeniableResponder::new(DeniableIdentity::new(ik(0xB0)), num_opks, 1, 1_700_000_000_000);
    (alice, bob)
}

#[test]
fn x3dh_completes_and_messages_flow_bidirectionally() {
    let (alice, mut bob) = setup(4);

    // Alice runs X3DH against Bob's published bundle and sends the first message.
    let (mut a_session, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "hi bob"))
        .expect("initiate");
    assert!(init.opk_ref.is_some(), "initiator consumes a one-time prekey when offered");

    // Bob accepts, completing the async handshake and decrypting the first message.
    let (mut b_session, first) = bob.accept(&init).expect("bob accepts init");
    assert_eq!(first.body, b"hi bob");
    assert_eq!(bob.opks_remaining(), 3, "the referenced opk is consumed");

    // Bob replies (drives the DH ratchet), Alice decrypts.
    let reply = b_session.encrypt(&payload(&bob.bundle().ik, "hi alice"));
    assert_eq!(a_session.decrypt(&reply).expect("alice decrypts reply").body, b"hi alice");

    // Alice sends again; Bob decrypts. Several turns, in order.
    for i in 0..3u8 {
        let m = a_session.encrypt(&payload(&alice.ik_public(), &format!("a{i}")));
        assert_eq!(b_session.decrypt(&m).unwrap().body, format!("a{i}").as_bytes());
        let r = b_session.encrypt(&payload(&bob.bundle().ik, &format!("b{i}")));
        assert_eq!(a_session.decrypt(&r).unwrap().body, format!("b{i}").as_bytes());
    }
}

#[test]
fn out_of_order_delivery_within_a_chain_decrypts() {
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, _) = bob.accept(&init).unwrap();

    let m1 = a.encrypt(&payload(&alice.ik_public(), "m1"));
    let m2 = a.encrypt(&payload(&alice.ik_public(), "m2"));
    // Deliver m2 before m1: m1's key is stashed as skipped, then used when m1 arrives.
    assert_eq!(b.decrypt(&m2).unwrap().body, b"m2");
    assert_eq!(b.decrypt(&m1).unwrap().body, b"m1");
}

#[test]
fn tampered_ciphertext_fails_the_mac() {
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "hello")).unwrap();
    let (mut b, _) = bob.accept(&init).unwrap();

    let mut msg = a.encrypt(&payload(&alice.ik_public(), "secret"));
    let last = msg.ct.len() - 1;
    msg.ct[last] ^= 0x01; // flip one ciphertext/tag bit
    assert!(matches!(b.decrypt(&msg), Err(DeniableError::MacFailed)));
}

#[test]
fn tampered_header_fails_the_mac() {
    // The header (dh/pn/n) is folded into the AEAD associated data, so tampering it breaks the tag.
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "hi")).unwrap();
    let (mut b, _) = bob.accept(&init).unwrap();

    let mut msg = a.encrypt(&payload(&alice.ik_public(), "x"));
    msg.n = msg.n.wrapping_add(1); // claim a different in-chain index
    assert!(matches!(b.decrypt(&msg), Err(DeniableError::MacFailed)));
}

#[test]
fn forward_secrecy_later_chain_key_cannot_decrypt_earlier() {
    // A compromise of the receiving state AFTER later messages must NOT recover earlier ones: the
    // symmetric chain KDF is one-way, so the ratchet cannot rewind.
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, m0) = bob.accept(&init).unwrap();
    assert_eq!(m0.body, b"m0");

    // Alice sends three more in the same sending chain (one-way burst, no replies).
    let m1 = a.encrypt(&payload(&alice.ik_public(), "m1"));
    let m2 = a.encrypt(&payload(&alice.ik_public(), "m2"));
    let m3 = a.encrypt(&payload(&alice.ik_public(), "m3"));

    b.decrypt(&m1).unwrap();
    b.decrypt(&m2).unwrap();
    b.decrypt(&m3).unwrap();

    // "Compromise" Bob's state now (after m3). It has ratcheted past m1/m2 and holds no earlier
    // key. Feeding an earlier message to this later state must fail — earlier plaintext stays secret.
    let mut compromised = b.snapshot();
    assert!(
        matches!(compromised.decrypt(&m1), Err(DeniableError::MacFailed | DeniableError::DecryptFailed)),
        "a later-compromised chain key must not decrypt an earlier message (forward secrecy)"
    );
}

#[test]
fn repudiation_receiver_can_forge_a_sender_message() {
    // The deniability property, constructively: the RECEIVER, holding only the shared receiving
    // chain, can mint a message indistinguishable from one authored by the sender — using no
    // signing key and no sender secret. Therefore a transcript proves nothing about authorship.
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "genuine")).unwrap();
    let (b_session, _first) = bob.accept(&init).unwrap();

    // Bob holds a receiving chain for Alice's next message. He forges "Alice said this" himself.
    // (`forge_peer_message` takes only `&self` on Bob's session — no access to Alice's keys.)
    let forged: DeniableMessage = b_session
        .forge_peer_message(&payload(&alice.ik_public(), "I, Alice, confess"))
        .expect("receiver can forge from the shared chain");

    // A genuine Alice message at the same position, for shape comparison.
    let genuine: DeniableMessage = a.encrypt(&payload(&alice.ik_public(), "I, Alice, confess"));

    // Structural indistinguishability: same header shape, same ciphertext length, no signature
    // field exists anywhere in the wire object (it is only dh/pn/n/ct).
    assert_eq!(forged.dh, genuine.dh, "forgery reuses Alice's ratchet public — same header");
    assert_eq!(forged.n, genuine.n);
    assert_eq!(forged.ct.len(), genuine.ct.len());

    // And it VERIFIES: a fresh copy of Bob's receiving state accepts the forgery as a valid,
    // authentic "from Alice" message. The MAC is symmetric, so Bob could always have produced it.
    let mut judge = b_session.snapshot();
    let opened = judge.decrypt(&forged).expect("the forged message authenticates as genuine");
    assert_eq!(opened.body, b"I, Alice, confess");
    assert_eq!(opened.from, alice.ik_public(), "it even claims Alice as the sender");

    // The same copy would equally accept Alice's genuine message — the two are interchangeable,
    // which is exactly the repudiation guarantee.
    let mut judge2 = b_session.snapshot();
    assert_eq!(judge2.decrypt(&genuine).unwrap().body, b"I, Alice, confess");
}

#[test]
fn forged_message_cannot_corrupt_ratchet_state() {
    // Exploit (a) — permanent session DoS. A single unauthenticated packet with a novel `dh` forces
    // a DH-ratchet (recomputing the root key from the attacker's fake ratchet key) and chain skips
    // BEFORE the AEAD tag is checked. Pre-fix those mutations persisted through the failed tag, so
    // the peer's next genuine message ratcheted from the corrupted root and never decrypted again.
    // Post-fix `decrypt` is transactional: a rejected forgery leaves the ratchet byte-for-byte
    // unchanged. (This assertion FAILS against the old code and PASSES after the fix.)
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, m0) = bob.accept(&init).unwrap();
    assert_eq!(m0.body, b"m0");

    // A valid-looking but forged packet: a novel ratchet key (any 32 bytes is a valid X25519
    // public), a large in-chain index, and garbage ciphertext whose tag cannot verify.
    let forged = DeniableMessage { dh: vec![0x42u8; 32], pn: 0, n: 900, ct: vec![0u8; 48] };
    assert!(b.decrypt(&forged).is_err(), "the forged tag must be rejected");
    assert_eq!(b.skipped_len(), 0, "a rejected forgery retains no skipped keys");

    // The peer's next GENUINE message still decrypts — proof the ratchet state never advanced.
    let m1 = a.encrypt(&payload(&alice.ik_public(), "m1"));
    assert_eq!(
        b.decrypt(&m1).unwrap().body,
        b"m1",
        "genuine peer traffic still decrypts after a rejected forgery"
    );
}

#[test]
fn repeated_forgeries_retain_no_skipped_keys() {
    // Exploit (b) — unbounded memory. Each novel-`dh` forgery pre-fix stashed up to ~2*MAX_SKIP
    // message keys that persisted across the failed tag; repeated injection exhausted memory.
    // Post-fix a rejected forgery commits nothing, so retained skipped-key memory never grows.
    let (alice, mut bob) = setup(2);
    let (_a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, _m0) = bob.accept(&init).unwrap();

    for i in 0..100u8 {
        // A distinct novel ratchet key each time (would each force a fresh dh-ratchet + big skip).
        let forged = DeniableMessage { dh: vec![i; 32], pn: 0, n: 900, ct: vec![0u8; 48] };
        assert!(b.decrypt(&forged).is_err(), "every forgery is rejected");
    }
    assert_eq!(
        b.skipped_len(),
        0,
        "no rejected forgery leaves skipped keys behind — retained memory stays bounded"
    );
}

#[test]
fn global_skipped_key_cap_rejects_unbounded_accumulation() {
    // The per-chain MAX_SKIP budget alone does not bound TOTAL retained keys: legitimate large gaps
    // across successive deliveries accumulate. The global cap (2*MAX_SKIP = 2000) rejects the excess
    // deterministically with TooManySkipped rather than allocating without bound.
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, _m0) = bob.accept(&init).unwrap();

    // One long in-order sending chain from Alice (no replies ⇒ no DH ratchet on her side). msgs[k]
    // carries in-chain index n = k + 1 (n = 0 was the init message Bob already consumed).
    let mut msgs = Vec::with_capacity(2100);
    for _ in 0..2100u32 {
        msgs.push(a.encrypt(&payload(&alice.ik_public(), "x")));
    }

    // Deliver n=1000 then n=2000: each individual gap is < MAX_SKIP so the per-call gate passes, but
    // together they stash 1998 keys — just under the global cap.
    assert!(b.decrypt(&msgs[999]).is_ok(), "n=1000 within per-call skip budget");
    assert!(b.decrypt(&msgs[1999]).is_ok(), "n=2000 within per-call skip budget");
    let before = b.skipped_len();
    assert_eq!(before, 1998, "two large-but-legit gaps stash 999 + 999 keys");

    // A further legitimate gap tips retained keys over the global cap ⇒ rejected, state unchanged.
    let over = b.decrypt(&msgs[2099]); // n = 2100, per-call gap 99 (< MAX_SKIP)
    assert!(
        matches!(over, Err(DeniableError::TooManySkipped)),
        "the global skipped-key cap rejects rather than allocating unboundedly"
    );
    assert_eq!(b.skipped_len(), before, "the rejected over-cap delivery changed nothing");
}

#[test]
fn normal_in_order_and_out_of_order_still_decrypt_after_fix() {
    // Regression: the transactional decrypt must preserve exact success-path behaviour — in-order
    // delivery, legitimately-skipped out-of-order delivery (stash then consume), and the DH ratchet.
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "m0")).unwrap();
    let (mut b, m0) = bob.accept(&init).unwrap();
    assert_eq!(m0.body, b"m0");

    // In order.
    let m1 = a.encrypt(&payload(&alice.ik_public(), "m1"));
    let m2 = a.encrypt(&payload(&alice.ik_public(), "m2"));
    assert_eq!(b.decrypt(&m1).unwrap().body, b"m1");

    // Out of order: deliver m4 before m3 (m3's key is stashed, then consumed on arrival).
    let m3 = a.encrypt(&payload(&alice.ik_public(), "m3"));
    let m4 = a.encrypt(&payload(&alice.ik_public(), "m4"));
    assert_eq!(b.decrypt(&m2).unwrap().body, b"m2");
    assert_eq!(b.decrypt(&m4).unwrap().body, b"m4");
    assert_eq!(b.skipped_len(), 1, "exactly m3's key is stashed");
    assert_eq!(b.decrypt(&m3).unwrap().body, b"m3");
    assert_eq!(b.skipped_len(), 0, "the stash is consumed on delivery");

    // The DH ratchet still turns: Bob replies, Alice decrypts, and Alice's next message ratchets.
    let r0 = b.encrypt(&payload(&bob.bundle().ik, "r0"));
    assert_eq!(a.decrypt(&r0).unwrap().body, b"r0");
    let m5 = a.encrypt(&payload(&alice.ik_public(), "m5"));
    assert_eq!(b.decrypt(&m5).unwrap().body, b"m5");
}

#[test]
fn payload_rejects_smuggled_signature() {
    // A DeniablePayload MUST NOT carry a signature (ERR_DENIABLE_SIGNATURE_PRESENT). The session
    // decrypt path decodes via DeniablePayload::from_det_cbor, which fails closed on any extra key.
    use dmtap_core::cbor::{self, Cv};
    let (alice, mut bob) = setup(2);
    let (mut a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "ok")).unwrap();
    let (mut b, _) = bob.accept(&init).unwrap();

    // Hand-craft a payload with a stray key-8 "signature" and ratchet-seal it as Alice.
    let p = payload(&alice.ik_public(), "leaky");
    let mut m = match cbor::decode(&p.det_cbor()).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    m.push((8, Cv::Bytes(vec![0u8; 64])));
    let leaky_pt = cbor::encode(&Cv::Map(m));

    // The plaintext that the ratchet would hand to the payload decoder is rejected: any extra key
    // (a smuggled signature) fails closed — the concrete ERR_DENIABLE_SIGNATURE_PRESENT.
    assert!(matches!(
        DeniablePayload::from_det_cbor(&leaky_pt),
        Err(dmtap_core::cbor::CborError::UnknownKey(8))
    ));
    // And a normal round-trip still works (sanity that the channel itself is fine).
    let good = a.encrypt(&p);
    assert_eq!(b.decrypt(&good).unwrap().body, b"leaky");
}

#[test]
fn last_resort_replay_is_rejected() {
    // Bob publishes a bundle with NO one-time prekeys, so Alice must take the last-resort path.
    let (alice, mut bob) = setup(0);
    let (_a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "first")).unwrap();
    assert!(init.opk_ref.is_none(), "no opk offered ⇒ last-resort init");

    // First contact is accepted and cached.
    let (_b, p) = bob.accept(&init).expect("first last-resort init accepted");
    assert_eq!(p.body, b"first");

    // Replaying the identical captured init must be rejected (replay cache of ek_a‖idk_a).
    assert!(matches!(bob.accept(&init), Err(DeniableError::ReplayRejected)));
}

#[test]
fn last_resort_rejected_while_a_one_time_prekey_is_available() {
    // If Bob still has an unspent opk, a last-resort-only init MUST be rejected (prefer-OPK rule),
    // closing the replayable path when a replay-resistant one exists.
    let (alice, mut bob) = setup(3);
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    // Force the last-resort shape (drop the opk reference the initiator chose).
    init = DeniableInit { opk_ref: None, ..init };
    assert!(matches!(bob.accept(&init), Err(DeniableError::X3dhFailed)));
}

#[test]
fn consumed_one_time_prekey_cannot_be_reused() {
    // An opk-consuming init, replayed, fails because the referenced opk is gone.
    let (alice, mut bob) = setup(2);
    let (_a, init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    assert!(bob.accept(&init).is_ok());
    assert_eq!(bob.opks_remaining(), 1);
    assert!(matches!(bob.accept(&init), Err(DeniableError::X3dhFailed)));
}

#[test]
fn forged_idk_certification_is_rejected() {
    // If the initiator's idk_a_cert does not verify under ik_a, accept must fail closed.
    let (alice, mut bob) = setup(2);
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    init.idk_a[0] ^= 0xff; // certificate no longer matches the (mutated) idk_a
    assert!(matches!(bob.accept(&init), Err(DeniableError::BadCertification)));
}

#[test]
fn exhausted_one_time_prekey_rejects_a_second_independent_initiator() {
    // Two different, independent initiators both pick the SAME advertised one-time prekey (the
    // published bundle only ever offers its first opk). Whichever arrives second must be
    // rejected: a one-time prekey is never legitimately consumed twice, even by two honest
    // parties racing on the same bundle — the concrete prekey-exhaustion failure mode.
    let (alice, mut bob) = setup(1);
    let carol = DeniableIdentity::new(ik(0xC0));

    let (_a, init_a) =
        initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "from alice")).unwrap();
    let (_c, init_c) =
        initiate(&carol, bob.bundle(), &payload(&carol.ik_public(), "from carol")).unwrap();
    assert_eq!(init_a.opk_ref, init_c.opk_ref, "both reference the bundle's only opk");

    // Alice arrives first and legitimately consumes the opk.
    bob.accept(&init_a).expect("first arrival consumes the one-time prekey");
    assert_eq!(bob.opks_remaining(), 0, "the prekey pool is now exhausted");

    // Carol's independently-built init, referencing the now-spent opk, must be rejected rather
    // than silently reusing key material that Alice's session already derived.
    assert!(matches!(bob.accept(&init_c), Err(DeniableError::X3dhFailed)));
}

#[test]
fn malformed_ephemeral_key_length_fails_closed() {
    // `ek_a` carries no certification (only `idk_a` does), so a length-tampered value must be
    // caught by the raw key-length check rather than slip past as a truncated/extended X25519
    // point — fail closed, no panic.
    let (alice, mut bob) = setup(2);
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    init.ek_a = vec![0u8; 10];
    assert!(matches!(bob.accept(&init), Err(DeniableError::BadKeyLength)));
}

#[test]
fn malformed_message_header_ratchet_key_fails_closed_no_panic() {
    // The embedded first Double-Ratchet message's `dh` (ratchet public key) is likewise
    // unauthenticated cleartext until the AEAD tag proves it; a wrong-length value must fail
    // closed at the key-parsing boundary rather than panic deeper in the ratchet.
    let (alice, mut bob) = setup(0); // last-resort path — no opk bookkeeping to entangle
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    init.msg.dh = vec![0u8; 5];
    assert!(matches!(bob.accept(&init), Err(DeniableError::BadKeyLength)));
}

#[test]
fn wrong_spk_ref_rejected() {
    // `spk_ref` must name the responder's CURRENT signed prekey; a stale/wrong reference (a
    // rotated or simply incorrect spk) is rejected before any DH is even attempted.
    let (alice, mut bob) = setup(2);
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    init.spk_ref = ContentId::of(b"not the responder's real spk");
    assert!(matches!(bob.accept(&init), Err(DeniableError::X3dhFailed)));
}

#[test]
fn initiate_rejects_unimplemented_pq_suite_bundle() {
    // Only the classical suite (0x01, X3DH) is implemented; a bundle claiming suite 0x02
    // (PQXDH) MUST fail closed rather than silently falling back to classical DH, exactly as
    // `dmtap-core` fails closed on the PQ identity suite (module doc).
    let (_alice, bob) = setup(1);
    let mut pq_bundle = bob.bundle().clone();
    pq_bundle.suite = Suite::PqHybrid;
    let carol = DeniableIdentity::new(ik(0xC1));
    // `DeniableSession` (the `Ok` side) carries no `Debug` impl, so match instead of
    // `unwrap_err()` (which would require `T: Debug` too).
    let err = match initiate(&carol, &pq_bundle, &payload(&carol.ik_public(), "x")) {
        Err(e) => e,
        Ok(_) => panic!("a PQXDH (0x02) bundle must not be accepted by the classical-only client"),
    };
    assert!(matches!(err, DeniableError::UnsupportedSuite(0x02)));
}

#[test]
fn accept_rejects_unimplemented_pq_suite_init() {
    let (alice, mut bob) = setup(1);
    let (_a, mut init) = initiate(&alice, bob.bundle(), &payload(&alice.ik_public(), "x")).unwrap();
    init.suite = Suite::PqHybrid;
    let err = match bob.accept(&init) {
        Err(e) => e,
        Ok(_) => panic!("a PQXDH (0x02) init must not be accepted by the classical-only responder"),
    };
    assert!(matches!(err, DeniableError::UnsupportedSuite(0x02)));
}

#[test]
fn ik_never_performs_dh_only_certifies() {
    // Sanity of the design invariant: the dedicated idk is a distinct key from the Ed25519 IK.
    // The bundle's idk is 32 bytes (X25519) and its certification verifies under the Ed25519 IK.
    let bob = DeniableResponder::new(DeniableIdentity::new(ik(0xB0)), 1, 1, 1);
    let bundle = bob.bundle();
    assert_eq!(bundle.idk.len(), 32);
    assert_ne!(bundle.idk, bundle.ik, "idk is NOT the IK");
    assert!(bundle.verify().is_ok(), "idk_sig/spk_sig/sig all verify under the IK");
}
