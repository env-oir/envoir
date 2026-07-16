//! DMTAP downgrade & fail-closed invariant suite — spec §10.7.
//!
//! §10.7 collects every downgrade-resistance / fail-closed rule scattered across the spec into
//! one auditable table (four sub-tables: §10.7.1 version/suite/capability, §10.7.2
//! metadata-privacy/mixnet, §10.7.3 trust-binding/KT/identity, §10.7.4 delivery/gateway/anti-abuse)
//! plus §10.7.5's one governing rule: **a security-relevant downgrade is either refused (fail
//! closed) or an explicit, user-surfaced choice — never silent.** This crate is that table's
//! regression backbone: for every row testable at the `dmtap-core` library level, a test here
//! constructs the weakening and asserts it is rejected. A future change that reopens a downgrade
//! must break a test in this file.
//!
//! Every test is driven **only** through `dmtap-core`'s public API (this is an external `tests/`
//! crate — it has no access to private fields/functions), and is doc-commented with the exact
//! §10.7 invariant, its spec clause, and its §21 error code (where one exists; some rows are a
//! bare signature/decoder rejection with no dedicated status, per §10.7's own reading note).
//!
//! ## Honest coverage map
//!
//! Real (non-`#[ignore]`) tests below lock invariants the reference **already enforces**:
//! - §10.7.1: unknown suite (Suite/Identity/Envelope), unknown key in a signed object.
//! - Canonical CBOR (§18.1.1, feeding the "signed-object extension gating" row): non-shortest
//!   integers, indefinite-length items, descending/duplicate map keys, `null` for an absent
//!   optional, floats/NaN, CBOR tags/`undefined`.
//! - §10.7.3 / §2.7: tampered ciphertext (content-address fail), forged `sender_sig`, forged
//!   `Payload.sig`, `DeniablePayload` carrying a signature (`0x040F`).
//! - §10.7.3 (Manifest, §18.3.8): forbidden key 5 (`0x0808`).
//! - §10.7.3 (KT, §3.5): forged `SignedTreeHead` signature (`0x0108`).
//! - §10.7.3 (identity/recovery, §1.3/§1.4): broken hash chain, empty `rotate_threshold`.
//!
//! `#[ignore]`-with-reason stubs below mark §10.7 rows that are **real, spec-mandated
//! invariants but not yet testable** because `dmtap-core` does not currently expose a public API
//! that *enforces* them (as opposed to merely modeling the object's shape). Each stub names the
//! exact gap and the §21 code the eventual enforcement would carry, so it can be turned into a
//! real test the moment the API lands, without anyone having to rediscover the gap:
//! - §10.7.1: the suite **high-water-mark ratchet** (`0x020F`) — no pinned-contact/ratchet state
//!   exists in the reference; `mote::validate` has no notion of a per-contact suite floor.
//! - §10.7.1: capability-announcement **anti-rollback** (`0x030A`) — no `caps_version` /
//!   capability-announcement object is modeled at all.
//! - §10.7.3 (KT): a Merkle **inclusion-proof verification** function (recomputing the audit path
//!   against an STH's `root_hash`) does not exist — `InclusionProof`/`ConsistencyProof` are
//!   structural decode-only objects (`0x0108`/`0x0117`).
//! - §10.7.3 (KT): **leaf-hash mismatch** rejection (`0x0117`) — `identity_leaf_hash` is exposed
//!   as a pure function; nothing in the library compares a presented proof's `leaf_hash` against
//!   the recomputed value and rejects on mismatch (that comparison is left to the caller).
//! - §10.7.3 (capability, §18.7.3): **attenuation-chain walking** (`0x0508`) —
//!   `CapabilityToken::verify()` explicitly checks only the token's own signature, not that a
//!   child's `caps`/`prnt` narrows its parent's.
//! - §10.7.3 (capability): **expiry / revocation** enforcement (`0x0508`/`0x050B`) — `nbf`/`exp`
//!   are decoded fields never compared against a clock, and `CapabilityRevocation` has no
//!   "is this token revoked" lookup API.
//! - §10.7.3 (recovery, §1.4 rules 3–4): the **72h asymmetric-veto quorum walk** for a
//!   recovery-weakening `RecoveryPolicy` change — only the structural
//!   `rotate_threshold`-non-empty invariant is enforced; the quorum/veto-window flow itself is not
//!   modeled.
//!
//! Rows from §10.7.2 (mixnet/Sphinx routing behavior — no-`private→fast` floor, active-attack
//! HALT, per-epoch replay, operator-diversity attestation, cover traffic) and most of §10.7.4
//! (gateway ack-before-`250`, `GatewayAuthz` fail-safe, postage/token budget rules) are runtime
//! **behavioral** properties of a live mixnet/gateway node, not decode/verify functions over a
//! static object — `dmtap-core` only models the wire objects for these layers (`MixNodeDescriptor`
//! / `MixDirectory` / `sphinx`), so they are out of scope for a library-level test and are the
//! conformance-runner / a future node-level harness's job, not this crate's. This is a deliberate
//! scoping choice, not an oversight — see this crate's task brief.

use dmtap_core::capability::{
    Capability, CapabilityAnnouncement, CapabilityError, CapabilityToken, CapsVersionTracker,
};
use dmtap_core::cbor::{self, CborError, Cv};
use dmtap_core::deniable::DeniablePayload;
use dmtap_core::id::ContentId;
use dmtap_core::identity::{
    authorize_recovery_change, recovery_change_is_weakening, sign_recovery_approval,
    sign_recovery_veto, GuardianApproval, IdentityError, IdentityKey, KeyPackageBundleRef,
    MethodPredicate, RecoveryGuardError, RecoveryMethod, RecoveryPolicy, Threshold,
    RECOVERY_VETO_WINDOW_MS,
};
use dmtap_core::kt::{identity_leaf_for, InclusionProof, KtError, MerkleTree, SignedTreeHead};
use dmtap_core::mote::{
    build_mote, validate, DeliveryTag, Envelope, Headers, Hpke, Kind, Manifest, MoteDraft,
    MoteError, Outcome, Payload, PayloadSeal, RecipientCtx, SealKeypair, ENVELOPE_SENDER_DS,
    MOTE_VERSION, PAYLOAD_SIG_DS,
};
use dmtap_core::suite::{SuiteRatchet, SuiteRatchetError};
use dmtap_core::{identity::Identity, Suite};

fn key(seed: u8) -> IdentityKey {
    IdentityKey::from_seed(&[seed; 32])
}

// ================================================================================================
// §10.7.1 — Version, suite & capability downgrades
// ================================================================================================

/// LOCKS §10.7.1 "Unknown `v`/`suite` → reject" (§10.1, §1.1): every byte other than the two
/// currently-defined suite ids MUST fail closed, never be guessed at.
#[test]
fn unknown_suite_byte_fails_closed() {
    assert_eq!(Suite::from_u8(0x01), Some(Suite::Classical));
    assert_eq!(Suite::from_u8(0x02), Some(Suite::PqHybrid));
    for b in [0x00u8, 0x03, 0x04, 0x0f, 0x7f, 0xfe, 0xff] {
        assert_eq!(Suite::from_u8(b), None, "suite byte 0x{b:02x} must fail closed, never guessed");
    }
}

/// LOCKS §10.7.1 "Unknown `v`/`suite` → reject" applied to a top-level signed object (§1.3): an
/// `Identity` that declares only the reserved PQ suite (`0x02`, which the reference core cannot
/// validate) MUST be rejected rather than silently downgraded/accepted by an implementation that
/// can't actually check it — spec §1.3's "reject rather than fall back silently".
#[test]
fn identity_declaring_only_unsupported_suite_is_rejected_not_downgraded() {
    use std::collections::BTreeMap;
    let mut iks = BTreeMap::new();
    iks.insert(Suite::PqHybrid.as_u8(), vec![0u8; 32]);
    let id = Identity {
        suites: vec![Suite::PqHybrid],
        iks,
        version: 0,
        devices: vec![],
        keypkgs: KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        recovery: ContentId::of(b"rec"),
        names: vec![],
        prev: None,
        ts: 0,
        sig: vec![vec![0u8; 64]], // bogus — but suite rejection MUST fire before the sig is even checked
    };
    assert_eq!(id.verify(None), Err(IdentityError::UnsupportedSuite(0x02)));
}

/// LOCKS §10.7.1 "Unknown `v`/`suite` → reject" at the MOTE envelope layer (§2.7 step 1): a
/// well-formed, correctly-signed envelope whose `suite` is the reserved PQ id is rejected by
/// `validate()` **before** any content-address/signature/decryption work, because the reference
/// cannot actually validate that suite. Built entirely through the public `Envelope` struct
/// (every field is `pub`) rather than `build_mote` (which only ever emits suite `Classical`).
#[test]
fn mote_validate_rejects_unsupported_envelope_suite_before_any_other_check() {
    let recipient = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let to = DeliveryTag::Key(recipient.public());
    let env = Envelope {
        v: MOTE_VERSION,
        suite: Suite::PqHybrid, // reserved, unsupported by the reference core
        id: ContentId::of(b"anything"), // deliberately not a real content address either —
        to,                              // suite rejection must fire first regardless
        epoch: None,
        ts: 1_700_000_000_000,
        kind: Kind::Chat,
        keypkg: None,
        challenge: None,
        ciphertext: b"not even real ciphertext".to_vec(),
        sender_sig: None,
        sender_eph: None,
    };
    let ctx = RecipientCtx {
        our_ik: &recipient.public(),
        seal_secret: seal.secret(),
        sender_is_known: true,
    };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::UnsupportedSuite(0x02)));
}

/// LOCKS §10.7.1 "Signed-object extension gating" (§10.2, §18.1.2): a decoder of a **signed**
/// object fails closed on any key beyond the recognized schema — an attacker can't smuggle a
/// reserved/extension field past the signature-covered preimage toward a peer that never
/// negotiated it. Exercised end to end against a real, correctly-built `Envelope` (via the public
/// `build_mote` API), not a hand-rolled map.
#[test]
fn envelope_decoder_rejects_smuggled_key_in_signed_object() {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let recipient = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, b"hello dmtap".to_vec());
    let env = build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft)
        .expect("build_mote must succeed");

    let mut m = match cbor::decode(&env.det_cbor()).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    m.push((63, Cv::U64(1))); // an unrecognized, reserved-range key — never negotiated
    let leaky = cbor::encode(&Cv::Map(m));
    assert_eq!(Envelope::from_det_cbor(&leaky), Err(CborError::UnknownKey(63)));
}

/// LOCKS §10.7.1 "Suite high-water-mark ratchet" (§1.3, §2.7 step 8, `ERR_SUITE_DOWNGRADE`
/// `0x020F`): a receiver tracks, per pinned contact, the highest `Envelope.suite` ever accepted
/// from them and rejects anything below that mark — and MUST NOT ratchet the mark down. Enforced by
/// [`dmtap_core::suite::SuiteRatchet`]: once a contact is pinned at the PQ suite (`0x02`), a later
/// object asserting the weaker classical suite (`0x01`) is a downgrade.
#[test]
fn suite_high_water_mark_ratchet_should_reject_downgrade_below_pinned_floor() {
    let contact = IdentityKey::generate().public();
    let mut ratchet = SuiteRatchet::new();
    // Both parties migrated to PQ: the contact's high-water-mark is pinned at suite 0x02.
    ratchet.accept(&contact, Suite::PqHybrid).expect("first PQ observation pins the mark");
    assert_eq!(ratchet.high_water_mark(&contact), Some(Suite::PqHybrid));

    // A later Envelope asserting the weaker classical suite (0x01 < 0x02) is a downgrade attempt.
    let err = ratchet.check(&contact, Suite::Classical).unwrap_err();
    assert_eq!(err, SuiteRatchetError::SuiteDowngrade);
    assert_eq!(err.code(), 0x020F);

    // accept() rejects it too and MUST NOT ratchet the high-water-mark down (§21.3 disposition).
    assert_eq!(
        ratchet.accept(&contact, Suite::Classical),
        Err(SuiteRatchetError::SuiteDowngrade)
    );
    assert_eq!(ratchet.high_water_mark(&contact), Some(Suite::PqHybrid));
}

/// LOCKS §10.7.1 "Capability-announce anti-rollback" (§10.2, `ERR_CAPABILITY_ANNOUNCE_ROLLBACK`
/// `0x030A`): a receiver rejects a capability announcement whose `caps_version` is
/// older-than-or-equal-to the last accepted from that peer — a stale replay attempting to suppress
/// an advertised capability. Enforced by [`dmtap_core::capability::CapsVersionTracker`] over the
/// signed, versioned [`CapabilityAnnouncement`] object: it retains the highest version per peer and
/// fails closed on a rollback (retain the higher set; do not roll back).
#[test]
fn capability_announcement_anti_rollback_should_reject_stale_caps_version() {
    let peer = IdentityKey::generate();
    let cap = Capability { resource: "ext:mls".into(), ability: "support".into(), caveats: None };
    let newer = CapabilityAnnouncement::issue(&peer, 7, vec![cap.clone()], 20);
    let stale = CapabilityAnnouncement::issue(&peer, 5, vec![cap], 10);

    let mut tracker = CapsVersionTracker::new();
    tracker.accept(&newer).expect("the newer (v7) announcement is accepted and retained");
    assert_eq!(tracker.last_version(&peer.public()), Some(7));

    // Replaying the older (v5 ≤ 7) announcement is a rollback — reject, retain the higher set.
    let err = tracker.accept(&stale).unwrap_err();
    assert_eq!(err, CapabilityError::AnnounceRollback);
    assert_eq!(err.code(), 0x030A);
    assert_eq!(tracker.last_version(&peer.public()), Some(7), "the retained floor is unchanged");
}

// ================================================================================================
// Canonical CBOR (§18.1.1) — the decode-time substrate every §10.7.1 signed-object rule rests on.
// ================================================================================================

/// LOCKS §18.1.1 rule 1 (shortest-form integers/lengths): a non-canonical, over-long integer head
/// MUST be rejected — otherwise the same value has more than one valid encoding, which would break
/// every signature/content-address that depends on "one canonical byte string per object".
#[test]
fn cbor_rejects_non_shortest_form_integer() {
    // uint 10 forced into a two-byte head (0x18 0x0a) instead of the one-byte 0x0a.
    assert_eq!(cbor::decode(&[0x18, 0x0a]), Err(CborError::NonShortestForm));
    // uint 200 forced into a three-byte (0x19) head instead of the two-byte 0x18 0xc8.
    assert_eq!(cbor::decode(&[0x19, 0x00, 0xc8]), Err(CborError::NonShortestForm));
}

/// LOCKS §18.1.1 rule 1 (definite-length only): an indefinite-length item (array/map/string with
/// the `0x1f` additional-info, terminated by `break`) MUST be rejected — DMTAP has no streaming
/// encoding, and accepting one would reopen a whole class of non-canonical byte strings.
#[test]
fn cbor_rejects_indefinite_length_items() {
    assert_eq!(cbor::decode(&[0x9f, 0xff]), Err(CborError::IndefiniteLength)); // array(*)
    assert_eq!(cbor::decode(&[0xbf, 0xff]), Err(CborError::IndefiniteLength)); // map(*)
}

/// LOCKS §18.1.1 rule 2 (strictly ascending map keys, by encoded bytes): a map presenting its keys
/// out of order MUST be rejected — canonical encoding requires exactly one byte-string ordering
/// per logical map, and a decoder that "normalizes" a descending map would accept bytes an honest
/// encoder could never produce.
#[test]
fn cbor_rejects_descending_map_keys() {
    // map {2:0, 1:0} — keys arrive 2 then 1, which is descending.
    assert_eq!(cbor::decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]), Err(CborError::MapKeyOrder));
}

/// LOCKS §18.1.1 rule 3 (no duplicate map keys): a map claiming the same key twice MUST be
/// rejected — otherwise which value "wins" is encoder/library-dependent, and a signature computed
/// over one interpretation would not match a verifier that resolved the duplicate differently.
#[test]
fn cbor_rejects_duplicate_map_key() {
    assert_eq!(cbor::decode(&[0xa2, 0x01, 0x00, 0x01, 0x01]), Err(CborError::DuplicateKey(1)));
}

/// LOCKS §18.1.1 (last paragraph): an absent optional field MUST be omitted entirely, never
/// present with a CBOR `null` value — "no `null` on the wire" is absolute, so a decoder that
/// accepted `null` as a stand-in for "absent" would give an attacker a second way to encode the
/// same logical object, breaking the one-canonical-byte-string guarantee.
#[test]
fn cbor_rejects_null_for_any_key() {
    assert_eq!(cbor::decode(&[0xa1, 0x01, 0xf6]), Err(CborError::NullPresent));
}

/// LOCKS §18.1.1 rule 4 (no floating-point, no NaN/Infinity): a float MUST be rejected outright —
/// "no NaN" isn't a special case carved out of an otherwise-permitted float type, it falls out of
/// floats being forbidden on the wire at all, half-precision NaN included.
#[test]
fn cbor_rejects_float_and_half_float_nan() {
    assert_eq!(cbor::decode(&[0xf9, 0x3e, 0x00]), Err(CborError::FloatPresent)); // half-float 1.5
    assert_eq!(cbor::decode(&[0xf9, 0x7e, 0x00]), Err(CborError::FloatPresent)); // half-float NaN
}

/// LOCKS §18.1.1 rule 5 (no tags, no `undefined`, no reserved simple values): DMTAP has no use for
/// CBOR tags or `undefined`/reserved simple values, and accepting either would be an unbounded,
/// unaudited extension point smuggled in outside the signed schema.
#[test]
fn cbor_rejects_tag_and_undefined() {
    assert_eq!(cbor::decode(&[0xc0, 0x61, 0x41]), Err(CborError::TagOrUndefined)); // tag(0) "A"
    assert!(cbor::decode(&[0xf7]).is_err(), "CBOR undefined (0xf7) must be rejected");
}

// ================================================================================================
// §10.7.3 / §2.7 — MOTE ordered recipient validation (fail-closed at every step)
// ================================================================================================

fn seal_and_recipient(kind: Kind) -> (Envelope, IdentityKey, SealKeypair) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let recipient = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let draft = MoteDraft::new(kind, 1_700_000_000_000, b"hello dmtap".to_vec());
    let env = build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft)
        .expect("build_mote must succeed");
    (env, recipient, seal)
}

/// LOCKS §10.7.3 (§2.7 step 2, decryption-DoS defense): a tampered ciphertext fails the
/// content-address check and is discarded **before** any decryption is attempted —
/// `MoteError::BadContentAddress`, no dedicated §21 code (a bare content-address rejection).
#[test]
fn tampered_ciphertext_fails_content_address_before_decrypt() {
    let (mut env, recipient, seal) = seal_and_recipient(Kind::Chat);
    env.ciphertext[0] ^= 0xff;
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadContentAddress));
}

/// LOCKS §10.7.3 (§2.7 step 3): a forged `sender_sig` — the ephemeral per-message signature
/// checked before decryption — is discarded rather than accepted or decrypted anyway.
#[test]
fn forged_sender_sig_is_discarded_before_decrypt() {
    let (mut env, recipient, seal) = seal_and_recipient(Kind::Chat);
    if let Some(sig) = env.sender_sig.as_mut() {
        sig[0] ^= 0xff;
    }
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadSignature));
}

fn manual_aad(suite: Suite, kind: Kind, ts: u64, to_cbor: &[u8]) -> Vec<u8> {
    // Reproduces the documented AAD binding (module doc of `dmtap_core::mote`: "suite, kind, ts,
    // to") — a public wire-contract formula, not a private internal we're reaching into.
    let mut a = Vec::with_capacity(2 + 8 + to_cbor.len());
    a.push(suite.as_u8());
    a.push(kind.as_u8());
    a.extend_from_slice(&ts.to_be_bytes());
    a.extend_from_slice(to_cbor);
    a
}

/// Build a full envelope+payload pair entirely by hand (every `Envelope`/`Payload` field is
/// `pub`), rather than via `build_mote`, so `Payload.sig` can be corrupted in isolation — the one
/// signature `build_mote` never lets a caller touch directly since it lives inside the sealed
/// ciphertext. `corrupt_payload_sig=false` is the positive control (proves the manual construction
/// itself is sound).
fn build_manual(corrupt_payload_sig: bool) -> (Envelope, IdentityKey, SealKeypair) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let recipient = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let suite = Suite::Classical;
    let kind = Kind::Chat;
    let ts: u64 = 1_700_000_000_000;
    let to = DeliveryTag::Key(recipient.public());

    let mut payload = Payload {
        from: sender.public(),
        sig: Vec::new(),
        headers: Headers::default(),
        body: b"hello dmtap".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    };
    let hash = payload.signing_hash();
    payload.sig = sender.sign_domain(PAYLOAD_SIG_DS, &hash);
    if corrupt_payload_sig {
        payload.sig[0] ^= 0xff; // forge AFTER computing the real hash/signature
    }

    let plaintext = payload.det_cbor();
    let to_cbor = to.det_cbor();
    let aad = manual_aad(suite, kind, ts, &to_cbor);
    let ciphertext = Hpke.seal(seal.public(), &aad, &plaintext).expect("seal must succeed");
    let id = ContentId::of(&ciphertext);

    let mut env = Envelope {
        v: MOTE_VERSION,
        suite,
        id,
        to,
        epoch: None,
        ts,
        kind,
        keypkg: None,
        challenge: None,
        ciphertext,
        sender_sig: None,
        sender_eph: Some(eph.public()),
    };
    let authed = env.sender_sig_body();
    env.sender_sig = Some(eph.sign_domain(ENVELOPE_SENDER_DS, &authed));
    (env, recipient, seal)
}

/// Positive control pairing the test below: an honestly-built envelope (manual construction, not
/// `build_mote`) with an untampered `Payload.sig` is accepted end to end — proves the forged-sig
/// test isn't failing for some unrelated construction bug.
#[test]
fn manually_built_mote_with_honest_payload_sig_is_accepted() {
    let (env, recipient, seal) = build_manual(false);
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    match validate(&Hpke, &env, &ctx).unwrap() {
        Outcome::Accepted(p) => assert_eq!(p.body, b"hello dmtap"),
        Outcome::Deferred => panic!("a known-contact MOTE must be accepted, not deferred"),
    }
}

/// LOCKS §10.7.3 "Payload-signature fail-closed" (§2.7 step 8): a `Payload.sig` that fails to
/// verify under `Payload.from` is discarded — no dedicated §21 code (a bare signature rejection,
/// "matching steps 1–3" per the §10.7 table). The envelope itself (content address, `sender_sig`)
/// is completely honest here — only the *inner*, post-decryption signature is forged — proving
/// `validate()` actually reaches and enforces step 8, not just the earlier anonymous checks.
#[test]
fn forged_payload_sig_is_rejected_after_honest_decrypt() {
    let (env, recipient, seal) = build_manual(true);
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadSignature));
}

/// LOCKS §10.7.3 / §10.7.4 "Deniable payload signature forbidden" (§5.2.1(c), §18.3.10,
/// `ERR_DENIABLE_SIGNATURE_PRESENT` `0x040F`): a `DeniablePayload` MUST NOT carry a signature —
/// the missing signature IS the repudiability property, so the decoder fails closed on *any*
/// extra/unrecognized key (an attacker smuggling a "signature" under a fresh key number is caught
/// exactly the same way an honestly-named one would be).
#[test]
fn deniable_payload_carrying_a_signature_field_is_rejected() {
    let p = DeniablePayload {
        from: key(0x11).public(),
        kind: Kind::Chat,
        headers: Headers { subject: Some("hi".into()), ..Default::default() },
        body: b"deniable hello".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    };
    let bytes = p.det_cbor();
    assert_eq!(DeniablePayload::from_det_cbor(&bytes).unwrap(), p, "well-formed payload must decode");

    let mut m = match cbor::decode(&bytes).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    m.push((8, Cv::Bytes(vec![0u8; 64]))); // smuggled "signature" under a fresh key
    let leaky = cbor::encode(&Cv::Map(m));
    assert_eq!(DeniablePayload::from_det_cbor(&leaky), Err(CborError::UnknownKey(8)));
}

// ================================================================================================
// §10.7.3 — Manifest: forbidden key 5 (§18.3.8, ERR_MANIFEST_KEY_PRESENT 0x0808)
// ================================================================================================

/// LOCKS §10.7.3 "Manifest key-5-present → reject" (§18.3.8, `ERR_MANIFEST_KEY_PRESENT` `0x0808`):
/// a `Manifest` is a content-addressed blob any swarm holder may serve; if it carried the file's
/// content key (forbidden field 5), anyone with the manifest could decrypt the whole file. The
/// decoder checks for key 5 before decoding anything else, so a leaky manifest is caught, never
/// silently honored.
#[test]
fn manifest_carrying_forbidden_key5_is_rejected() {
    let leaky = Cv::Map(vec![
        (1, Cv::Bytes(ContentId::of(b"root").as_bytes().to_vec())),
        (2, Cv::U64(1024)),
        (3, Cv::U64(1024)),
        (4, Cv::Array(vec![Cv::Bytes(ContentId::of(b"c0").as_bytes().to_vec())])),
        (5, Cv::Bytes(vec![0u8; 32])), // FORBIDDEN: the content key must never live here
        (6, Cv::U64(Suite::Classical.as_u8() as u64)),
    ]);
    let bytes = cbor::encode(&leaky);
    assert_eq!(Manifest::from_det_cbor(&bytes), Err(CborError::ManifestKeyPresent));
}

// ================================================================================================
// §10.7.3 — Key transparency (§3.5)
// ================================================================================================

/// LOCKS §10.7.3 "KT ... forged STH sig → reject" (§3.5, §18.4.9, §18.9.13,
/// `ERR_KT_PROOF_INVALID` `0x0108`): a signed tree head whose signed field is altered after
/// issuance fails verification under the log's own key — a forged/tampered STH is never accepted.
#[test]
fn forged_signed_tree_head_signature_is_rejected() {
    let sth = SignedTreeHead::issue(&key(0x11), 7, 1_700_000_000_000, ContentId::of(b"kt-root"));
    assert!(sth.verify().is_ok(), "an honestly-issued STH must verify");

    let mut forged = sth.clone();
    forged.tree_size = 8; // signed field changed post-issuance
    assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
}

/// LOCKS §10.7.3 "KT ... bad inclusion proof → reject" (§3.5, §18.4.10, `ERR_KT_PROOF_INVALID`
/// `0x0108`): a verifier recomputes the RFC 6962 Merkle audit path from an `InclusionProof` and
/// rejects if it doesn't reconstruct the pinned STH's `root_hash`. Enforced by
/// [`InclusionProof::verify_against`] (the RFC 6962 fold) — an honest proof folds to the STH root;
/// a tampered audit path or a wrong root fails closed.
#[test]
fn kt_inclusion_proof_with_bad_audit_path_should_be_rejected() {
    // Build a real RFC 6962 tree and a genuine inclusion proof for one of its leaves.
    let mut tree = MerkleTree::new();
    let leaves: Vec<ContentId> = (0u8..6).map(|n| ContentId::of(&[n; 4])).collect();
    for l in &leaves {
        tree.append(l).unwrap();
    }
    let sth = SignedTreeHead::issue(&key(0x11), tree.size(), 1_700_000_000_000, tree.root().unwrap());
    let good = InclusionProof {
        tree_size: tree.size(),
        leaf_index: 2,
        leaf_hash: leaves[2].clone(),
        audit_path: tree.inclusion_path(2).unwrap(),
    };
    assert!(good.verify_against(&sth).is_ok(), "an honest proof folds to the pinned STH root");

    // A tampered audit-path sibling no longer reconstructs the STH root.
    let mut bad_path = good.clone();
    bad_path.audit_path[0] = ContentId::of(b"tampered sibling");
    let err = bad_path.verify_against(&sth).unwrap_err();
    assert_eq!(err, KtError::ProofInvalid);
    assert_eq!(err.code(), 0x0108);

    // An honest proof presented against the wrong (forged) STH root also fails closed.
    let forged_sth =
        SignedTreeHead::issue(&key(0x11), tree.size(), 1_700_000_000_000, ContentId::of(b"not the root"));
    assert_eq!(good.verify_against(&forged_sth), Err(KtError::ProofInvalid));
}

/// LOCKS §10.7.3 "KT equivocation → HALT" applied at the leaf level (§3.5, §18.4.9,
/// `ERR_KT_LEAF_HASH_MISMATCH` `0x0117`): a verifier rejects a proof whose committed leaf differs
/// from the Identity-entry leaf hash it recomputes for the resolved identity — the log **indexes** a
/// binding, it does not **redefine** it. Enforced by [`InclusionProof::verify_identity`]: it
/// recomputes the §18.4.9 leaf from the resolved `Identity` (via [`identity_leaf_for`]) and rejects
/// on mismatch, even when the inclusion path itself is arithmetically valid.
#[test]
fn kt_leaf_hash_mismatch_should_be_rejected() {
    let name = "alice@abc.com";
    let bundle = KeyPackageBundleRef::new("/mesh/kp", ContentId::of(b"kp"));
    // The resolved (real) identity a verifier pins ...
    let real = Identity::create_classical(
        &key(0x01), 0, vec![], bundle.clone(), ContentId::of(b"rec"), vec![name.into()], None,
        1_700_000_000_000,
    );
    // ... vs a DIFFERENT identity (same name, different `ik`) the log actually committed.
    let evil = Identity::create_classical(
        &key(0x02), 0, vec![], bundle, ContentId::of(b"rec"), vec![name.into()], None,
        1_700_000_000_000,
    );
    let evil_leaf = identity_leaf_for(&evil, name).expect("classical ik present");

    let mut tree = MerkleTree::new();
    let idx = tree.append(&evil_leaf).unwrap();
    let sth = SignedTreeHead::issue(&key(0x11), tree.size(), 1_700_000_000_000, tree.root().unwrap());
    let proof = InclusionProof {
        tree_size: tree.size(),
        leaf_index: idx,
        leaf_hash: evil_leaf.clone(),
        audit_path: tree.inclusion_path(idx).unwrap(),
    };
    // The inclusion path IS valid (the evil leaf really is in the tree) ...
    assert!(proof.verify_against(&sth).is_ok());
    // ... but the committed leaf ≠ the leaf recomputed for the REAL identity — fail closed 0x0117.
    let err = proof.verify_identity(&sth, &real, name).unwrap_err();
    assert_eq!(err, KtError::LeafHashMismatch);
    assert_eq!(err.code(), 0x0117);
}

// ================================================================================================
// §10.7.3 — Capability (§18.7.3)
// ================================================================================================

/// LOCKS §10.7.3 capability **attenuation violation** (a child token whose `caps` exceed what its
/// `prnt` granted): `CapabilityToken::verify()` checks only the token's own signature, but the new
/// [`CapabilityToken::verify_chain`] walks the `prnt` chain and rejects a widened child grant
/// (`ERR_CAPABILITY_DELEGATION_INVALID`, `0x0508`, §13.5, §18.7.3) — no privilege escalation.
#[test]
fn capability_attenuation_violation_should_be_rejected() {
    let root_k = key(0x11);
    let mid_k = key(0x22);
    let leaf_aud = key(0x33).public();
    let read = Capability { resource: "mailbox:calendar".into(), ability: "read".into(), caveats: None };
    let write = Capability { resource: "mailbox:calendar".into(), ability: "write".into(), caveats: None };

    // Parent grants only `read`; the child, rooted at the parent, tries to widen it to `write`.
    let parent =
        CapabilityToken::issue(&root_k, mid_k.public(), vec![read], 1_000, 9_000, b"root".to_vec(), None);
    let child = CapabilityToken::issue(
        &mid_k,
        leaf_aud,
        vec![write],
        1_000,
        9_000,
        b"child".to_vec(),
        Some(parent.content_id()),
    );

    // Signature-only verify() passes — the child is validly self-signed by its own `iss` ...
    assert!(child.verify().is_ok());
    // ... but the full chain walk rejects the privilege escalation (child.caps ⊄ parent.caps).
    let err = child.verify_chain(&[parent]).unwrap_err();
    assert_eq!(err, CapabilityError::AttenuationViolation);
    assert_eq!(err.code(), 0x0508);
}

/// LOCKS §10.7.3 **revoked/expired capability → reject** (§13.5, §13.5.1,
/// `ERR_CAPABILITY_DELEGATION_INVALID` `0x0508` for expired/not-yet-valid, `ERR_CAPABILITY_REVOKED`
/// `0x050B` for revoked): the new [`CapabilityToken::verify_at`] compares `nbf`/`exp` against a
/// supplied clock (a parameter — no wall-clock read) and checks a revocation set, failing closed on
/// each. Expiry and revocation carry distinct codes per §21.3 (a *validly-formed but revoked* grant
/// is `0x050B`, not `0x0508`).
#[test]
fn capability_expired_or_revoked_should_be_rejected() {
    let iss = key(0x11);
    let read = Capability { resource: "mailbox:calendar".into(), ability: "read".into(), caveats: None };
    // Validity window [1_000, 2_000).
    let token =
        CapabilityToken::issue(&iss, key(0x22).public(), vec![read], 1_000, 2_000, b"n".to_vec(), None);

    // Inside the window, not revoked: valid.
    assert!(token.verify_at(1_500, &[]).is_ok());

    // At/after `exp` → expired, 0x0508.
    let e = token.verify_at(2_000, &[]).unwrap_err();
    assert_eq!(e, CapabilityError::Expired);
    assert_eq!(e.code(), 0x0508);

    // Before `nbf` → not yet valid, also 0x0508.
    let e = token.verify_at(500, &[]).unwrap_err();
    assert_eq!(e, CapabilityError::NotYetValid);
    assert_eq!(e.code(), 0x0508);

    // Inside the window but covered by a published revocation (its own content-address) → 0x050B.
    let e = token.verify_at(1_500, &[token.content_id()]).unwrap_err();
    assert_eq!(e, CapabilityError::Revoked);
    assert_eq!(e.code(), 0x050B);
}

// ================================================================================================
// §10.7.3 — Identity & recovery (§1.3, §1.4)
// ================================================================================================

/// LOCKS §10.7.3 (§1.3, §3.4) broken hash-chain rejection: a genesis (`version == 0`) `Identity`
/// MUST NOT carry a `prev` link — otherwise an attacker could splice a fabricated ancestor onto a
/// brand-new identity. `create_classical` will happily sign whatever `prev` it's given, so this
/// test proves `verify()`'s chain-sanity check is independent of (and fires despite) a valid
/// signature.
#[test]
fn identity_genesis_version_with_prev_link_is_rejected() {
    let ik = IdentityKey::generate();
    let genesis_with_prev = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        ContentId::of(b"rec"),
        vec!["a@b.com".into()],
        Some(ContentId::of(b"nonexistent-ancestor")), // illegal: genesis must have no ancestor
        1,
    );
    assert_eq!(genesis_with_prev.verify(None), Err(IdentityError::BrokenChain));
}

/// LOCKS §10.7.3 (§1.3, §3.4) broken hash-chain rejection, the complementary shape: a non-genesis
/// (`version > 0`) `Identity` MUST carry a `prev` link — a version bump with no ancestor is
/// equally a broken chain (an out-of-sequence / spliced-in update). Built directly with
/// `create_classical(version=5, prev=None, ..)` (rather than mutating an already-signed genesis)
/// so the signature is honestly valid over exactly this shape — isolating the chain-sanity check
/// from signature validity, the same way `identity_genesis_version_with_prev_link_is_rejected`
/// does for the opposite shape.
#[test]
fn identity_nonzero_version_without_prev_link_is_rejected() {
    let ik = IdentityKey::generate();
    let id = Identity::create_classical(
        &ik,
        5, // non-genesis version ...
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        ContentId::of(b"rec"),
        vec!["a@b.com".into()],
        None, // ... with no ancestor: a broken chain despite a fully valid signature
        1,
    );
    assert_eq!(id.verify(None), Err(IdentityError::BrokenChain));
}

/// LOCKS §10.7.3 "Recovery-weakening quorum + veto", the structural half (§1.4 rule 2): a
/// `RecoveryPolicy.rotate_threshold` MUST NOT be empty — an empty threshold means either no factor
/// can ever rewrite recovery policy again (permanent lockout) or an ambiguous default silently
/// grants universal rewrite, either of which defeats the whole quorum design. `verify()` checks
/// this independently of the signature (a validly-signed-but-empty-threshold policy still fails).
#[test]
fn recovery_policy_with_empty_rotate_threshold_is_rejected() {
    let ik = IdentityKey::generate();
    let mut policy = RecoveryPolicy {
        suite: Suite::Classical,
        ik: ik.public(),
        version: 1,
        methods: vec![RecoveryMethod::Phrase { recovery_key: vec![1, 2, 3] }],
        recover_threshold: Threshold { any_of: vec![] },
        rotate_threshold: Threshold { any_of: vec![] }, // ILLEGAL: must never be empty
        prev: None,
        ts: 1,
        sig: vec![],
    };
    policy.sign(&ik); // even a fully honest signature can't rescue a structurally-illegal policy
    assert_eq!(policy.verify(), Err(IdentityError::Malformed("rotate_threshold must not be empty")));
}

/// LOCKS §10.7.3 "Recovery-weakening quorum + veto", the dynamic half (§1.4 rules 3–4, §16.8): a
/// `RecoveryPolicy` change that *drops or weakens* a factor requires `rotate_threshold` quorum even
/// when signed by `IK` (`ERR_RECOVERY_WEAKENING_UNQUORUMED`, `0x010E`), and only takes effect after
/// a 72h asymmetric veto window (`ERR_RECOVERY_VETO_WINDOW`, `0x010F`). Enforced by
/// [`authorize_recovery_change`]: [`recovery_change_is_weakening`] detects the weakening,
/// [`sign_recovery_approval`]/[`sign_recovery_veto`] model the guardian counter-signatures, and the
/// clock / window are explicit parameters (no wall-clock read).
#[test]
fn recovery_weakening_without_quorum_and_veto_window_should_be_rejected() {
    let ik = IdentityKey::generate();
    let guardian_keys: Vec<IdentityKey> =
        (0..5).map(|s| IdentityKey::from_seed(&[s; 32])).collect();
    let guardians: Vec<Vec<u8>> = guardian_keys.iter().map(|g| g.public()).collect();

    let mk = |methods: Vec<RecoveryMethod>, recover: Threshold, rotate: Threshold, ver: u64| {
        let mut p = RecoveryPolicy {
            suite: Suite::Classical,
            ik: ik.public(),
            version: ver,
            methods,
            recover_threshold: recover,
            rotate_threshold: rotate,
            prev: None,
            ts: ver,
            sig: vec![],
        };
        p.sign(&ik);
        p
    };

    let prev = mk(
        vec![
            RecoveryMethod::Phrase { recovery_key: vec![1] },
            RecoveryMethod::Device { device_key: vec![9; 32], label: "phone".into() },
        ],
        Threshold { any_of: vec![MethodPredicate::Guardians(3)] },
        Threshold { any_of: vec![MethodPredicate::Guardians(3)] },
        1,
    );
    // Weakening: drops the device method AND lowers both thresholds to Guardians(1).
    let next = mk(
        vec![RecoveryMethod::Phrase { recovery_key: vec![1] }],
        Threshold { any_of: vec![MethodPredicate::Guardians(1)] },
        Threshold { any_of: vec![MethodPredicate::Guardians(1)] },
        2,
    );
    assert!(recovery_change_is_weakening(&prev, &next), "dropping a factor is a weakening");

    let announced = 1_000_000u64;
    let after_window = announced + RECOVERY_VETO_WINDOW_MS;

    // (a) No quorum — even past the window — fails closed: IK alone must not weaken recovery.
    let e = authorize_recovery_change(&prev, &next, &guardians, &[], &[], announced, after_window)
        .unwrap_err();
    assert_eq!(e, RecoveryGuardError::WeakeningUnquorumed);
    assert_eq!(e.code(), 0x010E);

    // A strict `> n/2` majority (3 of 5) of guardians approve the change.
    let approvals: Vec<GuardianApproval> =
        guardian_keys[..3].iter().map(|g| sign_recovery_approval(g, &next)).collect();

    // (b) Quorum met but still inside the 72h veto window — hold, 0x010F.
    let e = authorize_recovery_change(&prev, &next, &guardians, &approvals, &[], announced, announced + 1)
        .unwrap_err();
    assert_eq!(e, RecoveryGuardError::VetoWindowActive);
    assert_eq!(e.code(), 0x010F);

    // (c) Quorum met + a rotate_threshold-backed veto (3 of 5) — aborted, 0x010F.
    let vetoes: Vec<GuardianApproval> =
        guardian_keys[..3].iter().map(|g| sign_recovery_veto(g, &next)).collect();
    let e = authorize_recovery_change(&prev, &next, &guardians, &approvals, &vetoes, announced, after_window)
        .unwrap_err();
    assert_eq!(e, RecoveryGuardError::Vetoed);
    assert_eq!(e.code(), 0x010F);

    // (d) A lone-guardian veto is NOT a quorum veto and cannot block (asymmetric veto, §1.4 rule 4).
    let lone_veto = vec![sign_recovery_veto(&guardian_keys[0], &next)];
    assert!(authorize_recovery_change(&prev, &next, &guardians, &approvals, &lone_veto, announced, after_window).is_ok());

    // (e) Quorum met, no quorum veto, 72h window elapsed — the weakening is finally authorized.
    assert!(authorize_recovery_change(&prev, &next, &guardians, &approvals, &[], announced, after_window).is_ok());
}
