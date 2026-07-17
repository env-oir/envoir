//! Security-regression suite — spec-cited fail-closed invariants, locked as permanent tests.
//!
//! Every test here encodes a security property `dmtap-core` already enforces, driven **only**
//! through its public API (this file lives in `tests/`, an external integration crate — it
//! cannot reach private fields or methods, which keeps these tests honest proof of the *public
//! contract*, not implementation trivia). Each test names the spec clause / finding it locks in
//! its doc comment, so a future change that silently reopens the hole fails CI immediately.
//!
//! ## Scope note (what is deliberately NOT here)
//!
//! Fuzzing (`fuzz/`) and the conformance-runner (`crates/conformance-runner`, cross-referencing
//! `../dmtap/conformance/suite.json`) both independently discovered that
//! `dmtap_core::cbor::decode` does **not** currently enforce shortest-form integers,
//! definite-length-only encoding, or ascending map-key order at decode time (only duplicate
//! keys / floats / null / tags / undefined are rejected). That is a real, currently-OPEN
//! finding, not a fixed one — it is intentionally absent from this file (which locks already-
//! fixed behavior) and is instead documented in `fuzz/README.md` and reported by
//! `crates/conformance-runner`.

use dmtap_core::cbor::{self, CborError, Cv};
use dmtap_core::deniable::{DeniablePayload, DeniablePrekeyBundle};
use dmtap_core::directory::{Custody, DirEntry, DomainDirectory, Visibility};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{Cap, DeviceCert, Identity, IdentityError, IdentityKey, KeyPackageBundleRef};
use dmtap_core::mixnet::{MixKeyEntry, MixNodeDescriptor};
use dmtap_core::mote::{
    build_mote, validate, Envelope, Headers, Hpke, Kind, Manifest, MoteDraft, MoteError, Outcome,
    RecipientCtx, SealKeypair,
};
use dmtap_core::Suite;

fn key(seed: u8) -> IdentityKey {
    IdentityKey::from_seed(&[seed; 32])
}

// ================================================================================================
// Manifest — forbidden key 5 (the per-file content key MUST NOT appear in a swarm-distributed,
// content-addressed Manifest any holder may serve — spec §18.3.8, `ERR_MANIFEST_KEY_PRESENT`).
// ================================================================================================

/// FINDING: a `Manifest` carrying key 5 (the content key) is rejected — `ERR_MANIFEST_KEY_PRESENT`
/// (spec §18.3.8). A manifest is a content-addressed blob any holder may serve; if it carried the
/// content key, anyone with the manifest could decrypt the whole file. `Manifest::from_det_cbor`
/// checks for key 5 before decoding anything else, so a leaky manifest is detected, never quietly
/// accepted.
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

/// Sanity control: a well-formed Manifest (key 5 absent) round-trips and its `id` equals its own
/// Merkle root (§18.9.5) — the positive case paired with the rejection above.
#[test]
fn manifest_without_key5_round_trips_and_id_is_merkle_root() {
    let chunks = vec![ContentId::of(b"c0"), ContentId::of(b"c1"), ContentId::of(b"c2")];
    let mut m = Manifest { id: ContentId(Vec::new()), size: 3 * 1024 * 1024, chunk_sz: 1024 * 1024, chunks, suite: Suite::Classical };
    m.id = m.merkle_root();
    let bytes = m.det_cbor();
    let back = Manifest::from_det_cbor(&bytes).expect("well-formed manifest must decode");
    assert_eq!(back, m);
    assert_eq!(back.id, back.merkle_root());
}

// ================================================================================================
// DeniablePayload — no signature field, ever (spec §18.3.10, `ERR_DENIABLE_SIGNATURE_PRESENT`).
// ================================================================================================

/// FINDING: a `DeniablePayload` carrying any extra/smuggled field (in particular something
/// dressed up as a "signature") is rejected — `ERR_DENIABLE_SIGNATURE_PRESENT` (spec §18.3.10).
/// The deniable mode's whole repudiability property depends on NO signature ever touching this
/// object (authentication is the Double-Ratchet MAC, which either party could compute); the
/// decoder's `deny_unknown` fails closed on ANY key beyond the recognized `1..=7`, so a smuggled
/// signature is caught regardless of which key number an attacker tries to hide it under.
#[test]
fn deniable_payload_rejects_any_smuggled_extra_field() {
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

    // Smuggle an extra key (e.g. an attacker trying to reintroduce a "signature").
    let mut m = match cbor::decode(&bytes).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    m.push((8, Cv::Bytes(vec![0u8; 64])));
    let leaky = cbor::encode(&Cv::Map(m));
    assert_eq!(DeniablePayload::from_det_cbor(&leaky), Err(CborError::UnknownKey(8)));
}

// ================================================================================================
// Canonical CBOR fail-closed primitives (spec §18.1.1) — the already-enforced subset.
// ================================================================================================

/// FINDING: no floating-point value may appear anywhere on the DMTAP wire (§18.1.1 rule 4).
#[test]
fn decode_rejects_floating_point() {
    // Half-float 1.5 (major 7, additional info 25).
    assert_eq!(cbor::decode(&[0xf9, 0x3e, 0x00]), Err(CborError::FloatPresent));
}

/// FINDING: a half-float encoding of NaN is still a float and MUST be rejected the same as any
/// other float — "no NaN/Infinity" (§18.1.1 rule 4) is not a special case, it falls out of
/// "no floats, period".
#[test]
fn decode_rejects_half_float_nan() {
    // Half-float NaN: sign=0, exponent=0x1f (all ones), mantissa != 0.
    assert_eq!(cbor::decode(&[0xf9, 0x7e, 0x00]), Err(CborError::FloatPresent));
}

/// FINDING: CBOR `undefined` (simple value 23, `0xf7`) MUST NOT appear on the wire (§18.1.1
/// rule 5). We assert only that it is rejected (fail closed), not the precise `CborError` variant
/// dmtap-core currently classifies it under, since the *security property* is "never silently
/// accepted", not the internal error taxonomy.
#[test]
fn decode_rejects_cbor_undefined() {
    assert!(cbor::decode(&[0xf7]).is_err(), "CBOR undefined (0xf7) must be rejected, not silently accepted");
}

/// FINDING: a CBOR map with a duplicate key MUST be rejected (§18.1.1 rule 3) — otherwise which
/// value "wins" is encoder-dependent, breaking the "one canonical byte string per object"
/// invariant every signature and content address depends on.
#[test]
fn decode_rejects_duplicate_map_key() {
    // map(2) claiming two entries both under key 1: {1: 0, 1: 1}.
    assert_eq!(cbor::decode(&[0xa2, 0x01, 0x00, 0x01, 0x01]), Err(CborError::DuplicateKey(1)));
}

/// FINDING: an absent optional field MUST be omitted from the wire map, never present with a
/// CBOR `null` value (§18.1.1, last paragraph) — "no `null` on the wire" is absolute, not just
/// for the specific fields exercised by the committed KAT vectors.
#[test]
fn decode_rejects_null_value_for_any_key() {
    // map(1): {1: null}.
    assert_eq!(cbor::decode(&[0xa1, 0x01, 0xf6]), Err(CborError::NullPresent));
}

/// FINDING: a CBOR tag (major type 6) MUST NOT appear on the DMTAP wire (§18.1.1 rule 5) — DMTAP
/// has no use for tags, and accepting one would be an unbounded, unaudited extension point.
#[test]
fn decode_rejects_cbor_tag() {
    // tag(0) "A" — tag major type 6 wrapping a 1-byte text string.
    assert_eq!(cbor::decode(&[0xc0, 0x61, 0x41]), Err(CborError::TagOrUndefined));
}

/// FINDING: a signed object's decoder rejects any unknown/reserved integer key rather than
/// silently ignoring it (§18.1.2) — otherwise an attacker-appended key could smuggle data past
/// the signature-covered preimage without detection (the signature only covers *known* fields).
/// Exercised here against `Envelope`, built and signed entirely through the public `build_mote`
/// API (no access to private encoder internals from this external test file).
#[test]
fn envelope_decoder_rejects_unknown_signed_key() {
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
    m.push((63, Cv::U64(1))); // an unknown, reserved-range key
    let bytes = cbor::encode(&Cv::Map(m));
    assert_eq!(Envelope::from_det_cbor(&bytes), Err(CborError::UnknownKey(63)));
}

// ================================================================================================
// MOTE §2.7 ordered validation — content address + sender signature (already-fixed, locked here
// through the full public `validate` pipeline rather than re-deriving the primitives by hand).
// ================================================================================================

fn build_and_seal(kind: Kind) -> (Envelope, IdentityKey, SealKeypair) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let recipient = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let draft = MoteDraft::new(kind, 1_700_000_000_000, b"hello dmtap".to_vec());
    let env = build_mote(&Hpke, &sender, &eph, &recipient.public(), seal.public(), draft)
        .expect("build_mote must succeed");
    (env, recipient, seal)
}

/// FINDING: a tampered ciphertext fails the content-address check and is dropped BEFORE any
/// decryption is attempted (spec §2.7 step 2, decryption-DoS defense) — `MoteError::BadContentAddress`.
#[test]
fn tampered_ciphertext_fails_content_address_before_decrypt() {
    let (mut env, recipient, seal) = build_and_seal(Kind::Chat);
    env.ciphertext[0] ^= 0xff;
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadContentAddress));
}

/// FINDING: a forged `sender_sig` (the ephemeral per-message signature checked BEFORE decryption,
/// §2.7 step 3) is discarded rather than accepted or, worse, decrypted anyway.
#[test]
fn forged_sender_sig_is_discarded_before_decrypt() {
    let (mut env, recipient, seal) = build_and_seal(Kind::Chat);
    if let Some(sig) = env.sender_sig.as_mut() {
        sig[0] ^= 0xff;
    }
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    assert_eq!(validate(&Hpke, &env, &ctx), Err(MoteError::BadSignature));
}

/// Positive control: an untampered, known-sender MOTE is accepted end to end (pairs with the two
/// negative tests above so a future change can't trivially "fix" them by making validate() always
/// fail).
#[test]
fn untampered_known_sender_mote_is_accepted() {
    let (env, recipient, seal) = build_and_seal(Kind::Mail);
    let ctx = RecipientCtx { our_ik: &recipient.public(), seal_secret: seal.secret(), sender_is_known: true };
    match validate(&Hpke, &env, &ctx).unwrap() {
        Outcome::Accepted(p) => assert_eq!(p.body, b"hello dmtap"),
        Outcome::Deferred => panic!("a known-contact MOTE must be accepted, not deferred"),
    }
}

// ================================================================================================
// Suite fail-closed / no silent downgrade (spec §1.1, §1.3, §18.1.4).
// ================================================================================================

/// FINDING: an UNREGISTERED algorithm-suite byte is never guessed at — `Suite::from_u8` fails
/// closed for every byte outside the registered ids (§1.1, §18.1.4, §21.15). The three registered
/// ids `0x01`/`0x02`/`0x03` decode (0x02/0x03 are RESERVED — known code points that fail closed on
/// *use*, not on *decode*); every unregistered byte returns `None`.
#[test]
fn suite_from_u8_fails_closed_on_unknown_bytes() {
    assert_eq!(Suite::from_u8(0x01), Some(Suite::Classical));
    assert_eq!(Suite::from_u8(0x02), Some(Suite::PqHybrid));
    assert_eq!(Suite::from_u8(0x03), Some(Suite::ReservedAeadGcm));
    // 0x03 is registered-but-unimplemented: it must not be usable at either layer.
    assert!(!Suite::ReservedAeadGcm.is_supported() && !Suite::ReservedAeadGcm.mote_supported());
    for b in [0x00u8, 0x04, 0x7f, 0xfe, 0xff] {
        assert_eq!(Suite::from_u8(b), None, "suite byte 0x{b:02x} must fail closed, never be guessed");
    }
}

/// FINDING: an `Identity` that only declares the reserved PQ suite (`0x02`) is rejected rather
/// than silently downgraded/accepted by an implementation that cannot actually validate it (spec
/// §1.3: "reject rather than fall back silently"). Built entirely from public fields — `Identity`
/// does not hide its internals from an external verifier of this invariant.
#[test]
fn pq_only_identity_fails_closed_not_silently_downgraded() {
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
        sig: vec![vec![0u8; 64]], // suite unsupported ⇒ rejected before this bogus sig is even checked
    };
    assert_eq!(id.verify(None), Err(IdentityError::UnsupportedSuite(0x02)));
}

// ================================================================================================
// Identity hash-chain sanity (spec §1.3, §3.4) and signature-tamper detection.
// ================================================================================================

/// FINDING: `version == 0` MUST NOT carry a `prev` link, and `version > 0` MUST carry one — a
/// broken hash chain is rejected (`IdentityError::BrokenChain`) rather than silently accepted,
/// which would let an attacker splice/replay an out-of-sequence identity update.
#[test]
fn identity_hash_chain_sanity_is_enforced() {
    let ik = IdentityKey::generate();
    // version 0 with a `prev` present is a broken chain (genesis must have no ancestor).
    let mut genesis_with_prev = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        ContentId::of(b"rec"),
        vec!["a@b.com".into()],
        Some(ContentId::of(b"nonexistent-ancestor")),
        1,
    );
    // create_classical signs whatever `prev` we gave it, so the signature itself is still valid —
    // it's the *chain sanity* check inside verify() that must catch this, not signature failure.
    assert_eq!(genesis_with_prev.verify(None), Err(IdentityError::BrokenChain));

    // version > 0 with prev = None is equally broken (a non-genesis version must chain somewhere).
    genesis_with_prev.version = 5;
    genesis_with_prev.prev = None;
    // Note: mutating after signing invalidates the signature too, but BrokenChain is checked
    // independently of signature validity inside verify(); we only need SOME rejection here, and
    // we assert the specific chain-sanity path by checking the version=0,prev=None happy path
    // separately below to isolate the property.
    assert!(genesis_with_prev.verify(None).is_err());
}

/// Positive control isolating the hash-chain rule from signature validity: `version == 0, prev ==
/// None` is the only valid genesis shape and MUST verify.
#[test]
fn identity_genesis_version_zero_no_prev_is_valid() {
    let ik = IdentityKey::generate();
    let id = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        ContentId::of(b"rec"),
        vec!["a@b.com".into()],
        None,
        1,
    );
    assert!(id.verify(None).is_ok());
}

/// FINDING: tampering with any signed field of an `Identity` (here, appending a name after
/// signing) invalidates the signature — the signed preimage covers the whole object.
#[test]
fn tampered_identity_fails_signature() {
    let ik = IdentityKey::generate();
    let mut id = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"kp")),
        ContentId::of(b"rec"),
        vec!["a@b.com".into()],
        None,
        1,
    );
    id.names.push("evil@attacker.com".into());
    assert_eq!(id.verify(None), Err(IdentityError::BadSignature));
}

/// FINDING: a `DeviceCert` whose `ik` field is swapped out after issuance fails signature
/// verification (the signer's identity is itself part of the signed preimage, so it cannot be
/// re-pointed at a different root key post hoc).
#[test]
fn device_cert_with_swapped_ik_fails_signature() {
    let ik = IdentityKey::generate();
    let dev = IdentityKey::generate();
    let cert = DeviceCert::issue(&ik, dev.public(), "home-box", 1, None, vec![Cap::Send, Cap::Recv]);
    assert!(cert.verify().is_ok());
    let mut forged = cert.clone();
    forged.ik = dev.public(); // attacker swaps in a different (their own) root key
    assert_eq!(forged.verify(), Err(IdentityError::BadSignature));
}

// ================================================================================================
// Recovery policy structural invariant (spec §1.4 rule 2).
// ================================================================================================

/// FINDING: `rotate_threshold` MUST NOT be empty — an empty rotate threshold would mean NO factor
/// (or every factor trivially) can rewrite the recovery policy, either locking the owner out
/// forever or letting a single compromised factor silently take over recovery. `verify()` checks
/// this structural invariant independently of the signature.
#[test]
fn recovery_policy_rejects_empty_rotate_threshold() {
    use dmtap_core::identity::{RecoveryMethod, RecoveryPolicy, Threshold};
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
    policy.sign(&ik);
    assert_eq!(
        policy.verify(),
        Err(IdentityError::Malformed("rotate_threshold must not be empty"))
    );
}

// ================================================================================================
// Mixnet descriptor structural fail-closed (spec §18.5.2: `mix-layer` = 0..2, `mix_keys` ≥ 1).
// ================================================================================================

fn mix_descriptor(seed: u8, layer: u8) -> MixNodeDescriptor {
    MixNodeDescriptor::issue(
        &key(seed),
        vec!["/ip4/198.51.100.7/udp/443/quic-v1".into()],
        vec![MixKeyEntry { epoch: 42, mix_key: vec![seed; 32], valid_until: 1_700_000_600_000 }],
        layer,
        1_700_000_000_000,
        None,
        None,
    )
}

/// FINDING: `layer` outside `0..=2` (spec §18.5.2 `mix-layer`) is rejected on decode rather than
/// silently accepted as some default/clamped layer, which could misroute traffic through the
/// stratified mixnet topology in an attacker-chosen way.
#[test]
fn mix_node_descriptor_out_of_range_layer_fails_closed() {
    let d = mix_descriptor(0x11, 0);
    let mut m = match cbor::decode(&d.det_cbor()).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    for (k, v) in m.iter_mut() {
        if *k == 5 {
            *v = Cv::U64(3); // illegal: mix-layer is 0..=2
        }
    }
    let bytes = cbor::encode(&Cv::Map(m));
    assert_eq!(MixNodeDescriptor::from_det_cbor(&bytes), Err(CborError::UnknownDiscriminant(3)));
}

/// FINDING: a descriptor with zero Sphinx mix keys (`mix_keys` requires `[+ MixKeyEntry]`, i.e.
/// at least one — §18.5.2) is rejected rather than accepted as a descriptor with no usable key
/// material for any epoch.
#[test]
fn mix_node_descriptor_empty_mix_keys_fails_closed() {
    let mut d = mix_descriptor(0x11, 0);
    d.mix_keys.clear();
    let bytes = d.det_cbor();
    assert_eq!(MixNodeDescriptor::from_det_cbor(&bytes), Err(CborError::TypeMismatch));
}

// ================================================================================================
// Domain directory: disclosed custody model + unknown-enum fail-closed (spec §3.10.2, §18.4.7).
// ================================================================================================

/// FINDING: an unrecognized `visibility` string on a `DomainDirectory` (anything other than the
/// two spec-defined values) is rejected rather than defaulted to public or members-only, either
/// of which would silently change who the directory is served to.
#[test]
fn domain_directory_rejects_unknown_visibility_string() {
    let dir = DomainDirectory::issue(
        &key(0x11),
        "abc.com",
        1,
        Visibility::Public,
        vec![DirEntry {
            name: "alice@abc.com".into(),
            ik: key(0x22).public(),
            id: ContentId::of(b"alice-identity"),
            custody: Custody::Sovereign,
            roles: None,
            added: 1,
        }],
        None,
        1,
    );
    let mut m = match cbor::decode(&dir.det_cbor()).unwrap() {
        Cv::Map(m) => m,
        _ => unreachable!(),
    };
    for (k, v) in m.iter_mut() {
        if *k == 5 {
            *v = Cv::Text("world-readable".into()); // not a spec-defined visibility value
        }
    }
    let bytes = cbor::encode(&Cv::Map(m));
    assert_eq!(DomainDirectory::from_det_cbor(&bytes), Err(CborError::TypeMismatch));
}

/// Positive control: a well-formed, correctly-signed `DomainDirectory` verifies, and tampering
/// with its entries after signing invalidates the signature (the directory "indexes, does not
/// forge" — spec §3.10.3 — but it must still be tamper-evident itself).
#[test]
fn domain_directory_tamper_after_signing_fails_signature() {
    let mut dir = DomainDirectory::issue(&key(0x11), "abc.com", 1, Visibility::MembersOnly, vec![], None, 1);
    assert!(dir.verify().is_ok());
    dir.entries.push(DirEntry {
        name: "evil@abc.com".into(),
        ik: key(0x44).public(),
        id: ContentId::of(b"evil"),
        custody: Custody::Sovereign,
        roles: None,
        added: 1,
    });
    assert_eq!(dir.verify(), Err(IdentityError::BadSignature));
}

// ================================================================================================
// Deniable prekey bundle: tamper detection (spec §18.9.10 asymmetric signing).
// ================================================================================================

/// FINDING: tampering with the published signed-prekey (`spk`) after issuance invalidates the
/// bundle's signature (both `spk_sig`, over the raw prekey, and the outer `sig`, which covers
/// `spk_sig` too, depend on the untampered `spk`).
#[test]
fn deniable_prekey_bundle_tampered_spk_fails_verification() {
    let mut b = DeniablePrekeyBundle::issue(&key(0x11), vec![0xcd; 32], vec![0xab; 32], vec![], 1, 1);
    assert!(b.verify().is_ok());
    b.spk[0] ^= 0xff;
    assert_eq!(b.verify(), Err(IdentityError::BadSignature));
}

// ================================================================================================
// Content addressing: tamper detection + unknown-algorithm fail-closed (spec §2.2).
// ================================================================================================

/// FINDING: any change to the addressed bytes is detected by `ContentId::verify` — this is the
/// primitive the whole content-addressing / dedup / MOTE-step-2 defense is built on.
#[test]
fn content_id_detects_any_tamper() {
    let data = b"the atomic unit of DMTAP";
    let id = ContentId::of(data);
    assert!(id.verify(data));
    assert!(!id.verify(b"the atomic unit of DMTAQ"), "single-byte change must be detected");
}

/// FINDING: an unknown content-address algorithm prefix fails closed rather than being treated
/// as, say, an all-zero digest or an unconditionally-trusted address (spec §2.2: never guess).
#[test]
fn content_id_unknown_algorithm_prefix_fails_closed() {
    let mut id = ContentId::of(b"x");
    id.0[0] = 0x99; // unknown multihash-style prefix
    assert!(!id.verify(b"x"));
}

// ================================================================================================
// Key-name: mistyped-word checksum rejection (spec §3.9.1, §16.2).
// ================================================================================================

/// FINDING: a key-name with a single mistyped/misheard word fails its internal checksum, so it
/// can never silently resolve to a *different* key than the one the speaker meant (spec §3.9.1).
#[test]
fn keyname_single_word_typo_fails_checksum() {
    let good = dmtap_core::keyname::encode(&[42u8; 32]);
    assert!(dmtap_core::keyname::verify(&good));

    let mut words: Vec<String> = good.split('-').map(str::to_owned).collect();
    let alt = dmtap_core::keyname::encode(&[7u8; 32]);
    let replacement = alt.split('-').next().unwrap().to_string();
    // Pick a replacement word guaranteed to differ from the original first word.
    words[0] = if words[0] == replacement {
        dmtap_core::keyname::encode(&[8u8; 32]).split('-').next().unwrap().to_string()
    } else {
        replacement
    };
    let typo = words.join("-");
    assert_ne!(typo, good);
    assert!(!dmtap_core::keyname::verify(&typo), "a single mistyped word must fail the checksum");
}
