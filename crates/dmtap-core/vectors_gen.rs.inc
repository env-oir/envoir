// Shared conformance-vector logic — `include!`d by BOTH `examples/gen_vectors.rs` (which writes
// the JSON) and `tests/conformance_vectors.rs` (which re-derives and self-checks). Keeping the
// generator and the checker on one source of truth means the committed vectors can never silently
// drift from what the reference crate `dmtap-core` actually computes.
//
// Everything here is derived from FIXED seeds/inputs so the vectors are byte-for-byte
// reproducible (Ed25519 is deterministic per RFC 8032; BLAKE3 and CBOR are deterministic).
// Non-deterministic operations (HPKE ephemeral encapsulation, key generation) are NOT vectored;
// their deterministic sub-operations (content-address, sender_sig, payload_sig) are.

use dmtap_core::capability::{
    Capability, CapabilityRevocation, CapabilityToken, CAP_REVOCATION_DS, CAP_TOKEN_DS,
};
use dmtap_core::cbor::Cv;
use dmtap_core::deniable::{
    DeniableFrame, DeniableInit, DeniableMessage, DeniablePayload, DeniablePrekeyBundle,
    DENIABLE_IDK_DS, DENIABLE_PREKEYS_DS, DENIABLE_SPK_DS,
};
use dmtap_core::directory::{Custody, DirEntry, DomainDirectory, Visibility, DOMAIN_DIRECTORY_DS};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, Cap, DeviceCert, Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_core::kt::{
    identity_leaf_hash, ConsistencyProof, InclusionProof, SignedTreeHead, KT_STH_DS,
};
use dmtap_core::mixnet::{
    MixDirectory, MixKeyEntry, MixNodeDescriptor, MIX_DESCRIPTOR_DS, MIX_DIRECTORY_DS,
};
use dmtap_core::mote::{
    DeliveryTag, Envelope, Headers, Kind, Manifest, Payload, ENVELOPE_SENDER_DS, PAYLOAD_SIG_DS,
};
use dmtap_core::safety;
use dmtap_core::sphinx::{RoutingCommand, SphinxCell, SphinxFragmentHeader, Surb};
use dmtap_core::suite::Suite;
use dmtap_core::keyname;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// The exact §18.9 domain-separation tags (ASCII + trailing 0x00) the reference MOTE layer signs
// under, re-exported from `dmtap_core::mote`, so the sender_sig / payload_sig preimages are
// machine-checkable by any implementation.
const PAYLOAD_SIG_DOMAIN: &[u8] = PAYLOAD_SIG_DS;
const SENDER_SIG_DOMAIN: &[u8] = ENVELOPE_SENDER_DS;

// ---- helpers ------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn cbor(v: &impl Serialize) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).expect("infallible CBOR encode");
    buf
}

fn arr32(hexs: &str) -> [u8; 32] {
    unhex(hexs).try_into().expect("32-byte hex")
}

/// Reconstruct a Sphinx byte-layout object from a `sphinx_encode` vector's `input` and return its
/// fixed on-wire bytes (§18.5.4), asserting a `from_bytes` round-trip on the way.
fn sphinx_encode_from_input(inp: &Value) -> Vec<u8> {
    match inp["type"].as_str().unwrap() {
        "RoutingCommand" => {
            let rc = RoutingCommand {
                cmd: inp["cmd"].as_u64().unwrap() as u8,
                flags: inp["flags"].as_u64().unwrap() as u8,
                delay_ms: inp["delay_ms"].as_u64().unwrap() as u32,
                next_hop: arr32(inp["next_hop_hex"].as_str().unwrap()),
            };
            let bytes = rc.to_bytes();
            assert_eq!(RoutingCommand::from_bytes(&bytes).unwrap(), rc, "RoutingCommand round-trip");
            bytes.to_vec()
        }
        "Surb" => {
            let s = Surb {
                first_hop: arr32(inp["first_hop_hex"].as_str().unwrap()),
                header: unhex(inp["header_hex"].as_str().unwrap()),
                key_seed: arr32(inp["key_seed_hex"].as_str().unwrap()),
            };
            let bytes = s.to_bytes();
            assert_eq!(Surb::from_bytes(&bytes).unwrap(), s, "Surb round-trip");
            bytes
        }
        "SphinxFragmentHeader" => {
            let h = SphinxFragmentHeader {
                msg_id: unhex(inp["msg_id_hex"].as_str().unwrap()).try_into().expect("8-byte msg_id"),
                frag_index: inp["frag_index"].as_u64().unwrap() as u16,
                frag_count: inp["frag_count"].as_u64().unwrap() as u16,
                total_len: inp["total_len"].as_u64().unwrap() as u32,
            };
            let bytes = h.to_bytes();
            assert_eq!(SphinxFragmentHeader::from_bytes(&bytes).unwrap(), h, "fragment header round-trip");
            bytes.to_vec()
        }
        "SphinxCell" => {
            let c = SphinxCell {
                alpha: arr32(inp["alpha_hex"].as_str().unwrap()),
                beta: unhex(inp["beta_hex"].as_str().unwrap()),
                gamma: unhex(inp["gamma_hex"].as_str().unwrap()).try_into().expect("16-byte gamma"),
                delta: unhex(inp["delta_hex"].as_str().unwrap()),
            };
            let bytes = c.to_bytes();
            assert_eq!(SphinxCell::from_bytes(&bytes).unwrap(), c, "cell round-trip");
            bytes
        }
        other => panic!("unknown sphinx type {other}"),
    }
}

// ---- vector data model --------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Vector {
    name: String,
    operation: String,
    input: Value,
    expected: Value,
    note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct VectorFile {
    format: String,
    suite: String,
    generated_by: String,
    methodology: String,
    vectors: Vec<Vector>,
}

fn v(name: &str, operation: &str, input: Value, expected: Value, note: &str) -> Vector {
    Vector {
        name: name.into(),
        operation: operation.into(),
        input,
        expected,
        note: note.into(),
    }
}

// ---- fixed inputs -------------------------------------------------------------------------

// RFC 8032 §7.1 TEST 1 secret seed (all deterministic Ed25519 signatures below use from_seed).
const SEED_RFC8032_T1: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
// RFC 8032 §7.1 TEST 2 secret seed (message = single byte 0x72).
const SEED_RFC8032_T2: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

// Two distinct fixed identity seeds used across identity/keyname/safety/mote vectors.
const SEED_A: [u8; 32] = [0x11; 32];
const SEED_B: [u8; 32] = [0x22; 32];
const SEED_EPH: [u8; 32] = [0x33; 32];

// A multi-KiB deterministic content-address input: 4096 bytes, byte[i] = (i * 37 + 11) & 0xff.
fn multi_kib_input() -> Vec<u8> {
    (0..4096u32).map(|i| ((i.wrapping_mul(37).wrapping_add(11)) & 0xff) as u8).collect()
}

// ---- the vector set -----------------------------------------------------------------------

fn build_all() -> VectorFile {
    let mut vectors: Vec<Vector> = Vec::new();

    // === 1. Content address: [0x1e] || BLAKE3-256(bytes) (spec §2.2, §18.1.5) ===============
    for (name, bytes, note) in [
        ("content_address_empty", Vec::<u8>::new(), "empty input"),
        ("content_address_small", b"dmtap".to_vec(), "5-byte ASCII input"),
        (
            "content_address_phrase",
            b"the atomic unit of DMTAP".to_vec(),
            "human-readable phrase",
        ),
        ("content_address_multi_kib", multi_kib_input(), "4096-byte deterministic input, byte[i]=(i*37+11)&0xff"),
    ] {
        let id = ContentId::of(&bytes);
        vectors.push(v(
            name,
            "content_address",
            json!({ "bytes_hex": hex(&bytes) }),
            json!({ "id_hex": hex(id.as_bytes()) }),
            note,
        ));
    }

    // === 2. Key-name — 8 data words + 1 checksum word (spec §3.9.1, §16.2) ==================
    for (name, key, note) in [
        ("keyname_zero_key", [0u8; 32], "all-zero 32-byte key"),
        ("keyname_key_ones", [1u8; 32], "all-0x01 key (distinct from below)"),
        ("keyname_key_twos", [2u8; 32], "all-0x02 key (distinct from above → different name)"),
    ] {
        let nm = keyname::encode(&key);
        vectors.push(v(
            name,
            "keyname_encode",
            json!({ "pubkey_hex": hex(&key) }),
            json!({ "name": nm, "checksum_verifies": keyname::verify(&nm) }),
            note,
        ));
    }
    // A realistic Ed25519 public key (from SEED_A) → its name.
    {
        let pk = IdentityKey::from_seed(&SEED_A).public_array();
        let nm = keyname::encode(&pk);
        vectors.push(v(
            "keyname_real_pubkey",
            "keyname_encode",
            json!({ "pubkey_hex": hex(&pk) }),
            json!({ "name": nm, "checksum_verifies": keyname::verify(&nm) }),
            "key-name of the Ed25519 public key derived from seed 0x11*32",
        ));
    }
    // Negative: a mistyped name must fail the internal checksum (fail closed, §3.9.1).
    {
        let good = keyname::encode(&[42u8; 32]);
        // Corrupt the first word to a definitely-different word.
        let mut words: Vec<String> = good.split('-').map(str::to_owned).collect();
        // pick a replacement word that differs (use the first word from the zero-key name).
        let other_first = keyname::encode(&[7u8; 32]);
        let repl = other_first.split('-').next().unwrap().to_string();
        if words[0] == repl {
            // extremely unlikely; nudge to another
            words[0] = keyname::encode(&[8u8; 32]).split('-').next().unwrap().to_string();
        } else {
            words[0] = repl;
        }
        let typo = words.join("-");
        vectors.push(v(
            "keyname_typo_rejected",
            "keyname_verify",
            json!({ "name": typo }),
            json!({ "checksum_verifies": false }),
            "a single mistyped word must fail the folded checksum (fail closed)",
        ));
    }

    // === 3. Safety number — OOB key verification (spec §3.4.1) ==============================
    let ik_a = IdentityKey::from_seed(&SEED_A).public_array();
    let ik_b = IdentityKey::from_seed(&SEED_B).public_array();
    vectors.push(v(
        "safety_number_pair_ab",
        "safety_number",
        json!({ "ik_a_hex": hex(&ik_a), "ik_b_hex": hex(&ik_b) }),
        json!({
            "safety_number": safety::safety_number(&ik_a, &ik_b),
            "fingerprint_hex": safety::safety_number_hex(&ik_a, &ik_b),
        }),
        "safety number of the (seed 0x11, seed 0x22) identity-key pair",
    ));
    // Order independence: swapping the pair yields the identical value.
    vectors.push(v(
        "safety_number_order_independent",
        "safety_number",
        json!({ "ik_a_hex": hex(&ik_b), "ik_b_hex": hex(&ik_a) }),
        json!({
            "safety_number": safety::safety_number(&ik_b, &ik_a),
            "fingerprint_hex": safety::safety_number_hex(&ik_b, &ik_a),
        }),
        "same pair, keys swapped → MUST equal safety_number_pair_ab (order-independent)",
    ));

    // === 4. Ed25519 sign / verify (deterministic, RFC 8032) ================================
    // (a) Raw Ed25519 KAT with empty domain == RFC 8032 §7.1 Test 1 (empty message).
    {
        let sk = IdentityKey::from_seed(&SEED_RFC8032_T1);
        let sig = sk.sign_domain(b"", b"");
        vectors.push(v(
            "ed25519_rfc8032_test1",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_RFC8032_T1), "domain_hex": "", "msg_hex": "" }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "RFC 8032 §7.1 Test 1 cross-check (empty domain, empty message)",
        ));
    }
    // (b) Raw Ed25519 KAT == RFC 8032 §7.1 Test 2 (message = 0x72).
    {
        let sk = IdentityKey::from_seed(&SEED_RFC8032_T2);
        let msg = [0x72u8];
        let sig = sk.sign_domain(b"", &msg);
        vectors.push(v(
            "ed25519_rfc8032_test2",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_RFC8032_T2), "domain_hex": "", "msg_hex": hex(&msg) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "RFC 8032 §7.1 Test 2 cross-check (empty domain, 1-byte message 0x72)",
        ));
    }
    // (c) Domain-separated signature exactly as DMTAP signs a payload (sign_domain).
    {
        let sk = IdentityKey::from_seed(&SEED_A);
        let msg = b"conformance message for domain-separated signing";
        let sig = sk.sign_domain(PAYLOAD_SIG_DOMAIN, msg);
        vectors.push(v(
            "ed25519_domain_separated",
            "ed25519_sign",
            json!({
                "seed_hex": hex(&SEED_A),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(msg),
            }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "Ed25519 over (domain || msg) — how dmtap-core signs (sign_domain)",
        ));
        // Verify-succeeds vector.
        vectors.push(v(
            "ed25519_verify_ok",
            "ed25519_verify",
            json!({
                "pubkey_hex": hex(&sk.public_array()),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(msg),
                "sig_hex": hex(&sig),
            }),
            json!({ "valid": true }),
            "the signature above MUST verify",
        ));
        // Verify-fails: tampered message.
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 0x01;
        vectors.push(v(
            "ed25519_verify_tampered_msg",
            "ed25519_verify",
            json!({
                "pubkey_hex": hex(&sk.public_array()),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(&bad_msg),
                "sig_hex": hex(&sig),
            }),
            json!({ "valid": false }),
            "flipping one message bit MUST fail verification (fail closed)",
        ));
        // Verify-fails: tampered signature.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        vectors.push(v(
            "ed25519_verify_tampered_sig",
            "ed25519_verify",
            json!({
                "pubkey_hex": hex(&sk.public_array()),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(msg),
                "sig_hex": hex(&bad_sig),
            }),
            json!({ "valid": false }),
            "flipping one signature bit MUST fail verification (fail closed)",
        ));
    }

    // === 5. Canonical CBOR — fixed objects → exact bytes (spec §18.1.1) =====================
    // (a) A signed Identity built from a fixed seed (Ed25519 deterministic → stable bytes).
    let identity = Identity::create_classical(
        &IdentityKey::from_seed(&SEED_A),
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/keypkgs", ContentId::of(b"keypkgs-bundle")),
        ContentId::of(b"recovery-policy"),
        vec!["alice@example.com".into()],
        None,
        1_700_000_000_000,
    );
    {
        let bytes = identity.det_cbor();
        vectors.push(v(
            "cbor_identity",
            "cbor_encode",
            json!({ "type": "Identity", "note": "created via Identity::create_classical, seed 0x11*32, version 0; §18.4.1 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes), "content_id_hex": hex(identity.content_id().as_bytes()) }),
            "§18-canonical integer-keyed CBOR of a signed single-suite Identity; also its §18.9.4 content address",
        ));
    }
    // (b) A signed DeviceCert (fixed IK + fixed device key).
    {
        let ik = IdentityKey::from_seed(&SEED_A);
        let device_pk = IdentityKey::from_seed(&SEED_B).public();
        let cert = DeviceCert::issue(
            &ik,
            device_pk,
            "home-box",
            1_700_000_000_000,
            None,
            vec![Cap::Send, Cap::Recv, Cap::Relay],
        );
        let bytes = cert.det_cbor();
        vectors.push(v(
            "cbor_device_cert",
            "cbor_encode",
            json!({ "type": "DeviceCert", "note": "IK seed 0x11*32 signs device key seed 0x22*32; §18.4.2 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an IK-signed DeviceCert",
        ));
    }
    // (c) A fixed Payload (no crypto RNG → fully deterministic).
    let payload = Payload {
        from: IdentityKey::from_seed(&SEED_A).public(),
        sig: vec![0u8; 64], // fixed placeholder signature bytes
        headers: Headers {
            thread: Some(vec![0xaa, 0xbb]),
            subject: Some("hello".into()),
            mime: Some("text/plain; charset=utf-8".into()),
            cc: vec![],
        },
        body: b"hello dmtap".to_vec(),
        refs: vec![ContentId::of(b"parent-mote")],
        attach: vec![],
        expires: None,
    };
    {
        let bytes = payload.det_cbor();
        vectors.push(v(
            "cbor_payload",
            "cbor_encode",
            json!({ "type": "Payload", "note": "fixed fields; sig is a fixed 64-byte placeholder; §18.3.5 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a MOTE Payload",
        ));
    }
    // (d) A fully-fixed Envelope (fixed ciphertext/sig bytes → deterministic; HPKE not invoked).
    let fixed_ciphertext = multi_kib_input()[..48].to_vec();
    let envelope = Envelope {
        v: 0,
        suite: Suite::Classical,
        id: ContentId::of(&fixed_ciphertext),
        to: DeliveryTag::Key(IdentityKey::from_seed(&SEED_B).public()),
        epoch: None,
        ts: 1_700_000_000_000,
        kind: Kind::Mail,
        keypkg: None,
        challenge: None,
        ciphertext: fixed_ciphertext.clone(),
        sender_sig: Some(vec![0u8; 64]),
        sender_eph: Some(IdentityKey::from_seed(&SEED_EPH).public()),
    };
    {
        let bytes = envelope.det_cbor();
        vectors.push(v(
            "cbor_envelope",
            "cbor_encode",
            json!({ "type": "Envelope", "note": "fixed ciphertext (48 bytes) + fixed sig placeholders; to = KeyTag; id = content address of ciphertext; §18.3.1 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a MOTE Envelope; round-trip-checked in the self-test",
        ));
    }

    // === 6. Suite fail-closed — an UNREGISTERED suite byte MUST be rejected (spec §1.1, §18.1.4) =
    for (name, byte) in [
        ("suite_reject_0x00", 0x00u8),
        ("suite_reject_0x04", 0x04u8),
        ("suite_reject_0x05", 0x05u8),
        ("suite_reject_0xff", 0xffu8),
    ] {
        let cbor_bytes = cbor(&byte);
        vectors.push(v(
            name,
            "suite_decode",
            json!({ "cbor_hex": hex(&cbor_bytes) }),
            json!({ "accepted": false }),
            "an unregistered suite byte MUST fail to decode (never guess; fail closed)",
        ));
    }
    // Positive controls: 0x01/0x02/0x03 decode as KNOWN suite ids (0x02 reserved-PQ, 0x03
    // reserved AEAD-diverse — both known code points, §21.15; unimplemented ⇒ fail closed on USE).
    for (name, byte) in [
        ("suite_accept_0x01", 0x01u8),
        ("suite_accept_0x02", 0x02u8),
        ("suite_accept_0x03", 0x03u8),
    ] {
        let cbor_bytes = cbor(&byte);
        vectors.push(v(
            name,
            "suite_decode",
            json!({ "cbor_hex": hex(&cbor_bytes) }),
            json!({ "accepted": true }),
            "0x01 (classical), 0x02 (reserved PQ), and 0x03 (reserved AEAD-diverse) are known suite ids and decode",
        ));
    }

    // === 7. MOTE validation-ordering KATs (spec §2.7) ======================================
    // (a) Content-address check (§2.7 step 2) — recomputed BEFORE any decryption.
    vectors.push(v(
        "mote_content_address_ok",
        "content_address_verify",
        json!({ "ciphertext_hex": hex(&fixed_ciphertext), "id_hex": hex(envelope.id.as_bytes()) }),
        json!({ "valid": true }),
        "id MUST equal the content address of the ciphertext (checked before decryption)",
    ));
    {
        let mut tampered = fixed_ciphertext.clone();
        tampered[0] ^= 0xff;
        vectors.push(v(
            "mote_content_address_tampered",
            "content_address_verify",
            json!({ "ciphertext_hex": hex(&tampered), "id_hex": hex(envelope.id.as_bytes()) }),
            json!({ "valid": false }),
            "a tampered ciphertext MUST fail the content-address check (drop before decrypt)",
        ));
    }
    // (b) sender_sig KAT (§2.7 step 3, §18.9.1) — Ed25519 over the DS-tag ‖
    //     (id ‖ det_cbor(to) ‖ ts_be64 ‖ kind ‖ challenge_enc) preimage. `challenge_enc` is the
    //     single byte 0xf6 (CBOR null) when the challenge is absent.
    {
        let eph = IdentityKey::from_seed(&SEED_EPH);
        let preimage = envelope.sender_sig_body();
        let sig = eph.sign_domain(SENDER_SIG_DOMAIN, &preimage);
        vectors.push(v(
            "mote_sender_sig",
            "ed25519_sign",
            json!({
                "seed_hex": hex(&SEED_EPH),
                "domain_hex": hex(SENDER_SIG_DOMAIN),
                "msg_hex": hex(&preimage),
            }),
            json!({ "pubkey_hex": hex(&eph.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.1 sender_sig body = id||det_cbor(to)||ts_be64||kind||0xf6 (challenge absent); DS-tag 'DMTAP-v0/envelope-sender\\0'; ephemeral key seed 0x33*32",
        ));
        vectors.push(v(
            "mote_sender_sig_verify",
            "ed25519_verify",
            json!({
                "pubkey_hex": hex(&eph.public_array()),
                "domain_hex": hex(SENDER_SIG_DOMAIN),
                "msg_hex": hex(&preimage),
                "sig_hex": hex(&sig),
            }),
            json!({ "valid": true }),
            "the sender_sig above MUST verify under the ephemeral key (sender_key, §18.3.1 key 12)",
        ));
    }
    // (c) payload_sig KAT (§2.7 step 8, §18.9.2) — Ed25519 over the DS-tag ‖
    //     BLAKE3-256( det_cbor(Payload ∖ {sig}) ‖ u8(kind) ‖ u64be(ts) ‖ det_cbor(to) ). The
    //     envelope-context tail (kind/ts/to) is taken from the fixed `envelope` above.
    {
        let sk = IdentityKey::from_seed(&SEED_A);
        let ph = payload.signing_hash(envelope.kind, envelope.ts, &envelope.to);
        let sig = sk.sign_domain(PAYLOAD_SIG_DOMAIN, &ph);
        vectors.push(v(
            "mote_payload_sig",
            "ed25519_sign",
            json!({
                "seed_hex": hex(&SEED_A),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(&ph),
                "payload_hash_hex": hex(&ph),
                "kind": envelope.kind.as_u8(),
                "ts": envelope.ts,
                "to_cbor_hex": hex(&envelope.to.det_cbor()),
            }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.2 payload signature: BLAKE3-256(det_cbor(Payload ∖ {sig}) ‖ u8(kind) ‖ u64be(ts) ‖ det_cbor(to)) under DS-tag 'DMTAP-v0/payload\\0'; IK seed 0x11*32; kind/ts/to from the fixed envelope",
        ));
    }

    // === 8. Mixnet directory objects (§18.5.2 / §18.5.3) ====================================
    // A mix node's signed self-descriptor (node_ik = seed 0x11), one Sphinx mix key for epoch 42.
    let mix_descriptor = MixNodeDescriptor::issue(
        &IdentityKey::from_seed(&SEED_A),
        vec!["/ip4/198.51.100.7/udp/443/quic-v1".into()],
        vec![MixKeyEntry { epoch: 42, mix_key: vec![0xa1; 32], valid_until: 1_700_000_600_000 }],
        0, // entry layer
        1_700_000_000_000,
        None,
        None,
    );
    {
        let bytes = mix_descriptor.det_cbor();
        vectors.push(v(
            "cbor_mix_descriptor",
            "cbor_encode",
            json!({ "type": "MixNodeDescriptor", "note": "node_ik seed 0x11*32; one MixKeyEntry (epoch 42); layer 0; §18.5.2 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an IK-signed MixNodeDescriptor",
        ));
        // Signing KAT (§18.9.9): Ed25519 over DS-tag ‖ det_cbor(MixNodeDescriptor ∖ {7}).
        let sk = IdentityKey::from_seed(&SEED_A);
        let body = mix_descriptor.signing_body();
        let sig = sk.sign_domain(MIX_DESCRIPTOR_DS, &body);
        vectors.push(v(
            "mix_descriptor_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(MIX_DESCRIPTOR_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.9 MixNodeDescriptor.sig: DS-tag 'DMTAP-v0/mix-descriptor\\0' ‖ det_cbor(descriptor ∖ {7}); node_ik seed 0x11*32",
        ));
        vectors.push(v(
            "mix_descriptor_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(MIX_DESCRIPTOR_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the MixNodeDescriptor signature above MUST verify under node_ik (§18.5.2 key 2)",
        ));
    }
    // A signed MixDirectory (authority = seed 0x22) enclosing the descriptor above (+ a middle-layer
    // one from seed 0x33), each independently signed by its own node_ik.
    let mix_descriptor_mid = MixNodeDescriptor::issue(
        &IdentityKey::from_seed(&SEED_B),
        vec!["/ip4/203.0.113.9/udp/443/quic-v1".into()],
        vec![MixKeyEntry { epoch: 42, mix_key: vec![0xb2; 32], valid_until: 1_700_000_600_000 }],
        1, // middle layer
        1_700_000_000_000,
        None,
        None,
    );
    let mix_directory = MixDirectory::issue(
        &IdentityKey::from_seed(&SEED_EPH),
        42,
        1,
        vec![mix_descriptor.clone(), mix_descriptor_mid],
        ContentId::of(b"prev-mix-directory"),
        1_700_000_000_000,
    );
    {
        let bytes = mix_directory.det_cbor();
        vectors.push(v(
            "cbor_mix_directory",
            "cbor_encode",
            json!({ "type": "MixDirectory", "note": "authority seed 0x33*32; two independently-signed MixNodeDescriptors (layers 0,1); §18.5.3 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an authority-signed MixDirectory",
        ));
        let sk = IdentityKey::from_seed(&SEED_EPH);
        let body = mix_directory.signing_body();
        let sig = sk.sign_domain(MIX_DIRECTORY_DS, &body);
        vectors.push(v(
            "mix_directory_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_EPH), "domain_hex": hex(MIX_DIRECTORY_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.9 MixDirectory.sig: DS-tag 'DMTAP-v0/mix-directory\\0' ‖ det_cbor(directory ∖ {8}); authority seed 0x33*32",
        ));
        vectors.push(v(
            "mix_directory_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(MIX_DIRECTORY_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the MixDirectory signature above MUST verify under the pinned authority (§18.5.3 key 2)",
        ));
    }

    // === 9. Organization directory (§18.4.7) ================================================
    let domain_directory = DomainDirectory::issue(
        &IdentityKey::from_seed(&SEED_A),
        "abc.com",
        7,
        Visibility::Public,
        vec![
            DirEntry {
                name: "alice@abc.com".into(),
                ik: IdentityKey::from_seed(&SEED_B).public(),
                id: ContentId::of(b"alice-identity"),
                custody: Custody::Sovereign,
                roles: Some(vec!["admin".into()]),
                added: 1_700_000_000_000,
            },
            DirEntry {
                name: "bob@abc.com".into(),
                ik: IdentityKey::from_seed(&SEED_EPH).public(),
                id: ContentId::of(b"bob-identity"),
                custody: Custody::OrgManaged,
                roles: None,
                added: 1_700_000_000_000,
            },
        ],
        None,
        1_700_000_000_000,
    );
    {
        let bytes = domain_directory.det_cbor();
        vectors.push(v(
            "cbor_domain_directory",
            "cbor_encode",
            json!({ "type": "DomainDirectory", "note": "authority seed 0x11*32; two DirEntry (sovereign + org-managed); §18.4.7 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an authority-signed DomainDirectory",
        ));
        let sk = IdentityKey::from_seed(&SEED_A);
        let body = domain_directory.signing_body();
        let sig = sk.sign_domain(DOMAIN_DIRECTORY_DS, &body);
        vectors.push(v(
            "domain_directory_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(DOMAIN_DIRECTORY_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.3 DomainDirectory.sig: DS-tag 'DMTAP-v0/domain-directory\\0' ‖ det_cbor(directory ∖ {9}); authority seed 0x11*32",
        ));
        vectors.push(v(
            "domain_directory_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(DOMAIN_DIRECTORY_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the DomainDirectory signature above MUST verify under the pinned domain authority (§18.4.7 key 3)",
        ));
    }

    // === 10. Deniable 1:1 mode objects (§18.4.8 / §18.3.9 / §18.3.10) ========================
    // (a) DeniablePrekeyBundle — three signatures over public keys only: idk_sig (dedicated
    //     deniable-identity DH key, §18.4.8), spk_sig (signed prekey), and sig (the whole body).
    let deniable_idk = vec![0xcd; 32]; // dedicated X25519 deniable-identity DH key (NOT from IK)
    let prekey_bundle = DeniablePrekeyBundle::issue(
        &IdentityKey::from_seed(&SEED_A),
        deniable_idk.clone(),
        vec![0xab; 32],
        vec![vec![0x01; 32], vec![0x02; 32]],
        3,
        1_700_000_000_000,
    );
    {
        let bytes = prekey_bundle.det_cbor();
        vectors.push(v(
            "cbor_deniable_prekey_bundle",
            "cbor_encode",
            json!({ "type": "DeniablePrekeyBundle", "note": "ik seed 0x11*32; idk = 0xcd*32 (key 11) certified by idk_sig (key 12); spk = 0xab*32; two one-time prekeys; §18.4.8 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a device-signed DeniablePrekeyBundle (hardened: dedicated idk DH key, XEdDSA-from-IK dropped)",
        ));
        let sk = IdentityKey::from_seed(&SEED_A);
        // idk_sig KAT (§18.9.10): Ed25519 over DS-tag ‖ raw idk bytes (field 11) — the deniable-
        // identity DH-key certification that replaced XEdDSA-from-IK.
        let idk_sig = sk.sign_domain(DENIABLE_IDK_DS, &deniable_idk);
        vectors.push(v(
            "deniable_idk_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(DENIABLE_IDK_DS), "msg_hex": hex(&deniable_idk) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&idk_sig) }),
            "§18.9.10 DeniablePrekeyBundle.idk_sig (== DeniableInit.idk_a_cert): DS-tag 'DMTAP-v0/deniable-idk\\0' ‖ raw idk (field 11); device seed 0x11*32",
        ));
        vectors.push(v(
            "deniable_idk_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(DENIABLE_IDK_DS), "msg_hex": hex(&deniable_idk), "sig_hex": hex(&idk_sig) }),
            json!({ "valid": true }),
            "the idk certification above MUST verify under ik (§18.4.8 key 2)",
        ));
        // spk_sig KAT (§18.9.10): Ed25519 over DS-tag ‖ raw spk bytes (field 3).
        let spk = vec![0xabu8; 32];
        let spk_sig = sk.sign_domain(DENIABLE_SPK_DS, &spk);
        vectors.push(v(
            "deniable_spk_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(DENIABLE_SPK_DS), "msg_hex": hex(&spk) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&spk_sig) }),
            "§18.9.10 DeniablePrekeyBundle.spk_sig: DS-tag 'DMTAP-v0/deniable-spk\\0' ‖ raw spk (field 3); device seed 0x11*32",
        ));
        // bundle sig KAT (§18.9.10): Ed25519 over DS-tag ‖ det_cbor(bundle ∖ {10}) (covers spk_sig,
        // idk, and idk_sig).
        let body = prekey_bundle.signing_body();
        let sig = sk.sign_domain(DENIABLE_PREKEYS_DS, &body);
        vectors.push(v(
            "deniable_prekeys_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(DENIABLE_PREKEYS_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.10 DeniablePrekeyBundle.sig: DS-tag 'DMTAP-v0/deniable-prekeys\\0' ‖ det_cbor(bundle ∖ {10}); device seed 0x11*32",
        ));
        vectors.push(v(
            "deniable_prekeys_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(DENIABLE_PREKEYS_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the DeniablePrekeyBundle body signature above MUST verify under ik (§18.4.8 key 2)",
        ));
    }
    // (b) DeniableMessage frame (a subsequent Double-Ratchet message; NO signature).
    let deniable_message = DeniableMessage { dh: vec![0x09; 32], pn: 0, n: 5, ct: b"ratchet-ciphertext-with-mac".to_vec() };
    {
        let frame = DeniableFrame::Message(deniable_message.clone());
        let bytes = frame.det_cbor();
        vectors.push(v(
            "cbor_deniable_message",
            "cbor_encode",
            json!({ "type": "DeniableFrame", "note": "DeniableMessage (disc 2): dh=0x09*32, pn=0, n=5; NO signature; §18.3.9 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a deniable subsequent-message frame (auth = ratchet MAC, no sig)",
        ));
    }
    // (c) DeniableInit frame (the X3DH first message, embedding the DeniableMessage; NO content
    //     signature). Carries the initiator's dedicated deniable-identity DH key idk_a (key 9) and
    //     its certification idk_a_cert (key 10) — ik_a (key 2) is no longer a DH input (§18.3.9).
    let deniable_idk_a = vec![0x44; 32];
    let deniable_init = DeniableInit {
        suite: Suite::Classical,
        ik_a: IdentityKey::from_seed(&SEED_A).public(),
        idk_a: deniable_idk_a.clone(),
        idk_a_cert: IdentityKey::from_seed(&SEED_A).sign_domain(DENIABLE_IDK_DS, &deniable_idk_a),
        ek_a: vec![0x33; 32],
        spk_ref: ContentId::of(b"responder-signed-prekey"),
        opk_ref: Some(ContentId::of(b"responder-one-time-prekey")),
        kem_ct: None,
        kem_ref: None,
        msg: deniable_message,
    };
    {
        let frame = DeniableFrame::Init(deniable_init);
        let bytes = frame.det_cbor();
        vectors.push(v(
            "cbor_deniable_init",
            "cbor_encode",
            json!({ "type": "DeniableFrame", "note": "DeniableInit (disc 1): ik_a seed 0x11*32, idk_a = 0x44*32 (key 9) + idk_a_cert (key 10), embeds the DeniableMessage; NO content signature; §18.3.9 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a deniable X3DH first-message frame (auth = ratchet MAC, no content sig; idk_a is the DH input, ik_a only AD-binds)",
        ));
    }
    // (d) DeniablePayload — the ratchet plaintext (structural twin of Payload; NO signature field).
    let deniable_payload = DeniablePayload {
        from: IdentityKey::from_seed(&SEED_A).public(),
        kind: Kind::Chat,
        headers: Headers { subject: Some("deniable hi".into()), ..Default::default() },
        body: b"deniable hello dmtap".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    };
    {
        let bytes = deniable_payload.det_cbor();
        vectors.push(v(
            "cbor_deniable_payload",
            "cbor_encode",
            json!({ "type": "DeniablePayload", "note": "from seed 0x11*32; key 2 is the real content kind (chat), NOT a sig; §18.3.10 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a DeniablePayload; a smuggled signature MUST be rejected (§18.3.10)",
        ));
    }

    // === 11. File manifest (§18.3.8) + Merkle-DAG root (§18.9.5) =============================
    let manifest = {
        let chunks = vec![ContentId::of(b"chunk-0"), ContentId::of(b"chunk-1"), ContentId::of(b"chunk-2")];
        let mut m = Manifest {
            id: ContentId(Vec::new()),
            size: 3 * 1024 * 1024,
            chunk_sz: 1024 * 1024,
            chunks,
            suite: Suite::Classical,
        };
        m.id = m.merkle_root(); // §18.9.5: id MUST equal the Merkle root over the ordered chunks
        m
    };
    {
        let bytes = manifest.det_cbor();
        vectors.push(v(
            "cbor_manifest",
            "cbor_encode",
            json!({ "type": "Manifest", "note": "3 ordered chunk hashes; id = §18.9.5 Merkle root; forbidden key 5 absent; §18.3.8 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a swarm-distributed file Manifest",
        ));
        // Merkle-DAG root KAT (§18.9.5): RFC 6962 tree with domain-separated leaf/node prefixes.
        let chunk_hexes: Vec<String> = manifest.chunks.iter().map(|c| hex(c.as_bytes())).collect();
        vectors.push(v(
            "manifest_root",
            "manifest_root",
            json!({ "chunk_hashes_hex": chunk_hexes }),
            json!({ "id_hex": hex(manifest.id.as_bytes()) }),
            "§18.9.5 Manifest.id = 0x1e ‖ MTH(chunks): leaf=BLAKE3(0x00‖h), node=BLAKE3(0x01‖l‖r), RFC 6962 split, 3 chunks",
        ));
    }

    // === 12. Key-transparency objects (§18.4.9–.11, §18.9.13) ===============================
    // (a) SignedTreeHead — signed by the LOG's own key (log_id = seed 0x11), RFC-6962 profile.
    let sth = SignedTreeHead::issue(
        &IdentityKey::from_seed(&SEED_A),
        7,
        1_700_000_000_000,
        ContentId::of(b"kt-merkle-root"),
    );
    {
        let bytes = sth.det_cbor();
        vectors.push(v(
            "cbor_signed_tree_head",
            "cbor_encode",
            json!({ "type": "SignedTreeHead", "note": "log_id seed 0x11*32; tree_size 7; root = content-addr of 'kt-merkle-root'; §18.4.9 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of a log-signed SignedTreeHead (KT STH, RFC-6962 profile)",
        ));
        let sk = IdentityKey::from_seed(&SEED_A);
        let body = sth.signing_body();
        let sig = sk.sign_domain(KT_STH_DS, &body);
        vectors.push(v(
            "kt_sth_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(KT_STH_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.13 SignedTreeHead.sig: DS-tag 'DMTAP-v0/kt-sth\\0' ‖ det_cbor(STH ∖ {6}); signed by log_id seed 0x11*32",
        ));
        vectors.push(v(
            "kt_sth_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(KT_STH_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the STH signature above MUST verify under the pinned log_id (§18.4.9 key 2)",
        ));
    }
    // (b) The Identity-entry leaf-hash rule (§18.4.9 / §18.9.13).
    {
        let leaf_ik = IdentityKey::from_seed(&SEED_B).public();
        let identity_id = ContentId::of(b"alice-identity-object");
        let leaf = identity_leaf_hash("alice@abc.com", &leaf_ik, 3, &identity_id);
        vectors.push(v(
            "kt_identity_leaf_hash",
            "kt_leaf_hash",
            json!({
                "name": "alice@abc.com",
                "ik_hex": hex(&leaf_ik),
                "version": 3,
                "identity_id_hex": hex(identity_id.as_bytes()),
            }),
            json!({ "leaf_hash_hex": hex(leaf.as_bytes()) }),
            "§18.4.9 leaf_hash = 0x1e ‖ BLAKE3-256(0x00 ‖ det_cbor([name, ik, version, identity_id])); RFC-6962 leaf prefix 0x00",
        ));
    }
    // (c) InclusionProof and ConsistencyProof (unsigned; verified against the STH root).
    {
        let proof = InclusionProof {
            tree_size: 7,
            leaf_index: 2,
            leaf_hash: ContentId::of(b"kt-leaf"),
            audit_path: vec![ContentId::of(b"sibling-0"), ContentId::of(b"sibling-1"), ContentId::of(b"sibling-2")],
        };
        vectors.push(v(
            "cbor_inclusion_proof",
            "cbor_encode",
            json!({ "type": "InclusionProof", "note": "tree_size 7, leaf_index 2, 3-node audit path; unsigned (§18.4.10)" }),
            json!({ "cbor_hex": hex(&proof.det_cbor()) }),
            "§18-canonical integer-keyed CBOR of an RFC-6962 InclusionProof (audit path)",
        ));
        let cproof = ConsistencyProof {
            first_size: 4,
            second_size: 7,
            proof_path: vec![ContentId::of(b"cons-0"), ContentId::of(b"cons-1")],
        };
        vectors.push(v(
            "cbor_consistency_proof",
            "cbor_encode",
            json!({ "type": "ConsistencyProof", "note": "first_size 4, second_size 7, 2-node proof path; unsigned (§18.4.11)" }),
            json!({ "cbor_hex": hex(&cproof.det_cbor()) }),
            "§18-canonical integer-keyed CBOR of an RFC-6962 ConsistencyProof",
        ));
    }

    // === 13. Delegated capability objects (§18.7.3, §18.9.14) ===============================
    let cap_token = CapabilityToken::issue(
        &IdentityKey::from_seed(&SEED_A),
        IdentityKey::from_seed(&SEED_B).public(),
        vec![
            Capability {
                resource: "mailbox:calendar".into(),
                ability: "read".into(),
                caveats: Some(Cv::TextMap(vec![("before".into(), Cv::U64(1_800_000_000_000))])),
            },
            Capability { resource: "domain:abc.com/members".into(), ability: "directory/write".into(), caveats: None },
        ],
        1_700_000_000_000,
        1_700_000_600_000,
        b"cap-nonce-01".to_vec(),
        Some(ContentId::of(b"parent-capability-token")),
    );
    {
        let bytes = cap_token.det_cbor();
        vectors.push(v(
            "cbor_capability_token",
            "cbor_encode",
            json!({ "type": "CapabilityToken", "note": "iss seed 0x11*32 → aud seed 0x22*32; two caps (one with caveats); prnt present; §18.7.3 integer-keyed (UCAN v1.0 profile)" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an iss-signed CapabilityToken",
        ));
        let sk = IdentityKey::from_seed(&SEED_A);
        let body = cap_token.signing_body();
        let sig = sk.sign_domain(CAP_TOKEN_DS, &body);
        vectors.push(v(
            "cap_token_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(CAP_TOKEN_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.14 CapabilityToken.sig: DS-tag 'DMTAP-v0/cap-token\\0' ‖ det_cbor(token ∖ {9}); iss seed 0x11*32",
        ));
        vectors.push(v(
            "cap_token_sig_verify",
            "ed25519_verify",
            json!({ "pubkey_hex": hex(&sk.public_array()), "domain_hex": hex(CAP_TOKEN_DS), "msg_hex": hex(&body), "sig_hex": hex(&sig) }),
            json!({ "valid": true }),
            "the CapabilityToken signature above MUST verify under iss (§18.7.3 key 2)",
        ));
    }
    {
        let revocation = CapabilityRevocation::issue(
            &IdentityKey::from_seed(&SEED_A),
            ContentId::of(b"revoked-capability-token"),
            1_700_000_300_000,
        );
        let bytes = revocation.det_cbor();
        vectors.push(v(
            "cbor_capability_revocation",
            "cbor_encode",
            json!({ "type": "CapabilityRevocation", "note": "iss seed 0x11*32 revokes content-addr of 'revoked-capability-token'; §18.7.3 integer-keyed" }),
            json!({ "cbor_hex": hex(&bytes) }),
            "§18-canonical integer-keyed CBOR of an iss-signed CapabilityRevocation",
        ));
        let sk = IdentityKey::from_seed(&SEED_A);
        let body = revocation.signing_body();
        let sig = sk.sign_domain(CAP_REVOCATION_DS, &body);
        vectors.push(v(
            "cap_revocation_sig",
            "ed25519_sign",
            json!({ "seed_hex": hex(&SEED_A), "domain_hex": hex(CAP_REVOCATION_DS), "msg_hex": hex(&body) }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.14 CapabilityRevocation.sig: DS-tag 'DMTAP-v0/cap-revocation\\0' ‖ det_cbor(revocation ∖ {5}); iss seed 0x11*32",
        ));
    }

    // === 14. Sphinx fixed-length byte layouts (§18.5.4; NOT CBOR) ===========================
    // These are on the mixnet wire as constant-length binary, so they are pinned as byte layouts.
    {
        let rc = RoutingCommand { cmd: 0x00, flags: 0x01, delay_ms: 1234, next_hop: [0xab; 32] };
        vectors.push(v(
            "sphinx_routing_command",
            "sphinx_encode",
            json!({ "type": "RoutingCommand", "cmd": 0, "flags": 1, "delay_ms": 1234, "next_hop_hex": hex(&[0xab; 32]) }),
            json!({ "bytes_hex": hex(&rc.to_bytes()), "len": rc.to_bytes().len() }),
            "§18.5.4 RoutingCommand: 48 B = cmd(1) ‖ flags(1) ‖ delay_ms(4,BE) ‖ next_hop(32) ‖ reserved(10=0)",
        ));
        let surb = Surb { first_hop: [0x11; 32], header: vec![0x22; 288], key_seed: [0x33; 32] };
        vectors.push(v(
            "sphinx_surb",
            "sphinx_encode",
            json!({ "type": "Surb", "first_hop_hex": hex(&[0x11; 32]), "header_hex": hex(&vec![0x22u8; 288]), "key_seed_hex": hex(&[0x33; 32]) }),
            json!({ "bytes_hex": hex(&surb.to_bytes()), "len": surb.to_bytes().len() }),
            "§18.5.4 SURB: 352 B = first_hop(32) ‖ header(288 = α‖β‖γ) ‖ key_seed(32)",
        ));
        let fh = SphinxFragmentHeader { msg_id: [1, 2, 3, 4, 5, 6, 7, 8], frag_index: 3, frag_count: 16, total_len: 40000 };
        vectors.push(v(
            "sphinx_fragment_header",
            "sphinx_encode",
            json!({ "type": "SphinxFragmentHeader", "msg_id_hex": hex(&[1u8, 2, 3, 4, 5, 6, 7, 8]), "frag_index": 3, "frag_count": 16, "total_len": 40000 }),
            json!({ "bytes_hex": hex(&fh.to_bytes()), "len": fh.to_bytes().len() }),
            "§18.5.4 SphinxFragmentHeader: 16 B = msg_id(8) ‖ frag_index(2,BE) ‖ frag_count(2,BE) ‖ total_len(4,BE)",
        ));
        // A deterministic cell: alpha/beta/gamma fixed bytes; delta byte[i] = (i*31+7)&0xff.
        let delta: Vec<u8> = (0..2048u32).map(|i| ((i.wrapping_mul(31).wrapping_add(7)) & 0xff) as u8).collect();
        let cell = SphinxCell { alpha: [0x01; 32], beta: vec![0x02; 240], gamma: [0x03; 16], delta: delta.clone() };
        vectors.push(v(
            "sphinx_cell",
            "sphinx_encode",
            json!({ "type": "SphinxCell", "alpha_hex": hex(&[0x01; 32]), "beta_hex": hex(&vec![0x02u8; 240]), "gamma_hex": hex(&[0x03; 16]), "delta_hex": hex(&delta) }),
            json!({ "bytes_hex": hex(&cell.to_bytes()), "len": cell.to_bytes().len() }),
            "§18.5.4 SphinxCell: 2336 B = α(32) ‖ β(240) ‖ γ(16) ‖ δ(2048); delta[i]=(i*31+7)&0xff",
        ));
    }

    VectorFile {
        format: "dmtap-conformance-vectors/1".into(),
        suite: "0x01 (classical): Ed25519 / X25519-HPKE / ChaCha20-Poly1305 / BLAKE3-256".into(),
        generated_by: "dmtap-core (reference crate) — examples/gen_vectors.rs".into(),
        methodology: "All values computed from FIXED seeds/inputs by the reference crate. Ed25519 is deterministic (RFC 8032); BLAKE3 and CBOR are deterministic. Non-deterministic ops (HPKE ephemeral, keygen) are excluded; their deterministic sub-operations are vectored. CBOR here is the §18 canonical, INTEGER-KEYED (COSE/CWT-style) deterministic encoding (RFC 8949 §4.2, spec §18.1.1/§18.1.2/§18.3.x); signing preimages and content addresses follow §18.9. A second implementer following §18 alone reproduces these bytes.".into(),
        vectors,
    }
}

// Re-derive every INPUT-DETERMINED vector straight from dmtap-core and assert it reproduces the
// committed `expected`. This is the core of the self-check: it proves the vectors are correct
// against the reference (not hand-written), independently of build_all().
fn recheck_against_reference(vf: &VectorFile) {
    for vec in &vf.vectors {
        let inp = &vec.input;
        let exp = &vec.expected;
        match vec.operation.as_str() {
            "content_address" => {
                let bytes = unhex(inp["bytes_hex"].as_str().unwrap());
                let id = ContentId::of(&bytes);
                assert_eq!(hex(id.as_bytes()), exp["id_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "content_address_verify" => {
                let ct = unhex(inp["ciphertext_hex"].as_str().unwrap());
                let id = ContentId(unhex(inp["id_hex"].as_str().unwrap()));
                assert_eq!(id.verify(&ct), exp["valid"].as_bool().unwrap(), "{}", vec.name);
            }
            "keyname_encode" => {
                let pk = unhex(inp["pubkey_hex"].as_str().unwrap());
                let nm = keyname::encode(&pk);
                assert_eq!(nm, exp["name"].as_str().unwrap(), "{}", vec.name);
                assert_eq!(keyname::verify(&nm), exp["checksum_verifies"].as_bool().unwrap(), "{}", vec.name);
            }
            "keyname_verify" => {
                let nm = inp["name"].as_str().unwrap();
                assert_eq!(keyname::verify(nm), exp["checksum_verifies"].as_bool().unwrap(), "{}", vec.name);
            }
            "safety_number" => {
                let a = unhex(inp["ik_a_hex"].as_str().unwrap());
                let b = unhex(inp["ik_b_hex"].as_str().unwrap());
                assert_eq!(safety::safety_number(&a, &b), exp["safety_number"].as_str().unwrap(), "{}", vec.name);
                assert_eq!(safety::safety_number_hex(&a, &b), exp["fingerprint_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "ed25519_sign" => {
                let seed: [u8; 32] = unhex(inp["seed_hex"].as_str().unwrap()).try_into().unwrap();
                let domain = unhex(inp["domain_hex"].as_str().unwrap());
                let msg = unhex(inp["msg_hex"].as_str().unwrap());
                let sk = IdentityKey::from_seed(&seed);
                let sig = sk.sign_domain(&domain, &msg);
                assert_eq!(hex(&sk.public_array()), exp["pubkey_hex"].as_str().unwrap(), "{}", vec.name);
                assert_eq!(hex(&sig), exp["sig_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "ed25519_verify" => {
                let pk = unhex(inp["pubkey_hex"].as_str().unwrap());
                let domain = unhex(inp["domain_hex"].as_str().unwrap());
                let msg = unhex(inp["msg_hex"].as_str().unwrap());
                let sig = unhex(inp["sig_hex"].as_str().unwrap());
                let ok = verify_domain(&pk, &domain, &msg, &sig).is_ok();
                assert_eq!(ok, exp["valid"].as_bool().unwrap(), "{}", vec.name);
            }
            "suite_decode" => {
                let bytes = unhex(inp["cbor_hex"].as_str().unwrap());
                let r: Result<Suite, _> = ciborium::from_reader(&bytes[..]);
                assert_eq!(r.is_ok(), exp["accepted"].as_bool().unwrap(), "{}", vec.name);
            }
            "manifest_root" => {
                let chunks: Vec<ContentId> = inp["chunk_hashes_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| ContentId(unhex(h.as_str().unwrap())))
                    .collect();
                let m = Manifest {
                    id: ContentId(Vec::new()),
                    size: 0,
                    chunk_sz: 0,
                    chunks,
                    suite: Suite::Classical,
                };
                assert_eq!(hex(m.merkle_root().as_bytes()), exp["id_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "kt_leaf_hash" => {
                let name = inp["name"].as_str().unwrap();
                let ik = unhex(inp["ik_hex"].as_str().unwrap());
                let version = inp["version"].as_u64().unwrap();
                let id = ContentId(unhex(inp["identity_id_hex"].as_str().unwrap()));
                let leaf = identity_leaf_hash(name, &ik, version, &id);
                assert_eq!(hex(leaf.as_bytes()), exp["leaf_hash_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "sphinx_encode" => {
                let got = sphinx_encode_from_input(inp);
                assert_eq!(hex(&got), exp["bytes_hex"].as_str().unwrap(), "{}", vec.name);
            }
            "cbor_encode" => { /* byte-exactness covered by whole-file equality + round-trip tests */ }
            other => panic!("unhandled operation in recheck: {other} ({})", vec.name),
        }
    }
}
