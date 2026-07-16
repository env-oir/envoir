// Shared conformance-vector logic — `include!`d by BOTH `examples/gen_vectors.rs` (which writes
// the JSON) and `tests/conformance_vectors.rs` (which re-derives and self-checks). Keeping the
// generator and the checker on one source of truth means the committed vectors can never silently
// drift from what the reference crate `dmtap-core` actually computes.
//
// Everything here is derived from FIXED seeds/inputs so the vectors are byte-for-byte
// reproducible (Ed25519 is deterministic per RFC 8032; BLAKE3 and CBOR are deterministic).
// Non-deterministic operations (HPKE ephemeral encapsulation, key generation) are NOT vectored;
// their deterministic sub-operations (content-address, sender_sig, payload_sig) are.

use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, Cap, DeviceCert, Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_core::mote::{DeliveryTag, Envelope, Headers, Kind, Payload, ENVELOPE_SENDER_DS, PAYLOAD_SIG_DS};
use dmtap_core::safety;
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

    // === 6. Suite fail-closed — unknown suite byte MUST be rejected (spec §1.1, §18.1.4) =====
    for (name, byte) in [
        ("suite_reject_0x00", 0x00u8),
        ("suite_reject_0x03", 0x03u8),
        ("suite_reject_0x05", 0x05u8),
        ("suite_reject_0xff", 0xffu8),
    ] {
        let cbor_bytes = cbor(&byte);
        vectors.push(v(
            name,
            "suite_decode",
            json!({ "cbor_hex": hex(&cbor_bytes) }),
            json!({ "accepted": false }),
            "an unknown suite byte MUST fail to decode (never guess; fail closed)",
        ));
    }
    // Positive controls: 0x01 and 0x02 decode as suite ids (0x02 is reserved but a known id).
    for (name, byte) in [("suite_accept_0x01", 0x01u8), ("suite_accept_0x02", 0x02u8)] {
        let cbor_bytes = cbor(&byte);
        vectors.push(v(
            name,
            "suite_decode",
            json!({ "cbor_hex": hex(&cbor_bytes) }),
            json!({ "accepted": true }),
            "0x01 (classical) and 0x02 (reserved PQ) are known suite ids and decode",
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
    //     BLAKE3-256(det_cbor(Payload ∖ {sig})).
    {
        let sk = IdentityKey::from_seed(&SEED_A);
        let ph = payload.signing_hash();
        let sig = sk.sign_domain(PAYLOAD_SIG_DOMAIN, &ph);
        vectors.push(v(
            "mote_payload_sig",
            "ed25519_sign",
            json!({
                "seed_hex": hex(&SEED_A),
                "domain_hex": hex(PAYLOAD_SIG_DOMAIN),
                "msg_hex": hex(&ph),
                "payload_hash_hex": hex(&ph),
            }),
            json!({ "pubkey_hex": hex(&sk.public_array()), "sig_hex": hex(&sig) }),
            "§18.9.2 payload signature: BLAKE3-256(det_cbor(Payload ∖ {sig})) under DS-tag 'DMTAP-v0/payload\\0'; IK seed 0x11*32",
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
            "cbor_encode" => { /* byte-exactness covered by whole-file equality + round-trip tests */ }
            other => panic!("unhandled operation in recheck: {other} ({})", vec.name),
        }
    }
}
