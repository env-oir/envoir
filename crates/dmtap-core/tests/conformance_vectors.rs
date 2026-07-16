//! Self-verification of the committed DMTAP conformance vectors.
//!
//! This proves two things, so the vectors are trustworthy and drift is caught:
//!   1. **Correct against the reference** — every input-determined vector is re-derived straight
//!      from `dmtap-core` and MUST reproduce the committed `expected` value.
//!   2. **No drift** — the committed `vectors.json` MUST byte-for-byte match what the current
//!      reference crate generates. If someone changes a primitive, this fails until the vectors
//!      are regenerated (`cargo run -p dmtap-core --example gen_vectors`).

#![allow(dead_code)]

include!("../vectors_gen.rs.inc");

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../dmtap/conformance/vectors/vectors.json")
}

fn load_committed() -> VectorFile {
    let text = std::fs::read_to_string(vectors_path())
        .expect("committed vectors.json must exist (run: cargo run --example gen_vectors)");
    serde_json::from_str(&text).expect("committed vectors.json must be valid JSON")
}

/// (1) Every input-determined vector re-derives from dmtap-core to its committed expected value.
#[test]
fn committed_vectors_reproduce_from_reference() {
    let committed = load_committed();
    assert!(!committed.vectors.is_empty(), "vectors must not be empty");
    recheck_against_reference(&committed);
}

/// (2) The committed file matches exactly what the reference currently generates (drift guard).
#[test]
fn committed_vectors_match_current_reference() {
    let committed = load_committed();
    let fresh = build_all();
    assert_eq!(
        committed, fresh,
        "committed vectors.json is stale — regenerate with `cargo run -p dmtap-core --example gen_vectors`"
    );
}

/// Names are unique (so a vector can be referenced unambiguously by an implementation).
#[test]
fn vector_names_are_unique() {
    let vf = build_all();
    let mut names: Vec<&str> = vf.vectors.iter().map(|v| v.name.as_str()).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "vector names must be unique");
}

/// CBOR vectors must round-trip: decode(committed_hex) == the reference object, and re-encode is
/// byte-identical (deterministic encoding).
#[test]
fn cbor_vectors_round_trip() {
    let vf = build_all();
    for vec in &vf.vectors {
        if vec.operation != "cbor_encode" {
            continue;
        }
        let cbor_hex = vec.expected["cbor_hex"].as_str().unwrap();
        let bytes = unhex(cbor_hex);
        match vec.input["type"].as_str().unwrap() {
            "Identity" => {
                let obj: Identity = ciborium::from_reader(&bytes[..]).unwrap();
                assert!(obj.verify(None).is_ok(), "decoded Identity must verify: {}", vec.name);
                assert_eq!(hex(&cbor(&obj)), cbor_hex, "re-encode must be byte-identical: {}", vec.name);
            }
            "DeviceCert" => {
                let obj: DeviceCert = ciborium::from_reader(&bytes[..]).unwrap();
                assert!(obj.verify().is_ok(), "decoded DeviceCert must verify: {}", vec.name);
                assert_eq!(hex(&cbor(&obj)), cbor_hex, "{}", vec.name);
            }
            "Payload" => {
                let obj: Payload = ciborium::from_reader(&bytes[..]).unwrap();
                assert_eq!(hex(&cbor(&obj)), cbor_hex, "{}", vec.name);
            }
            "Envelope" => {
                let obj: Envelope = ciborium::from_reader(&bytes[..]).unwrap();
                // Envelope carries its own content address — it must still verify after decode.
                assert!(obj.id.verify(&obj.ciphertext), "Envelope id must match ciphertext: {}", vec.name);
                assert_eq!(hex(&cbor(&obj)), cbor_hex, "{}", vec.name);
            }
            other => panic!("unknown cbor type {other}"),
        }
    }
}

/// Suite fail-closed is exercised by the vectors, but assert the property directly too.
#[test]
fn unknown_suite_bytes_fail_closed() {
    for b in [0x00u8, 0x03, 0x05, 0x7f, 0xfe, 0xff] {
        let mut buf = Vec::new();
        ciborium::into_writer(&b, &mut buf).unwrap();
        let r: Result<Suite, _> = ciborium::from_reader(&buf[..]);
        assert!(r.is_err(), "suite 0x{b:02x} must fail closed");
    }
}
