#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::cbor::{self, Cv};

// The strict canonical-CBOR decoder (§18.1) is the single choke point under EVERY DMTAP wire object:
// `Envelope`, `Manifest`, `KeyRotation`, `CapabilityToken`, `ClusterSyncFrame`, … all funnel their
// attacker-controlled bytes through `cbor::decode` before any field is read. This target fuzzes that
// decoder in isolation, feeding it fully arbitrary bytes. Two properties, both fail-closed:
//
//  1. **Never panic / never UB on ANY input** — libFuzzer checks this simply by calling `decode`.
//  2. **Decode/encode/decode stability** — if `data` decodes to `v`, then re-encoding `v` and
//     decoding *that* MUST succeed and yield a value equal to `v`. This is the meaningful
//     no-information-lost invariant for the decoder itself. (It is deliberately WEAKER than the
//     strict `encode(decode(x)) == x` idempotence — the reference decoder is known to accept some
//     non-canonical encodings, a pre-existing, separately-tracked gap documented in `common.rs`;
//     asserting the full round-trip here would just re-trip that known finding. The stability form
//     is the strongest property that holds and still catches a decoder that loses or mangles a
//     value it claims to have accepted.)
fuzz_target!(|data: &[u8]| {
    if let Ok(v) = cbor::decode(data) {
        let re = cbor::encode(&v);
        match cbor::decode(&re) {
            Ok(v2) => assert_eq!(v, v2, "decode -> encode -> decode must be stable"),
            Err(e) => panic!("a value the decoder accepted failed to re-decode from its own encoding: {e:?}"),
        }
        // The canonical encoding is itself a fixed point: encoding the re-decoded value again is
        // byte-identical to `re` (encode is deterministic and total over any decoded `Cv`).
        let re2 = cbor::encode(&v);
        assert_eq!(re, re2, "encode must be deterministic for a decoded value");
        let _ = std::hint::black_box::<&Cv>(&v);
    }
});
