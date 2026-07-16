// Shared fuzz-target helper for `dmtap-naming`'s TEXT-based decoders (`#[path]`-included by each
// target binary — see `common.rs`'s module docs for why this pattern is needed per-`[[bin]]`).
//
// Unlike `dmtap-core`'s canonical CBOR wire objects (§18.1.2, checked by `common.rs`), the DNS
// `_dmtap` TXT/SVCB presentation format (§3.2) is explicitly NOT a canonical/deterministic wire
// format: whitespace around `;`/`,` separators, `key=value` field order, and comma-list spacing
// are all legitimate variation for the *same* semantic record (`DmtapTxtRecord::parse`'s own
// tests exercise this tolerance). So "re-encodes to byte-identical input" would be the WRONG
// property here — it would flag harmless formatting differences as bugs. The right property,
// literally "decode∘encode∘decode stability": if `data` decodes to `v`, then encoding `v` and
// decoding *that* MUST succeed and produce a value equal to `v`. That is the meaningful
// no-information-lost invariant for a non-canonical presentation format.
//
// Both properties this enforces:
//   1. Never panic / never UB on ANY input (checked by libFuzzer just by calling `decode`).
//   2. `decode(data) = Ok(v)` implies `decode(encode(v)) = Ok(v2)` with `v2 == v`.
pub fn check_decode_encode_decode<T, E>(
    data: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, E>,
    encode: impl Fn(&T) -> Vec<u8>,
) where
    T: PartialEq + std::fmt::Debug,
{
    if let Ok(v) = decode(data) {
        let re = encode(&v);
        match decode(&re) {
            Ok(v2) => assert_eq!(v, v2, "decode -> encode -> decode must be stable"),
            Err(_) => panic!(
                "a successfully decoded value's own re-encoding failed to decode back \
                 (re-encoded {} bytes)",
                re.len()
            ),
        }
    }
}
