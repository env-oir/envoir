#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_naming::dns::DmtapSvcbRecord;

// No round-trip check here (unlike `dns_txt.rs`): `DmtapSvcbRecord`'s current API is parse-only
// (`parse` + `kt_anchors()`) — this reference implementation consumes SVCB records, it never
// re-emits them, so there is no `encode` to check decode∘encode∘decode stability against. This is
// a real, documented scope limit, not a weakened check: this target still proves the one property
// that DOES apply — decode-must-not-panic on fully attacker-controlled bytes (§3.2). If a
// `to_svcb()`/serializer is ever added to `dmtap-naming`, extend this target to the same
// `naming_common::check_decode_encode_decode` pattern `dns_txt.rs` uses.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = DmtapSvcbRecord::parse(s);
    }
});
