#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_naming::dns::DmtapTxtRecord;
use dmtap_naming::error::ResolveError;
#[path = "naming_common.rs"]
mod naming_common;

/// The record's presentation form is UTF-8 text (§3.2); non-UTF-8 input simply fails to decode
/// (fail-closed, same disposition as any other malformed record) rather than being excluded from
/// the fuzz corpus's mutation space.
fn decode(data: &[u8]) -> Result<DmtapTxtRecord, ResolveError> {
    let s = std::str::from_utf8(data).map_err(|_| ResolveError::MalformedDns("not utf8"))?;
    DmtapTxtRecord::parse(s)
}

fuzz_target!(|data: &[u8]| {
    naming_common::check_decode_encode_decode(data, decode, |r: &DmtapTxtRecord| {
        r.to_txt().into_bytes()
    });
});
