#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::capability::CapabilityToken;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, CapabilityToken::from_det_cbor, |o: &CapabilityToken| o.det_cbor());
});
