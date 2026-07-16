#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::capability::CapabilityRevocation;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, CapabilityRevocation::from_det_cbor, |o: &CapabilityRevocation| o.det_cbor());
});
