#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::kt::InclusionProof;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, InclusionProof::from_det_cbor, |o: &InclusionProof| o.det_cbor());
});
