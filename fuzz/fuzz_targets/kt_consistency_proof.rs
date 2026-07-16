#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::kt::ConsistencyProof;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, ConsistencyProof::from_det_cbor, |o: &ConsistencyProof| o.det_cbor());
});
