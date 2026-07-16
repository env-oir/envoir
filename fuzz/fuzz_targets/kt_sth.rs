#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::kt::SignedTreeHead;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, SignedTreeHead::from_det_cbor, |o: &SignedTreeHead| o.det_cbor());
});
