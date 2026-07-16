#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::sphinx::SphinxFragmentHeader;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, SphinxFragmentHeader::from_bytes, |o: &SphinxFragmentHeader| {
        o.to_bytes().to_vec()
    });
});
