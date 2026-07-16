#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::sphinx::SphinxCell;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, SphinxCell::from_bytes, |o: &SphinxCell| o.to_bytes());
});
