#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::sphinx::Surb;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, Surb::from_bytes, |o: &Surb| o.to_bytes());
});
