#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::sphinx::RoutingCommand;
#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::check_roundtrip(data, RoutingCommand::from_bytes, |o: &RoutingCommand| o.to_bytes().to_vec());
});
