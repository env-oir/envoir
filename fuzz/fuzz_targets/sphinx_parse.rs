#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_core::sphinx::{RoutingCommand, SphinxCell, SphinxFragmentHeader, Surb};

// Sphinx fixed-length binary parsing (§18.5.4), fed fully attacker-controlled bytes across ALL four
// on-wire layouts in one target: the 2336-byte `SphinxCell`, the 48-byte `RoutingCommand`, the
// 352-byte `Surb`, and the 16-byte `SphinxFragmentHeader`. Unlike the CBOR objects these are
// constant-length binary structures, so the fail-closed contract is length + reserved-byte + unknown-
// command rejection. Properties:
//
//  1. Never panic / never UB on ANY input (checked by simply calling each parser — no slice-index
//     out-of-bounds, no arithmetic overflow on a truncated/oversized buffer).
//  2. Any `Ok` parse re-serializes to a buffer of exactly the layout's fixed length, and (for the
//     canonically-validated `RoutingCommand`, which rejects unknown `cmd`, reserved flag bits, and a
//     non-zero next-hop on an exit command) re-parsing that serialization yields the same value.
fuzz_target!(|data: &[u8]| {
    if let Ok(cell) = SphinxCell::from_bytes(data) {
        assert_eq!(cell.to_bytes().len(), dmtap_core::sphinx::CELL_LEN);
    }
    if let Ok(surb) = Surb::from_bytes(data) {
        assert_eq!(surb.to_bytes().len(), dmtap_core::sphinx::SURB_LEN);
    }
    if let Ok(hdr) = SphinxFragmentHeader::from_bytes(data) {
        // The 16-byte header is a pure fixed layout: it round-trips byte-for-byte.
        assert_eq!(SphinxFragmentHeader::from_bytes(&hdr.to_bytes()), Ok(hdr));
    }
    if let Ok(rc) = RoutingCommand::from_bytes(data) {
        // `RoutingCommand` decode is canonically validated (unknown cmd / reserved bits / exit
        // next-hop all rejected), so a decoded command re-encodes and re-decodes identically.
        assert_eq!(RoutingCommand::from_bytes(&rc.to_bytes()), Ok(rc));
    }
});
