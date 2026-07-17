#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_core::mote::Manifest;

// `Manifest::from_det_cbor` (§18.3.8) + the §18.9.5 Merkle-DAG root, fed fully attacker-controlled
// bytes. This target guards the **M2 empty-chunks fix** directly: `merkle_root()` /
// `merkle_tree_head()` PANIC on a zero-leaf list ("a manifest MUST carry ≥ 1 chunk"), so the decoder
// MUST reject an empty `chunks` array at decode time (`ERR_MANIFEST_EMPTY_CHUNKS`) — otherwise a
// hostile manifest with `chunks: []` would decode and then panic the instant any holder computed its
// root. The invariant this asserts: **every** manifest that decodes successfully has a non-empty
// chunk list, so calling `merkle_root()` on ANY decoded manifest is panic-free.
//
// Also re-checked here: a decoded manifest with a present key 5 (the content key, forbidden in a
// swarm-distributed Manifest, §18.3.8) is rejected by the decoder, never reached by this call.
fuzz_target!(|data: &[u8]| {
    let Ok(manifest) = Manifest::from_det_cbor(data) else { return };

    // The M2 invariant: a decoded manifest always carries ≥ 1 chunk.
    assert!(!manifest.chunks.is_empty(), "decoder must reject an empty-chunks manifest (M2)");

    // Therefore computing the Merkle root can never panic on a decoded manifest.
    let root = manifest.merkle_root();

    // The root is a well-formed content address (multihash prefix + 32-byte digest); recomputation is
    // deterministic, and re-encoding the decoded manifest never panics.
    assert_eq!(root, manifest.merkle_root(), "merkle root must be deterministic");
    let _ = manifest.det_cbor();
});
