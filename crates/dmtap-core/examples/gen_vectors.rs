//! Generate the DMTAP conformance vectors from the reference crate.
//!
//! Run with:
//! ```sh
//! cargo run -p dmtap-core --example gen_vectors
//! ```
//! It writes `../../../dmtap/conformance/vectors/vectors.json` (relative to this crate) with
//! byte-exact known-answer vectors computed by `dmtap-core`. The self-check test
//! (`tests/conformance_vectors.rs`) then proves the committed file still matches the reference.

#![allow(dead_code)]

include!("../vectors_gen.rs.inc");

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../dmtap/conformance/vectors/vectors.json")
}

fn main() {
    let vf = build_all();
    // Sanity: the vectors we are about to write must re-derive from the reference.
    recheck_against_reference(&vf);

    let path = vectors_path();
    std::fs::create_dir_all(path.parent().unwrap()).expect("create vectors dir");
    let mut json = serde_json::to_string_pretty(&vf).expect("serialize vectors");
    json.push('\n');
    std::fs::write(&path, json).expect("write vectors.json");

    eprintln!("wrote {} vectors to {}", vf.vectors.len(), path.display());
}
