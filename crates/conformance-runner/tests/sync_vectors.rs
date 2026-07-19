//! `cargo test`-visible gate over the **Sync substrate** vectors
//! (`../dmtap/conformance/vectors/sync_vectors.json`, `substrate/SYNC.md` §10), executed through
//! the `dmtap-sync` reference crate.
//!
//! The counts are asserted **exactly**, in both directions: a regression in `dmtap-sync` fails
//! here, and so does an upstream *fix* to an allowlisted vector (that makes it pass, which this
//! test also notices, so the allowlist cannot rot). That second direction has now fired for real:
//! SYNC-PN-01 was corrected upstream (`SYNC.md` §14 C-02), this test failed because the
//! allowlisted vector had started passing, and the entry was deleted. The allowlist is empty and
//! all **22/22** vectors pass — 20 for the algebra and, since correction C-05, `SYNC-FJ-01`/
//! `SYNC-FJ-02` for the §5.2.1 fast-join pull path.

use std::path::{Path, PathBuf};

use conformance_runner::{check_all_vectors, load_vectors, Verdict, SYNC_KNOWN_DISCREPANCIES};

fn sync_vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/vectors/sync_vectors.json")
}

/// Every Sync vector passes byte-exactly (the discrepancy allowlist is currently empty, so this is
/// a 22/22 assertion).
#[test]
fn sync_vectors_pass_except_the_documented_discrepancy() {
    let path = sync_vectors_path();
    if !path.exists() {
        eprintln!("sibling spec repo not checked out at {} — skipping", path.display());
        return;
    }
    let vf = load_vectors(&path).expect("sync_vectors.json must load");
    assert_eq!(vf.vectors.len(), 22, "SYNC.md §10 freezes exactly 22 vectors");

    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for (name, verdict) in check_all_vectors(&vf) {
        match verdict {
            Verdict::Pass => passed.push(name),
            // No sync vector may pass "generically": every one has a real executor.
            Verdict::PassGeneric => panic!("{name} fell through to the generic round-trip check"),
            Verdict::Fail(e) => failed.push((name, e)),
        }
    }

    let known: Vec<&str> = SYNC_KNOWN_DISCREPANCIES.iter().map(|(n, _)| *n).collect();
    let unexpected: Vec<&(String, String)> =
        failed.iter().filter(|(n, _)| !known.contains(&n.as_str())).collect();
    assert!(unexpected.is_empty(), "unexpected sync vector failures: {unexpected:#?}");

    for name in &known {
        assert!(
            failed.iter().any(|(n, _)| n == name),
            "`{name}` is allowlisted as a spec/vector discrepancy but now PASSES — the vector was \
             fixed upstream; delete the SYNC_KNOWN_DISCREPANCIES entry"
        );
    }
    assert_eq!(passed.len(), 22 - known.len(), "expected {} passing sync vectors", 22 - known.len());
}

/// The discrepancy allowlist is not a silent escape hatch: every entry must carry an explanation
/// long enough to be actionable in the `dmtap` repo, since this repo cannot fix the vector itself.
#[test]
fn every_known_discrepancy_is_explained() {
    for (name, why) in SYNC_KNOWN_DISCREPANCIES {
        assert!(!name.is_empty());
        assert!(
            why.len() > 200 && why.contains("MINIMAL FIX"),
            "discrepancy `{name}` must state the contradiction AND the minimal upstream fix"
        );
    }
}
