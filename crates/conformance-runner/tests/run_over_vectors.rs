//! `cargo test`-visible proof that the conformance-runner engine is green over the current
//! `dmtap-core/vectors.json` (the VERIFICATION GATE for this crate). Also locks the current,
//! honestly-reported suite.json coverage numbers so any change (new vectors, a dmtap-core fix
//! that closes one of the known self-contained gaps, a suite.json catalog update) is *noticed*
//! here rather than silently drifting.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use conformance_runner::{check_all_vectors, load_suite, load_vectors, run_all_suite_cases, CaseOutcome, Verdict};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dmtap-core/vectors.json")
}

fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/suite.json")
}

/// The mandatory gate: every vector in the committed `vectors.json` passes (reproduces from the
/// reference; every `cbor_*` vector canonically round-trips).
#[test]
fn all_vectors_pass() {
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    assert!(!vf.vectors.is_empty(), "vectors.json must not be empty");
    let results = check_all_vectors(&vf);
    let failures: Vec<String> = results
        .iter()
        .filter_map(|(name, v)| match v {
            Verdict::Fail(e) => Some(format!("{name}: {e}")),
            _ => None,
        })
        .collect();
    assert!(failures.is_empty(), "conformance-runner found FAILing vectors:\n{}", failures.join("\n"));
}

/// Every `cbor_*` vector this crate recognizes by `input.type` gets the stronger typed check
/// (not just the generic canonical round-trip) — i.e. no vector silently falls back to
/// `PassGeneric` without us knowing. If this starts failing, either a new cbor_* vector type
/// appeared (extend `check_cbor_encode_vector`) or a dispatch regressed.
#[test]
fn every_known_cbor_type_gets_the_typed_check() {
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let results = check_all_vectors(&vf);
    let generic_only: Vec<&str> = results
        .iter()
        .filter(|(_, v)| matches!(v, Verdict::PassGeneric))
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        generic_only.is_empty(),
        "these cbor_* vectors only got the generic round-trip check (no `input.type` or unrecognized type): {generic_only:?}"
    );
}

/// Cross-reference the sibling spec repo's conformance-suite catalog, when checked out next to
/// this worktree (`../../../dmtap`). This is a soft dependency: if the sibling repo is absent
/// (e.g. a CI checkout of only this repo), the test is skipped rather than failing — the
/// mandatory proof is `all_vectors_pass` above, not this cross-reference.
#[test]
fn suite_json_cross_reference_matches_known_state() {
    let sp = suite_path();
    if !sp.exists() {
        eprintln!("skipping: sibling spec repo not found at {}", sp.display());
        return;
    }
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let suite = load_suite(&sp).expect("suite.json must parse");
    let results: BTreeMap<String, Verdict> = check_all_vectors(&vf).into_iter().collect();
    let outcomes = run_all_suite_cases(&suite, &vf, &results);

    let mut pass = 0usize;
    let mut skip = 0usize;
    let mut fails: Vec<(String, String)> = Vec::new();
    for (id, outcome) in &outcomes {
        match outcome {
            CaseOutcome::Pass => pass += 1,
            CaseOutcome::Skipped(_) => skip += 1,
            CaseOutcome::Fail(reason) => fails.push((id.clone(), reason.clone())),
        }
    }

    // GAPS CLOSED: dmtap-core's low-level `cbor::decode` now enforces the full §18.1.1 canonical
    // ruleset on input — shortest-form integers/lengths, definite-length only, strictly ascending
    // map-key order (by encoded bytes), no duplicates — so the three previously-failing
    // self-contained MUST-reject cases (DMTAP-CBOR-05/06/07) now correctly REJECT and pass.
    //
    // The former spec-repo stale reference is now resolved: the sibling spec repo regenerated
    // `DMTAP-SUITE-02` to a reserved-suite `suite_accept_0x03` decode (0x03 is a registered reserved
    // code point — AES-256-GCM AEAD-diverse PQ-hybrid, §1.1/§21.15 — that DECODES as a known id but
    // fails closed on *use*) and added `DMTAP-SUITE-07`/`suite_reject_0x04` for the still-
    // unregistered 0x04, matching this crate's `vectors.json`.
    //
    // KNOWN GAPS (2026-07-18): the spec repo added §22 "public objects" + the §23 CAD artifact
    // profile with 21 new DMTAP-PUB cases. The 12 `vectored` ones reference `pub_*` vectors this
    // crate cannot generate yet — no crate in this workspace implements §22 (public manifests,
    // pub_announce, feeds) — so they are honest, listed gaps rather than silent skips. The 8
    // `construction-todo` PUB cases skip with per-case reasons and the 1 `manual-attestation`
    // case skips by status. Closing these means implementing §22 in dmtap-core and regenerating
    // vectors.json.
    let expected_gap_ids: Vec<&str> = vec![
        "DMTAP-PUB-01", "DMTAP-PUB-02", "DMTAP-PUB-03", "DMTAP-PUB-04", "DMTAP-PUB-05",
        "DMTAP-PUB-06", "DMTAP-PUB-07", "DMTAP-PUB-08", "DMTAP-PUB-13", "DMTAP-PUB-14",
        "DMTAP-PUB-15", "DMTAP-PUB-16",
    ];
    let actual_gap_ids: Vec<&str> = fails.iter().map(|(id, _)| id.as_str()).collect();
    let mut sorted_actual = actual_gap_ids.clone();
    sorted_actual.sort_unstable();
    let mut sorted_expected = expected_gap_ids.clone();
    sorted_expected.sort_unstable();
    assert_eq!(
        sorted_actual, sorted_expected,
        "suite.json known-gap set changed — investigate (either a regression, or dmtap-core fixed \
         a gap and this expectation needs updating). Full failure detail: {fails:?}"
    );

    // Sanity: the catalog has grown past its original shape (124 cases as of writing, up from 104;
    // see SUITE.md/README) and this crate now executes the large majority of them — 116/124 (up from
    // 111/124 after the suite-negotiation / tier-enforcement / mix-descriptor-freshness / pinned-
    // domain-directory / random-mode gateway-alias reference surfaces landed and were wired here),
    // with only 8 honestly left `Skipped` for behavior no crate in this workspace can exercise yet
    // (see the `skip_reason` table in `construction.rs`). Rather than pin an exact
    // total (which would break on every new spec case), just sanity-check the three buckets sum
    // correctly and that both "some cases pass" and "some cases are honestly skipped" hold.
    assert_eq!(pass + skip + fails.len(), outcomes.len());
    assert!(skip > 0, "expected at least some construction-todo cases to be skipped-with-note");
    assert!(pass > 0, "expected at least some vectored/self-contained cases to pass");
}

/// No silent coverage gaps: EVERY case marked `status: "vectored"` in `suite.json` MUST actually
/// be executed (Pass or Fail), never `Skipped`. Structurally `run_vectored_case` never returns
/// `Skipped`, but this is a dedicated regression test so a future refactor that accidentally
/// routes a vectored case through the skip path is caught immediately, not discovered later as a
/// silently-inflated coverage number.
#[test]
fn every_vectored_case_is_actually_executed() {
    let sp = suite_path();
    if !sp.exists() {
        eprintln!("skipping: sibling spec repo not found at {}", sp.display());
        return;
    }
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let suite = load_suite(&sp).expect("suite.json must parse");
    let results: BTreeMap<String, Verdict> = check_all_vectors(&vf).into_iter().collect();
    let outcomes = run_all_suite_cases(&suite, &vf, &results);

    let vectored_ids: std::collections::BTreeSet<&str> = suite
        .cases
        .iter()
        .filter(|c| c.status == "vectored")
        .map(|c| c.id.as_str())
        .collect();
    assert!(!vectored_ids.is_empty(), "expected at least one `vectored` case in suite.json");

    let silently_skipped: Vec<&str> = outcomes
        .iter()
        .filter(|(id, outcome)| {
            vectored_ids.contains(id.as_str()) && matches!(outcome, CaseOutcome::Skipped(_))
        })
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(
        silently_skipped.is_empty(),
        "these `vectored` cases were SKIPPED instead of executed (coverage gap): {silently_skipped:?}"
    );
}

/// Regression guard for task item 3 (construction-todo cases): a meaningful number of them must
/// be ACTUALLY EXECUTED (Pass/Fail) against dmtap-core, not just uniformly skipped. This pins a
/// floor so a future change that reverts `construction::run_construction_case` back to "skip
/// everything" is caught here rather than silently shrinking real coverage.
#[test]
fn a_meaningful_share_of_construction_todo_cases_are_executed() {
    let sp = suite_path();
    if !sp.exists() {
        eprintln!("skipping: sibling spec repo not found at {}", sp.display());
        return;
    }
    let vf = load_vectors(&vectors_path()).expect("vectors.json must load");
    let suite = load_suite(&sp).expect("suite.json must parse");
    let results: BTreeMap<String, Verdict> = check_all_vectors(&vf).into_iter().collect();
    let outcomes = run_all_suite_cases(&suite, &vf, &results);

    let construction_todo_ids: std::collections::BTreeSet<&str> = suite
        .cases
        .iter()
        .filter(|c| c.status == "construction-todo")
        .map(|c| c.id.as_str())
        .collect();
    assert!(!construction_todo_ids.is_empty(), "expected at least one construction-todo case");

    let executed: Vec<&str> = outcomes
        .iter()
        .filter(|(id, outcome)| {
            construction_todo_ids.contains(id.as_str()) && !matches!(outcome, CaseOutcome::Skipped(_))
        })
        .map(|(id, _)| id.as_str())
        .collect();
    let failed: Vec<&str> = outcomes
        .iter()
        .filter(|(id, outcome)| {
            construction_todo_ids.contains(id.as_str()) && matches!(outcome, CaseOutcome::Fail(_))
        })
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "construction-todo cases FAILED their construction (not just skipped): {failed:?}"
    );
    assert!(
        executed.len() >= 77,
        "expected at least 77 construction-todo cases to be actually executed (against dmtap-core \
         directly, plus more via dmtap-auth/dmtap-naming/dmtap-deniable/dmtap-mls/dmtap-clustersync/ \
         envoir-gateway — see the Cargo.toml comment; this floor rose from 71 when the suite- \
         negotiation, tier-enforcement, mix-descriptor-freshness, pinned-domain-directory and \
         random-mode gateway-alias cases were wired), got {} ({executed:?}) — did \
         construction::run_construction_case regress?",
        executed.len()
    );
}
