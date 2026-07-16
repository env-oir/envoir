//! CLI: run the conformance-runner engine (`lib.rs`) over `dmtap-core`'s committed `vectors.json`
//! and, when the sibling spec repo is checked out, cross-reference the conformance-suite catalog
//! (`../dmtap/conformance/{suite.json,SUITE.md}`).
//!
//! Exit code is driven **only** by the vectors.json-backed checks (the mandatory charter: every
//! vector must reproduce from the reference and every `cbor_*` vector must canonically round
//! trip). Suite.json cross-reference is printed as an additional, clearly-labeled report section:
//! `construction-todo` cases are skipped-with-note, and any `self-contained`/`vectored` case that
//! does not hold is reported as a named gap (see the KNOWN GAPS section of the report) rather than
//! silently hidden or allowed to fail the build — fixing `dmtap-core` itself is out of scope for
//! this harness.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use conformance_runner::{
    check_all_vectors, load_suite, load_vectors, run_all_suite_cases, CaseOutcome, Verdict,
};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../dmtap-core/vectors.json")
}

/// The sibling spec repo's conformance-suite catalog. Optional: this harness's mandatory proof
/// (vectors.json) does not depend on it, but when present we cross-reference it for extra
/// coverage reporting.
fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/suite.json")
}

fn main() {
    let vectors_path = vectors_path();
    let vf = match load_vectors(&vectors_path) {
        Ok(vf) => vf,
        Err(e) => {
            eprintln!("FATAL: could not load {}: {e}", vectors_path.display());
            std::process::exit(2);
        }
    };

    println!("=== DMTAP conformance-runner ===");
    println!("vectors file : {}", vectors_path.display());
    println!("format       : {}", vf.format);
    println!("suite        : {}", vf.suite);
    println!("generated_by : {}", vf.generated_by);
    println!("vector count : {}", vf.vectors.len());
    println!();

    let results = check_all_vectors(&vf);
    let mut pass = 0usize;
    let mut pass_generic = 0usize;
    let mut fail = 0usize;
    for (name, verdict) in &results {
        match verdict {
            Verdict::Pass => {
                pass += 1;
                println!("PASS   {name}");
            }
            Verdict::PassGeneric => {
                pass_generic += 1;
                println!("PASS   {name}  (generic canonical round-trip only; no typed verifier for this input.type)");
            }
            Verdict::Fail(e) => {
                fail += 1;
                println!("FAIL   {name}: {e}");
            }
        }
    }

    println!();
    println!(
        "--- vectors.json summary: {pass} pass, {pass_generic} pass (generic), {fail} FAIL, {} total ---",
        results.len()
    );

    // suite.json cross-reference (optional; report only, does not affect exit code — see docs).
    let suite_path = suite_path();
    if suite_path.exists() {
        match load_suite(&suite_path) {
            Ok(suite) => {
                let by_name: BTreeMap<String, Verdict> =
                    results.iter().cloned().collect();
                let case_outcomes = run_all_suite_cases(&suite, &vf, &by_name);
                let mut c_pass = 0usize;
                let mut c_fail = 0usize;
                let mut c_skip = 0usize;
                let mut gaps: Vec<(String, String)> = Vec::new();
                println!();
                println!("=== suite.json cross-reference: {} ===", suite_path.display());
                for (id, outcome) in &case_outcomes {
                    match outcome {
                        CaseOutcome::Pass => {
                            c_pass += 1;
                        }
                        CaseOutcome::Skipped(note) => {
                            c_skip += 1;
                            let _ = note; // printed in totals only; SUITE.md has the recipe text
                        }
                        CaseOutcome::Fail(reason) => {
                            c_fail += 1;
                            gaps.push((id.clone(), reason.clone()));
                        }
                    }
                }
                println!(
                    "case outcomes: {c_pass} pass, {c_skip} skipped (construction-todo), {c_fail} FAIL, {} total",
                    case_outcomes.len()
                );
                let executed = c_pass + c_fail;
                println!(
                    "coverage: {executed} executed / {} total suite.json cases ({c_pass} passed, {c_skip} skipped-with-reason, {c_fail} failed)",
                    case_outcomes.len()
                );

                // Coverage broken down by level and category (case_outcomes is in the same order
                // as suite.cases — see run_all_suite_cases), so the orchestrator can see exactly
                // where the honest gaps are, not just a single aggregate number.
                #[derive(Default, Clone, Copy)]
                struct Bucket {
                    pass: usize,
                    fail: usize,
                    skip: usize,
                }
                let mut by_level: BTreeMap<String, Bucket> = BTreeMap::new();
                let mut by_category: BTreeMap<String, Bucket> = BTreeMap::new();
                for (case, (_, outcome)) in suite.cases.iter().zip(case_outcomes.iter()) {
                    let lvl = by_level.entry(case.level.clone()).or_default();
                    let cat = by_category.entry(case.category.clone()).or_default();
                    match outcome {
                        CaseOutcome::Pass => {
                            lvl.pass += 1;
                            cat.pass += 1;
                        }
                        CaseOutcome::Fail(_) => {
                            lvl.fail += 1;
                            cat.fail += 1;
                        }
                        CaseOutcome::Skipped(_) => {
                            lvl.skip += 1;
                            cat.skip += 1;
                        }
                    }
                }
                println!();
                println!("--- coverage by level (executed = pass+fail / total) ---");
                for (level, b) in &by_level {
                    println!(
                        "  {level:<20} {:>3} executed / {:>3} total  ({} pass, {} fail, {} skipped)",
                        b.pass + b.fail,
                        b.pass + b.fail + b.skip,
                        b.pass,
                        b.fail,
                        b.skip
                    );
                }
                println!("--- coverage by category (executed = pass+fail / total) ---");
                for (category, b) in &by_category {
                    println!(
                        "  {category:<12} {:>3} executed / {:>3} total  ({} pass, {} fail, {} skipped)",
                        b.pass + b.fail,
                        b.pass + b.fail + b.skip,
                        b.pass,
                        b.fail,
                        b.skip
                    );
                }

                // Skip reasons, deduplicated (many cases share one root-cause reason), so the
                // orchestrator can see exactly which dmtap-core APIs are still missing.
                let mut skip_reasons: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for (id, outcome) in &case_outcomes {
                    if let CaseOutcome::Skipped(reason) = outcome {
                        skip_reasons.entry(reason.clone()).or_default().push(id.clone());
                    }
                }
                println!();
                println!("--- skipped-with-reason ({c_skip} cases, {} distinct reasons) ---", skip_reasons.len());
                for (reason, ids) in &skip_reasons {
                    println!("  [{}] {}", ids.join(", "), reason);
                }

                if !gaps.is_empty() {
                    println!();
                    println!("--- KNOWN GAPS (suite.json cases whose expected outcome does not hold against the current dmtap-core reference) ---");
                    for (id, reason) in &gaps {
                        println!("GAP    {id}: {reason}");
                    }
                    println!(
                        "\nThese are NOT vectors.json failures (the mandatory gate above is green) and do not \
                         fail this run's exit code: fixing dmtap-core's decoder is out of scope for this harness. \
                         They are surfaced here because they are real, reproducible conformance gaps a second \
                         implementer would also hit."
                    );
                }
            }
            Err(e) => {
                println!();
                println!("(suite.json present at {} but failed to parse: {e})", suite_path.display());
            }
        }
    } else {
        println!();
        println!("(sibling spec repo's suite.json not found at {} — skipping cross-reference; vectors.json-only run)", suite_path.display());
    }

    if fail > 0 {
        eprintln!("\nconformance-runner: {fail} vector(s) FAILED — this is the mandatory gate, exiting non-zero.");
        std::process::exit(1);
    }
    println!("\nconformance-runner: all {} vectors.json checks PASS.", pass + pass_generic);
}
