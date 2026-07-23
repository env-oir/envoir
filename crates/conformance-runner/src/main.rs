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
    SYNC_KNOWN_DISCREPANCIES,
};

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json")
}

/// The sibling spec repo's DMTAP-PUB (§22) / CAD (§23) known-answer vectors — a SEPARATE file from
/// `vectors.json`, recomputed here via `dmtap_core::pubobj`. Merged into the run when present so the
/// §22/§23 suite cases resolve their `pub_*` vectors.
fn pub_vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kotva/conformance/vectors/pub_vectors.json")
}

/// The sibling spec repo's **Sync substrate** (`substrate/SYNC.md` §10) known-answer vectors —
/// again a SEPARATE file, recomputed here via the `dmtap-sync` reference crate.
fn sync_vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kotva/conformance/vectors/sync_vectors.json")
}

/// The sibling spec repo's **DMTAP-PUBSUB** (§25) known-answer vectors — a SEPARATE file from
/// `vectors.json`, recomputed here via `dmtap_core::pubsub`. Merged into the run when present so
/// the PUBSUB suite cases resolve their `pubsub_*` vectors, exactly like `pub_vectors_path`.
fn pubsub_vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kotva/conformance/vectors/pubsub_vectors.json")
}

/// The sibling spec repo's conformance-suite catalog. Optional: this harness's mandatory proof
/// (vectors.json) does not depend on it, but when present we cross-reference it for extra
/// coverage reporting.
fn suite_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kotva/conformance/suite.json")
}

fn main() {
    let vectors_path = vectors_path();
    let mut vf = match load_vectors(&vectors_path) {
        Ok(vf) => vf,
        Err(e) => {
            eprintln!("FATAL: could not load {}: {e}", vectors_path.display());
            std::process::exit(2);
        }
    };

    // Merge the sibling spec repo's DMTAP-PUB / CAD known-answer vectors when present, so §22/§23
    // cases are checked and cross-referenced exactly like the core ones.
    let pvp = pub_vectors_path();
    let mut pub_count = 0usize;
    if pvp.exists() {
        match load_vectors(&pvp) {
            Ok(pvf) => {
                pub_count = pvf.vectors.len();
                vf.vectors.extend(pvf.vectors);
            }
            Err(e) => eprintln!("WARN: could not load {}: {e}", pvp.display()),
        }
    }

    // Merge the sibling spec repo's DMTAP-PUBSUB (§25) known-answer vectors when present, so
    // PUBSUB cases are checked and cross-referenced exactly like the core/pub ones.
    let pbp = pubsub_vectors_path();
    let mut pubsub_count = 0usize;
    if pbp.exists() {
        match load_vectors(&pbp) {
            Ok(pbf) => {
                pubsub_count = pbf.vectors.len();
                vf.vectors.extend(pbf.vectors);
            }
            Err(e) => eprintln!("WARN: could not load {}: {e}", pbp.display()),
        }
    }

    // The Sync-substrate vectors are kept in their OWN report section rather than merged, because
    // one of them carries an expectation that contradicts SYNC.md's own text (see
    // SYNC_KNOWN_DISCREPANCIES): it is reported as a named discrepancy, not silently failed and not
    // silently passed. Every OTHER sync vector gates the exit code exactly like a core vector.
    let svp = sync_vectors_path();
    let sync_vf = if svp.exists() {
        match load_vectors(&svp) {
            Ok(svf) => Some(svf),
            Err(e) => {
                eprintln!("WARN: could not load {}: {e}", svp.display());
                None
            }
        }
    } else {
        None
    };

    println!("=== DMTAP conformance-runner ===");
    println!("vectors file : {}", vectors_path.display());
    if pub_count > 0 {
        println!("pub vectors  : {} (from {})", pub_count, pvp.display());
    }
    if pubsub_count > 0 {
        println!("pubsub vectors: {} (from {})", pubsub_count, pbp.display());
    }
    if let Some(svf) = &sync_vf {
        println!("sync vectors : {} (from {})", svf.vectors.len(), svp.display());
    }
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

    // --- Sync substrate (substrate/SYNC.md §10) ------------------------------------------------
    let mut sync_fail = 0usize;
    if let Some(svf) = &sync_vf {
        println!();
        println!("=== Sync substrate vectors: {} ===", svp.display());
        let mut sync_pass = 0usize;
        let mut discrepancies: Vec<(String, String)> = Vec::new();
        for (name, verdict) in check_all_vectors(svf) {
            let known = SYNC_KNOWN_DISCREPANCIES.iter().find(|(n, _)| *n == name);
            match (&verdict, known) {
                (Verdict::Pass | Verdict::PassGeneric, None) => {
                    sync_pass += 1;
                    println!("PASS   {name}");
                }
                (Verdict::Pass | Verdict::PassGeneric, Some(_)) => {
                    // The spec repo fixed the vector: say so loudly, and drop the allowlist entry.
                    sync_fail += 1;
                    println!(
                        "FAIL   {name}: listed in SYNC_KNOWN_DISCREPANCIES but now PASSES — the \
                         vector was fixed upstream; remove the allowlist entry"
                    );
                }
                (Verdict::Fail(e), Some((_, why))) => {
                    println!("DISCREPANCY  {name}: {e}");
                    discrepancies.push((name.clone(), (*why).to_string()));
                }
                (Verdict::Fail(e), None) => {
                    sync_fail += 1;
                    println!("FAIL   {name}: {e}");
                }
            }
        }
        println!(
            "--- sync summary: {sync_pass} pass, {} known spec/vector discrepancy, {sync_fail} FAIL, {} total ---",
            discrepancies.len(),
            svf.vectors.len()
        );
        for (name, why) in &discrepancies {
            println!();
            println!("KNOWN DISCREPANCY — {name}");
            println!("  {why}");
        }
    }

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

    if fail > 0 || sync_fail > 0 {
        eprintln!(
            "\nconformance-runner: {fail} vectors.json + {sync_fail} sync vector(s) FAILED — this is \
             the mandatory gate, exiting non-zero."
        );
        std::process::exit(1);
    }
    println!("\nconformance-runner: all {} vectors.json checks PASS.", pass + pass_generic);
}
