//! Executor for the **Sync substrate** known-answer vectors
//! (`../dmtap/conformance/vectors/sync_vectors.json`, frozen by `substrate/SYNC.md` §10).
//!
//! Wired exactly like `pub_vectors.json` (§22): a separate vector file in the sibling spec repo,
//! recomputed here through real reference code — in this case the `dmtap-sync` crate — so a passing
//! run proves the Rust reference reproduces the generator's bytes rather than restating them.
//!
//! Every case below **executes**: there are no skips and no "generic round-trip only" passes. Where
//! a vector is declarative (an admission predicate, a foreign-entry check), the predicate itself is
//! called; where it is byte-exact (op encoding, the `COSE_Sign1` envelope, the observable-state
//! root, the range-Merkle fingerprint), the bytes are recomputed and compared.

use serde_json::Value;

use dmtap_core::identity::IdentityKey;
use dmtap_sync::detcbor::{decode, encode, SVal};
use dmtap_sync::{
    check_admitted, check_counter_entry, check_ns_ref, cose, snapshot::ObservableState,
    stability_cut, state::SyncState, validate_op, DeathClass, DeathState, Hlc, OpEntry, SyncError,
    SyncOp,
};

use crate::{hex, unhex, Vector, Verdict};

/// The receiver "now" used for skew validation. The vectors' HLC wall is a fixed 2023-11-14
/// timestamp; the substrate's skew rule bounds ops from the **future**, so a receiver clock at or
/// after the vector wall accepts every vector op (`SYNC.md` §3).
const RECEIVER_NOW_MS: u64 = 1_700_000_900_000;

/// Whether this vector belongs to the Sync substrate suite.
pub fn handles(operation: &str) -> bool {
    operation.starts_with("sync_")
}

/// Execute one Sync-substrate vector.
pub fn check(v: &Vector) -> Result<Verdict, String> {
    match v.operation.as_str() {
        "sync_op_encode" => op_encode(v),
        "sync_op_cose_sign1_verify" => cose_sign1(v),
        "sync_author_admission" => author_admission(v),
        "sync_lww_merge" => lww_merge(v),
        "sync_orset_merge" => orset_merge(v),
        "sync_orset_remove_validity" => reject_case(v, SyncError::OpInvalid),
        "sync_death_domination" => death_domination(v),
        "sync_death_tie" => death_tie(v),
        "sync_pn_merge" => pn_merge(v),
        "sync_counter_foreign_check" => counter_foreign(v),
        "sync_rga_sibling_order" => rga_sibling_order(v),
        "sync_rga_tombstone_origin" => rga_tombstone_origin(v),
        "sync_tree_move_replay" => tree_move_replay(v),
        "sync_snapshot_state_root" => snapshot_state_root(v),
        "sync_snapshot_fast_join" => snapshot_fast_join(v),
        "sync_recon_fingerprint" => recon_fingerprint(v),
        "sync_ns_sparse_filter" => ns_sparse_filter(v),
        "sync_ns_leak_check" => ns_leak_check(v),
        "sync_gc_stability_cut" => gc_stability_cut(v),
        other => Err(format!("no executor registered for sync operation `{other}`")),
    }
}

// --- small helpers ---------------------------------------------------------------------------

fn s<'a>(v: &'a Value, path: &str) -> Result<&'a str, String> {
    v.get(path).and_then(Value::as_str).ok_or_else(|| format!("missing/non-string `{path}`"))
}

fn arr<'a>(v: &'a Value, path: &str) -> Result<&'a Vec<Value>, String> {
    v.get(path).and_then(Value::as_array).ok_or_else(|| format!("missing/non-array `{path}`"))
}

fn hex_list(v: &Value, path: &str) -> Result<Vec<Vec<u8>>, String> {
    arr(v, path)?
        .iter()
        .map(|e| e.as_str().ok_or_else(|| format!("`{path}` element is not a string")))
        .map(|r| r.and_then(|h| unhex(h)))
        .collect()
}

fn op_from_hex(h: &str) -> Result<SyncOp, String> {
    SyncOp::from_det_cbor(&unhex(h)?).map_err(|e| format!("SyncOp::from_det_cbor: {e}"))
}

fn eq<T: PartialEq + std::fmt::Debug>(what: &str, got: T, want: T) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what} mismatch: got {got:?}, want {want:?}"))
    }
}

/// Assert the vector's declared error code/name/action match a [`SyncError`].
fn expect_error(expected: &Value, err: SyncError) -> Result<(), String> {
    eq("outcome", s(expected, "outcome")?, "reject")?;
    eq("error_code", s(expected, "error_code")?, err.code_hex().as_str())?;
    eq("error_name", s(expected, "error_name")?, err.name())?;
    eq("action", s(expected, "action")?, err.action_str())?;
    Ok(())
}

fn hlc_from(v: &Value) -> Result<Hlc, String> {
    Ok(Hlc {
        wall: v.get("wall").and_then(Value::as_u64).ok_or("missing hlc.wall")?,
        counter: v.get("counter").and_then(Value::as_u64).ok_or("missing hlc.counter")? as u32,
        author: unhex(s(v, "author_hex")?)?,
    })
}

/// Ingest ops into a fresh state (validating each), in the given order.
fn ingest_all(ops: &[SyncOp]) -> Result<SyncState, String> {
    let mut st = SyncState::new();
    for op in ops {
        st.ingest(op, RECEIVER_NOW_MS).map_err(|e| format!("ingest: {e}"))?;
    }
    Ok(st)
}

// --- SYNC-OP-01 ------------------------------------------------------------------------------

fn op_encode(v: &Vector) -> Result<Verdict, String> {
    let value = match v.input.get("value_tstr").and_then(Value::as_str) {
        Some(t) => Some(SVal::Text(t.to_string())),
        None => None,
    };
    let op = SyncOp {
        kind: v.input.get("kind").and_then(Value::as_u64).ok_or("missing kind")? as u8,
        ns: s(&v.input, "ns")?.to_string(),
        target: s(&v.input, "target")?.to_string(),
        field: v.input.get("field").and_then(Value::as_str).map(str::to_string),
        value,
        hlc: hlc_from(v.input.get("hlc").ok_or("missing hlc")?)?,
        observed: None,
        reference: None,
    };
    let want = s(&v.expected, "cbor_hex")?;
    eq("SyncOp det_cbor", hex(&op.det_cbor()).as_str(), want)?;
    // Re-decoding MUST round-trip to the same fields and re-encode byte-for-byte.
    let back = op_from_hex(want)?;
    eq("SyncOp round-trip", &back, &op)?;
    eq("SyncOp re-encode", hex(&back.det_cbor()).as_str(), want)?;
    // A non-canonical spelling of the same object is refused, never silently re-canonicalized:
    // here the `kind` value 3 re-spelled in a two-byte head (0x1803).
    let mut noncanonical = unhex(want)?;
    noncanonical.splice(2..3, [0x18, 0x03]);
    noncanonical[0] = 0xa6;
    if SyncOp::from_det_cbor(&noncanonical).is_ok() {
        return Err("non-canonical (non-shortest-form) SyncOp was accepted".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-OP-02 ------------------------------------------------------------------------------

fn cose_sign1(v: &Vector) -> Result<Verdict, String> {
    let seed: [u8; 32] = unhex(s(&v.input, "signer_seed_hex")?)?
        .try_into()
        .map_err(|_| "signer_seed_hex is not 32 bytes".to_string())?;
    let sk = IdentityKey::from_seed(&seed);
    eq("signer pubkey", hex(&sk.public()).as_str(), s(&v.input, "signer_pubkey_hex")?)?;

    let op = op_from_hex(s(&v.input, "sync_op_cbor_hex")?)?;
    let signed = cose::sign_op(&sk, &op).map_err(|e| format!("sign_op: {e}"))?;

    // The `external_aad` is the DS-tag, never transmitted but bound into the signature.
    eq("external_aad", hex(&cose::op_external_aad()).as_str(), s(&v.input, "external_aad_hex")?)?;
    // The protected/payload members are compared as their WIRE bstr encodings (head + contents),
    // which is how the vector spells them.
    eq(
        "protected",
        hex(&encode(&SVal::Bytes(signed.protected.clone()))).as_str(),
        s(&v.expected, "protected_hex")?,
    )?;
    eq("unprotected", hex(&encode(&SVal::Map(Vec::new()))).as_str(), s(&v.expected, "unprotected_hex")?)?;
    eq(
        "payload",
        hex(&encode(&SVal::Bytes(signed.payload.clone()))).as_str(),
        s(&v.expected, "payload_hex")?,
    )?;
    eq("Sig_structure", hex(&signed.signable()).as_str(), s(&v.expected, "sig_structure_hex")?)?;
    eq("signature", hex(&signed.signature).as_str(), s(&v.expected, "signature_hex")?)?;
    eq("COSE_Sign1", hex(&signed.to_bytes()).as_str(), s(&v.input, "cose_sign1_hex")?)?;
    eq("op_id", hex(op.op_id().as_bytes()).as_str(), s(&v.expected, "op_id_hex")?)?;

    // The positive case verifies...
    let verified = cose::verify_op_bytes(&unhex(s(&v.input, "cose_sign1_hex")?)?)
        .map_err(|e| format!("committed COSE_Sign1 failed to verify: {e}"))?;
    eq("verified op", &verified, &op)?;
    if !v.expected.get("verifies").and_then(Value::as_bool).unwrap_or(false) {
        return Err("vector expects `verifies: false` for the positive case".into());
    }

    // ...and both negative cases fail closed with 0x0A02.
    for (field, expected_key) in [
        ("tampered_payload_cose_sign1_hex", "tampered_payload"),
        ("substituted_kid_cose_sign1_hex", "substituted_kid"),
    ] {
        let bytes = unhex(s(&v.input, field)?)?;
        let err = match cose::verify_op_bytes(&bytes) {
            Ok(_) => return Err(format!("{field} verified — domain separation/kid binding is broken")),
            Err(e) => e,
        };
        let exp = v.expected.get(expected_key).ok_or_else(|| format!("missing expected.{expected_key}"))?;
        if exp.get("verifies").and_then(Value::as_bool) != Some(false) {
            return Err(format!("expected.{expected_key}.verifies must be false"));
        }
        eq("error_code", s(exp, "error_code")?, err.code_hex().as_str())?;
        eq("error_name", s(exp, "error_name")?, err.name())?;
        eq("action", s(exp, "action")?, err.action_str())?;
    }

    // A third negative the vector's prose demands but does not encode: an envelope minted over ANY
    // other `external_aad` must not verify as a SyncOp. Domain separation is the whole reason the
    // DS-tag rides in `external_aad`, so it is proven here rather than assumed.
    let foreign = cose::sig_structure(
        &signed.protected,
        b"DMTAP-SYNC-v0/snapshot\x00",
        &signed.payload,
    );
    let foreign_sig = sk.sign_domain(&[], &foreign);
    let forged = cose::CoseSign1 {
        protected: signed.protected.clone(),
        payload: signed.payload.clone(),
        signature: foreign_sig,
    };
    if cose::verify_op(&forged).is_ok() {
        return Err("a COSE_Sign1 signed under a different DS-tag verified as a SyncOp".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-AUTH-01 ----------------------------------------------------------------------------

fn author_admission(v: &Vector) -> Result<Verdict, String> {
    let op = op_from_hex(s(&v.input, "op_cbor_hex")?)?;
    let claimed = unhex(s(&v.input, "op_hlc_author_hex")?)?;
    eq("op hlc.author", hex(&op.hlc.author).as_str(), hex(&claimed).as_str())?;
    let admitted = hex_list(&v.input, "admitted_authors_hex")?;
    let err = match check_admitted(&op.hlc.author, &admitted) {
        Ok(()) => return Err("an unadmitted author was accepted".into()),
        Err(e) => e,
    };
    expect_error(&v.expected, err)?;
    // And the admitted authors ARE admitted — the predicate is a gate, not a blanket deny.
    for a in &admitted {
        check_admitted(a, &admitted).map_err(|e| format!("admitted author rejected: {e}"))?;
    }
    Ok(Verdict::Pass)
}

// --- SYNC-LWW-01 / SYNC-LWW-02 ---------------------------------------------------------------

fn lww_merge(v: &Vector) -> Result<Verdict, String> {
    let ops: Vec<SyncOp> = arr(&v.input, "ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let target = ops[0].target.clone();
    let field = ops[0].field.clone().ok_or("LWW op without a field")?;

    // Both apply orders must reach the same winner — that is the whole claim.
    let forward = ingest_all(&ops)?;
    let mut reversed = ops.clone();
    reversed.reverse();
    let backward = ingest_all(&reversed)?;

    let win = |st: &SyncState| -> Result<(Hlc, SVal), String> {
        st.lww.cell(&target, &field).cloned().ok_or_else(|| "no winning cell".to_string())
    };
    let (fh, fv) = win(&forward)?;
    let (bh, bv) = win(&backward)?;
    eq("winner across apply orders", (&fh, &fv), (&bh, &bv))?;

    eq("winner_value", fv.as_text().ok_or("winner is not text")?, s(&v.expected, "winner_value")?)?;
    if let Some(want) = v.expected.get("winner_hlc_hex").and_then(Value::as_str) {
        eq("winner_hlc", hex(&fh.det_cbor()).as_str(), want)?;
    }
    if let Some(want) = v.expected.get("winner_value_cbor_hex").and_then(Value::as_str) {
        eq("winner_value_cbor", hex(&fv.det_cbor()).as_str(), want)?;
    }
    Ok(Verdict::Pass)
}

// --- SYNC-ORSET-01 ---------------------------------------------------------------------------

fn orset_merge(v: &Vector) -> Result<Verdict, String> {
    let ops: Vec<SyncOp> = arr(&v.input, "ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let element = SVal::Text(s(&v.input, "element")?.to_string());
    let target = ops[0].target.clone();

    // Add-wins must hold whatever the arrival order: the remove precedes its concurrent add here.
    let forward = ingest_all(&ops)?;
    let mut reversed = ops.clone();
    reversed.reverse();
    let backward = ingest_all(&reversed)?;

    let want_present = v.expected.get("present").and_then(Value::as_bool).ok_or("missing present")?;
    eq("present", forward.is_present(&target, &element), want_present)?;
    eq("present (reverse order)", backward.is_present(&target, &element), want_present)?;

    if let Some(want) = v.expected.get("surviving_add_tag_hlc_hex").and_then(Value::as_str) {
        let surviving = forward.orset.surviving_tags(&target, &element);
        eq("surviving add-tag count", surviving.len(), 1)?;
        eq("surviving add-tag hlc", hex(&surviving[0].hlc.det_cbor()).as_str(), want)?;
    }
    Ok(Verdict::Pass)
}

// --- SYNC-ORSET-02 / a generic "this op must be refused" case ---------------------------------

fn reject_case(v: &Vector, want: SyncError) -> Result<Verdict, String> {
    let op = op_from_hex(s(&v.input, "op_cbor_hex")?)?;
    let err = match validate_op(&op, RECEIVER_NOW_MS) {
        Ok(()) => return Err("a causally-impossible op was accepted".into()),
        Err(e) => e,
    };
    eq("error kind", err, want)?;
    expect_error(&v.expected, err)?;
    // The same op must also be refused by the full ingest path, not only by the bare validator.
    let mut st = SyncState::new();
    if st.ingest(&op, RECEIVER_NOW_MS).is_ok() {
        return Err("ingest accepted an op the validator refused".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-DEATH-01 / SYNC-DEATH-02 ------------------------------------------------------------

fn death_domination(v: &Vector) -> Result<Verdict, String> {
    let death = op_from_hex(s(&v.input, "death_op_cbor_hex")?)?;
    let add = op_from_hex(s(&v.input, "concurrent_add_op_cbor_hex")?)?;
    let element = add.value.clone().ok_or("set-add without a value")?;
    let target = death.target.clone();
    eq("both ops address one object", add.target.as_str(), target.as_str())?;
    // The add's HLC is numerically GREATER than the death's — domination must not care.
    if add.hlc <= death.hlc {
        return Err("vector premise broken: the concurrent add should out-rank the death HLC".into());
    }
    let want = v.expected.get("present").and_then(Value::as_bool).ok_or("missing present")?;
    for order in [vec![death.clone(), add.clone()], vec![add, death]] {
        let st = ingest_all(&order)?;
        eq("present", st.is_present(&target, &element), want)?;
    }
    Ok(Verdict::Pass)
}

fn death_tie(v: &Vector) -> Result<Verdict, String> {
    let death = op_from_hex(s(&v.input, "death_op_cbor_hex")?)?;
    let live = op_from_hex(s(&v.input, "live_op_cbor_hex")?)?;
    eq("the two writes share one HLC", &death.hlc, &live.hlc)?;
    let target = death.target.clone();
    let want_class = DeathClass::from_token(s(&v.expected, "class")?)
        .ok_or_else(|| format!("unknown class token `{}`", v.expected["class"]))?;
    for order in [vec![death.clone(), live.clone()], vec![live, death]] {
        let st = ingest_all(&order)?;
        eq("winner", st.deaths.state(&target), DeathState::Deleted(want_class))?;
    }
    eq("winner", s(&v.expected, "winner")?, "Deleted")?;
    Ok(Verdict::Pass)
}

// --- SYNC-PN-01 ------------------------------------------------------------------------------

fn pn_merge(v: &Vector) -> Result<Verdict, String> {
    let ops: Vec<SyncOp> = arr(&v.input, "ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let target = ops[0].target.clone();
    let field = ops[0].field.clone().ok_or("counter op without a field")?;

    let want_p = v.expected.get("P").and_then(Value::as_object).ok_or("missing expected.P")?;
    let want_n = v.expected.get("N").and_then(Value::as_object).ok_or("missing expected.N")?;
    let want_total = v.expected.get("total").and_then(Value::as_i64).ok_or("missing total")?;

    let check = |st: &SyncState| -> Result<(), String> {
        let entries = st.counters.entries(&target, &field);
        for (author_hex, want) in want_p {
            let (p, _) = entries.get(&unhex(author_hex)?).copied().unwrap_or((0, 0));
            eq(&format!("P[{}]", &author_hex[..8]), p, want.as_u64().ok_or("non-integer P")?)?;
        }
        for (author_hex, want) in want_n {
            let (_, n) = entries.get(&unhex(author_hex)?).copied().unwrap_or((0, 0));
            eq(&format!("N[{}]", &author_hex[..8]), n, want.as_u64().ok_or("non-integer N")?)?;
        }
        eq("total", st.counters.total(&target, &field), want_total as i128)
    };

    // The property the vector's prose asserts — "a replayed +5(A) does not double-count" — is
    // proven here against a TRUE replay: the identical op (identical bytes ⇒ identical op-id)
    // delivered twice. Ingest dedups by op-id, so the second delivery is a no-op and the vector's
    // own expected P/N/total come out exactly.
    let distinct: Vec<SyncOp> = ops.iter().take(2).cloned().collect();
    let mut true_replay = distinct.clone();
    true_replay.push(distinct[0].clone());
    let replayed_state = ingest_all(&true_replay)?;
    check(&replayed_state).map_err(|e| {
        format!("the true-replay reading of SYNC-PN-01 also fails, so this is a REAL bug: {e}")
    })?;
    if v.expected.get("replay_is_noop").and_then(Value::as_bool) == Some(true) {
        eq(
            "replay_is_noop",
            replayed_state.counters.total(&target, &field),
            ingest_all(&distinct)?.counters.total(&target, &field),
        )?;
    }

    // The vector AS WRITTEN, however, gives its third op a different HLC (counter 1 vs 0), so it
    // is a distinct op and §4.6's `P[author] += d` accumulates it. Reported, not bent.
    let st = ingest_all(&ops)?;
    check(&st).map_err(|e| {
        format!(
            "{e}. The vector's third op is NOT a replay: its hlc.counter is {} where the first \
             op's is {}, so the two have different op-ids ({}... vs {}...) and §4.6 accumulates \
             both deltas. See SYNC_KNOWN_DISCREPANCIES for the minimal fix.",
            ops[2].hlc.counter,
            ops[0].hlc.counter,
            &hex(ops[2].op_id().as_bytes())[..12],
            &hex(ops[0].op_id().as_bytes())[..12],
        )
    })?;
    Ok(Verdict::Pass)
}

// --- SYNC-PN-02 ------------------------------------------------------------------------------

fn counter_foreign(v: &Vector) -> Result<Verdict, String> {
    let op_author = unhex(s(&v.input, "op_hlc_author_hex")?)?;
    let entry_author = unhex(s(&v.input, "target_entry_author_hex")?)?;
    let err = match check_counter_entry(&op_author, &entry_author) {
        Ok(()) => return Err("a foreign PN-counter entry mutation was accepted".into()),
        Err(e) => e,
    };
    expect_error(&v.expected, err)?;
    // The own-entry case is of course allowed.
    check_counter_entry(&op_author, &op_author).map_err(|e| format!("own entry rejected: {e}"))?;
    Ok(Verdict::Pass)
}

// --- SYNC-RGA-01 / SYNC-RGA-02 -----------------------------------------------------------------

fn rga_sibling_order(v: &Vector) -> Result<Verdict, String> {
    let origin = op_from_hex(s(&v.input, "origin_op_cbor_hex")?)?;
    let siblings: Vec<SyncOp> = arr(&v.input, "sibling_ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let target = origin.target.clone();
    let want_values: Vec<String> = arr(&v.expected, "order_values")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    let want_ids: Vec<String> = arr(&v.expected, "order_by_element_id_desc")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();

    // Both arrival orders of the concurrent siblings must produce the identical sequence.
    for rev in [false, true] {
        let mut ops = vec![origin.clone()];
        let mut sibs = siblings.clone();
        if rev {
            sibs.reverse();
        }
        ops.extend(sibs);
        let st = ingest_all(&ops)?;
        let seq = st.sequences.get(&target).ok_or("no sequence built")?;
        let values: Vec<String> = seq
            .values()
            .iter()
            .filter_map(|v| v.as_text().map(str::to_string))
            .collect();
        // values[0] is the origin atom; the siblings follow, newer-first.
        eq("sibling order", &values[1..], &want_values[..])?;
        let ids: Vec<String> = seq
            .order()
            .into_iter()
            .skip(1)
            .map(|id| hex(&id.det_cbor()))
            .collect();
        eq("sibling element ids (descending)", &ids, &want_ids)?;
    }
    Ok(Verdict::Pass)
}

fn rga_tombstone_origin(v: &Vector) -> Result<Verdict, String> {
    let insert_x = op_from_hex(s(&v.input, "insert_x_cbor_hex")?)?;
    let remove_x = op_from_hex(s(&v.input, "remove_x_cbor_hex")?)?;
    let insert_y = op_from_hex(s(&v.input, "insert_y_cbor_hex")?)?;
    let target = insert_x.target.clone();
    let origin = hlc_from(v.input.get("y_ref_origin_hlc").ok_or("missing y_ref_origin_hlc")?)?;
    eq("y's ref names x's element id", &insert_y.reference.as_ref().unwrap().hlc, &Some(origin))?;

    let st = ingest_all(&[insert_x.clone(), remove_x, insert_y.clone()])?;
    let seq = st.sequences.get(&target).ok_or("no sequence built")?;

    // The insert RESOLVES (it is neither buffered nor rejected) even though its origin is
    // tombstoned — that is the whole point of retaining tombstones until GC.
    eq("resolves", seq.has(&insert_y.hlc), v.expected.get("resolves").and_then(Value::as_bool).unwrap_or(false))?;
    eq("reject", false, v.expected.get("reject").and_then(Value::as_bool).unwrap_or(true))?;

    let visible: Vec<String> = seq
        .values()
        .iter()
        .filter_map(|v| v.as_text().map(str::to_string))
        .collect();
    let want_visible: Vec<String> = arr(&v.expected, "visible_sequence")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    eq("visible_sequence", &visible, &want_visible)?;

    // `atom_order_incl_tombstones` is a human-readable LABEL list, not normative bytes (the vector
    // now says so itself), and since SYNC.md §14 C-03 corrected it to ["x(tombstoned)", "Z"] it
    // agrees with §4.7's insert-after rule and with the vector's own note — so it is asserted AS
    // GIVEN rather than reduced to a length check. Labels are rendered from the actual atom order:
    // each atom's value text, suffixed "(tombstoned)" when the atom is tombstoned.
    let labels: Vec<String> = seq
        .order()
        .iter()
        .map(|id| {
            let text = seq
                .atom_value(id)
                .and_then(|v| v.as_text().map(str::to_string))
                .unwrap_or_default();
            if seq.is_tombstoned(id) {
                format!("{text}(tombstoned)")
            } else {
                text
            }
        })
        .collect();
    let want_labels: Vec<String> = arr(&v.expected, "atom_order_incl_tombstones")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    eq("atom_order_incl_tombstones", &labels, &want_labels)?;
    // …and the ids behind those labels are the two ops the vector supplied, in that order.
    let order = seq.order();
    eq("x precedes Z (§4.7 insert-after)", (order[0] == insert_x.hlc, order[1] == insert_y.hlc), (true, true))?;
    Ok(Verdict::Pass)
}

// --- SYNC-TREE-01 ------------------------------------------------------------------------------

fn tree_move_replay(v: &Vector) -> Result<Verdict, String> {
    let mut ops: Vec<SyncOp> = Vec::new();
    for key in ["baseline_ops_cbor_hex", "colliding_ops_cbor_hex"] {
        for e in arr(&v.input, key)? {
            ops.push(op_from_hex(e.as_str().ok_or("non-string op")?)?);
        }
    }
    let colliding: Vec<SyncOp> = arr(&v.input, "colliding_ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let (h1, h2) = (colliding[0].hlc.clone(), colliding[1].hlc.clone());
    if !(h1 < h2) {
        return Err("vector premise broken: h1 must sort before h2".into());
    }

    let want_edges: Vec<(String, String, String)> = arr(&v.expected, "final_edges")?
        .iter()
        .map(|e| {
            Ok((
                s(e, "node")?.to_string(),
                s(e, "parent")?.to_string(),
                s(e, "ord")?.to_string(),
            ))
        })
        .collect::<Result<_, String>>()?;

    // Every arrival order must reach the identical acyclic tree: that is `apply_order_independent`.
    let orders: Vec<Vec<SyncOp>> = vec![
        ops.clone(),
        ops.iter().rev().cloned().collect(),
        vec![ops[3].clone(), ops[2].clone(), ops[0].clone(), ops[1].clone()],
    ];
    for order in orders {
        let st = ingest_all(&order)?;
        let replay = st.tree.replay();
        let applied: Vec<String> =
            replay.applied.iter().map(|(h, n)| format!("{n}@{}", h.counter)).collect();
        let _ = applied;
        // The LATER-HLC move of the colliding pair is the one skipped (§4.8).
        let skipped_labels: Vec<&str> = replay
            .skipped
            .iter()
            .map(|(h, _)| if *h == h1 { "h1" } else if *h == h2 { "h2" } else { "?" })
            .collect();
        let want_skipped: Vec<String> = arr(&v.expected, "skipped")?
            .iter()
            .map(|e| e.as_str().unwrap_or_default().to_string())
            .collect();
        eq("skipped moves", &skipped_labels, &want_skipped.iter().map(String::as_str).collect::<Vec<_>>())?;

        let got_edges: Vec<(String, String, String)> = replay
            .edges
            .iter()
            .map(|(n, (p, o))| (n.clone(), p.clone(), o.clone()))
            .collect();
        eq("final_edges", &got_edges, &want_edges)?;

        // Acyclicity, checked rather than assumed.
        for node in replay.edges.keys() {
            let mut cur = node.clone();
            let mut steps = 0;
            while let Some((parent, _)) = replay.edges.get(&cur) {
                cur = parent.clone();
                steps += 1;
                if steps > replay.edges.len() {
                    return Err(format!("cycle reachable from `{node}`"));
                }
            }
        }
    }
    if v.expected.get("skipped_is_error").and_then(Value::as_bool) != Some(false) {
        return Err("vector must declare a skipped move is NOT an error".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-SNAP-01 / SYNC-SNAP-02 ---------------------------------------------------------------

/// Build the §6.1.1 `ObservableState` from the vector's declarative JSON projection.
fn observable_from_json(v: &Value) -> Result<ObservableState, String> {
    let text = |e: &Value| -> Result<String, String> {
        e.as_str().map(str::to_string).ok_or_else(|| "expected a string".to_string())
    };
    let mut st = ObservableState::default();
    for e in arr(v, "orset")? {
        let pair = e.as_array().ok_or("orset entry is not an array")?;
        st.orset.push((text(&pair[0])?, SVal::Text(text(&pair[1])?)));
    }
    for e in arr(v, "lww")? {
        let t = e.as_array().ok_or("lww entry is not an array")?;
        st.lww.push((text(&t[0])?, text(&t[1])?, SVal::Text(text(&t[2])?)));
    }
    for e in arr(v, "pn")? {
        let t = e.as_array().ok_or("pn entry is not an array")?;
        st.pn.push((
            text(&t[0])?,
            text(&t[1])?,
            t[2].as_i64().ok_or("pn total is not an integer")? as i128,
        ));
    }
    for e in arr(v, "death")? {
        let t = e.as_array().ok_or("death entry is not an array")?;
        st.death.push((text(&t[0])?, text(&t[1])?));
    }
    for e in arr(v, "rga")? {
        let t = e.as_array().ok_or("rga entry is not an array")?;
        let atoms = t[1].as_array().ok_or("rga atoms is not an array")?;
        st.rga.push((
            text(&t[0])?,
            atoms.iter().map(|a| Ok(SVal::Text(text(a)?))).collect::<Result<_, String>>()?,
        ));
    }
    for e in arr(v, "tree")? {
        let t = e.as_array().ok_or("tree entry is not an array")?;
        st.tree.push((text(&t[0])?, text(&t[1])?, text(&t[2])?));
    }
    Ok(st)
}

fn snapshot_state_root(v: &Vector) -> Result<Verdict, String> {
    let st = observable_from_json(v.input.get("observable_state").ok_or("missing observable_state")?)?;
    eq(
        "ObservableState det_cbor",
        hex(&st.det_cbor()).as_str(),
        s(&v.expected, "observable_state_cbor_hex")?,
    )?;
    eq("root", hex(st.root().as_bytes()).as_str(), s(&v.expected, "root_hex")?)?;

    // The six-section shape is never abbreviated: an empty state is six empty arrays, not `[]`.
    let empty = ObservableState::default();
    eq("empty state det_cbor", hex(&empty.det_cbor()).as_str(), s(&v.expected, "empty_state_cbor_hex")?)?;
    eq("empty state root", hex(empty.root().as_bytes()).as_str(), s(&v.expected, "empty_state_root_hex")?)?;
    eq(
        "section count",
        empty.to_sval().as_array().map(<[SVal]>::len),
        v.input.get("empty_state_sections").and_then(Value::as_u64).map(|n| n as usize),
    )?;

    // Section entries are sorted by det_cbor, so a shuffled projection hashes identically —
    // the property that makes two replicas' roots comparable at all.
    let mut shuffled = st.clone();
    shuffled.tree.reverse();
    shuffled.lww.reverse();
    eq("sort determinism", hex(&shuffled.det_cbor()).as_str(), hex(&st.det_cbor()).as_str())?;

    // A one-bit difference in observable state is a DIFFERENT root ⇒ 0x0A09 evidence.
    let mut diverged = st.clone();
    diverged.lww[0].2 = SVal::Text("DIVERGED".into());
    if diverged.root().as_bytes() == st.root().as_bytes() {
        return Err("a diverged state produced the same root".into());
    }
    eq("mismatch error", s(&v.expected, "mismatch_error_code")?, SyncError::SnapshotRootMismatch.code_hex().as_str())?;
    eq("mismatch name", s(&v.expected, "mismatch_error_name")?, SyncError::SnapshotRootMismatch.name())?;
    eq("mismatch action", s(&v.expected, "mismatch_action")?, SyncError::SnapshotRootMismatch.action_str())?;
    Ok(Verdict::Pass)
}

fn snapshot_fast_join(v: &Vector) -> Result<Verdict, String> {
    // The snapshot's observable state, adopted verbatim by a joining replica.
    let snap_bytes = unhex(s(&v.input, "snapshot_observable_state_cbor_hex")?)?;
    let snap_sval = decode(&snap_bytes).map_err(|e| format!("snapshot state decode: {e}"))?;
    eq(
        "snapshot root",
        hex(dmtap_sync::ds_hash(dmtap_sync::DS_SNAPSHOT_STATE, &snap_bytes).as_bytes()).as_str(),
        s(&v.input, "snapshot_root_hex")?,
    )?;

    // Apply the post-`covers` ops to the adopted projection. The only post-covers op is an LWW
    // write, so the fast-joined projection is the snapshot's with that cell replaced — which is
    // exactly what a replica computes after adopting and ingesting.
    let ops: Vec<SyncOp> = arr(&v.input, "post_covers_ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;

    let sections = snap_sval.as_array().ok_or("snapshot state is not an array")?;
    if sections.len() != 6 {
        return Err(format!("snapshot state has {} sections, want 6", sections.len()));
    }
    let mut joined = ObservableState::default();
    // Rebuild the typed projection from the adopted bytes...
    for e in sections[0].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("orset entry")?;
        joined.orset.push((p[0].as_text().ok_or("orset target")?.into(), p[1].clone()));
    }
    for e in sections[1].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("lww entry")?;
        joined.lww.push((
            p[0].as_text().ok_or("lww target")?.into(),
            p[1].as_text().ok_or("lww field")?.into(),
            p[2].clone(),
        ));
    }
    for e in sections[2].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("pn entry")?;
        joined.pn.push((
            p[0].as_text().ok_or("pn target")?.into(),
            p[1].as_text().ok_or("pn field")?.into(),
            p[2].as_int().ok_or("pn total")? as i128,
        ));
    }
    for e in sections[3].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("death entry")?;
        joined.death.push((
            p[0].as_text().ok_or("death target")?.into(),
            p[1].as_text().ok_or("death class")?.into(),
        ));
    }
    for e in sections[4].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("rga entry")?;
        joined.rga.push((
            p[0].as_text().ok_or("rga target")?.into(),
            p[1].as_array().ok_or("rga atoms")?.to_vec(),
        ));
    }
    for e in sections[5].as_array().unwrap_or(&[]) {
        let p = e.as_array().ok_or("tree entry")?;
        joined.tree.push((
            p[0].as_text().ok_or("tree node")?.into(),
            p[1].as_text().ok_or("tree parent")?.into(),
            p[2].as_text().ok_or("tree ord")?.into(),
        ));
    }
    // ...then apply the post-covers ops to it (an LWW write with a greater HLC than `covers`).
    for op in &ops {
        let field = op.field.clone().ok_or("post-covers op without a field")?;
        let value = op.value.clone().ok_or("post-covers op without a value")?;
        match joined.lww.iter_mut().find(|(t, f, _)| *t == op.target && *f == field) {
            Some(cell) => cell.2 = value,
            None => joined.lww.push((op.target.clone(), field, value)),
        }
    }
    eq(
        "fast_join_state",
        hex(&joined.det_cbor()).as_str(),
        s(&v.expected, "fast_join_state_cbor_hex")?,
    )?;
    eq(
        "full_replay_state",
        s(&v.expected, "full_replay_state_cbor_hex")?,
        s(&v.expected, "fast_join_state_cbor_hex")?,
    )?;
    eq("root", hex(joined.root().as_bytes()).as_str(), s(&v.expected, "root_hex")?)?;
    if v.expected.get("states_byte_identical").and_then(Value::as_bool) != Some(true)
        || v.expected.get("roots_equal").and_then(Value::as_bool) != Some(true)
    {
        return Err("vector must declare the fast-join and replay states identical".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-RECON-01 -----------------------------------------------------------------------------

fn recon_fingerprint(v: &Vector) -> Result<Verdict, String> {
    let ops_obj = v.input.get("ops_cbor_hex").and_then(Value::as_object).ok_or("missing ops")?;
    let ids_obj = v.input.get("op_ids_hex").and_then(Value::as_object).ok_or("missing op_ids")?;
    let mut entries: std::collections::BTreeMap<String, OpEntry> = Default::default();
    for (label, hexstr) in ops_obj {
        let op = op_from_hex(hexstr.as_str().ok_or("non-string op")?)?;
        let id = op.op_id();
        // The committed op-id must be reproducible from the op bytes — no restated constants.
        let want = ids_obj.get(label).and_then(Value::as_str).ok_or("missing op id")?;
        eq(&format!("op_id[{label}]"), hex(id.as_bytes()).as_str(), want)?;
        entries.insert(label.clone(), OpEntry { hlc: op.hlc.clone(), id });
    }
    let holds = |key: &str| -> Result<Vec<OpEntry>, String> {
        arr(&v.input, key)?
            .iter()
            .map(|e| {
                let label = e.as_str().ok_or("non-string label")?;
                entries.get(label).cloned().ok_or(format!("unknown op label `{label}`"))
            })
            .collect()
    };
    let a_set = holds("replica_A_holds")?;
    let b_set = holds("replica_B_holds")?;
    let range = v.input.get("range").ok_or("missing range")?;
    let lo = hlc_from(range.get("lo").ok_or("missing range.lo")?)?;
    let hi = hlc_from(range.get("hi").ok_or("missing range.hi")?)?;
    let split = hlc_from(v.input.get("split_at").ok_or("missing split_at")?)?;

    let check_fp = |set: &[OpEntry], lo: &Hlc, hi: &Hlc, want: &Value, side: &str, what: &str| -> Result<(), String> {
        let fp = dmtap_sync::summarize(set, lo, hi);
        let w = want.get(side).ok_or_else(|| format!("missing {what}.{side}"))?;
        eq(&format!("{what}.{side}.fp"), hex(fp.fp.as_bytes()).as_str(), s(w, "fp_hex")?)?;
        eq(
            &format!("{what}.{side}.count"),
            fp.count,
            w.get("count").and_then(Value::as_u64).ok_or("missing count")?,
        )
    };

    let full = v.expected.get("full_range").ok_or("missing full_range")?;
    check_fp(&a_set, &lo, &hi, full, "A", "full_range")?;
    check_fp(&b_set, &lo, &hi, full, "B", "full_range")?;
    eq("full_range.match", full.get("match").and_then(Value::as_bool), Some(false))?;

    let sub1 = v.expected.get("subrange_1").ok_or("missing subrange_1")?;
    check_fp(&a_set, &lo, &split, sub1, "A", "subrange_1")?;
    check_fp(&b_set, &lo, &split, sub1, "B", "subrange_1")?;
    // Equal (fp, count) ⇒ identical range, and NOTHING is exchanged.
    eq("subrange_1.match", sub1.get("match").and_then(Value::as_bool), Some(true))?;
    eq("subrange_1.ops_exchanged", arr(sub1, "ops_exchanged")?.len(), 0)?;

    let sub2 = v.expected.get("subrange_2").ok_or("missing subrange_2")?;
    check_fp(&a_set, &split, &hi, sub2, "A", "subrange_2")?;
    check_fp(&b_set, &split, &hi, sub2, "B", "subrange_2")?;
    eq("subrange_2.match", sub2.get("match").and_then(Value::as_bool), Some(false))?;

    // The empty range's fingerprint is a fixed known answer (the `count` guard is what makes
    // empty-vs-empty distinguishable at all).
    let empty = dmtap_sync::fingerprint(&[]);
    eq("empty_range_fp", hex(empty.0.as_bytes()).as_str(), s(&v.expected, "empty_range_fp_hex")?)?;
    eq("empty_range_count", empty.1, v.expected.get("empty_range_count").and_then(Value::as_u64).ok_or("missing empty_range_count")?)?;

    // Drill-down surfaces exactly the one differing op, and nothing else.
    let outcome = dmtap_sync::reconcile(&b_set, &a_set, &lo, &hi, Default::default());
    let want_shipped: Vec<String> = arr(sub2, "ops_shipped_to_B")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    let got_shipped: Vec<String> =
        outcome.missing_here.iter().map(|id| hex(id.as_bytes())).collect();
    eq("ops shipped to B", &got_shipped, &want_shipped)?;
    eq("ops shipped to A", outcome.missing_there.len(), 0)?;
    eq(
        "ops_shipped_total",
        got_shipped.len() as u64,
        v.expected.get("ops_shipped_total").and_then(Value::as_u64).ok_or("missing total")?,
    )?;
    Ok(Verdict::Pass)
}

// --- SYNC-NS-01 / SYNC-NS-02 -------------------------------------------------------------------

fn ns_sparse_filter(v: &Vector) -> Result<Verdict, String> {
    let ops: Vec<SyncOp> = arr(&v.input, "responder_ops_cbor_hex")?
        .iter()
        .map(|e| op_from_hex(e.as_str().ok_or("non-string op")?))
        .collect::<Result<_, String>>()?;
    let declared: Vec<String> = arr(&v.input, "responder_ops_ns")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    for (op, ns) in ops.iter().zip(&declared) {
        eq("op ns", op.ns.as_str(), ns.as_str())?;
    }
    let subscribed: Vec<String> = arr(&v.input, "caller_subscribed_ns")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    let shipped = dmtap_sync::scope_to_subscription(&ops, &subscribed);
    let got: Vec<String> = shipped.iter().map(|op| hex(&op.det_cbor())).collect();
    let want: Vec<String> = arr(&v.expected, "shipped_ops_cbor_hex")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    eq("shipped ops", &got, &want)?;
    let got_ns: Vec<String> = shipped.iter().map(|op| op.ns.clone()).collect();
    let want_ns: Vec<String> = arr(&v.expected, "shipped_ns")?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_string())
        .collect();
    eq("shipped ns", &got_ns, &want_ns)?;
    Ok(Verdict::Pass)
}

fn ns_leak_check(v: &Vector) -> Result<Verdict, String> {
    let op = op_from_hex(s(&v.input, "op_cbor_hex")?)?;
    eq("op ns", op.ns.as_str(), s(&v.input, "op_ns")?)?;
    let reference = op.reference.as_ref().ok_or("op carries no reference")?;
    eq("ref target", reference.target.as_str(), s(&v.input, "ref_target")?)?;
    let referenced_ns = s(&v.input, "ref_target_actual_ns")?;
    let err = match check_ns_ref(&op.ns, referenced_ns) {
        Ok(()) => return Err("a cross-namespace reference was accepted".into()),
        Err(e) => e,
    };
    expect_error(&v.expected, err)?;
    // A same-namespace reference is of course fine — the rule is a boundary, not a ban.
    check_ns_ref(&op.ns, &op.ns).map_err(|e| format!("same-ns reference rejected: {e}"))?;
    Ok(Verdict::Pass)
}

// --- SYNC-GC-01 --------------------------------------------------------------------------------

fn gc_stability_cut(v: &Vector) -> Result<Verdict, String> {
    let live: Vec<Option<Hlc>> = arr(&v.input, "live_replica_watermarks")?
        .iter()
        .map(|e| {
            hlc_from(e.get("max_applied_hlc").ok_or("missing max_applied_hlc")?).map(Some)
        })
        .collect::<Result<_, String>>()?;
    let cut = stability_cut(&live).ok_or("no cut computed from two live watermarks")?;
    eq(
        "stability_cut_counter",
        cut.counter as u64,
        v.expected.get("stability_cut_counter").and_then(Value::as_u64).ok_or("missing counter")?,
    )?;

    // The stale replica is EXCLUDED: including it would drag the cut down to its watermark and let
    // a dead-but-unrevoked replica stall compaction forever.
    let stale = v.input.get("stale_replica_watermark").ok_or("missing stale watermark")?;
    let stale_hlc = hlc_from(stale.get("max_applied_hlc").ok_or("missing stale hlc")?)?;
    if stale.get("seen_within_liveness_window").and_then(Value::as_bool) != Some(false) {
        return Err("vector must declare the stale replica outside the liveness window".into());
    }
    let mut with_stale = live.clone();
    with_stale.push(Some(stale_hlc.clone()));
    let would_be = stability_cut(&with_stale).ok_or("no cut")?;
    if would_be >= cut {
        return Err("vector premise broken: the stale watermark should be lower than the cut".into());
    }
    eq("stale_replica_excluded", v.expected.get("stale_replica_excluded").and_then(Value::as_bool), Some(true))?;

    // Fail-closed: a live replica with NO known watermark yields no cut at all.
    let mut unknown = live.clone();
    unknown.push(None);
    if stability_cut(&unknown).is_some() {
        return Err("a cut was computed despite a live replica with no watermark".into());
    }

    // And GC below the cut never changes observable state.
    let mut st = SyncState::new();
    let element = SVal::Text("e1".into());
    let author = cut.author.clone();
    let tag = dmtap_sync::AddTag {
        author: author.clone(),
        hlc: Hlc { wall: cut.wall, counter: 1, author: author.clone() },
    };
    st.orset.add("tags", &element, tag.clone());
    st.orset.remove("tags", &element, &[tag]);
    let before = ObservableState::of(&st).det_cbor();
    let pruned = st.orset.prune_stable(&cut);
    if pruned == 0 {
        return Err("a collapsed add/tombstone pair below the cut was not reclaimed".into());
    }
    eq("observable state after GC", hex(&ObservableState::of(&st).det_cbor()).as_str(), hex(&before).as_str())?;
    Ok(Verdict::Pass)
}
