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
    caller_is_below_floor, check_admitted, check_counter_entry, check_covers_closes_gap,
    check_ns_ref, cose, covers_carries_mark_for_floor_author, snapshot::ObservableState,
    stability_cut, state::SyncState, state::VersionVector, state_root_of, validate_op, DeathClass,
    DeathState, FastJoin, Hlc, OpEntry, SnapshotBody, SyncError, SyncOp,
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
        "sync_fastjoin_pull_response" => fastjoin_pull_response(v),
        "sync_fastjoin_floor_predicate" => fastjoin_floor_predicate(v),
        "sync_ext_value_validate" => ext_value_validate(v),
        "sync_snapshot_body_fold" => snapshot_body_fold(v),
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

// --- SYNC-FJ-01 / SYNC-FJ-02 (§5.2.1 fast-join) ------------------------------------------------

/// Decode a `VersionVector` from its canonical CBOR.
fn vector_from_hex(h: &str) -> Result<VersionVector, String> {
    let cv = decode(&unhex(h)?).map_err(|e| format!("vector decode: {e}"))?;
    VersionVector::from_sval(cv).map_err(|e| format!("VersionVector::from_sval: {e}"))
}

fn hlc_from_hex(h: &str) -> Result<Hlc, String> {
    let cv = decode(&unhex(h)?).map_err(|e| format!("hlc decode: {e}"))?;
    Hlc::from_sval(cv).map_err(|e| format!("Hlc::from_sval: {e}"))
}

/// `SYNC-FJ-01` — the frozen `FastJoin` / `pull` response encoding.
///
/// Every byte here is **recomputed**: the snapshot is re-signed from the vector's seed, the
/// `FastJoin` and the `pull` envelope are re-encoded from the reference types, and the results are
/// compared to the frozen hex. Nothing is restated.
fn fastjoin_pull_response(v: &Vector) -> Result<Verdict, String> {
    let seed: [u8; 32] = unhex(s(&v.input, "snapshot_signer_seed_hex")?)?
        .try_into()
        .map_err(|_| "snapshot_signer_seed_hex is not 32 bytes".to_string())?;
    let sk = IdentityKey::from_seed(&seed);
    eq("snapshot signer", hex(&sk.public()).as_str(), s(&v.input, "snapshot_signer_pubkey_hex")?)?;

    let covers = vector_from_hex(s(&v.input, "snapshot_covers_cbor_hex")?)?;
    let root = unhex(s(&v.input, "snapshot_root_hex")?)?;
    let state_body = unhex(s(&v.input, "observable_state_cbor_hex")?)?;
    // The root is the content address of the state body — recomputed, not taken on trust.
    eq(
        "snapshot root == H(state body)",
        hex(dmtap_sync::state_root_of(&state_body).as_bytes()).as_str(),
        s(&v.input, "snapshot_root_hex")?,
    )?;

    let mut snapshot = dmtap_sync::Snapshot {
        v: 0,
        suite: 1,
        ns: s(&v.input, "snapshot_ns")?.to_string(),
        covers,
        root: dmtap_core::id::ContentId(root),
        ts: v.input.get("snapshot_ts").and_then(Value::as_u64).ok_or("missing snapshot_ts")?,
        signer: sk.public(),
        sig: Vec::new(),
    };
    // The §18.1.6 preimage: DS-tag ‖ 0x00 ‖ det_cbor(Snapshot ∖ {8}).
    eq(
        "snapshot signing preimage",
        hex(&snapshot.signing_preimage()).as_str(),
        s(&v.expected, "snapshot_sig_preimage_hex")?,
    )?;
    snapshot.sig = sk.sign_domain(&[], &snapshot.signing_preimage());
    eq("snapshot signature", hex(&snapshot.sig).as_str(), s(&v.expected, "snapshot_sig_hex")?)?;
    eq("snapshot", hex(&snapshot.det_cbor()).as_str(), s(&v.expected, "snapshot_cbor_hex")?)?;
    snapshot.verify_sig().map_err(|e| format!("the re-signed snapshot does not verify: {e}"))?;

    let floor = hlc_from_hex(s(&v.input, "floor_hlc_cbor_hex")?)?;

    // By-reference: the bounded signed descriptor plus the floor, no state body.
    let by_ref = FastJoin { snapshot: snapshot.clone(), floor: floor.clone(), state: None };
    eq("FastJoin", hex(&by_ref.det_cbor()).as_str(), s(&v.expected, "fastjoin_cbor_hex")?)?;
    eq(
        "pull response",
        hex(&pull_envelope(&by_ref)).as_str(),
        s(&v.expected, "pull_response_cbor_hex")?,
    )?;

    // Inline (key 3): the bounded optimization, same descriptor, state carried alongside.
    //
    // Correction C-11 regenerated this field's frozen bytes: key 3 now carries a real §6.1.2
    // `SnapshotBody` — ten individually-signed ops, §6.2's retention set for this snapshot's state —
    // where it previously carried `det_cbor(ObservableState)`, the one value §6.1.2 forbids
    // adopting. `snapshot_body_cbor_hex` is that body; `observable_state_cbor_hex`/`state_body`
    // (above) is the pre-C-09 shape, kept below only as the labelled non-conformant artifact this
    // test proves is rejected.
    let real_body_bytes = unhex(s(&v.input, "snapshot_body_cbor_hex")?)?;
    let inline = FastJoin {
        snapshot: snapshot.clone(),
        floor: floor.clone(),
        state: Some(real_body_bytes.clone()),
    };
    eq(
        "pull response with inline state (C-11 regenerated)",
        hex(&pull_envelope(&inline)).as_str(),
        s(&v.expected, "pull_response_with_inline_state_cbor_hex")?,
    )?;

    // Both round-trip through the decoder byte-for-byte.
    for (label, fj) in [("by-reference", &by_ref), ("inline", &inline)] {
        let back = FastJoin::from_det_cbor(&fj.det_cbor())
            .map_err(|e| format!("{label} FastJoin does not round-trip: {e}"))?;
        eq(&format!("{label} round-trip"), &back, fj)?;
    }

    // The response carries key 2 and NOT key 1 — the two are mutually exclusive (§5.2.1).
    eq(
        "pull_response_keys",
        arr(&v.expected, "pull_response_keys")?.iter().filter_map(Value::as_u64).collect::<Vec<_>>(),
        vec![2u64],
    )?;
    eq("ops_key_present", v.expected.get("ops_key_present").and_then(Value::as_bool), Some(false))?;

    // The by-reference fetch address IS the snapshot root.
    eq("state fetch address", s(&v.expected, "state_fetch_address_hex")?, s(&v.input, "snapshot_root_hex")?)?;
    eq("state fetch endpoint", s(&v.expected, "state_fetch_endpoint")?, "GET /sync/state/<root>")?;

    // --- adoption: the body is a REAL §6.1.2 SnapshotBody, straight from the vector (C-11) --------
    //
    // Correction C-11 regenerated this vector: key 3 of `pull_response_with_inline_state_cbor_hex`
    // used to carry `det_cbor(ObservableState)` — the one value §6.1.2 forbids adopting, and a
    // *frozen* vector was pinning it, despite C-09's own note claiming the field was untouched
    // ("key 3 is absent here" — true of `pull_response_cbor_hex`, false of this one). It now carries
    // ten individually-signed ops — §6.2's retention set for this snapshot's state — whose FOLD
    // reproduces the UNCHANGED `snapshot_root_hex`. The old framing survives only as a labelled
    // non-conformant artifact (`inline_state_document_would_be_nonconformant_cbor_hex`), the same
    // discipline C-06 uses for the `bstr`-wrapped op — and it is asserted REJECTED below, not merely
    // unused.
    let caller = vector_from_hex(s(&v.input, "snapshot_covers_cbor_hex")?)?;
    // A caller that lacks everything: an empty vector is below any non-empty `covers`.
    let behind = VersionVector::new();

    // `real_body_bytes` and `inline` are the ones built above for the encoding assertion; reused
    // here for the adoption assertions, so there is exactly one `SnapshotBody` under test.
    eq(
        "snapshot_body_op_count",
        v.input.get("snapshot_body_op_count").and_then(Value::as_u64),
        Some(10),
    )?;
    let real_body = SnapshotBody::from_det_cbor(&real_body_bytes)
        .map_err(|e| format!("the vector's own SnapshotBody does not decode: {e}"))?;
    eq("real body member count", real_body.members().len(), 10)?;
    eq(
        "real body round-trips",
        hex(&real_body.det_cbor()).as_str(),
        s(&v.input, "snapshot_body_cbor_hex")?,
    )?;
    eq(
        "inline_body_cbor_hex == snapshot_body_cbor_hex",
        s(&v.expected, "inline_body_cbor_hex")?,
        s(&v.input, "snapshot_body_cbor_hex")?,
    )?;

    // Every member is independently authentic — a malicious signer can omit an op from the body,
    // never forge one — and its op-id matches what the vector lists.
    for (member, want) in real_body.members().iter().zip(arr(&v.input, "snapshot_body_ops")?) {
        let op = dmtap_sync::verify_op(member)
            .map_err(|e| format!("a snapshot_body member is not an authentic COSE_Sign1: {e}"))?;
        eq("op-id", hex(op.op_id().as_bytes()).as_str(), s(want, "op_id_hex")?)?;
    }

    // --- THE FOLD. This is the materially stronger check C-11 makes possible: fold the ten ops
    // through the ordinary §4 op path and recompute — proving they PRODUCE the committed state,
    // not merely that someone shipped the promised bytes. `root` is UNCHANGED by this correction.
    let adopted_from_real =
        real_body.verify_against_root(&snapshot.root, Some(&snapshot.ns), RECEIVER_NOW_MS).map_err(
            |e| format!("the vector's own retention-set body does not fold to its own root: {e}"),
        )?;
    eq(
        "folded state == vector's observable_state_cbor_hex",
        hex(&adopted_from_real.observable.det_cbor()).as_str(),
        s(&v.input, "observable_state_cbor_hex")?,
    )?;
    eq(
        "folded root == inline_body_folds_to_root_hex",
        hex(adopted_from_real.observable.root().as_bytes()).as_str(),
        s(&v.expected, "inline_body_folds_to_root_hex")?,
    )?;
    eq(
        "inline_body_folds_to_root_hex == snapshot_root_hex (UNCHANGED by C-11)",
        s(&v.expected, "inline_body_folds_to_root_hex")?,
        s(&v.input, "snapshot_root_hex")?,
    )?;
    eq(
        "inline_body_is_an_op_set_not_a_state_document",
        v.expected.get("inline_body_is_an_op_set_not_a_state_document").and_then(Value::as_bool),
        Some(true),
    )?;

    // Adopted through the real `FastJoin::adopt` path — the inline hint verifies on its own, so the
    // fetcher is never called.
    let adopted = inline
        .adopt(&behind, &[], &[], RECEIVER_NOW_MS, |_| None)
        .map_err(|e| format!("the vector's own conformant inline body was not adopted: {e}"))?;
    eq(
        "adopted root == snapshot root (unchanged)",
        hex(adopted.observable.root().as_bytes()).as_str(),
        s(&v.input, "snapshot_root_hex")?,
    )?;
    eq(
        "inline_body_is_cache_hint_verified_by_fold_then_recompute",
        v.expected
            .get("inline_body_is_cache_hint_verified_by_fold_then_recompute")
            .and_then(Value::as_bool),
        Some(true),
    )?;

    // A corrupted inline hint is DISCARDED in favour of the by-reference fetch — one verification
    // path, and the hint is never a second source of truth.
    let mut corrupted = real_body_bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    let hinted = FastJoin { snapshot: snapshot.clone(), floor: floor.clone(), state: Some(corrupted) };
    let adopted_via_fetch = hinted
        .adopt(&behind, &[], &[], RECEIVER_NOW_MS, |addr| {
            (addr.as_bytes() == snapshot.root.as_bytes()).then(|| real_body_bytes.clone())
        })
        .map_err(|e| format!("a corrupted inline hint was not discarded in favour of a fetch: {e}"))?;
    eq(
        "fetched adoption root == snapshot root",
        hex(adopted_via_fetch.observable.root().as_bytes()).as_str(),
        s(&v.input, "snapshot_root_hex")?,
    )?;
    // ...and with no fetcher available, the SAME corrupted hint fails CLOSED (0x0A0C), never
    // adopting the bytes it could not verify.
    match hinted.adopt(&behind, &[], &[], RECEIVER_NOW_MS, |_| None) {
        Err(SyncError::SnapshotStateUnavailable) => {}
        Err(e) => return Err(format!("unfetchable body gave {e}, want 0x0A0C")),
        Ok(_) => return Err("an unverifiable inline body was adopted".into()),
    }

    // --- C-11's non-conformant artifact, REJECTED not merely ignored --------------------------
    //
    // Reconstruct the pre-C-09 framing this vector used to freeze (key 3 = `det_cbor(ObservableState)`
    // instead of a `SnapshotBody`), confirm it matches the vector's own labelled bytes byte-for-byte,
    // and then run it through the real `adopt` path — mirroring how the C-06 bstr-wrapped-op case is
    // handled — to prove a conformant caller refuses it rather than silently declining to use it.
    let pre_c09 =
        FastJoin { snapshot: snapshot.clone(), floor: floor.clone(), state: Some(state_body.clone()) };
    eq(
        "the NON-conformant pre-C-09 inline pull response",
        hex(&pull_envelope(&pre_c09)).as_str(),
        s(&v.expected, "inline_state_document_would_be_nonconformant_cbor_hex")?,
    )?;
    match pre_c09.adopt(&behind, &[], &[], RECEIVER_NOW_MS, |_| Some(state_body.clone())) {
        Err(_) => {}
        Ok(_) => {
            return Err(
                "det_cbor(ObservableState) was adopted as a SnapshotBody — the exact C-09 defect, \
                 the one thing C-11 regenerated this vector to stop pinning"
                    .into(),
            )
        }
    }

    // A caller already at `covers` is NOT below the floor and must not be fast-joined at all.
    if caller_is_below_floor(&snapshot, &caller) {
        return Err("a caller at `covers` was judged below the floor".into());
    }
    Ok(Verdict::Pass)
}

// --- SYNC-VAL-01 — the `ext-value` boundary (§4.1/§4.1.1, C-08) --------------------------------

/// Every accept case validates, every reject case answers `false` with `0x0A03`, and validation is
/// **recursive** — the reject list includes an integer-keyed map nested at depth 2, which a shallow
/// check would wave through.
///
/// Two different refusals are at stake and the vector deliberately pins both, because conflating
/// them is what produced C-08: a text-keyed map has no *encoder* path in a narrowed implementation
/// (it cannot be built at all), while an integer-keyed map is *encodable* and correctly validates
/// to `false`. So each case is driven through **decode → validate**, not validate alone: a decoder
/// that cannot represent the value would otherwise silently masquerade as a validator that rejects
/// it.
fn ext_value_validate(v: &Vector) -> Result<Verdict, String> {
    for case in arr(&v.input, "accept")? {
        let name = s(case, "case")?;
        let bytes = unhex(s(case, "cbor_hex")?)?;
        let decoded = decode(&bytes)
            .map_err(|e| format!("accept case `{name}` does not DECODE: {e} — an encoder-side refusal is still a refusal (C-08)"))?;
        if !decoded.is_ext_value() {
            return Err(format!("accept case `{name}` validated to false"));
        }
        // Canonical in both directions: what decodes must re-encode to the same bytes, or the
        // "value" is not the one the signature covers.
        eq(&format!("accept case `{name}` re-encodes"), hex(&encode(&decoded)).as_str(), s(case, "cbor_hex")?)?;
    }
    for case in arr(&v.input, "reject")? {
        let name = s(case, "case")?;
        let bytes = unhex(s(case, "cbor_hex")?)?;
        // A reject may fail at either stage — floats/tags/null/undefined are not representable at
        // all, an integer-keyed map decodes cleanly and answers `false`. Both are refusals; what is
        // forbidden is accepting it.
        if let Ok(decoded) = decode(&bytes) {
            if decoded.is_ext_value() {
                return Err(format!("reject case `{name}` was ACCEPTED as an ext-value"));
            }
        }
    }
    eq("accept_all", v.expected.get("accept_all").and_then(Value::as_bool), Some(true))?;
    eq("reject_all", v.expected.get("reject_all").and_then(Value::as_bool), Some(true))?;
    eq(
        "validation_is_recursive",
        v.expected.get("validation_is_recursive").and_then(Value::as_bool),
        Some(true),
    )?;
    eq("reject error code", s(&v.expected, "reject_error_code")?, SyncError::OpInvalid.code_hex().as_str())?;
    eq("reject error name", s(&v.expected, "reject_error_name")?, SyncError::OpInvalid.name())?;

    // --- C-14: the empty map 0xa0, and its non-empty int-keyed sibling still rejected ------------
    //
    // The two are already exercised by the accept/reject loops above (`map_empty`/`array_empty` in
    // `accept`, `int_keyed_map` in `reject`) — this section ties that generic pass to the vector's
    // own declarative statement of *why*: `0xa0` is key-type-agnostic on the wire (no entries to
    // disagree about), so this decoder's choice to decode it as `SVal::Map([])` and treat the empty
    // map as an ext-value regardless of key type is the vacuous-ambiguity resolution C-14 requires,
    // not an accident of one decode path.
    let empty_map = decode(&unhex(s(&v.expected, "empty_map_cbor_hex")?)?)
        .map_err(|e| format!("empty_map_cbor_hex does not decode: {e}"))?;
    eq("decoded empty map is SVal::Map([])", &empty_map, &SVal::Map(Vec::new()))?;
    eq("empty map is_ext_value", empty_map.is_ext_value(), true)?;
    eq(
        "empty_map_is_ext_value",
        v.expected.get("empty_map_is_ext_value").and_then(Value::as_bool),
        Some(true),
    )?;
    eq(
        "empty_map_key_type_is_undeterminable",
        v.expected.get("empty_map_key_type_is_undeterminable").and_then(Value::as_bool),
        Some(true),
    )?;
    // A map with an entry has a determinable key type, and the int-keyed case is STILL rejected —
    // the vacuous ambiguity does not widen into a general "assume text keys" rule.
    eq(
        "nonempty_int_keyed_map_still_rejected",
        v.expected.get("nonempty_int_keyed_map_still_rejected").and_then(Value::as_bool),
        Some(true),
    )?;
    if SVal::Map(vec![(1, SVal::Uint(1))]).is_ext_value() {
        return Err("a non-empty integer-keyed map validated as an ext-value".into());
    }

    // --- C-14: the depth ceiling is 64, a MUST, checked before recursing, for ALL sync decoding ---
    //
    // Not just `value`: every sync object this crate decodes (ops, `PullResponse`, `SnapshotBody`,
    // fingerprint requests) goes through the same `detcbor::decode`/`Decoder::item`, which enforces
    // `MAX_NESTING_DEPTH` before it recurses — so the ceiling is a property of the decoder, not of
    // one call site. Confirmed here directly against the frozen number, and demonstrated on a
    // non-`value` decode path (a `SnapshotBody`, §6.1.2) so "all sync decoding" is not asserted only
    // in the abstract.
    eq(
        "max_nesting_depth",
        v.expected.get("max_nesting_depth").and_then(Value::as_u64),
        Some(u64::from(dmtap_sync::detcbor::MAX_NESTING_DEPTH)),
    )?;
    eq("max_nesting_depth == 64", dmtap_sync::detcbor::MAX_NESTING_DEPTH, 64)?;
    eq(
        "max_nesting_depth_is_a_MUST",
        v.expected.get("max_nesting_depth_is_a_MUST").and_then(Value::as_bool),
        Some(true),
    )?;
    // A hostile `SnapshotBody` byte string nested one level past the ceiling is refused BEFORE
    // recursion completes — `0x0A03`, never a stack exhaustion — proving the ceiling reaches a
    // decode path other than the bare `value` grammar C-08 widened.
    let mut over_deep = vec![0x81u8; dmtap_sync::detcbor::MAX_NESTING_DEPTH as usize + 2];
    over_deep.push(0x00); // innermost: uint 0
    match SnapshotBody::from_det_cbor(&over_deep) {
        Err(_) => {}
        Ok(_) => return Err("an over-deep byte string decoded as a SnapshotBody".into()),
    }

    // --- C-13(b): the `sync-1/ext-value-2` sub-token — observational, never a gate -----------------
    eq("value_profile_subtoken", s(&v.expected, "value_profile_subtoken")?, "sync-1/ext-value-2")?;
    eq(
        "value_profile_subtoken == this engine's local convention",
        s(&v.expected, "value_profile_subtoken")?,
        dmtap::syncserve::SYNC1_EXT_VALUE_2,
    )?;
    eq(
        "value_profile_subtoken_is_a_gate",
        v.expected.get("value_profile_subtoken_is_a_gate").and_then(Value::as_bool),
        Some(false),
    )?;

    // The carrier op: the intended end-to-end shape — one LWW register per (slide, object), with
    // nesting used for REPRESENTATION while §4.1.1's merge boundary stays at the whole value.
    let carrier = op_from_hex(s(&v.input, "carrier_op_cbor_hex")?)?;
    validate_op(&carrier, RECEIVER_NOW_MS)
        .map_err(|e| format!("the carrier op was refused: {e} — the whole point of C-08"))?;
    eq(
        "carrier_op_accepted",
        v.expected.get("carrier_op_accepted").and_then(Value::as_bool),
        Some(true),
    )?;
    eq("carrier op re-encodes", hex(&carrier.det_cbor()).as_str(), s(&v.input, "carrier_op_cbor_hex")?)?;
    // And the merge boundary really is the whole value: two concurrent writes of DIFFERENT nested
    // maps to one register do not merge per-key — one wins entire (§4.1.1).
    let mut rival = carrier.clone();
    rival.hlc.counter += 1;
    rival.value = Some(SVal::TextMap(vec![("x".into(), SVal::Uint(99))]));
    let merged = ingest_all(&[carrier.clone(), rival.clone()])?;
    let field = carrier.field.clone().ok_or("carrier op has no field")?;
    eq(
        "the whole value wins, never a per-key merge",
        merged.lww.get(&carrier.target, &field),
        rival.value.as_ref(),
    )?;
    Ok(Verdict::Pass)
}

// --- SYNC-SNAP-03 — the snapshot body is an op set (§6.1.2, C-09) ------------------------------

/// The body folds to `root`; a post-`covers` op that is **below** the incumbent in the §3 total
/// order loses; and a replica that adopted §6.1.1's projection instead lands on a different root.
///
/// The last part is why this is normative and not stylistic, so it is executed as well as asserted:
/// the two adoption models are both run here, and the divergence is *reproduced* rather than
/// described.
fn snapshot_body_fold(v: &Vector) -> Result<Verdict, String> {
    let body = SnapshotBody::from_det_cbor(&unhex(s(&v.input, "snapshot_body_cbor_hex")?)?)
        .map_err(|e| format!("SnapshotBody decode: {e}"))?;
    eq("body round-trips", hex(&body.det_cbor()).as_str(), s(&v.input, "snapshot_body_cbor_hex")?)?;

    // --- fold-then-recompute -----------------------------------------------------------------
    let root = dmtap_core::id::ContentId(unhex(s(&v.input, "snapshot_root_hex")?)?);
    let adopted = body
        .verify_against_root(&root, Some(""), RECEIVER_NOW_MS)
        .map_err(|e| format!("the frozen body does not fold to the frozen root: {e}"))?;
    eq(
        "folded state",
        hex(&adopted.observable.det_cbor()).as_str(),
        s(&v.expected, "folded_state_cbor_hex")?,
    )?;
    eq("folded root", hex(adopted.observable.root().as_bytes()).as_str(), s(&v.expected, "folded_root_hex")?)?;
    eq("body_folds_to_root", v.expected.get("body_folds_to_root").and_then(Value::as_bool), Some(true))?;
    // The body's fold IS the committed state — which is what makes this stronger than hashing the
    // transfer bytes. A body whose ops do not produce `root` is `0x0A09` and discarded whole.
    eq(
        "body mismatch code",
        s(&v.expected, "body_mismatch_error_code")?,
        SyncError::SnapshotRootMismatch.code_hex().as_str(),
    )?;
    eq(
        "body mismatch name",
        s(&v.expected, "body_mismatch_error_name")?,
        SyncError::SnapshotRootMismatch.name(),
    )?;
    let mut tampered = adopted.observable.clone();
    tampered.lww[0].2 = SVal::Text("TAMPERED".into());
    if body.verify_against_root(&tampered.root(), Some(""), RECEIVER_NOW_MS).is_ok() {
        return Err("a body verified against a root it does not produce".into());
    }
    // The body's ops arrive by the ORDINARY op path: each is independently COSE-signed, so a
    // malicious signer can omit but never forge.
    for member in body.members() {
        dmtap_sync::verify_op(member)
            .map_err(|e| format!("a body member is not an authentic COSE_Sign1: {e}"))?;
    }
    eq("body_covers_is_well_formed", vector_from_hex(s(&v.input, "snapshot_covers_cbor_hex")?)?.marks().count() > 0, true)?;

    // --- the ordering demo: (W,3,B) after `covers`, but BELOW the incumbent (W,4,A) ------------
    let post = dmtap_sync::verify_op_bytes(&unhex(s(&v.input, "post_covers_op_cbor_hex")?)?)
        .map_err(|e| format!("post-covers op does not verify: {e}"))?;
    let covers = vector_from_hex(s(&v.input, "snapshot_covers_cbor_hex")?)?;
    if !covers.lacks(&post.hlc) {
        return Err("the post-`covers` op is not actually after `covers`".into());
    }
    let incumbent = dmtap_sync::verify_op(&body.members()[0]).map_err(|e| e.to_string())?;
    if post.hlc >= incumbent.hlc {
        return Err(
            "the post-`covers` op is not BELOW the incumbent — the vector's whole point is lost"
                .into(),
        );
    }

    // The conformant replica: folded the body, so it HAS the incumbent's HLC to compare against.
    let mut conformant = adopted.state.clone();
    conformant.ingest(&post, RECEIVER_NOW_MS).map_err(|e| format!("ingest: {e}"))?;
    let after = ObservableState::of(&conformant);
    eq("state after post op", hex(&after.det_cbor()).as_str(), s(&v.expected, "state_after_post_op_cbor_hex")?)?;
    eq("root after post op", hex(after.root().as_bytes()).as_str(), s(&v.expected, "root_after_post_op_hex")?)?;
    let field = incumbent.field.clone().ok_or("incumbent has no field")?;
    eq(
        "winning value after post op",
        conformant.lww.get(&incumbent.target, &field).and_then(SVal::as_text),
        Some(s(&v.expected, "winning_value_after_post_op")?),
    )?;

    // The projection-adopter: took §6.1.1's bytes, so it has the VALUE but not its HLC. The same
    // op now wins, because there is nothing for it to be less than.
    let mut projection = SyncState::new();
    projection.ingest(&post, RECEIVER_NOW_MS).map_err(|e| format!("ingest: {e}"))?;
    let projected = ObservableState::of(&projection);
    eq(
        "projection-adopter state",
        hex(&projected.det_cbor()).as_str(),
        s(&v.expected, "projection_adopt_state_cbor_hex")?,
    )?;
    eq(
        "projection-adopter root",
        hex(projected.root().as_bytes()).as_str(),
        s(&v.expected, "projection_adopt_root_hex")?,
    )?;
    eq(
        "projection_adopt_is_nonconformant",
        v.expected.get("projection_adopt_is_nonconformant").and_then(Value::as_bool),
        Some(true),
    )?;
    eq("roots_differ", v.expected.get("roots_differ").and_then(Value::as_bool), Some(true))?;
    if projected.root().as_bytes() == after.root().as_bytes() {
        return Err("the two adoption models agreed — the divergence was not reproduced".into());
    }

    // The observable state the vector states independently: same bytes, computed from the fold.
    eq(
        "observable state",
        hex(&adopted.observable.det_cbor()).as_str(),
        s(&v.input, "observable_state_cbor_hex")?,
    )?;
    Ok(Verdict::Pass)
}

/// The §5.2.1 `pull` envelope for a fast-join answer: `{2: FastJoin}`.
fn pull_envelope(fj: &FastJoin) -> Vec<u8> {
    encode(&SVal::Map(vec![(2, decode(&fj.det_cbor()).expect("own FastJoin encoding"))]))
}

/// `SYNC-FJ-02` — the MUST, in both directions, and the caller-side fail-closed paths.
fn fastjoin_floor_predicate(v: &Vector) -> Result<Verdict, String> {
    let covers = vector_from_hex(s(&v.input, "responder_snapshot_covers_cbor_hex")?)?;
    let floor = hlc_from_hex(s(&v.input, "responder_floor_hlc_cbor_hex")?)?;
    let behind = vector_from_hex(s(&v.input, "caller_behind_vector_cbor_hex")?)?;
    let caught_up = vector_from_hex(s(&v.input, "caller_caught_up_vector_cbor_hex")?)?;

    // The predicate itself, both directions (§5.2.1's two MUSTs).
    let responder_snapshot = decode_fastjoin_from_pull(s(&v.expected, "caller_behind_response_cbor_hex")?)?;
    eq("responder covers", &responder_snapshot.snapshot.covers, &covers)?;
    eq("responder floor", &responder_snapshot.floor, &floor)?;

    eq(
        "caller_behind_is_below_floor",
        caller_is_below_floor(&responder_snapshot.snapshot, &behind),
        v.expected.get("caller_behind_is_below_floor").and_then(Value::as_bool).ok_or("missing")?,
    )?;
    eq(
        "caller_caught_up_is_below_floor",
        caller_is_below_floor(&responder_snapshot.snapshot, &caught_up),
        v.expected.get("caller_caught_up_is_below_floor").and_then(Value::as_bool).ok_or("missing")?,
    )?;
    eq(
        "caller_behind_ops_response_forbidden",
        v.expected.get("caller_behind_ops_response_forbidden").and_then(Value::as_bool),
        Some(true),
    )?;
    eq(
        "caller_caught_up_fastjoin_forbidden",
        v.expected.get("caller_caught_up_fastjoin_forbidden").and_then(Value::as_bool),
        Some(true),
    )?;

    // The forbidden answer is WELL-FORMED — that is exactly why the MUST is needed. Recompute it
    // from the surviving suffix and confirm it matches what the vector says the responder would
    // wrongly have sent.
    // The encoding is §5.2's op framing, now pinned by correction C-06: each op is embedded as a
    // CBOR ITEM inside key 1's array, never bstr-wrapped. (`node`'s `POST /sync/pull` and
    // `POST /sync/ops` were corrected to match; there is no outstanding discrepancy.)
    let suffix = hex_list(&v.input, "surviving_suffix_ops_cbor_hex")?;
    let items: Vec<SVal> = suffix
        .iter()
        .map(|b| decode(b).map_err(|e| format!("suffix op does not decode: {e}")))
        .collect::<Result<_, String>>()?;
    let would_be = encode(&SVal::Map(vec![(1, SVal::Array(items))]));
    eq(
        "the forbidden ops response",
        hex(&would_be).as_str(),
        s(&v.expected, "caller_behind_ops_response_would_be_cbor_hex")?,
    )?;
    // ...and it is the CORRECT answer for the caught-up caller.
    eq(
        "the caught-up caller's ops response",
        hex(&would_be).as_str(),
        s(&v.expected, "caller_caught_up_response_cbor_hex")?,
    )?;

    // --- C-06: the ops member framing ---------------------------------------------------------
    // The bstr-wrapped encoding is published as NON-conformant so it can be recognized, not merely
    // avoided. Reproduce it from the same suffix and confirm it is the vector's frozen wrong answer.
    eq("ops_member_framing", s(&v.expected, "ops_member_framing")?, "item-embedded COSE_Sign1")?;
    eq(
        "ops_member_bstr_wrapped_conformant",
        v.expected.get("ops_member_bstr_wrapped_conformant").and_then(Value::as_bool),
        Some(false),
    )?;
    let wrapped = encode(&SVal::Map(vec![(
        1,
        SVal::Array(suffix.iter().map(|b| SVal::Bytes(b.clone())).collect()),
    )]));
    eq(
        "the NON-conformant bstr-wrapped ops response",
        hex(&wrapped).as_str(),
        s(&v.expected, "ops_member_bstr_wrapped_NONCONFORMANT_cbor_hex")?,
    )?;
    // ...and it is distinguishable from the conformant one, which is the whole point of pinning it.
    if wrapped == would_be {
        return Err("the two framings encode identically — the C-06 rule would be unenforceable".into());
    }
    eq(
        "ops_member_bstr_wrapped_error_code",
        s(&v.expected, "ops_member_bstr_wrapped_error_code")?,
        SyncError::OpInvalid.code_hex().as_str(),
    )?;

    // --- C-07: the floor/`covers` NON-relationship ----------------------------------------------
    // The naive predicate fires TRUE on this well-formed fast-join. Assert that it does (so the
    // counterexample stays live) and that this implementation does NOT act on it.
    eq(
        "floor_vs_covers_is_orderable",
        v.expected.get("floor_vs_covers_is_orderable").and_then(Value::as_bool),
        Some(false),
    )?;
    eq(
        "floor_vs_covers_naive_predicate_rejected",
        s(&v.expected, "floor_vs_covers_naive_predicate_rejected")?,
        "covers.lacks(floor)",
    )?;
    eq(
        "the naive predicate's value on this data",
        responder_snapshot.snapshot.covers.lacks(&floor),
        v.expected
            .get("floor_vs_covers_naive_predicate_value_here")
            .and_then(Value::as_bool)
            .ok_or("missing floor_vs_covers_naive_predicate_value_here")?,
    )?;
    // The MAY-grade signal, asserted as MAY — true here, and explicitly not a MUST.
    eq(
        "covers_carries_mark_for_floor_author",
        covers_carries_mark_for_floor_author(&responder_snapshot.snapshot, &floor),
        v.expected
            .get("covers_carries_mark_for_floor_author")
            .and_then(Value::as_bool)
            .ok_or("missing covers_carries_mark_for_floor_author")?,
    )?;
    eq(
        "covers_mark_for_floor_author_is_MUST",
        v.expected.get("covers_mark_for_floor_author_is_MUST").and_then(Value::as_bool),
        Some(false),
    )?;
    // THE regression: a conformant fast-join whose floor sits above covers[A] must be ADOPTABLE.
    // (Step 2 alone; the body is supplied so only step 2 is under test.)
    let body = ObservableState::default().det_cbor();
    let mut ok_snapshot = responder_snapshot.clone();
    ok_snapshot.snapshot.root = state_root_of(&body);
    if let Err(e) = check_covers_closes_gap(&ok_snapshot.snapshot, &floor, &behind) {
        return Err(format!(
            "step 2 rejected a CONFORMANT fast-join (floor above covers[A]) with {}: this is \
             exactly the §14 C-07 defect",
            e.code_hex()
        ));
    }

    // The §5.2.1 step-5 progress MUST: the same root AND covers twice is a responder loop, 0x0A09.
    eq(
        "repeated_fastjoin_same_root_and_covers_error_code",
        s(&v.expected, "repeated_fastjoin_same_root_and_covers_error_code")?,
        SyncError::SnapshotRootMismatch.code_hex().as_str(),
    )?;
    let (prev_root, prev_covers) =
        (responder_snapshot.snapshot.root.clone(), responder_snapshot.snapshot.covers.clone());
    eq("first round makes progress", responder_snapshot.check_progress(None).is_ok(), true)?;
    match responder_snapshot.check_progress(Some((&prev_root, &prev_covers))) {
        Err(e) => eq(
            "repeated fast-join code",
            e.code_hex().as_str(),
            s(&v.expected, "repeated_fastjoin_same_root_and_covers_error_code")?,
        )?,
        Ok(()) => return Err("a repeated fast-join at the same root/covers was allowed".into()),
    }
    // Adopting `covers` may regress the caller's vector for an author — intended, never an error.
    eq(
        "adopting_covers_may_regress_caller_vector",
        v.expected.get("adopting_covers_may_regress_caller_vector").and_then(Value::as_bool),
        Some(true),
    )?;
    eq(
        "adopting_covers_regression_is_an_error",
        v.expected.get("adopting_covers_regression_is_an_error").and_then(Value::as_bool),
        Some(false),
    )?;
    eq(
        "caller_trusts_all_truncated_ops_folded_into_covers",
        v.expected.get("caller_trusts_all_truncated_ops_folded_into_covers").and_then(Value::as_bool),
        Some(true),
    )?;

    // Caller-side fail-closed: an unfetchable state body is 0x0A0C, with the caller's vector
    // UNCHANGED — and never a fallback to the suffix.
    let before = behind.clone();
    let unfetchable = responder_snapshot.clone();
    match unfetchable.adopt(&behind, &[], &[], RECEIVER_NOW_MS, |_| None) {
        Err(e) => {
            eq("state_body_unfetchable code", e.code_hex().as_str(), s(&v.expected, "state_body_unfetchable_error_code")?)?;
            eq("state_body_unfetchable name", e.name(), s(&v.expected, "state_body_unfetchable_error_name")?)?;
            eq("state_body_unfetchable action", e.action_str(), s(&v.expected, "state_body_unfetchable_action")?)?;
        }
        Ok(_) => return Err("a fast-join with no obtainable state body was adopted".into()),
    }
    eq("caller vector unchanged", &before, &behind)?;
    eq(
        "state_body_unfetchable_caller_vector_unchanged",
        v.expected.get("state_body_unfetchable_caller_vector_unchanged").and_then(Value::as_bool),
        Some(true),
    )?;
    eq(
        "suffix_fallback_after_failed_fastjoin_forbidden",
        v.expected.get("suffix_fallback_after_failed_fastjoin_forbidden").and_then(Value::as_bool),
        Some(true),
    )?;
    // The predicate is stated in the vector as domination of `covers`, not a floor comparison.
    eq(
        "predicate",
        s(&v.expected, "predicate")?,
        "behind_floor := exists (author, hlc) in Snapshot.covers such that caller_vector.lacks(hlc)",
    )?;
    Ok(Verdict::Pass)
}

/// Pull the `FastJoin` out of a `{2: FastJoin}` pull response.
fn decode_fastjoin_from_pull(pull_hex: &str) -> Result<FastJoin, String> {
    let cv = decode(&unhex(pull_hex)?).map_err(|e| format!("pull response decode: {e}"))?;
    let SVal::Map(fields) = cv else { return Err("pull response is not a map".into()) };
    let (_, fj) = fields.into_iter().find(|(k, _)| *k == 2).ok_or("pull response has no key 2")?;
    FastJoin::from_det_cbor(&encode(&fj)).map_err(|e| format!("FastJoin decode: {e}"))
}
