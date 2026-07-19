//! The **native** half of the cross-surface parity proof (`substrate/BINDINGS.md` §4).
//!
//! This test drives the frozen `sync_vectors.json` through `dmtap-sync` directly — no
//! `wasm-bindgen`, no JS, no marshalling layer — and records the same named outputs that
//! `test/trace.mjs` records by calling the WASM binding from JavaScript. The result is committed as
//! `test/native-trace.json`, and both surfaces assert against it:
//!
//! * this test fails if native Rust stops reproducing the committed trace,
//! * `test/vectors.test.mjs` fails if the WASM build stops reproducing it.
//!
//! Between them, "the browser computes what the server computes" is a test, not a claim. If the two
//! ever disagree, that is a **bug in the binding**, because there is exactly one implementation of
//! the algebra for it to disagree with — never a reason to relax an assertion here.
//!
//! Regenerate after a deliberate, reviewed change:
//!
//! ```text
//! UPDATE_SYNC_TRACE=1 cargo test -p dmtap-sync-wasm --test native_trace
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use dmtap_core::identity::IdentityKey;
use dmtap_sync::detcbor::{decode, encode, SVal};
use dmtap_sync::snapshot::ObservableState;
use dmtap_sync::state::SyncState;
use dmtap_sync::wire::{AddTag, Hlc, SyncOp};
use dmtap_sync::state::VersionVector;
use dmtap_sync::{cose, FastJoin, OpEntry, SyncError};
use serde_json::{json, Value};

/// Same receiver clock as the native conformance runner and the JS harness (§3).
const RECEIVER_NOW_MS: u64 = 1_700_000_900_000;

type Case = BTreeMap<String, String>;

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../dmtap/conformance/vectors/sync_vectors.json")
}

fn trace_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test/native-trace.json")
}

// --- small helpers -------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The refusal spelling both surfaces record: `code name action`.
fn refusal(e: SyncError) -> String {
    format!("{} {} {}", e.code_hex(), e.name(), e.action_str())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing string `{k}`"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v.get(k).and_then(Value::as_array).unwrap_or_else(|| panic!("missing array `{k}`"))
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    arr(v, k).iter().map(|e| e.as_str().unwrap_or_default().to_owned()).collect()
}

fn hlc_of(v: &Value) -> Hlc {
    Hlc {
        wall: v.get("wall").and_then(Value::as_u64).expect("hlc.wall"),
        counter: v.get("counter").and_then(Value::as_u64).expect("hlc.counter") as u32,
        author: unhex(s(v, "author_hex")),
    }
}

fn op_of(h: &str) -> SyncOp {
    SyncOp::from_det_cbor(&unhex(h)).expect("vector op does not decode")
}

fn ingest(ops: &[SyncOp]) -> SyncState {
    let mut st = SyncState::new();
    for op in ops {
        st.ingest(op, RECEIVER_NOW_MS).expect("vector op was refused by ingest");
    }
    st
}

fn ops_of(v: &Value, k: &str) -> Vec<SyncOp> {
    strs(v, k).iter().map(|h| op_of(h)).collect()
}

fn text_of(v: &SVal) -> String {
    v.as_text().unwrap_or_default().to_owned()
}

/// `deleted:class` / `live` — the same label the JS harness records.
fn death_label(st: &SyncState, object: &str) -> String {
    match st.deaths.state(object).class() {
        Some(c) => format!("deleted:{}", c.token()),
        None => "live".into(),
    }
}

/// `author:P:N` per entry, joined.
fn counter_label(st: &SyncState, target: &str, field: &str) -> String {
    st.counters
        .entries(target, field)
        .iter()
        .map(|(a, (p, n))| format!("{}:{p}:{n}", hex(a)))
        .collect::<Vec<_>>()
        .join(",")
}

/// The state built from a JSON observable-state projection whose values are bare strings, exactly
/// as the vectors spell them.
fn observable_of(v: &Value) -> ObservableState {
    let mut st = ObservableState::default();
    for e in arr(v, "orset") {
        let t = e.as_array().unwrap();
        st.orset.push((t[0].as_str().unwrap().into(), SVal::Text(t[1].as_str().unwrap().into())));
    }
    for e in arr(v, "lww") {
        let t = e.as_array().unwrap();
        st.lww.push((
            t[0].as_str().unwrap().into(),
            t[1].as_str().unwrap().into(),
            SVal::Text(t[2].as_str().unwrap().into()),
        ));
    }
    for e in arr(v, "pn") {
        let t = e.as_array().unwrap();
        st.pn.push((
            t[0].as_str().unwrap().into(),
            t[1].as_str().unwrap().into(),
            t[2].as_i64().unwrap() as i128,
        ));
    }
    for e in arr(v, "death") {
        let t = e.as_array().unwrap();
        st.death.push((t[0].as_str().unwrap().into(), t[1].as_str().unwrap().into()));
    }
    for e in arr(v, "rga") {
        let t = e.as_array().unwrap();
        st.rga.push((
            t[0].as_str().unwrap().into(),
            t[1].as_array().unwrap().iter().map(|a| SVal::Text(a.as_str().unwrap().into())).collect(),
        ));
    }
    for e in arr(v, "tree") {
        let t = e.as_array().unwrap();
        st.tree.push((
            t[0].as_str().unwrap().into(),
            t[1].as_str().unwrap().into(),
            t[2].as_str().unwrap().into(),
        ));
    }
    st
}

/// Rebuild a typed `ObservableState` from canonical bytes (what a fast-joining replica adopts).
fn observable_from_cbor(bytes: &[u8]) -> ObservableState {
    let v = decode(bytes).expect("state body is not canonical CBOR");
    let sections = v.as_array().expect("state is an array").to_vec();
    assert_eq!(sections.len(), 6, "an observable state is exactly six sections (§6.1.1)");
    let rows = |i: usize| sections[i].as_array().unwrap_or(&[]).to_vec();
    let mut st = ObservableState::default();
    for e in rows(0) {
        let t = e.as_array().unwrap().to_vec();
        st.orset.push((text_of(&t[0]), t[1].clone()));
    }
    for e in rows(1) {
        let t = e.as_array().unwrap().to_vec();
        st.lww.push((text_of(&t[0]), text_of(&t[1]), t[2].clone()));
    }
    for e in rows(2) {
        let t = e.as_array().unwrap().to_vec();
        st.pn.push((text_of(&t[0]), text_of(&t[1]), t[2].as_int().unwrap() as i128));
    }
    for e in rows(3) {
        let t = e.as_array().unwrap().to_vec();
        st.death.push((text_of(&t[0]), text_of(&t[1])));
    }
    for e in rows(4) {
        let t = e.as_array().unwrap().to_vec();
        st.rga.push((text_of(&t[0]), t[1].as_array().unwrap().to_vec()));
    }
    for e in rows(5) {
        let t = e.as_array().unwrap().to_vec();
        st.tree.push((text_of(&t[0]), text_of(&t[1]), text_of(&t[2])));
    }
    st
}

// --- the executors, mirroring `test/trace.mjs` ---------------------------------------------------

fn sync_op_encode(v: &Value) -> Case {
    let input = &v["input"];
    let op = SyncOp {
        kind: input["kind"].as_u64().unwrap() as u8,
        ns: s(input, "ns").into(),
        target: s(input, "target").into(),
        field: input.get("field").and_then(Value::as_str).map(str::to_owned),
        value: input.get("value_tstr").and_then(Value::as_str).map(|t| SVal::Text(t.into())),
        hlc: hlc_of(&input["hlc"]),
        observed: None,
        reference: None,
    };
    let built = op.det_cbor();
    let reencoded = SyncOp::from_det_cbor(&built).unwrap().det_cbor();
    // The same non-canonical respelling the JS harness builds: `kind` 3 in a two-byte head.
    let mut bad = built.clone();
    bad.splice(2..3, [0x18, 0x03]);
    bad[0] = 0xa6;
    let noncanonical = SyncOp::from_det_cbor(&bad).expect_err("non-canonical op accepted");
    Case::from([
        ("op_cbor".into(), hex(&built)),
        ("op_id".into(), hex(dmtap_sync::op_id_of(&built).as_bytes())),
        ("reencoded".into(), hex(&reencoded)),
        ("noncanonical".into(), refusal(noncanonical)),
    ])
}

fn sync_op_cose_sign1_verify(v: &Value) -> Case {
    let input = &v["input"];
    let seed: [u8; 32] = unhex(s(input, "signer_seed_hex")).try_into().unwrap();
    let sk = IdentityKey::from_seed(&seed);
    let op = op_of(s(input, "sync_op_cbor_hex"));
    let signed = cose::sign_op(&sk, &op).expect("sign_op");

    let tampered = cose::verify_op_bytes(&unhex(s(input, "tampered_payload_cose_sign1_hex")))
        .expect_err("a tampered payload verified");
    let substituted = cose::verify_op_bytes(&unhex(s(input, "substituted_kid_cose_sign1_hex")))
        .expect_err("a substituted kid verified");
    // The DS-tag negative: sign the same payload under the SNAPSHOT tag and offer it to the op
    // verifier.
    let foreign_preimage =
        cose::sig_structure(&signed.protected, b"DMTAP-SYNC-v0/snapshot\x00", &signed.payload);
    let forged = cose::CoseSign1 {
        protected: signed.protected.clone(),
        payload: signed.payload.clone(),
        signature: sk.sign_domain(&[], &foreign_preimage),
    };
    let foreign = cose::verify_op(&forged).expect_err("a foreign-DS-tag envelope verified");

    Case::from([
        ("author".into(), hex(&op.hlc.author)),
        ("protected_bstr".into(), hex(&encode(&SVal::Bytes(signed.protected.clone())))),
        ("unprotected".into(), hex(&encode(&SVal::Map(Vec::new())))),
        ("payload_bstr".into(), hex(&encode(&SVal::Bytes(signed.payload.clone())))),
        ("external_aad".into(), hex(&cose::op_external_aad())),
        ("sig_structure".into(), hex(&signed.signable())),
        ("signature".into(), hex(&signed.signature)),
        ("cose".into(), hex(&signed.to_bytes())),
        ("op_id".into(), hex(op.op_id().as_bytes())),
        (
            "verified_op".into(),
            hex(&cose::verify_op_bytes(&unhex(s(input, "cose_sign1_hex")))
                .expect("the committed envelope failed to verify")
                .det_cbor()),
        ),
        ("tampered".into(), refusal(tampered)),
        ("substituted_kid".into(), refusal(substituted)),
        ("foreign_ds_tag".into(), refusal(foreign)),
    ])
}

fn sync_author_admission(v: &Value) -> Case {
    let input = &v["input"];
    let admitted: Vec<Vec<u8>> = strs(input, "admitted_authors_hex").iter().map(|h| unhex(h)).collect();
    let author = unhex(s(input, "op_hlc_author_hex"));
    let mut case = Case::from([
        (
            "refusal".into(),
            refusal(dmtap_sync::check_admitted(&author, &admitted).expect_err("unadmitted accepted")),
        ),
        ("op_author".into(), hex(&op_of(s(input, "op_cbor_hex")).hlc.author)),
    ]);
    for (i, a) in admitted.iter().enumerate() {
        dmtap_sync::check_admitted(a, &admitted).expect("an admitted author was refused");
        case.insert(format!("admitted_{i}_ok"), "true".into());
    }
    case
}

fn sync_lww_merge(v: &Value) -> Case {
    let ops = ops_of(&v["input"], "ops_cbor_hex");
    let target = ops[0].target.clone();
    let field = ops[0].field.clone().expect("LWW op without a field");
    let fwd = ingest(&ops);
    let rev = ingest(&ops.iter().rev().cloned().collect::<Vec<_>>());
    let cell = |st: &SyncState| {
        let (h, val) = st.lww.cell(&target, &field).expect("no winning cell").clone();
        (hex(&h.det_cbor()), hex(&val.det_cbor()), text_of(&val))
    };
    let (fh, fv, ft) = cell(&fwd);
    let (rh, rv, _) = cell(&rev);
    Case::from([
        ("winner_hlc".into(), fh),
        ("winner_value".into(), fv),
        ("winner_value_text".into(), ft),
        ("reverse_winner_hlc".into(), rh),
        ("reverse_winner_value".into(), rv),
        ("forward_root".into(), hex(dmtap_sync::state_root(&fwd).as_bytes())),
        ("reverse_root".into(), hex(dmtap_sync::state_root(&rev).as_bytes())),
    ])
}

fn sync_orset_merge(v: &Value) -> Case {
    let input = &v["input"];
    let ops = ops_of(input, "ops_cbor_hex");
    let target = ops[0].target.clone();
    let element = SVal::Text(s(input, "element").into());
    let fwd = ingest(&ops);
    let rev = ingest(&ops.iter().rev().cloned().collect::<Vec<_>>());
    let tags = fwd.orset.surviving_tags(&target, &element);
    Case::from([
        ("present_forward".into(), fwd.is_present(&target, &element).to_string()),
        ("present_reverse".into(), rev.is_present(&target, &element).to_string()),
        ("surviving_count".into(), tags.len().to_string()),
        (
            "surviving_hlc".into(),
            tags.first().map(|t| hex(&t.hlc.det_cbor())).unwrap_or_default(),
        ),
        (
            "members".into(),
            fwd.present_members()
                .iter()
                .map(|(t, val)| format!("{t}={}", hex(&val.det_cbor())))
                .collect::<Vec<_>>()
                .join(","),
        ),
    ])
}

fn sync_orset_remove_validity(v: &Value) -> Case {
    let op = op_of(s(&v["input"], "op_cbor_hex"));
    let validate = dmtap_sync::validate_op(&op, RECEIVER_NOW_MS).expect_err("impossible op accepted");
    let ingest_err = SyncState::new()
        .ingest(&op, RECEIVER_NOW_MS)
        .expect_err("ingest accepted an op the validator refused");
    Case::from([("validate".into(), refusal(validate)), ("ingest".into(), refusal(ingest_err))])
}

fn sync_death_domination(v: &Value) -> Case {
    let input = &v["input"];
    let death = op_of(s(input, "death_op_cbor_hex"));
    let add = op_of(s(input, "concurrent_add_op_cbor_hex"));
    let target = death.target.clone();
    let element = add.value.clone().expect("set-add without a value");
    Case::from([
        (
            "present_death_first".into(),
            ingest(&[death.clone(), add.clone()]).is_present(&target, &element).to_string(),
        ),
        (
            "present_add_first".into(),
            ingest(&[add.clone(), death.clone()]).is_present(&target, &element).to_string(),
        ),
        ("add_outranks_death".into(), (add.hlc > death.hlc).to_string()),
    ])
}

fn sync_death_tie(v: &Value) -> Case {
    let input = &v["input"];
    let death = op_of(s(input, "death_op_cbor_hex"));
    let live = op_of(s(input, "live_op_cbor_hex"));
    let target = death.target.clone();
    Case::from([
        (
            "state_death_first".into(),
            death_label(&ingest(&[death.clone(), live.clone()]), &target),
        ),
        ("state_live_first".into(), death_label(&ingest(&[live, death.clone()]), &target)),
        ("hlcs_tie".into(), (death.hlc == op_of(s(input, "live_op_cbor_hex")).hlc).to_string()),
    ])
}

fn sync_pn_merge(v: &Value) -> Case {
    let ops = ops_of(&v["input"], "ops_cbor_hex");
    let target = ops[0].target.clone();
    let field = ops[0].field.clone().expect("counter op without a field");
    let all = ingest(&ops);
    let distinct = ingest(&ops[..2]);
    let replayed = ingest(&[ops[0].clone(), ops[1].clone(), ops[0].clone()]);
    let ids: std::collections::BTreeSet<String> =
        ops.iter().map(|o| hex(o.op_id().as_bytes())).collect();
    Case::from([
        ("entries".into(), counter_label(&all, &target, &field)),
        ("total".into(), all.counters.total(&target, &field).to_string()),
        ("distinct_total".into(), distinct.counters.total(&target, &field).to_string()),
        ("replay_total".into(), replayed.counters.total(&target, &field).to_string()),
        ("replay_entries".into(), counter_label(&replayed, &target, &field)),
        ("distinct_op_ids".into(), ids.len().to_string()),
    ])
}

fn sync_counter_foreign_check(v: &Value) -> Case {
    let input = &v["input"];
    let op_author = unhex(s(input, "op_hlc_author_hex"));
    let entry_author = unhex(s(input, "target_entry_author_hex"));
    Case::from([
        (
            "refusal".into(),
            refusal(
                dmtap_sync::check_counter_entry(&op_author, &entry_author)
                    .expect_err("a foreign entry mutation was accepted"),
            ),
        ),
        (
            "own_entry_ok".into(),
            dmtap_sync::check_counter_entry(&op_author, &op_author).is_ok().to_string(),
        ),
    ])
}

fn sync_rga_sibling_order(v: &Value) -> Case {
    let input = &v["input"];
    let origin = op_of(s(input, "origin_op_cbor_hex"));
    let siblings = ops_of(input, "sibling_ops_cbor_hex");
    let target = origin.target.clone();
    let run = |sibs: Vec<SyncOp>| {
        let mut ops = vec![origin.clone()];
        ops.extend(sibs);
        let st = ingest(&ops);
        let seq = st.sequences.get(&target).expect("no sequence built");
        (
            seq.values().iter().map(text_of).collect::<Vec<_>>().join(","),
            seq.order().iter().map(|id| hex(&id.det_cbor())).collect::<Vec<_>>().join(","),
        )
    };
    let (vf, idf) = run(siblings.clone());
    let (vr, idr) = run(siblings.iter().rev().cloned().collect());
    Case::from([
        ("values_forward".into(), vf),
        ("ids_forward".into(), idf),
        ("values_reverse".into(), vr),
        ("ids_reverse".into(), idr),
    ])
}

fn sync_rga_tombstone_origin(v: &Value) -> Case {
    let input = &v["input"];
    let insert_x = op_of(s(input, "insert_x_cbor_hex"));
    let remove_x = op_of(s(input, "remove_x_cbor_hex"));
    let insert_y = op_of(s(input, "insert_y_cbor_hex"));
    let target = insert_x.target.clone();
    let st = ingest(&[insert_x, remove_x, insert_y.clone()]);
    let seq = st.sequences.get(&target).expect("no sequence built");
    Case::from([
        ("visible".into(), seq.values().iter().map(text_of).collect::<Vec<_>>().join(",")),
        (
            "labels".into(),
            seq.order()
                .iter()
                .map(|id| {
                    let text = seq.atom_value(id).map(text_of).unwrap_or_default();
                    if seq.is_tombstoned(id) {
                        format!("{text}(tombstoned)")
                    } else {
                        text
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("resolves".into(), seq.has(&insert_y.hlc).to_string()),
    ])
}

fn sync_tree_move_replay(v: &Value) -> Case {
    let input = &v["input"];
    let mut ops = ops_of(input, "baseline_ops_cbor_hex");
    let colliding = ops_of(input, "colliding_ops_cbor_hex");
    ops.extend(colliding.clone());
    let (h1, h2) = (colliding[0].hlc.clone(), colliding[1].hlc.clone());
    let mut case = Case::from([("h1_before_h2".into(), (h1 < h2).to_string())]);
    let orders: Vec<Vec<SyncOp>> = vec![
        ops.clone(),
        ops.iter().rev().cloned().collect(),
        vec![ops[3].clone(), ops[2].clone(), ops[0].clone(), ops[1].clone()],
    ];
    for (i, order) in orders.iter().enumerate() {
        let replay = ingest(order).tree.replay();
        case.insert(
            format!("edges_{i}"),
            replay
                .edges
                .iter()
                .map(|(n, (p, o))| format!("{n}>{p}:{o}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        case.insert(
            format!("skipped_{i}"),
            replay
                .skipped
                .iter()
                .map(|(h, _)| if *h == h1 { "h1" } else if *h == h2 { "h2" } else { "?" })
                .collect::<Vec<_>>()
                .join(","),
        );
        // Acyclicity, checked rather than assumed — same walk as the JS harness.
        for node in replay.edges.keys() {
            let mut cur = node.clone();
            let mut steps = 0;
            while let Some((parent, _)) = replay.edges.get(&cur) {
                cur = parent.clone();
                steps += 1;
                assert!(steps <= replay.edges.len(), "cycle reachable from `{node}`");
            }
        }
        case.insert(format!("acyclic_{i}"), "true".into());
    }
    case
}

fn sync_snapshot_state_root(v: &Value) -> Case {
    let st = observable_of(&v["input"]["observable_state"]);
    let cbor = st.det_cbor();
    let empty = ObservableState::default();
    let mut shuffled = st.clone();
    shuffled.tree.reverse();
    shuffled.lww.reverse();
    let mut diverged = st.clone();
    diverged.lww[0].2 = SVal::Text("DIVERGED".into());
    Case::from([
        ("state_cbor".into(), hex(&cbor)),
        ("root".into(), hex(st.root().as_bytes())),
        ("empty_cbor".into(), hex(&empty.det_cbor())),
        ("empty_root".into(), hex(empty.root().as_bytes())),
        ("shuffled_cbor".into(), hex(&shuffled.det_cbor())),
        ("diverged_root".into(), hex(diverged.root().as_bytes())),
        ("roundtrip_cbor".into(), hex(&observable_from_cbor(&cbor).det_cbor())),
    ])
}

fn sync_snapshot_fast_join(v: &Value) -> Case {
    let input = &v["input"];
    let body = unhex(s(input, "snapshot_observable_state_cbor_hex"));
    let mut joined = observable_from_cbor(&body);
    for op in ops_of(input, "post_covers_ops_cbor_hex") {
        let field = op.field.clone().expect("post-covers op without a field");
        let value = op.value.clone().expect("post-covers op without a value");
        match joined.lww.iter_mut().find(|(t, f, _)| *t == op.target && *f == field) {
            Some(cell) => cell.2 = value,
            None => joined.lww.push((op.target.clone(), field, value)),
        }
    }
    let joined_cbor = joined.det_cbor();
    Case::from([
        (
            "snapshot_root_recomputed".into(),
            hex(dmtap_sync::ds_hash(dmtap_sync::DS_SNAPSHOT_STATE, &body).as_bytes()),
        ),
        ("fast_join_state".into(), hex(&joined_cbor)),
        ("root".into(), hex(joined.root().as_bytes())),
    ])
}

fn sync_recon_fingerprint(v: &Value) -> Case {
    let input = &v["input"];
    let mut case = Case::new();
    let mut entries: BTreeMap<String, OpEntry> = BTreeMap::new();
    for (label, h) in input["ops_cbor_hex"].as_object().expect("ops map") {
        let op = op_of(h.as_str().unwrap());
        let id = op.op_id();
        case.insert(format!("op_id_{label}"), hex(id.as_bytes()));
        entries.insert(label.clone(), OpEntry { hlc: op.hlc.clone(), id });
    }
    let holds = |key: &str| -> Vec<OpEntry> {
        strs(input, key).iter().map(|l| entries[l].clone()).collect()
    };
    let (a_set, b_set) = (holds("replica_A_holds"), holds("replica_B_holds"));
    let lo = hlc_of(&input["range"]["lo"]);
    let hi = hlc_of(&input["range"]["hi"]);
    let split = hlc_of(&input["split_at"]);
    for (name, set) in [("A", &a_set), ("B", &b_set)] {
        for (range, l, h) in
            [("full", &lo, &hi), ("sub1", &lo, &split), ("sub2", &split, &hi)]
        {
            let fp = dmtap_sync::summarize(set, l, h);
            case.insert(format!("{range}_{name}_fp"), hex(fp.fp.as_bytes()));
            case.insert(format!("{range}_{name}_count"), fp.count.to_string());
        }
    }
    let (efp, ecount) = dmtap_sync::fingerprint(&[]);
    case.insert("empty_fp".into(), hex(efp.as_bytes()));
    case.insert("empty_count".into(), ecount.to_string());
    let outcome = dmtap_sync::reconcile(&b_set, &a_set, &lo, &hi, Default::default());
    case.insert(
        "shipped_to_B".into(),
        outcome.missing_here.iter().map(|i| hex(i.as_bytes())).collect::<Vec<_>>().join(","),
    );
    case.insert(
        "shipped_to_A".into(),
        outcome.missing_there.iter().map(|i| hex(i.as_bytes())).collect::<Vec<_>>().join(","),
    );
    case
}

fn sync_ns_sparse_filter(v: &Value) -> Case {
    let input = &v["input"];
    let ops = ops_of(input, "responder_ops_cbor_hex");
    let subs = strs(input, "caller_subscribed_ns");
    let shipped = dmtap_sync::scope_to_subscription(&ops, &subs);
    Case::from([
        (
            "shipped".into(),
            shipped.iter().map(|op| hex(&op.det_cbor())).collect::<Vec<_>>().join(","),
        ),
        ("shipped_ns".into(), shipped.iter().map(|op| op.ns.clone()).collect::<Vec<_>>().join(",")),
    ])
}

fn sync_ns_leak_check(v: &Value) -> Case {
    let input = &v["input"];
    let op = op_of(s(input, "op_cbor_hex"));
    let referenced = s(input, "ref_target_actual_ns");
    Case::from([
        ("op_ns".into(), op.ns.clone()),
        (
            "ref_target".into(),
            op.reference.as_ref().expect("op carries no reference").target.clone(),
        ),
        (
            "refusal".into(),
            refusal(
                dmtap_sync::check_ns_ref(&op.ns, referenced)
                    .expect_err("a cross-namespace reference was accepted"),
            ),
        ),
        ("same_ns_ok".into(), dmtap_sync::check_ns_ref(&op.ns, &op.ns).is_ok().to_string()),
    ])
}

fn sync_gc_stability_cut(v: &Value) -> Case {
    let input = &v["input"];
    let live: Vec<Option<Hlc>> = arr(input, "live_replica_watermarks")
        .iter()
        .map(|e| Some(hlc_of(&e["max_applied_hlc"])))
        .collect();
    let cut = dmtap_sync::stability_cut(&live).expect("no cut from two live watermarks");
    let stale = hlc_of(&input["stale_replica_watermark"]["max_applied_hlc"]);
    let mut with_stale = live.clone();
    with_stale.push(Some(stale));
    let would_be = dmtap_sync::stability_cut(&with_stale).expect("no cut");
    let mut unknown = live.clone();
    unknown.push(None);

    // The same collapsed add/tombstone pair the JS harness builds, through real ops.
    let author = cut.author.clone();
    let add_hlc = Hlc { wall: cut.wall, counter: 1, author: author.clone() };
    let element = SVal::Text("e1".into());
    let add = SyncOp {
        kind: dmtap_sync::OP_SET_ADD,
        ns: String::new(),
        target: "tags".into(),
        field: None,
        value: Some(element.clone()),
        hlc: add_hlc.clone(),
        observed: None,
        reference: None,
    };
    let remove = SyncOp {
        kind: dmtap_sync::OP_SET_REMOVE,
        ns: String::new(),
        target: "tags".into(),
        field: None,
        value: Some(element),
        hlc: Hlc { wall: cut.wall, counter: 2, author: author.clone() },
        observed: Some(vec![AddTag { author, hlc: add_hlc }]),
        reference: None,
    };
    let mut st = ingest(&[add, remove]);
    let before = hex(&ObservableState::of(&st).det_cbor());
    let pruned = st.orset.prune_stable(&cut);

    Case::from([
        ("cut".into(), hex(&cut.det_cbor())),
        ("cut_counter".into(), cut.counter.to_string()),
        ("with_stale".into(), hex(&would_be.det_cbor())),
        ("stale_drags_cut_down".into(), (would_be < cut).to_string()),
        (
            "unknown_watermark_cut".into(),
            match dmtap_sync::stability_cut(&unknown) {
                Some(_) => "NOT NULL — a cut was computed with an unknown watermark".into(),
                None => "null".into(),
            },
        ),
        ("pruned_something".into(), (pruned > 0).to_string()),
        ("state_before_gc".into(), before),
        ("state_after_gc".into(), hex(&ObservableState::of(&st).det_cbor())),
    ])
}

// --- §5.2.1 fast-join ---------------------------------------------------------------------------

fn vector_of(h: &str) -> VersionVector {
    VersionVector::from_sval(decode(&unhex(h)).expect("vector CBOR")).expect("VersionVector")
}

fn hlc_of_hex(h: &str) -> Hlc {
    Hlc::from_sval(decode(&unhex(h)).expect("hlc CBOR")).expect("Hlc")
}

/// `{2: FastJoin}` — the §5.2.1 pull envelope.
fn pull_envelope(fj: &FastJoin) -> Vec<u8> {
    encode(&SVal::Map(vec![(2, decode(&fj.det_cbor()).expect("own FastJoin encoding"))]))
}

fn sync_fastjoin_pull_response(v: &Value) -> Case {
    let i = &v["input"];
    let seed: [u8; 32] = unhex(s(i, "snapshot_signer_seed_hex")).try_into().unwrap();
    let sk = IdentityKey::from_seed(&seed);
    let body = unhex(s(i, "observable_state_cbor_hex"));

    let mut snapshot = dmtap_sync::Snapshot {
        v: 0,
        suite: 1,
        ns: s(i, "snapshot_ns").to_owned(),
        covers: vector_of(s(i, "snapshot_covers_cbor_hex")),
        root: dmtap_core::id::ContentId(unhex(s(i, "snapshot_root_hex"))),
        ts: i["snapshot_ts"].as_u64().expect("snapshot_ts"),
        signer: sk.public(),
        sig: Vec::new(),
    };
    let preimage = snapshot.signing_preimage();
    snapshot.sig = sk.sign_domain(&[], &preimage);
    let floor = hlc_of_hex(s(i, "floor_hlc_cbor_hex"));

    let by_ref = FastJoin { snapshot: snapshot.clone(), floor: floor.clone(), state: None };
    let inline =
        FastJoin { snapshot: snapshot.clone(), floor: floor.clone(), state: Some(body.clone()) };

    // The corrupted inline hint: discarded in favour of a fetch, never adopted.
    let mut corrupt = body.clone();
    corrupt[3] ^= 0xff;
    let hinted = FastJoin { snapshot: snapshot.clone(), floor, state: Some(corrupt) };
    let empty = VersionVector::new();
    let adopted = hinted
        .adopt(&empty, &[], &[], |_| Some(body.clone()))
        .expect("a corrupted inline hint must fall back to the fetched body");

    Case::from([
        ("snapshot_preimage".into(), hex(&preimage)),
        ("snapshot_sig".into(), hex(&snapshot.sig)),
        ("snapshot_cbor".into(), hex(&snapshot.det_cbor())),
        ("state_root".into(), hex(dmtap_sync::state_root_of(&body).as_bytes())),
        ("fastjoin_cbor".into(), hex(&by_ref.det_cbor())),
        ("pull_cbor".into(), hex(&pull_envelope(&by_ref))),
        ("pull_inline_cbor".into(), hex(&pull_envelope(&inline))),
        (
            "fastjoin_roundtrip".into(),
            hex(&FastJoin::from_det_cbor(&by_ref.det_cbor()).expect("round-trip").det_cbor()),
        ),
        ("state_address".into(), hex(snapshot.root.as_bytes())),
        ("adopted_state".into(), hex(&adopted.det_cbor())),
        (
            "corrupt_hint_unfetchable".into(),
            refusal(hinted.adopt(&empty, &[], &[], |_| None).expect_err("adopted unverified bytes")),
        ),
        (
            "caller_at_covers_below_floor".into(),
            dmtap_sync::caller_is_below_floor(
                &snapshot,
                &vector_of(s(i, "snapshot_covers_cbor_hex")),
            )
            .to_string(),
        ),
    ])
}

fn sync_fastjoin_floor_predicate(v: &Value) -> Case {
    let i = &v["input"];
    // The responder's FastJoin, taken from the frozen pull response.
    let pull = decode(&unhex(s(&v["expected"], "caller_behind_response_cbor_hex"))).expect("pull");
    let SVal::Map(fields) = pull else { panic!("pull response is not a map") };
    let (_, fj_sval) = fields.into_iter().find(|(k, _)| *k == 2).expect("key 2");
    let fj = FastJoin::from_det_cbor(&encode(&fj_sval)).expect("FastJoin decodes");

    let behind = vector_of(s(i, "caller_behind_vector_cbor_hex"));
    let caught_up = vector_of(s(i, "caller_caught_up_vector_cbor_hex"));
    let floor = hlc_of_hex(s(i, "responder_floor_hlc_cbor_hex"));

    // The forbidden answer, recomputed — well-formed, which is exactly why the MUST exists. Each op
    // is embedded as a CBOR ITEM, as the vector freezes it.
    let items: Vec<SVal> =
        strs(i, "surviving_suffix_ops_cbor_hex").iter().map(|h| decode(&unhex(h)).unwrap()).collect();
    let would_be = encode(&SVal::Map(vec![(1, SVal::Array(items))]));

    let gap_fj = FastJoin {
        snapshot: dmtap_sync::Snapshot::from_det_cbor(&unhex(s(i, "snapshot_not_covering_gap_cbor_hex")))
            .expect("snapshot decodes"),
        floor,
        state: None,
    };

    Case::from([
        (
            "behind_is_below_floor".into(),
            dmtap_sync::caller_is_below_floor(&fj.snapshot, &behind).to_string(),
        ),
        (
            "caught_up_is_below_floor".into(),
            dmtap_sync::caller_is_below_floor(&fj.snapshot, &caught_up).to_string(),
        ),
        ("ops_response_would_be".into(), hex(&would_be)),
        (
            "fastjoin_roundtrip".into(),
            hex(&FastJoin { snapshot: fj.snapshot.clone(), floor: fj.floor.clone(), state: None }
                .det_cbor()),
        ),
        (
            "gap_not_closed".into(),
            refusal(
                gap_fj
                    .adopt(&behind, &[], &[], |_| Some(Vec::new()))
                    .expect_err("a snapshot that does not close the gap was adopted"),
            ),
        ),
        (
            "state_unavailable".into(),
            refusal(
                fj.adopt(&behind, &[], &[], |_| None)
                    .expect_err("a fast-join with no obtainable body was adopted"),
            ),
        ),
        (
            "caught_up_refuses_fastjoin".into(),
            refusal(
                fj.adopt(&caught_up, &[], &[], |_| None)
                    .expect_err("a caught-up caller was fast-joined"),
            ),
        ),
    ])
}

/// Operations deliberately not traced. MUST match `NOT_COVERED` in `test/trace.mjs`. Empty: both
/// surfaces drive all 22 vectors, including the §5.2.1 fast-join path.
const NOT_COVERED: [&str; 0] = [];

fn execute(operation: &str, v: &Value) -> Option<Case> {
    Some(match operation {
        "sync_op_encode" => sync_op_encode(v),
        "sync_op_cose_sign1_verify" => sync_op_cose_sign1_verify(v),
        "sync_author_admission" => sync_author_admission(v),
        "sync_lww_merge" => sync_lww_merge(v),
        "sync_orset_merge" => sync_orset_merge(v),
        "sync_orset_remove_validity" => sync_orset_remove_validity(v),
        "sync_death_domination" => sync_death_domination(v),
        "sync_death_tie" => sync_death_tie(v),
        "sync_pn_merge" => sync_pn_merge(v),
        "sync_counter_foreign_check" => sync_counter_foreign_check(v),
        "sync_rga_sibling_order" => sync_rga_sibling_order(v),
        "sync_rga_tombstone_origin" => sync_rga_tombstone_origin(v),
        "sync_tree_move_replay" => sync_tree_move_replay(v),
        "sync_snapshot_state_root" => sync_snapshot_state_root(v),
        "sync_snapshot_fast_join" => sync_snapshot_fast_join(v),
        "sync_recon_fingerprint" => sync_recon_fingerprint(v),
        "sync_ns_sparse_filter" => sync_ns_sparse_filter(v),
        "sync_ns_leak_check" => sync_ns_leak_check(v),
        "sync_gc_stability_cut" => sync_gc_stability_cut(v),
        "sync_fastjoin_pull_response" => sync_fastjoin_pull_response(v),
        "sync_fastjoin_floor_predicate" => sync_fastjoin_floor_predicate(v),
        other if NOT_COVERED.contains(&other) => return None,
        other => panic!(
            "no native executor for sync operation `{other}` — a new vector must be driven \
             through BOTH surfaces or named in NOT_COVERED with a reason"
        ),
    })
}

#[test]
fn native_trace_matches_the_committed_artifact() {
    let vp = vectors_path();
    assert!(
        vp.exists(),
        "the frozen vectors are missing at {}. This test IS the native half of the cross-surface \
         proof; it must never be skipped because the sibling spec repo is not checked out.",
        vp.display()
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&vp).unwrap()).unwrap();

    let mut trace = serde_json::Map::new();
    for v in file["vectors"].as_array().expect("vectors array") {
        let name = s(v, "name").to_owned();
        if let Some(case) = execute(s(v, "operation"), v) {
            trace.insert(name, json!(case));
        }
    }
    assert!(trace.len() >= 22, "only {} vectors driven natively", trace.len());

    let document = json!({
        "note": "Recorded by `cargo test -p dmtap-sync-wasm --test native_trace` from dmtap-sync \
                 directly (no wasm, no JS). `test/vectors.test.mjs` asserts the WASM binding \
                 reproduces every value here byte-for-byte — see substrate/BINDINGS.md §4.",
        "receiver_now_ms": RECEIVER_NOW_MS,
        "vectors_sha_note": "traces the frozen sync_vectors.json in the sibling dmtap repo",
        "trace": trace,
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&document).unwrap());

    let tp = trace_path();
    if std::env::var("UPDATE_SYNC_TRACE").is_ok() {
        std::fs::write(&tp, &rendered).expect("write trace");
        eprintln!("wrote {}", tp.display());
        return;
    }
    let committed = std::fs::read_to_string(&tp).unwrap_or_else(|_| {
        panic!(
            "{} is missing. Regenerate with:\n  UPDATE_SYNC_TRACE=1 cargo test -p dmtap-sync-wasm \
             --test native_trace",
            tp.display()
        )
    });
    assert_eq!(
        committed, rendered,
        "the native engine no longer reproduces the committed parity trace. Either dmtap-sync's \
         behavior changed (in which case the WASM binding and every other surface change with it, \
         deliberately) or this is a regression. Do not regenerate without understanding which."
    );
}
