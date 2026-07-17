#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_clustersync::crdt::{validate_op, ClusterState};
use dmtap_clustersync::wire::{
    AddTag, ClusterOp, ClusterSyncFrame, DeleteClass, Hlc, OP_LWW_SET, OP_SET_ADD, OP_SET_REMOVE,
};
use dmtap_core::cbor::Cv;

// Clustersync ClusterOp / ClusterSyncFrame decode + the §5.6.4 CRDT merge, driven by arbitrary bytes.
// Two surfaces in one target:
//
//  1. **Decode** — the raw bytes are fed straight to `ClusterSyncFrame::from_det_cbor`; any decoded
//     op is run through `validate_op`. Neither may panic on any input (fail-closed on garbage).
//
//  2. **Merge convergence (the D3 / OR-Set + DeathReg core property)** — a set of well-formed ops is
//     generated FROM the same bytes, then applied/merged in several different orders (forward,
//     reverse, per-op singleton fold, and an interleaved merge). Because the OR-Set, the per-field
//     LWW register, and the remove-wins death register are all CvRDTs, every ordering MUST converge
//     to a **byte-identical** snapshot — and a durable delete must never be resurrected by a
//     concurrent add regardless of schedule. A divergent snapshot (or a panic) is a real bug.
fuzz_target!(|data: &[u8]| {
    // ── Surface 1: decode arbitrary bytes, validate any ops, never panic. ───────────────────────
    if let Ok(frame) = ClusterSyncFrame::from_det_cbor(data) {
        for op in &frame.ops {
            let _ = validate_op(op, u64::MAX / 2);
        }
    }

    // ── Surface 2: generate well-formed ops from the bytes and test merge convergence. ──────────
    let ops = gen_ops(data);
    if ops.is_empty() {
        return;
    }

    // Every generated op is well-formed (fail-closed check never panics; kept ops are valid).
    for op in &ops {
        // A generous receiver clock so no op is rejected purely for skew.
        let _ = validate_op(op, u64::MAX / 2);
    }

    // (a) Apply the whole set to a fresh state, forward order.
    let fwd = state_of(ops.iter());
    // (b) Apply the same set in reverse order.
    let rev = state_of(ops.iter().rev());
    // (c) Merge per-op singleton states (each op applied to its own fresh state, then joined).
    let mut folded = ClusterState::new();
    for op in &ops {
        let mut single = ClusterState::new();
        single.apply(op);
        folded.merge(&single);
    }
    // (d) Split the ops in two halves, build each state, and merge the halves (both directions).
    let mid = ops.len() / 2;
    let left = state_of(ops[..mid].iter());
    let right = state_of(ops[mid..].iter());
    let mut lr = left.clone();
    lr.merge(&right);
    let mut rl = right.clone();
    rl.merge(&left);

    // All five constructions are the SAME join over the SAME op set ⇒ byte-identical snapshots.
    let s = fwd.snapshot();
    assert_eq!(s, rev.snapshot(), "reverse-order apply must converge (commutativity)");
    assert_eq!(s, folded.snapshot(), "singleton-merge fold must converge");
    assert_eq!(s, lr.snapshot(), "half-merge (L∨R) must converge (associativity)");
    assert_eq!(s, rl.snapshot(), "half-merge (R∨L) must converge (commutativity)");

    // Idempotence: merging a state with itself changes nothing (join(x,x) = x).
    let mut again = fwd.clone();
    again.merge(&fwd);
    assert_eq!(s, again.snapshot(), "merge(x, x) must equal x (idempotence)");

    // D3 invariant: any object bearing a durable death certificate is NEVER reported present, in any
    // of the converged states — a concurrent OR-Set add can never resurrect a durable delete.
    for op in &ops {
        if op.kind == dmtap_clustersync::wire::OP_DELETE
            && op.field.as_deref().map(DeleteClass::from_token).unwrap_or(None).is_some()
        {
            // The object was durably deleted by *some* op; whether THIS certificate is the winner
            // depends on HLCs, but if the converged death state is Deleted it must dominate presence.
            if fwd.is_deleted(&op.target) {
                assert!(
                    !fwd.is_present(&op.target),
                    "a durably-deleted object must never be present (remove-wins, D3)"
                );
                assert!(!fwd.present_elements().contains(&op.target));
            }
        }
    }
});

/// Apply an op sequence to a fresh state.
fn state_of<'a>(ops: impl Iterator<Item = &'a ClusterOp>) -> ClusterState {
    let mut s = ClusterState::new();
    for op in ops {
        s.apply(op);
    }
    s
}

/// Deterministically turn arbitrary bytes into a bounded list of WELL-FORMED cluster ops. A small
/// target alphabet ("o0".."o3") and device set (0..3) forces genuine concurrency/collisions across
/// ops so the CRDT merge is actually exercised rather than every op touching a distinct object.
fn gen_ops(data: &[u8]) -> Vec<ClusterOp> {
    const MAX_OPS: usize = 48;
    let mut ops = Vec::new();
    let mut it = data.iter().copied();
    while ops.len() < MAX_OPS {
        let Some(sel) = it.next() else { break };
        let target = format!("o{}", (it.next().unwrap_or(0) % 4));
        let wall = u64::from(it.next().unwrap_or(0)); // 0..=255 — dense collisions in HLC space
        let counter = u32::from(it.next().unwrap_or(0) % 4);
        let device = vec![it.next().unwrap_or(0) % 3];
        let hlc = Hlc { wall, counter, device: device.clone() };
        let op = match sel % 5 {
            0 => ClusterOp {
                kind: OP_SET_ADD,
                target,
                field: None,
                value: None,
                hlc,
                observed: None,
            },
            1 => {
                // A remove observing a causally-valid tag (its hlc ≤ the remove's hlc).
                let obs_wall = wall.saturating_sub(u64::from(it.next().unwrap_or(0) % 8));
                let obs = AddTag {
                    device: vec![it.next().unwrap_or(0) % 3],
                    hlc: Hlc { wall: obs_wall, counter: 0, device: vec![it.next().unwrap_or(0) % 3] },
                };
                ClusterOp {
                    kind: OP_SET_REMOVE,
                    target,
                    field: None,
                    value: None,
                    hlc,
                    observed: Some(vec![obs]),
                }
            }
            2 => ClusterOp {
                kind: OP_LWW_SET,
                target,
                field: Some(format!("f{}", it.next().unwrap_or(0) % 3)),
                value: Some(Cv::U64(u64::from(it.next().unwrap_or(0)))),
                hlc,
                observed: None,
            },
            3 => {
                let class = match it.next().unwrap_or(0) % 3 {
                    0 => DeleteClass::Redact,
                    1 => DeleteClass::Expires,
                    _ => DeleteClass::Sensitive,
                };
                ClusterOp::durable_delete(target, class, hlc)
            }
            _ => ClusterOp::undelete(target, hlc),
        };
        ops.push(op);
    }
    ops
}
