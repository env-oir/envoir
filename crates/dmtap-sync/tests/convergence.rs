//! **The convergence property tests** (`SYNC.md` §2.2): any two replicas that have applied the
//! same set of ops compute the **same bytes**.
//!
//! The property under test is stated at the level that actually matters — the §6.1.1
//! `ObservableState` encoding — because that is what a `Snapshot.root` commits to and what two
//! independent implementations must agree on. Internal bookkeeping (add-tags, per-author `P`/`N`
//! maps, RGA element ids, superseded cells) is deliberately *not* compared: it may legitimately
//! differ between a fast-joined and a fully-replayed replica.
//!
//! Three algebraic laws are exercised over pseudo-random op sets spanning **all six** CRDT types:
//!
//! * **commutativity** — every permutation of an op set yields identical bytes;
//! * **idempotence** — re-applying ops already applied changes nothing;
//! * **associativity** — merging partial states in any grouping yields identical bytes.
//!
//! The generator is a fixed-seed LCG, so a failure is reproducible from the seed printed in the
//! assertion rather than being a flaky one-off.

use dmtap_sync::{
    snapshot::ObservableState, state::SyncState, AddTag, Hlc, OpRef, SVal, SyncOp, OP_COUNTER,
    OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT, OP_SEQ_REMOVE, OP_SET_ADD, OP_SET_REMOVE, OP_TREE_MOVE,
};

const NOW: u64 = 1_700_000_900_000;
const WALL: u64 = 1_700_000_100_000;

/// A tiny deterministic LCG — reproducible op sets with no dev-dependency on a PRNG crate.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn author(i: usize) -> Vec<u8> {
    vec![0xa0 + i as u8; 32]
}

fn hlc(counter: u32, a: usize) -> Hlc {
    Hlc { wall: WALL, counter, author: author(a) }
}

/// Build a pseudo-random but **valid** op set covering all six CRDT types, with deliberate
/// concurrency: several authors, interleaved counters, colliding tree moves, same-origin RGA
/// inserts, and a death certificate racing a later `set-add`.
fn generate(seed: u64, n: usize) -> Vec<SyncOp> {
    let mut rng = Lcg(seed);
    let mut ops = Vec::new();
    let targets = ["t1", "t2", "t3"];
    let nodes = ["A", "B", "C"];
    // A shared RGA head so later inserts have a real origin to race over.
    let head = hlc(0, 0);
    ops.push(SyncOp {
        kind: OP_SEQ_INSERT,
        ns: String::new(),
        target: "line".into(),
        field: None,
        value: Some(SVal::Text("head".into())),
        hlc: head.clone(),
        observed: None,
        reference: None,
    });
    for i in 1..n {
        let a = rng.pick(3);
        let h = hlc(i as u32, a);
        let target = targets[rng.pick(targets.len())].to_string();
        let op = match rng.pick(8) {
            0 => SyncOp {
                kind: OP_SET_ADD,
                ns: String::new(),
                target,
                field: None,
                value: Some(SVal::Text(format!("e{}", rng.pick(4)))),
                hlc: h,
                observed: None,
                reference: None,
            },
            1 => SyncOp {
                kind: OP_SET_REMOVE,
                ns: String::new(),
                target,
                field: None,
                value: Some(SVal::Text(format!("e{}", rng.pick(4)))),
                // Cites an add-tag strictly in the past, so the §4.3 causal check passes.
                observed: Some(vec![AddTag {
                    author: author(a),
                    hlc: hlc((i as u32).saturating_sub(1), a),
                }]),
                hlc: h,
                reference: None,
            },
            2 => SyncOp {
                kind: OP_LWW_SET,
                ns: String::new(),
                target,
                field: Some(format!("f{}", rng.pick(2))),
                value: Some(SVal::Text(format!("v{}", rng.pick(5)))),
                hlc: h,
                observed: None,
                reference: None,
            },
            3 => SyncOp {
                kind: OP_DEATH,
                ns: String::new(),
                target,
                field: Some(
                    ["redact", "expires", "sensitive", "live"][rng.pick(4)].to_string(),
                ),
                value: None,
                hlc: h,
                observed: None,
                reference: None,
            },
            4 => SyncOp {
                kind: OP_COUNTER,
                ns: String::new(),
                target,
                field: Some("qty".into()),
                value: Some(SVal::int(rng.pick(11) as i64 - 5)),
                hlc: h,
                observed: None,
                reference: None,
            },
            5 => SyncOp {
                kind: OP_SEQ_INSERT,
                ns: String::new(),
                target: "line".into(),
                field: None,
                value: Some(SVal::Text(format!("a{i}"))),
                hlc: h,
                observed: None,
                reference: Some(OpRef { target: "line".into(), hlc: Some(head.clone()) }),
            },
            6 => SyncOp {
                kind: OP_SEQ_REMOVE,
                ns: String::new(),
                target: "line".into(),
                field: None,
                value: None,
                hlc: h,
                observed: None,
                reference: Some(OpRef {
                    target: "line".into(),
                    hlc: Some(hlc(rng.pick(i.max(1)) as u32, rng.pick(3))),
                }),
            },
            _ => {
                let node = rng.pick(nodes.len());
                let mut parent = rng.pick(nodes.len() + 1);
                if parent == node {
                    parent = nodes.len(); // the root sentinel; a self-parent is not a valid op
                }
                SyncOp {
                    kind: OP_TREE_MOVE,
                    ns: String::new(),
                    target: nodes[node].into(),
                    field: Some(format!("o{}", rng.pick(3))),
                    value: None,
                    hlc: h,
                    observed: None,
                    reference: Some(OpRef {
                        target: nodes.get(parent).copied().unwrap_or("").into(),
                        hlc: None,
                    }),
                }
            }
        };
        ops.push(op);
    }
    ops
}

fn apply_all(ops: &[&SyncOp]) -> SyncState {
    let mut s = SyncState::new();
    for op in ops {
        s.ingest(op, NOW).expect("generated ops must be valid");
    }
    s
}

fn observable(s: &SyncState) -> Vec<u8> {
    ObservableState::of(s).det_cbor()
}

/// Deterministically shuffle with the same LCG, so a failing permutation is reproducible.
fn shuffled<'a>(ops: &'a [SyncOp], seed: u64) -> Vec<&'a SyncOp> {
    let mut rng = Lcg(seed);
    let mut v: Vec<&SyncOp> = ops.iter().collect();
    for i in (1..v.len()).rev() {
        v.swap(i, rng.pick(i + 1));
    }
    v
}

#[test]
fn commutative_every_apply_order_yields_identical_observable_bytes() {
    for seed in 1..=12u64 {
        let ops = generate(seed, 40);
        let reference = observable(&apply_all(&ops.iter().collect::<Vec<_>>()));
        for perm in 0..8u64 {
            let got = observable(&apply_all(&shuffled(&ops, seed * 1000 + perm)));
            assert_eq!(
                got, reference,
                "apply order changed the observable state (seed {seed}, perm {perm})"
            );
        }
    }
}

#[test]
fn idempotent_reapplying_the_same_ops_changes_nothing() {
    for seed in 1..=12u64 {
        let ops = generate(seed, 40);
        let refs: Vec<&SyncOp> = ops.iter().collect();
        let once = apply_all(&refs);
        let mut twice = apply_all(&refs);
        for op in &refs {
            twice.ingest(op, NOW).unwrap();
        }
        assert_eq!(observable(&twice), observable(&once), "replay must be a no-op (seed {seed})");
    }
}

#[test]
fn associative_any_grouping_of_partial_states_merges_to_the_same_bytes() {
    for seed in 1..=12u64 {
        let ops = generate(seed, 45);
        let all: Vec<&SyncOp> = ops.iter().collect();
        let reference = observable(&apply_all(&all));
        let third = all.len() / 3;
        let (a, b, c) = (&all[..third], &all[third..2 * third], &all[2 * third..]);

        // (A ∪ B) ∪ C
        let mut left = apply_all(a);
        left.merge(&apply_all(b));
        left.merge(&apply_all(c));

        // A ∪ (B ∪ C)
        let mut bc = apply_all(b);
        bc.merge(&apply_all(c));
        let mut right = apply_all(a);
        right.merge(&bc);

        assert_eq!(observable(&left), reference, "(A∪B)∪C diverged (seed {seed})");
        assert_eq!(observable(&right), reference, "A∪(B∪C) diverged (seed {seed})");
    }
}

#[test]
fn merge_is_commutative_between_two_replicas() {
    for seed in 1..=12u64 {
        let ops = generate(seed, 40);
        let all: Vec<&SyncOp> = ops.iter().collect();
        let half = all.len() / 2;
        let mut x = apply_all(&all[..half]);
        let y = apply_all(&all[half..]);
        let mut y2 = y.clone();
        x.merge(&y);
        y2.merge(&apply_all(&all[..half]));
        assert_eq!(observable(&x), observable(&y2), "X∪Y ≠ Y∪X (seed {seed})");
    }
}

#[test]
fn snapshot_roots_agree_wherever_observable_bytes_agree() {
    // The root is a pure function of the observable bytes, so agreement must be exact — this is
    // the property `SYNC-SNAP-01` pins across replicas.
    for seed in 1..=6u64 {
        let ops = generate(seed, 30);
        let a = apply_all(&ops.iter().collect::<Vec<_>>());
        let b = apply_all(&shuffled(&ops, seed));
        assert_eq!(
            dmtap_sync::state_root(&a).as_bytes(),
            dmtap_sync::state_root(&b).as_bytes()
        );
    }
}

#[test]
fn the_tree_is_always_acyclic_however_the_moves_arrive() {
    for seed in 1..=12u64 {
        let ops = generate(seed, 40);
        let s = apply_all(&shuffled(&ops, seed));
        let edges = s.tree.edges();
        for node in edges.keys() {
            // Walk to the root; a cycle would loop past the edge count.
            let mut cur = node.clone();
            for _ in 0..=edges.len() {
                match edges.get(&cur) {
                    Some((parent, _)) => cur = parent.clone(),
                    None => break,
                }
            }
            assert!(
                edges.get(&cur).is_none() || cur.is_empty(),
                "cycle reachable from {node} (seed {seed})"
            );
        }
    }
}
