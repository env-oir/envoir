//! [`SyncState`] — one replica's state for one namespace, and the idempotent ingest path.
//!
//! Ingest is the §5.2 contract in code: **verify, validate, dedup, then merge.** Dedup is by the
//! §4.1 `op-id` content address, which is what makes a re-pushed or relayed op a no-op (matching
//! flowstock's `INSERT OR IGNORE` oplog dedup) and what makes the PN-counter's accumulate-on-apply
//! safe under redelivery.

use std::collections::{BTreeMap, BTreeSet};

use crate::crdt::{
    validate_op, DeathClass, DeathReg, DeathState, LwwMap, OrSet, PnCounter,
    RgaSeq, Tree,
};
use crate::detcbor::{decode, SVal};
use crate::error::SyncError;
use crate::wire::{
    AddTag, Hlc, SyncOp, DEATH_LIVE, OP_COUNTER, OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT,
    OP_SEQ_REMOVE, OP_SET_ADD, OP_SET_REMOVE, OP_TREE_MOVE,
};

/// A per-author high-water-mark of applied HLCs (§5.1) — a compact summary of "what I already
/// have", used to compute the difference to ship. It is **not** causal-delivery state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionVector {
    marks: BTreeMap<Vec<u8>, Hlc>,
}

impl VersionVector {
    /// An empty vector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold an HLC in, keeping the per-author maximum.
    pub fn observe(&mut self, hlc: &Hlc) {
        let e = self.marks.entry(hlc.author.clone()).or_insert_with(|| hlc.clone());
        if *hlc > *e {
            *e = hlc.clone();
        }
    }

    /// The high-water mark for `author`, if any.
    pub fn get(&self, author: &[u8]) -> Option<&Hlc> {
        self.marks.get(author)
    }

    /// Whether `hlc` is **after** this vector — i.e. an op the holder of this vector lacks: its
    /// author is absent, or its HLC exceeds that author's mark (§5.2).
    pub fn lacks(&self, hlc: &Hlc) -> bool {
        match self.marks.get(&hlc.author) {
            None => true,
            Some(mark) => hlc > mark,
        }
    }

    /// The `{ * ik-pub => Hlc }` canonical encoding (§5.1).
    pub fn to_sval(&self) -> SVal {
        SVal::BytesMap(
            self.marks.iter().map(|(a, h)| (a.clone(), h.to_sval())).collect(),
        )
    }

    /// Every `(author, mark)` pair in canonical order.
    pub fn marks(&self) -> impl Iterator<Item = (&Vec<u8>, &Hlc)> {
        self.marks.iter()
    }
}

/// One replica's converged state for one namespace (§2.1), across all six CRDT types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// §4.3 add-wins membership.
    pub orset: OrSet,
    /// §4.4 LWW registers.
    pub lww: LwwMap,
    /// §4.5 remove-wins death certificates (dominates `orset`).
    pub deaths: DeathReg,
    /// §4.6 PN-counters.
    pub counters: PnCounter,
    /// §4.7 RGA sequences, keyed by target.
    pub sequences: BTreeMap<String, RgaSeq>,
    /// §4.8 movable tree.
    pub tree: Tree,
    /// The `op-id`s already applied — the §5.2 dedup set that makes apply idempotent.
    applied: BTreeSet<Vec<u8>>,
    /// The per-author high-water marks of everything applied (§5.1).
    pub vector: VersionVector,
}

impl SyncState {
    /// An empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the op with this `op-id` has already been applied.
    pub fn has_op(&self, op_id: &[u8]) -> bool {
        self.applied.contains(op_id)
    }

    /// Validate and apply one op. Returns `true` if it was **newly** applied, `false` if it was a
    /// duplicate (a no-op, never an error — a relayed op arriving twice is normal).
    ///
    /// Signature verification is the caller's step ([`crate::cose::verify_op`]): this method takes
    /// an op that is *already* authentic, so a state machine can be driven from a snapshot or a
    /// trusted local journal without re-verifying every signature.
    pub fn ingest(&mut self, op: &SyncOp, receiver_now_ms: u64) -> Result<bool, SyncError> {
        validate_op(op, receiver_now_ms)?;
        let op_id = op.op_id().as_bytes().to_vec();
        if self.applied.contains(&op_id) {
            return Ok(false);
        }
        self.apply(op)?;
        self.applied.insert(op_id);
        self.vector.observe(&op.hlc);
        Ok(true)
    }

    fn apply(&mut self, op: &SyncOp) -> Result<(), SyncError> {
        let op_id = op.op_id();
        match op.kind {
            OP_SET_ADD => {
                let element = op.value.as_ref().ok_or(SyncError::OpInvalid)?;
                let tag = AddTag { author: op.hlc.author.clone(), hlc: op.hlc.clone() };
                self.orset.add(&op.target, element, tag);
            }
            OP_SET_REMOVE => {
                let element = op.value.as_ref().ok_or(SyncError::OpInvalid)?;
                let observed = op.observed.as_ref().ok_or(SyncError::OpInvalid)?;
                self.orset.remove(&op.target, element, observed);
            }
            OP_LWW_SET => {
                let field = op.field.as_deref().ok_or(SyncError::OpInvalid)?;
                let value = op.value.clone().ok_or(SyncError::OpInvalid)?;
                self.lww.set(&op.target, field, op.hlc.clone(), value);
            }
            OP_DEATH => {
                let field = op.field.as_deref().ok_or(SyncError::OpInvalid)?;
                let state = if field == DEATH_LIVE {
                    DeathState::Live
                } else {
                    DeathState::Deleted(DeathClass::from_token(field).ok_or(SyncError::OpInvalid)?)
                };
                self.deaths.write(&op.target, op.hlc.clone(), state);
            }
            OP_COUNTER => {
                let field = op.field.as_deref().ok_or(SyncError::OpInvalid)?;
                let delta = op
                    .value
                    .as_ref()
                    .and_then(SVal::as_int)
                    .ok_or(SyncError::OpInvalid)?;
                // §4.6: a delta applies to the **author's own** entry, and the entry author is
                // taken from `hlc.author` — the field the op signature binds — so an op is
                // *structurally* incapable of naming a foreign entry. [`check_counter_entry`] is
                // the same rule stated as a predicate, for an ingest path that carries an
                // explicitly-named entry author (a store-level import, a legacy bridge) where the
                // structural guarantee does not hold.
                self.counters.apply(
                    &op.target,
                    field,
                    &op.hlc.author,
                    op_id.as_bytes(),
                    delta,
                );
            }
            OP_SEQ_INSERT => {
                let value = op.value.clone().ok_or(SyncError::OpInvalid)?;
                let origin = op.reference.as_ref().and_then(|r| r.hlc.clone());
                self.sequences
                    .entry(op.target.clone())
                    .or_default()
                    .insert(op.hlc.clone(), value, origin)?;
            }
            OP_SEQ_REMOVE => {
                let r = op.reference.as_ref().ok_or(SyncError::OpInvalid)?;
                let id = r.hlc.clone().ok_or(SyncError::OpInvalid)?;
                self.sequences.entry(op.target.clone()).or_default().remove(id);
            }
            OP_TREE_MOVE => {
                let ord = op.field.as_deref().ok_or(SyncError::OpInvalid)?;
                let parent = &op.reference.as_ref().ok_or(SyncError::OpInvalid)?.target;
                self.tree.record(op.hlc.clone(), &op.target, parent, ord);
            }
            _ => return Err(SyncError::OpInvalid),
        }
        Ok(())
    }

    /// Whether `(target, element)` is **observably** present: the D3 invariant (§4.5) —
    /// `!deaths.is_deleted(target)` **AND** the OR-Set says present. A bare `set-add` never writes
    /// the death dimension, so it can never outrank a death certificate however large its clock.
    pub fn is_present(&self, target: &str, element: &SVal) -> bool {
        !self.deaths.is_deleted(target) && self.orset.contains(target, element)
    }

    /// The observably-present `(target, element)` pairs, death-domination applied.
    pub fn present_members(&self) -> Vec<(String, SVal)> {
        self.orset
            .present()
            .into_iter()
            .filter(|(t, _)| !self.deaths.is_deleted(t))
            .filter_map(|(t, elem_bytes)| decode(&elem_bytes).ok().map(|e| (t, e)))
            .collect()
    }

    /// Join with `other` — every dimension's own join, plus the union of the dedup and
    /// high-water-mark sets. State-based merge: commutative, associative, idempotent.
    pub fn merge(&mut self, other: &SyncState) {
        self.orset.merge(&other.orset);
        self.lww.merge(&other.lww);
        self.deaths.merge(&other.deaths);
        self.counters.merge(&other.counters);
        for (target, seq) in &other.sequences {
            self.sequences.entry(target.clone()).or_default().merge(seq);
        }
        self.tree.merge(&other.tree);
        self.applied.extend(other.applied.iter().cloned());
        for (_, hlc) in other.vector.marks() {
            self.vector.observe(hlc);
        }
    }
}

/// The §7 sparse-sync filter: ship an op to a caller only if the op's namespace is in the caller's
/// subscription. A namespace the caller did not subscribe to is **never** shipped to it, and the
/// caller's silence about a namespace it does not hold is never read as "empty" (§7,
/// absence-is-not-authority).
pub fn scope_to_subscription<'a>(ops: &'a [SyncOp], subscribed: &[String]) -> Vec<&'a SyncOp> {
    ops.iter().filter(|op| subscribed.iter().any(|ns| *ns == op.ns)).collect()
}

/// The §6.2 **stability cut**: the minimum, across every *live* subscribed replica, of that
/// replica's max-applied HLC. A **stale** replica (not seen within the liveness window) is excluded
/// so a dead-but-unrevoked replica cannot stall compaction; a live replica with **no known
/// watermark** yields **no cut at all** — fail-closed, never GC on incomplete knowledge.
pub fn stability_cut(live_watermarks: &[Option<Hlc>]) -> Option<Hlc> {
    if live_watermarks.is_empty() || live_watermarks.iter().any(Option::is_none) {
        return None;
    }
    live_watermarks.iter().flatten().min().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::OpRef;

    fn a(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn h(counter: u32, author: u8) -> Hlc {
        Hlc { wall: 1_700_000_100_000, counter, author: a(author) }
    }

    fn now() -> u64 {
        1_700_000_200_000
    }

    fn add(target: &str, element: &str, counter: u32, author: u8) -> SyncOp {
        SyncOp {
            kind: OP_SET_ADD,
            ns: String::new(),
            target: target.into(),
            field: None,
            value: Some(SVal::Text(element.into())),
            hlc: h(counter, author),
            observed: None,
            reference: None,
        }
    }

    fn counter_op(delta: i64, counter: u32, author: u8) -> SyncOp {
        SyncOp {
            kind: OP_COUNTER,
            ns: String::new(),
            target: "stock1".into(),
            field: Some("qty".into()),
            value: Some(SVal::int(delta)),
            hlc: h(counter, author),
            observed: None,
            reference: None,
        }
    }

    #[test]
    fn duplicate_ops_are_no_ops_so_counter_replay_cannot_double_count() {
        let mut s = SyncState::new();
        assert!(s.ingest(&counter_op(5, 0, 0xcc), now()).unwrap());
        assert!(s.ingest(&counter_op(-2, 0, 0xdd), now()).unwrap());
        assert!(!s.ingest(&counter_op(5, 0, 0xcc), now()).unwrap(), "replay is a no-op");
        assert_eq!(s.counters.total("stock1", "qty"), 3);
    }

    #[test]
    fn death_dominates_a_later_concurrent_add() {
        let mut s = SyncState::new();
        let death = SyncOp {
            kind: OP_DEATH,
            ns: String::new(),
            target: "rec1".into(),
            field: Some("redact".into()),
            value: None,
            hlc: h(1, 0xcc),
            observed: None,
            reference: None,
        };
        s.ingest(&death, now()).unwrap();
        s.ingest(&add("rec1", "rec1-payload", 5, 0xdd), now()).unwrap();
        assert!(!s.is_present("rec1", &SVal::Text("rec1-payload".into())));
        assert!(s.present_members().is_empty());
    }

    #[test]
    fn sparse_scoping_ships_only_subscribed_namespaces() {
        let mut x = add("item1", "v", 0, 0xcc);
        x.ns = "x".into();
        let mut y = add("item2", "v", 0, 0xdd);
        y.ns = "y".into();
        let ops = vec![x.clone(), y];
        let shipped = scope_to_subscription(&ops, &["x".to_string()]);
        assert_eq!(shipped, vec![&x]);
    }

    #[test]
    fn stability_cut_is_fail_closed_on_incomplete_knowledge() {
        assert_eq!(stability_cut(&[Some(h(10, 0xcc)), Some(h(15, 0xcc))]), Some(h(10, 0xcc)));
        assert_eq!(stability_cut(&[Some(h(10, 0xcc)), None]), None, "no watermark ⇒ no cut");
        assert_eq!(stability_cut(&[]), None);
    }

    #[test]
    fn version_vector_lacks_identifies_the_ops_to_ship() {
        let mut v = VersionVector::new();
        v.observe(&h(4, 0xcc));
        assert!(!v.lacks(&h(3, 0xcc)));
        assert!(v.lacks(&h(5, 0xcc)));
        assert!(v.lacks(&h(0, 0xdd)), "an absent author means every one of its ops is missing");
    }

    #[test]
    fn rga_ops_build_a_sequence() {
        let mut s = SyncState::new();
        let root = h(0, 0xcc);
        let mut ins = SyncOp {
            kind: OP_SEQ_INSERT,
            ns: String::new(),
            target: "line1".into(),
            field: None,
            value: Some(SVal::Text("atom0".into())),
            hlc: root.clone(),
            observed: None,
            reference: None,
        };
        s.ingest(&ins, now()).unwrap();
        ins.hlc = h(3, 0xcc);
        ins.value = Some(SVal::Text("X".into()));
        ins.reference = Some(OpRef { target: "line1".into(), hlc: Some(root.clone()) });
        s.ingest(&ins, now()).unwrap();
        ins.hlc = h(4, 0xcc);
        ins.value = Some(SVal::Text("Y".into()));
        s.ingest(&ins, now()).unwrap();
        let seq = &s.sequences["line1"];
        assert_eq!(
            seq.values(),
            vec![SVal::Text("atom0".into()), SVal::Text("Y".into()), SVal::Text("X".into())]
        );
    }
}
