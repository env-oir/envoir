//! CRDT merge semantics for the cluster's mutable metadata (spec §5.6.4).
//!
//! Immutable objects (MOTEs, file chunks) need no merge — a content address means the same thing
//! whenever it arrives. **Mutable metadata** — folder/label membership, read/unread, stars, moves,
//! deletes — does, and §5.6.4 fixes the concrete CRDT primitives so two implementations converge
//! **byte-identically**:
//!
//! * **Membership / folders / labels / deletes → Observed-Remove Set (OR-Set)** with tombstones.
//!   Each add carries a globally-unique add-tag `{device, HLC}`; a remove tombstones the *specific*
//!   add-tags it observed. An element is present **iff it has ≥1 add-tag not covered by a
//!   tombstone** — so a concurrent add *wins over* a remove that never saw it, and deletes are
//!   tombstones (non-destructive), never resurrecting or losing data.
//! * **Per-field flags & moves → Last-Writer-Wins register per field**, keyed by the HLC. The
//!   winner of two concurrent writes is the one with the greater HLC under the total order
//!   `(wall, counter, device)` — deterministic on every replica, never a wall-clock coin-flip.
//!
//! Why these are the right primitives: mailbox metadata is **concurrent, add-and-remove, no
//! coordinator** — a grow-only set cannot model un-reading/un-labelling, a plain LWW-set loses the
//! "concurrent add beats an unseen delete" property mail needs, and a naive LWW register on
//! membership would drop a concurrent add. OR-Set gives add-wins membership with real deletes;
//! HLC-LWW gives a deterministic single-value winner for scalar flags. Both are **CvRDTs**: their
//! `merge` is a join (set union / HLC-max) that is **commutative, associative, and idempotent** ⇒
//! strong eventual consistency with no primary and no coordination round (§5.6.4).
//!
//! Every op is validated **fail-closed** ([`validate_op`]) before it touches state: unknown kind,
//! an out-of-skew HLC, a kind-3 op missing its field/value, a remove citing a causally-impossible
//! add-tag, or an op embedding a `DeniablePayload`/its plaintext (§5.2.1) is rejected
//! (`ERR_CLUSTER_CRDT_OP_INVALID`, `0x0413`).

use crate::error::SyncError;
use crate::wire::{AddTag, ClusterOp, Hlc, OP_LWW_SET, OP_SET_ADD, OP_SET_REMOVE};
use dmtap_core::cbor::{self, Cv};
use dmtap_core::deniable::DeniablePayload;
use std::collections::{BTreeMap, BTreeSet};

/// HLC wall-clock skew bound: ±120 s (§16.10, = §16.1). An op whose `wall` is more than this ahead
/// of the receiver's clock is a "win-forever" attempt and is rejected (`0x0413`).
pub const HLC_SKEW_MS: u64 = 120_000;

/// Validate a single [`ClusterOp`] against the receiver's clock, **fail-closed** per §5.6.4. This
/// is a pure, state-free structural + causal + skew + deniable-embed check — the §18.6.3 gate a
/// receiver applies to every op before merging it, independent of local state or delivery order.
///
/// The "OR-Set remove citing an unknown add-tag" rule (§5.6.4) is enforced causally and without
/// reference to local state (which would make validity order-dependent and break convergence): a
/// remove MUST cite ≥1 add-tag, and **no cited add-tag may post-date the remove's own HLC** — you
/// cannot have *observed* an add from the future, so such a tag is unknowable/forged. Legitimate
/// removes only ever tombstone adds they causally saw, so this never rejects an honest op.
pub fn validate_op(op: &ClusterOp, receiver_now_ms: u64) -> Result<(), SyncError> {
    // Unknown kind ⇒ invalid.
    if !matches!(op.kind, OP_SET_ADD | OP_SET_REMOVE | OP_LWW_SET) {
        return Err(SyncError::CrdtOpInvalid);
    }
    // Out-of-skew HLC ⇒ invalid ("win-forever" clock).
    if op.hlc.wall > receiver_now_ms.saturating_add(HLC_SKEW_MS) {
        return Err(SyncError::CrdtOpInvalid);
    }
    match op.kind {
        OP_SET_ADD => {
            // An add carries no field/value/observed and no LWW value to smuggle content in.
            if op.field.is_some() || op.value.is_some() || op.observed.is_some() {
                return Err(SyncError::CrdtOpInvalid);
            }
        }
        OP_SET_REMOVE => {
            // A remove MUST cite ≥1 observed add-tag, each causally ≤ the remove's HLC.
            let observed = op.observed.as_ref().ok_or(SyncError::CrdtOpInvalid)?;
            if observed.is_empty() {
                return Err(SyncError::CrdtOpInvalid);
            }
            for tag in observed {
                if tag.hlc > op.hlc {
                    return Err(SyncError::CrdtOpInvalid); // observed an add from the future
                }
            }
            if op.field.is_some() || op.value.is_some() {
                return Err(SyncError::CrdtOpInvalid);
            }
        }
        OP_LWW_SET => {
            // A LWW write MUST carry a field and a value, and no observed set.
            let value = op.value.as_ref().ok_or(SyncError::CrdtOpInvalid)?;
            if op.field.is_none() || op.observed.is_some() {
                return Err(SyncError::CrdtOpInvalid);
            }
            // No `DeniablePayload` (or its plaintext) may hide inside the value (§5.2.1): the CRDT
            // wraps entries in signed history, and a durable MLS-signed copy of deniable content is
            // exactly what deniability exists to prevent.
            if embeds_deniable(value) {
                return Err(SyncError::CrdtOpInvalid);
            }
        }
        _ => unreachable!("kind range checked above"),
    }
    Ok(())
}

/// Whether any byte string reachable within `v` decodes as a `DeniablePayload` (§18.3.10) — the
/// concrete deniable-embed guard (§5.2.1). Scanned recursively so a payload buried inside an array
/// or a text-keyed map is caught, not only a top-level blob.
fn embeds_deniable(v: &Cv) -> bool {
    match v {
        Cv::Bytes(b) => DeniablePayload::from_det_cbor(b).is_ok(),
        Cv::Array(a) => a.iter().any(embeds_deniable),
        Cv::TextMap(m) => m.iter().any(|(_, val)| embeds_deniable(val)),
        _ => false,
    }
}

/// An Observed-Remove Set (§5.6.4): add-wins membership with tombstoned deletes. Both maps are
/// grow-only per element; presence is derived, never stored — so `merge` is a pure set union.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrSet {
    /// element → the add-tags observed for it.
    adds: BTreeMap<String, BTreeSet<AddTag>>,
    /// element → the add-tags tombstoned by removes.
    tombstones: BTreeMap<String, BTreeSet<AddTag>>,
}

impl OrSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an add of `element` with the unique `tag` (§5.6.4).
    pub fn add(&mut self, element: &str, tag: AddTag) {
        self.adds.entry(element.to_owned()).or_default().insert(tag);
    }

    /// Tombstone the `observed` add-tags of `element` (an OR-Set remove, §5.6.4). Tombstones are
    /// grow-only and recorded even if the corresponding add has not yet arrived — a remove that
    /// precedes its add still converges (the add is covered the instant it lands).
    pub fn remove(&mut self, element: &str, observed: &[AddTag]) {
        let t = self.tombstones.entry(element.to_owned()).or_default();
        for tag in observed {
            t.insert(tag.clone());
        }
    }

    /// Whether `element` is present: it has **≥1 add-tag not covered by a tombstone** (§5.6.4).
    pub fn contains(&self, element: &str) -> bool {
        match self.adds.get(element) {
            None => false,
            Some(adds) => {
                let empty = BTreeSet::new();
                let dead = self.tombstones.get(element).unwrap_or(&empty);
                adds.iter().any(|t| !dead.contains(t))
            }
        }
    }

    /// The present elements, in sorted (deterministic) order.
    pub fn elements(&self) -> Vec<String> {
        self.adds.keys().filter(|e| self.contains(e)).cloned().collect()
    }

    /// Join with `other` (§5.6.4): union the add-tag and tombstone sets per element. Set union is
    /// commutative, associative, and idempotent ⇒ this is a CvRDT merge.
    pub fn merge(&mut self, other: &OrSet) {
        for (elem, tags) in &other.adds {
            let e = self.adds.entry(elem.clone()).or_default();
            for t in tags {
                e.insert(t.clone());
            }
        }
        for (elem, tags) in &other.tombstones {
            let e = self.tombstones.entry(elem.clone()).or_default();
            for t in tags {
                e.insert(t.clone());
            }
        }
    }
}

/// A per-field Last-Writer-Wins register map (§5.6.4), keyed by `(target, field)`. Each cell keeps
/// the single winning `(HLC, value)`; the winner is the greater HLC under the total order
/// `(wall, counter, device)`, with a final deterministic tiebreak on the encoded value bytes so
/// even the degenerate "identical HLC, different value" case converges identically on every replica.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LwwMap {
    regs: BTreeMap<(String, String), (Hlc, Cv)>,
}

/// Whether a write `(new_hlc, new_val)` beats the incumbent `(cur_hlc, cur_val)` — the total,
/// deterministic join order. Primary key is the HLC; the secondary key (encoded value bytes) only
/// matters for the pathological equal-HLC case, and keeps `merge` commutative there too.
fn lww_wins(new_hlc: &Hlc, new_val: &Cv, cur_hlc: &Hlc, cur_val: &Cv) -> bool {
    match new_hlc.cmp(cur_hlc) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => cbor::encode(new_val) > cbor::encode(cur_val),
    }
}

impl LwwMap {
    /// An empty register map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a LWW write to `(target, field)`; keeps it only if it beats the incumbent.
    pub fn set(&mut self, target: &str, field: &str, hlc: Hlc, value: Cv) {
        let key = (target.to_owned(), field.to_owned());
        match self.regs.get(&key) {
            Some((cur_hlc, cur_val)) if !lww_wins(&hlc, &value, cur_hlc, cur_val) => {}
            _ => {
                self.regs.insert(key, (hlc, value));
            }
        }
    }

    /// The current winning value of `(target, field)`, if any write has landed.
    pub fn get(&self, target: &str, field: &str) -> Option<&Cv> {
        self.regs.get(&(target.to_owned(), field.to_owned())).map(|(_, v)| v)
    }

    /// Join with `other` (§5.6.4): per cell, keep the winner. HLC-max with a deterministic tiebreak
    /// is commutative, associative, and idempotent ⇒ a CvRDT merge.
    pub fn merge(&mut self, other: &LwwMap) {
        for (key, (hlc, val)) in &other.regs {
            match self.regs.get(key) {
                Some((cur_hlc, cur_val)) if !lww_wins(hlc, val, cur_hlc, cur_val) => {}
                _ => {
                    self.regs.insert(key.clone(), (hlc.clone(), val.clone()));
                }
            }
        }
    }
}

/// The full synced metadata state: the OR-Set of memberships/deletes and the LWW register map of
/// scalar flags (§5.6.4). `merge` joins both halves, so `ClusterState` is itself a CvRDT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterState {
    /// Object / folder / label membership + deletes.
    pub set: OrSet,
    /// Per-field flags & moves (read/unread, star, current folder, …).
    pub lww: LwwMap,
}

impl ClusterState {
    /// An empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one **already-validated** op (call [`validate_op`] first). The add-tag of a set-add is
    /// `{op.hlc.device, op.hlc}` — the op's origin device and clock (§5.6.4).
    pub fn apply(&mut self, op: &ClusterOp) {
        match op.kind {
            OP_SET_ADD => {
                self.set.add(&op.target, AddTag { device: op.hlc.device.clone(), hlc: op.hlc.clone() });
            }
            OP_SET_REMOVE => {
                if let Some(observed) = &op.observed {
                    self.set.remove(&op.target, observed);
                }
            }
            OP_LWW_SET => {
                if let (Some(field), Some(value)) = (&op.field, &op.value) {
                    self.lww.set(&op.target, field, op.hlc.clone(), value.clone());
                }
            }
            _ => {}
        }
    }

    /// Validate (fail-closed, §5.6.4) then apply an op. The single ingest path a receiver uses.
    pub fn ingest(&mut self, op: &ClusterOp, receiver_now_ms: u64) -> Result<(), SyncError> {
        validate_op(op, receiver_now_ms)?;
        self.apply(op);
        Ok(())
    }

    /// Join with `other` (§5.6.4): merge both halves. Commutative, associative, idempotent.
    pub fn merge(&mut self, other: &ClusterState) {
        self.set.merge(&other.set);
        self.lww.merge(&other.lww);
    }

    /// A canonical, order-independent snapshot of the *observable* state — present set elements and
    /// each cell's winning value — as deterministic CBOR bytes. Two replicas that have seen the same
    /// ops (in any order, with any duplication) produce **byte-identical** snapshots; this is the
    /// strong-eventual-consistency equality used by the convergence tests (§5.6.4).
    pub fn snapshot(&self) -> Vec<u8> {
        let members: Vec<Cv> = self.set.elements().into_iter().map(Cv::Text).collect();
        let mut cells: Vec<Cv> = self
            .lww
            .regs
            .iter()
            .map(|((t, f), (_, v))| {
                Cv::Array(vec![Cv::Text(t.clone()), Cv::Text(f.clone()), v.clone()])
            })
            .collect();
        cells.sort_by(|a, b| cbor::encode(a).cmp(&cbor::encode(b)));
        cbor::encode(&Cv::Array(vec![Cv::Array(members), Cv::Array(cells)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::AddTag;

    fn hlc(w: u64, c: u32, d: u8) -> Hlc {
        Hlc { wall: w, counter: c, device: vec![d] }
    }
    fn add(target: &str, w: u64, d: u8) -> ClusterOp {
        ClusterOp {
            kind: OP_SET_ADD,
            target: target.into(),
            field: None,
            value: None,
            hlc: hlc(w, 0, d),
            observed: None,
        }
    }
    fn remove(target: &str, w: u64, d: u8, observed: Vec<AddTag>) -> ClusterOp {
        ClusterOp {
            kind: OP_SET_REMOVE,
            target: target.into(),
            field: None,
            value: None,
            hlc: hlc(w, 0, d),
            observed: Some(observed),
        }
    }
    fn lww(target: &str, field: &str, w: u64, d: u8, v: Cv) -> ClusterOp {
        ClusterOp {
            kind: OP_LWW_SET,
            target: target.into(),
            field: Some(field.into()),
            value: Some(v),
            hlc: hlc(w, 0, d),
            observed: None,
        }
    }
    /// Apply a list of ops (assumed valid) to a fresh state in the given order.
    fn state_of(ops: &[ClusterOp]) -> ClusterState {
        let mut s = ClusterState::new();
        for op in ops {
            s.apply(op);
        }
        s
    }

    #[test]
    fn or_set_add_wins_over_unseen_remove() {
        // Device A adds tag@(10,A); device B concurrently adds a *different* tag@(11,B). A remove
        // that observed only A's tag cannot tombstone B's unseen add ⇒ element stays present.
        let a_add = add("m", 10, 0xA);
        let b_add = add("m", 11, 0xB);
        let a_tag = AddTag { device: vec![0xA], hlc: hlc(10, 0, 0xA) };
        let rm = remove("m", 12, 0xA, vec![a_tag]);
        let s = state_of(&[a_add, b_add, rm]);
        assert!(s.set.contains("m"), "concurrent unseen add must win over the remove");
    }

    #[test]
    fn or_set_delete_is_a_tombstone_seen_add_disappears() {
        let a_add = add("m", 10, 0xA);
        let a_tag = AddTag { device: vec![0xA], hlc: hlc(10, 0, 0xA) };
        let rm = remove("m", 11, 0xA, vec![a_tag]);
        let s = state_of(&[a_add, rm]);
        assert!(!s.set.contains("m"), "a remove observing the only add tombstones the element");
    }

    #[test]
    fn lww_greater_hlc_wins_regardless_of_apply_order() {
        let lo = lww("m", "folder", 10, 0xA, Cv::Text("inbox".into()));
        let hi = lww("m", "folder", 20, 0xB, Cv::Text("archive".into()));
        // Apply low-then-high and high-then-low; both must land on the greater HLC's value.
        let s1 = state_of(&[lo.clone(), hi.clone()]);
        let s2 = state_of(&[hi, lo]);
        assert_eq!(s1.lww.get("m", "folder").unwrap(), &Cv::Text("archive".into()));
        assert_eq!(s1.snapshot(), s2.snapshot());
    }

    #[test]
    fn merge_is_idempotent() {
        // Merging a state with itself changes nothing (join(x,x) = x) — the CvRDT idempotency law.
        let mut s = state_of(&[
            add("m1", 10, 0xA),
            lww("m1", "read", 12, 0xA, Cv::Bool(true)),
            add("m2", 11, 0xB),
        ]);
        let before = s.snapshot();
        let copy = s.clone();
        s.merge(&copy); // merge with itself
        assert_eq!(s.snapshot(), before, "merge(x, x) must equal x");
        // And applying the identical ops a second time is likewise a no-op (op idempotency).
        s.apply(&add("m1", 10, 0xA));
        s.apply(&lww("m1", "read", 12, 0xA, Cv::Bool(true)));
        assert_eq!(s.snapshot(), before, "re-applying seen ops must not change state");
    }

    #[test]
    fn merge_is_commutative_and_associative() {
        let x = state_of(&[add("a", 10, 1), lww("a", "read", 11, 1, Cv::Bool(true))]);
        let y = state_of(&[add("b", 12, 2), lww("a", "read", 20, 2, Cv::Bool(false))]);
        let z = state_of(&[
            add("c", 13, 3),
            remove(
                "b",
                14,
                3,
                vec![AddTag { device: vec![2], hlc: hlc(12, 0, 2) }],
            ),
        ]);
        // (x ∨ y) ∨ z
        let mut left = x.clone();
        left.merge(&y);
        left.merge(&z);
        // z ∨ (y ∨ x)  — reversed order and reassociated
        let mut right = z.clone();
        let mut yx = y.clone();
        yx.merge(&x);
        right.merge(&yx);
        assert_eq!(left.snapshot(), right.snapshot(), "merge must be commutative + associative");
    }

    #[test]
    fn validate_rejects_unknown_kind() {
        let mut op = add("m", 10, 1);
        op.kind = 9;
        assert_eq!(validate_op(&op, 10), Err(SyncError::CrdtOpInvalid));
    }

    #[test]
    fn validate_rejects_far_future_hlc() {
        // wall 300 s ahead of a receiver at t=0 exceeds the ±120 s skew bound (§16.10).
        let op = add("m", 300_000, 1);
        assert_eq!(validate_op(&op, 0), Err(SyncError::CrdtOpInvalid));
        // Right at the bound is accepted.
        assert!(validate_op(&add("m", HLC_SKEW_MS, 1), 0).is_ok());
    }

    #[test]
    fn validate_rejects_remove_observing_a_future_add_tag() {
        // A remove@wall=10 that claims to have observed an add@wall=99 is causally impossible —
        // an "unknown add-tag" it could not have seen (§5.6.4).
        let future = AddTag { device: vec![1], hlc: hlc(99, 0, 1) };
        let op = remove("m", 10, 1, vec![future]);
        assert_eq!(validate_op(&op, 1_000_000), Err(SyncError::CrdtOpInvalid));
    }

    #[test]
    fn validate_rejects_empty_remove() {
        let op = ClusterOp {
            kind: OP_SET_REMOVE,
            target: "m".into(),
            field: None,
            value: None,
            hlc: hlc(10, 0, 1),
            observed: Some(vec![]),
        };
        assert_eq!(validate_op(&op, 1_000_000), Err(SyncError::CrdtOpInvalid));
    }

    #[test]
    fn validate_rejects_lww_missing_field_or_value() {
        let mut op = lww("m", "read", 10, 1, Cv::Bool(true));
        op.value = None;
        assert_eq!(validate_op(&op, 1_000_000), Err(SyncError::CrdtOpInvalid));
    }
}
