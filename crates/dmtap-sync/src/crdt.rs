//! The CRDT operation algebra (`SYNC.md` §4) — all six types.
//!
//! Three are the §5.6 device-cluster CRDTs, generalized here from one owner's device set to any
//! author set (the semantics are unchanged; `tests/clustersync_parity.rs` proves op-for-op
//! agreement with the `dmtap-clustersync` reference on the subset both cover):
//!
//! * [`OrSet`] — add-wins observed-remove set (§4.3),
//! * [`LwwMap`] — last-writer-wins register by HLC, encoded-value tiebreak (§4.4),
//! * [`DeathReg`] — remove-wins durable death certificate that **dominates** the OR-Set (§4.5).
//!
//! Three are new in the substrate, completing the algebra:
//!
//! * [`PnCounter`] — positive/negative counter, per-author op-id-keyed deltas joined by union (§4.6),
//! * [`RgaSeq`] — replicated growable array: an ordered sequence with newer-first sibling order (§4.7),
//! * [`Tree`] — cycle-safe movable tree, resolved by deterministic HLC-ordered replay (§4.8).
//!
//! Five of the six are pure **joins** (commutative, associative, idempotent), so replicas that
//! applied the same op set hold the same state regardless of arrival order. The movable tree is
//! the one exception, and it is deliberate: its apply is a deterministic *replay in HLC order*, so
//! ordering is recovered by sorting rather than by the merge, and the outcome is still identical
//! on every replica (§4.8, §11 item 5).

use std::collections::{BTreeMap, BTreeSet};

use crate::detcbor::SVal;
use crate::error::SyncError;
use crate::wire::{
    AddTag, Hlc, SyncOp, DEATH_LIVE, HLC_SKEW_MS, OP_COUNTER, OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT,
    OP_SEQ_REMOVE, OP_SET_ADD, OP_SET_REMOVE, OP_TREE_MOVE, TREE_ROOT,
};

/// The maximum number of RGA inserts held awaiting an unseen left-origin before the causal buffer
/// is declared overflowed (`ERR_SYNC_SEQ_ORIGIN_MISSING`, `0x0A07`). A missing origin is a
/// *readiness* condition, never a convergence fault (§4.7).
pub const SEQ_BUFFER_LIMIT: usize = 4096;

// ============================================================================================
// validation (§4, state-free and fail-closed)
// ============================================================================================

/// Validate an op structurally, causally, and against the receiver's clock — **before** it touches
/// state (§4). The check is deliberately **state-free**, so validity never depends on delivery
/// order (a rule that depended on local state could make two replicas disagree about whether an op
/// is admissible, which is divergence).
///
/// The skew bound is applied to the **future** direction only. §3's window bounds how far a
/// malicious author can push ordering *ahead* of everyone else's clock; refusing ops whose `wall`
/// is far in the *past* would make history backfill and snapshot-gap replay (§6) impossible, since
/// every genuinely old op is arbitrarily far behind the receiver's present. A deployment that also
/// wants a freshness bound on *live* ingest applies it at the transport (§5.4), not here.
pub fn validate_op(op: &SyncOp, receiver_now_ms: u64) -> Result<(), SyncError> {
    if !(OP_SET_ADD..=OP_TREE_MOVE).contains(&op.kind) {
        return Err(SyncError::OpInvalid);
    }
    if op.hlc.wall > receiver_now_ms.saturating_add(HLC_SKEW_MS) {
        return Err(SyncError::HlcSkew);
    }
    if op.hlc.author.is_empty() {
        return Err(SyncError::OpInvalid);
    }
    // Every value that appears on the wire is confined to the `ext-value` subset (§4.1), so a
    // value can never smuggle an un-canonicalizable or ambiguous encoding into replicated state.
    if let Some(v) = &op.value {
        if !v.is_ext_value() {
            return Err(SyncError::OpInvalid);
        }
    }
    match op.kind {
        OP_SET_ADD => {
            if op.value.is_none() || op.observed.is_some() || op.reference.is_some() {
                return Err(SyncError::OpInvalid);
            }
        }
        OP_SET_REMOVE => {
            if op.value.is_none() {
                return Err(SyncError::OpInvalid);
            }
            let observed = op.observed.as_ref().ok_or(SyncError::OpInvalid)?;
            if observed.is_empty() {
                return Err(SyncError::OpInvalid);
            }
            for tag in observed {
                // "You cannot have observed an add from the future" (§4.3) — causal integrity,
                // checkable without any local state.
                if tag.hlc > op.hlc {
                    return Err(SyncError::OpInvalid);
                }
            }
        }
        OP_LWW_SET => {
            if op.field.is_none() || op.value.is_none() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
        }
        OP_DEATH => {
            let field = op.field.as_deref().ok_or(SyncError::OpInvalid)?;
            if op.value.is_some() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
            if field != DEATH_LIVE && DeathClass::from_token(field).is_none() {
                return Err(SyncError::OpInvalid);
            }
        }
        OP_COUNTER => {
            if op.field.is_none() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
            let v = op.value.as_ref().ok_or(SyncError::OpInvalid)?;
            if v.as_int().is_none() {
                return Err(SyncError::OpInvalid);
            }
        }
        OP_SEQ_INSERT => {
            if op.value.is_none() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
            if let Some(r) = &op.reference {
                // The left-origin names an element of the SAME sequence object.
                if r.target != op.target || r.hlc.is_none() {
                    return Err(SyncError::OpInvalid);
                }
            }
        }
        OP_SEQ_REMOVE => {
            if op.value.is_some() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
            let r = op.reference.as_ref().ok_or(SyncError::OpInvalid)?;
            if r.target != op.target || r.hlc.is_none() {
                return Err(SyncError::OpInvalid);
            }
        }
        OP_TREE_MOVE => {
            if op.field.is_none() || op.value.is_some() || op.observed.is_some() {
                return Err(SyncError::OpInvalid);
            }
            let r = op.reference.as_ref().ok_or(SyncError::OpInvalid)?;
            // A tree edge names a node, not an element, so it carries no element HLC. A node can
            // never be its own parent, whatever the clock says.
            if r.hlc.is_some() || r.target == op.target {
                return Err(SyncError::OpInvalid);
            }
        }
        _ => unreachable!("kind range checked above"),
    }
    Ok(())
}

/// The §8/§9 admission predicate: an op is applied only if its author is admitted by the
/// namespace's policy. Every deployment shape (device cluster, closed multi-owner set, open
/// namespace) differs in **how** the admitted set is computed, never in whether the check runs.
pub fn check_admitted(author: &[u8], admitted: &[Vec<u8>]) -> Result<(), SyncError> {
    if admitted.iter().any(|a| a.as_slice() == author) {
        Ok(())
    } else {
        Err(SyncError::AuthorUnauthorized)
    }
}

/// The §4.6 own-entry rule: a signed op from author `a` may only advance `P[a]`/`N[a]`. A PN-counter
/// op that would mutate another author's entry is `ERR_SYNC_COUNTER_FOREIGN` (`0x0A06`).
pub fn check_counter_entry(op_author: &[u8], entry_author: &[u8]) -> Result<(), SyncError> {
    if op_author == entry_author {
        Ok(())
    } else {
        Err(SyncError::CounterForeign)
    }
}

/// The §7 causal-self-containment rule: an RGA `ref` or tree `parent` MUST name a `target` in the
/// **same** namespace. A cross-namespace reference is `ERR_SYNC_NS_LEAK` (`0x0A0A`) — the rule that
/// makes sparse subscription *correct* rather than merely partial, since a subscriber never needs
/// ops outside its subscription to converge its own namespaces.
pub fn check_ns_ref(op_ns: &str, referenced_target_ns: &str) -> Result<(), SyncError> {
    if op_ns == referenced_target_ns {
        Ok(())
    } else {
        Err(SyncError::NsLeak)
    }
}

// ============================================================================================
// §4.3 OR-Set — add-wins observed-remove
// ============================================================================================

/// An element key: `(target, det_cbor(element))`. The element is keyed by its canonical bytes so
/// any `ext-value` (not just a text id) can be a set member while the ordering stays
/// implementation-independent.
type ElemKey = (String, Vec<u8>);

/// Add-wins observed-remove set (§4.3), keyed per `(target, element)`. Both maps are grow-only;
/// presence is *derived*, never stored — so `merge` is a pure set union (a join).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrSet {
    adds: BTreeMap<ElemKey, BTreeSet<AddTag>>,
    tombstones: BTreeMap<ElemKey, BTreeSet<AddTag>>,
}

impl OrSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an add of `element` under `target` with its globally-unique tag.
    pub fn add(&mut self, target: &str, element: &SVal, tag: AddTag) {
        self.adds.entry((target.to_owned(), element.det_cbor())).or_default().insert(tag);
    }

    /// Tombstone the `observed` add-tags of `(target, element)`. Tombstones are recorded even if
    /// the corresponding add has not yet arrived — a remove that precedes its add still converges.
    pub fn remove(&mut self, target: &str, element: &SVal, observed: &[AddTag]) {
        let e = self.tombstones.entry((target.to_owned(), element.det_cbor())).or_default();
        for tag in observed {
            e.insert(tag.clone());
        }
    }

    /// Whether `(target, element)` is present: it has **≥1 add-tag not covered by a tombstone**.
    pub fn contains(&self, target: &str, element: &SVal) -> bool {
        self.contains_key(&(target.to_owned(), element.det_cbor()))
    }

    fn contains_key(&self, key: &ElemKey) -> bool {
        match self.adds.get(key) {
            None => false,
            Some(adds) => {
                let empty = BTreeSet::new();
                let dead = self.tombstones.get(key).unwrap_or(&empty);
                adds.iter().any(|t| !dead.contains(t))
            }
        }
    }

    /// The surviving (non-tombstoned) add-tags of `(target, element)`.
    pub fn surviving_tags(&self, target: &str, element: &SVal) -> Vec<AddTag> {
        let key = (target.to_owned(), element.det_cbor());
        let empty = BTreeSet::new();
        let dead = self.tombstones.get(&key).unwrap_or(&empty);
        self.adds
            .get(&key)
            .map(|adds| adds.iter().filter(|t| !dead.contains(t)).cloned().collect())
            .unwrap_or_default()
    }

    /// The present `(target, element-bytes)` pairs, in canonical order.
    pub fn present(&self) -> Vec<ElemKey> {
        self.adds.keys().filter(|k| self.contains_key(k)).cloned().collect()
    }

    /// Join with `other`: per-element union of adds and of tombstones — commutative, associative,
    /// idempotent.
    pub fn merge(&mut self, other: &OrSet) {
        for (k, tags) in &other.adds {
            self.adds.entry(k.clone()).or_default().extend(tags.iter().cloned());
        }
        for (k, tags) in &other.tombstones {
            self.tombstones.entry(k.clone()).or_default().extend(tags.iter().cloned());
        }
    }

    /// **Stability-cut GC (§6.2).** Drop every add-tag present in *both* adds and tombstones whose
    /// HLC is at or below `cut`: its `{author, hlc}` is globally unique, so it can never again
    /// affect presence. Observable state is unchanged; only proof-obligations no live replica can
    /// still raise are discarded. Returns the number of tags reclaimed.
    pub fn prune_stable(&mut self, cut: &Hlc) -> usize {
        let mut pruned = 0usize;
        let keys: Vec<ElemKey> = self.tombstones.keys().cloned().collect();
        for key in keys {
            let reclaim: Vec<AddTag> = {
                let dead = &self.tombstones[&key];
                let adds = self.adds.get(&key);
                dead.iter()
                    .filter(|t| t.hlc <= *cut && adds.is_some_and(|a| a.contains(*t)))
                    .cloned()
                    .collect()
            };
            if reclaim.is_empty() {
                continue;
            }
            if let Some(dead) = self.tombstones.get_mut(&key) {
                for t in &reclaim {
                    dead.remove(t);
                }
                if dead.is_empty() {
                    self.tombstones.remove(&key);
                }
            }
            if let Some(adds) = self.adds.get_mut(&key) {
                for t in &reclaim {
                    adds.remove(t);
                }
                if adds.is_empty() {
                    self.adds.remove(&key);
                }
            }
            pruned += reclaim.len();
        }
        pruned
    }
}

// ============================================================================================
// §4.4 LWW register
// ============================================================================================

/// Whether a write `(new_hlc, new_val)` beats the incumbent — the total, deterministic join order.
/// The primary key is the HLC; the secondary key (**larger encoded value bytes wins**) matters only
/// at an exact HLC tie, and is what keeps `merge` commutative even there (§4.4).
fn lww_wins(new_hlc: &Hlc, new_val: &SVal, cur_hlc: &Hlc, cur_val: &SVal) -> bool {
    match new_hlc.cmp(cur_hlc) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new_val.det_cbor() > cur_val.det_cbor(),
    }
}

/// Per-`(target, field)` last-writer-wins registers (§4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LwwMap {
    regs: BTreeMap<(String, String), (Hlc, SVal)>,
}

impl LwwMap {
    /// An empty register map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a write; keeps it only if it beats the incumbent.
    pub fn set(&mut self, target: &str, field: &str, hlc: Hlc, value: SVal) {
        let key = (target.to_owned(), field.to_owned());
        match self.regs.get(&key) {
            Some((cur_hlc, cur_val)) if !lww_wins(&hlc, &value, cur_hlc, cur_val) => {}
            _ => {
                self.regs.insert(key, (hlc, value));
            }
        }
    }

    /// The winning value of `(target, field)`.
    pub fn get(&self, target: &str, field: &str) -> Option<&SVal> {
        self.regs.get(&(target.to_owned(), field.to_owned())).map(|(_, v)| v)
    }

    /// The winning cell (HLC + value) of `(target, field)`.
    pub fn cell(&self, target: &str, field: &str) -> Option<&(Hlc, SVal)> {
        self.regs.get(&(target.to_owned(), field.to_owned()))
    }

    /// Every winning cell, in canonical `(target, field)` order.
    pub fn cells(&self) -> impl Iterator<Item = (&(String, String), &(Hlc, SVal))> {
        self.regs.iter()
    }

    /// Join with `other`: per cell, keep the winner (a join).
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

// ============================================================================================
// §4.5 death certificate — remove-wins durable delete
// ============================================================================================

/// The durable-delete class of a death certificate (§4.5), ordered so the join is total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeathClass {
    /// A privacy redaction.
    Redact,
    /// A reached expiry.
    Expires,
    /// A policy removal of sensitive content.
    Sensitive,
}

impl DeathClass {
    /// The wire token carried in `field`.
    pub fn token(self) -> &'static str {
        match self {
            DeathClass::Redact => "redact",
            DeathClass::Expires => "expires",
            DeathClass::Sensitive => "sensitive",
        }
    }

    /// Parse a wire token, failing closed on anything outside the ordered enum.
    pub fn from_token(t: &str) -> Option<DeathClass> {
        match t {
            "redact" => Some(DeathClass::Redact),
            "expires" => Some(DeathClass::Expires),
            "sensitive" => Some(DeathClass::Sensitive),
            _ => None,
        }
    }
}

/// `Live` or `Deleted(class)`. Ordered so that at an exact HLC tie `Deleted` beats `Live`
/// (remove-wins, fail-safe toward deletion) and a later class deterministically beats an earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeathState {
    /// Never deleted, or explicitly un-deleted.
    Live,
    /// Durably deleted under this class.
    Deleted(DeathClass),
}

impl DeathState {
    /// The class if deleted.
    pub fn class(self) -> Option<DeathClass> {
        match self {
            DeathState::Live => None,
            DeathState::Deleted(c) => Some(c),
        }
    }
}

fn death_wins(new_hlc: &Hlc, new_state: DeathState, cur_hlc: &Hlc, cur_state: DeathState) -> bool {
    match new_hlc.cmp(cur_hlc) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new_state > cur_state,
    }
}

/// The remove-wins death dimension (§4.5) — a per-object LWW register over `DeathState` that
/// **dominates** the OR-Set (the D3 invariant). A bare `set-add` never writes this dimension, so it
/// can never outrank a certificate however large its wall clock; only an explicit `Live` write with
/// a strictly greater HLC revives an object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeathReg {
    regs: BTreeMap<String, (Hlc, DeathState)>,
}

impl DeathReg {
    /// An empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a death write; keeps it only if it beats the incumbent.
    pub fn write(&mut self, object: &str, hlc: Hlc, state: DeathState) {
        match self.regs.get(object) {
            Some((cur_hlc, cur_state)) if !death_wins(&hlc, state, cur_hlc, *cur_state) => {}
            _ => {
                self.regs.insert(object.to_owned(), (hlc, state));
            }
        }
    }

    /// The winning death state of `object` (default `Live`).
    pub fn state(&self, object: &str) -> DeathState {
        self.regs.get(object).map(|(_, s)| *s).unwrap_or(DeathState::Live)
    }

    /// Whether `object` currently bears a `Deleted` certificate.
    pub fn is_deleted(&self, object: &str) -> bool {
        matches!(self.regs.get(object), Some((_, DeathState::Deleted(_))))
    }

    /// The deleted objects with their classes, in canonical order.
    pub fn deleted(&self) -> Vec<(String, DeathClass)> {
        self.regs.iter().filter_map(|(o, (_, s))| s.class().map(|c| (o.clone(), c))).collect()
    }

    /// Join with `other`: per object, keep the winning certificate (a join).
    pub fn merge(&mut self, other: &DeathReg) {
        for (object, (hlc, state)) in &other.regs {
            match self.regs.get(object) {
                Some((cur_hlc, cur_state)) if !death_wins(hlc, *state, cur_hlc, *cur_state) => {}
                _ => {
                    self.regs.insert(object.clone(), (hlc.clone(), *state));
                }
            }
        }
    }
}

// ============================================================================================
// §4.6 PN-counter (NEW)
// ============================================================================================

/// A positive-negative counter (§4.6): per `(target, field)`, per author, the set of that author's
/// **applied deltas keyed by `op-id`**. `P[a]` is the sum of that author's positive deltas and
/// `N[a]` the magnitude of its negative ones, so the observable value is `Σ_a P[a] − Σ_a N[a]`
/// exactly as §4.6 defines it.
///
/// An author may only advance its **own** entries; a signed op from `a` that would mutate `P[b]` is
/// `ERR_SYNC_COUNTER_FOREIGN` ([`check_counter_entry`]).
///
/// ## The join is the per-author **union of op-ids** — normative since §4.6 C-01
///
/// §4.6 originally specified the merge as per-author `max` of `P` and `N` (the classical
/// *state-based* PN-counter join, sound only when `P[a]` is a cumulative value each replica derives
/// from the **whole** of `a`'s op prefix). The substrate's op carries a **delta** (§4.2 kind 5), so
/// two replicas can legitimately hold *different subsets* of one author's deltas (partition, sparse
/// backfill, snapshot fast-join); under `max` those partial states merge to the larger subtotal and
/// the other subset's deltas are **silently lost** — the merge is not a join, and
/// `(A∪B)∪C ≠ A∪(B∪C)`.
///
/// This implementation reported that, and §4.6 was corrected (`SYNC.md` §14 C-01) to specify
/// exactly what is implemented here: state is per `(target, field)`, per author `a`, a map
/// `D[a]: op-id → int`, with `P[a]`/`N[a]` **derived** as the sums of the positive deltas and the
/// magnitudes of the negative ones, merged by per-author **union**. Associativity is now an
/// explicit REQUIREMENT of the section. Keying each delta by its globally-unique `op-id` makes the
/// merge a set union: commutative, associative and idempotent, so a redelivered delta cannot
/// double-count and no delta is lost when partial states merge.
///
/// (`max` survives in one place: §4.6's compaction note reinstates it for the *below-stability-cut*
/// aggregate, which is safe precisely because §6.2's cut gives the completeness guarantee `max`
/// needs — every replica has seen every op below it.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PnCounter {
    /// `(target, field)` → author → `op-id` → signed delta.
    cells: BTreeMap<(String, String), BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, i64>>>,
}

impl PnCounter {
    /// An empty counter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a signed delta from `author`, identified by its `op_id` (§4.1). Re-recording the same
    /// `op_id` is a no-op, so redelivery never double-counts.
    pub fn apply(&mut self, target: &str, field: &str, author: &[u8], op_id: &[u8], delta: i64) {
        self.cells
            .entry((target.to_owned(), field.to_owned()))
            .or_default()
            .entry(author.to_vec())
            .or_default()
            .insert(op_id.to_vec(), delta);
    }

    /// The `(P[a], N[a])` pair for one author of a cell (§4.6).
    pub fn author_pn(&self, target: &str, field: &str, author: &[u8]) -> (u64, u64) {
        match self
            .cells
            .get(&(target.to_owned(), field.to_owned()))
            .and_then(|c| c.get(author))
        {
            None => (0, 0),
            Some(deltas) => deltas.values().fold((0u64, 0u64), |(p, n), d| {
                if *d >= 0 {
                    (p.saturating_add(*d as u64), n)
                } else {
                    (p, n.saturating_add(d.unsigned_abs()))
                }
            }),
        }
    }

    /// `Σ_a P[a] − Σ_a N[a]` for `(target, field)`.
    pub fn total(&self, target: &str, field: &str) -> i128 {
        match self.cells.get(&(target.to_owned(), field.to_owned())) {
            None => 0,
            Some(entries) => entries
                .values()
                .flat_map(|deltas| deltas.values())
                .map(|d| *d as i128)
                .sum(),
        }
    }

    /// Every author of a cell, with its `(P, N)` entry — the §4.6 internal state.
    pub fn entries(&self, target: &str, field: &str) -> BTreeMap<Vec<u8>, (u64, u64)> {
        match self.cells.get(&(target.to_owned(), field.to_owned())) {
            None => BTreeMap::new(),
            Some(entries) => entries
                .keys()
                .map(|a| (a.clone(), self.author_pn(target, field, a)))
                .collect(),
        }
    }

    /// Every cell with its total, in canonical order.
    pub fn totals(&self) -> Vec<(String, String, i128)> {
        self.cells
            .keys()
            .map(|(t, f)| (t.clone(), f.clone(), self.total(t, f)))
            .collect()
    }

    /// Join with `other`: per author, the union of `op-id`-keyed deltas — commutative, associative,
    /// idempotent.
    pub fn merge(&mut self, other: &PnCounter) {
        for (key, authors) in &other.cells {
            let cell = self.cells.entry(key.clone()).or_default();
            for (author, deltas) in authors {
                let e = cell.entry(author.clone()).or_default();
                for (op_id, d) in deltas {
                    e.insert(op_id.clone(), *d);
                }
            }
        }
    }
}

// ============================================================================================
// §4.7 RGA sequence (NEW)
// ============================================================================================

/// One RGA atom: an `ext-value` payload with its left-origin.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Atom {
    value: SVal,
    /// The element id this atom was inserted immediately after; `None` = the list head sentinel `⊥`.
    origin: Option<Hlc>,
}

/// A replicated growable array (§4.7): a set of atoms keyed by their insertion HLC (a globally
/// unique element id), plus tombstones.
///
/// **Order:** atoms sharing a left-origin sort by **descending element-id HLC** (later insertions
/// sort *earlier* among same-origin siblings — the standard RGA newer-first rule), recursively; the
/// sequence is the pre-order walk of that tree with tombstoned atoms skipped. Element ids are
/// HLC-total-ordered, so every replica that applied the same ops computes the identical sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RgaSeq {
    atoms: BTreeMap<Hlc, Atom>,
    tombstones: BTreeSet<Hlc>,
    /// Inserts whose left-origin has not arrived yet: causal readiness, buffered rather than
    /// rejected (§4.7). A missing origin is never a convergence fault.
    pending: Vec<(Hlc, Atom)>,
}

impl RgaSeq {
    /// An empty sequence.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an atom with element id `id` after `origin` (`None` = list head). If the origin is
    /// not yet known the insert is buffered until it arrives; overflowing the bounded buffer is
    /// `ERR_SYNC_SEQ_ORIGIN_MISSING` (`0x0A07`), a defer-and-retry condition, not a rejection of
    /// the op's validity.
    pub fn insert(&mut self, id: Hlc, value: SVal, origin: Option<Hlc>) -> Result<(), SyncError> {
        let atom = Atom { value, origin: origin.clone() };
        match &origin {
            // A tombstoned origin still resolves: tombstones are retained until GC precisely so a
            // concurrent insert after a removed atom keeps a well-defined position (§4.7).
            Some(o) if !self.atoms.contains_key(o) => {
                if self.pending.len() >= SEQ_BUFFER_LIMIT {
                    return Err(SyncError::SeqOriginMissing);
                }
                self.pending.push((id, atom));
                Ok(())
            }
            _ => {
                self.atoms.insert(id, atom);
                self.flush_pending();
                Ok(())
            }
        }
    }

    fn flush_pending(&mut self) {
        loop {
            let ready: Vec<usize> = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, (_, a))| a.origin.as_ref().map_or(true, |o| self.atoms.contains_key(o)))
                .map(|(i, _)| i)
                .collect();
            if ready.is_empty() {
                return;
            }
            for i in ready.into_iter().rev() {
                let (id, atom) = self.pending.remove(i);
                self.atoms.insert(id, atom);
            }
        }
    }

    /// Tombstone the atom named by `id` (retained until GC, §6.2).
    pub fn remove(&mut self, id: Hlc) {
        self.tombstones.insert(id);
    }

    /// Whether `id` names a known atom.
    pub fn has(&self, id: &Hlc) -> bool {
        self.atoms.contains_key(id)
    }

    /// The full atom order **including** tombstoned atoms (the RGA tree's pre-order walk).
    pub fn order(&self) -> Vec<Hlc> {
        let mut children: BTreeMap<Option<Hlc>, Vec<Hlc>> = BTreeMap::new();
        for (id, atom) in &self.atoms {
            children.entry(atom.origin.clone()).or_default().push(id.clone());
        }
        for sibs in children.values_mut() {
            sibs.sort_by(|a, b| b.cmp(a)); // descending element id: newer-first
        }
        let mut out = Vec::with_capacity(self.atoms.len());
        let mut stack: Vec<Hlc> = children.get(&None).cloned().unwrap_or_default();
        stack.reverse(); // so the first sibling is popped first
        while let Some(id) = stack.pop() {
            out.push(id.clone());
            if let Some(kids) = children.get(&Some(id)) {
                for k in kids.iter().rev() {
                    stack.push(k.clone());
                }
            }
        }
        out
    }

    /// The live (non-tombstoned) sequence, in order.
    pub fn values(&self) -> Vec<SVal> {
        self.order()
            .into_iter()
            .filter(|id| !self.tombstones.contains(id))
            .filter_map(|id| self.atoms.get(&id).map(|a| a.value.clone()))
            .collect()
    }

    /// The value of the atom named by `id`, tombstoned or not — the accessor needed to render the
    /// full atom order (tombstones included) rather than only the live sequence.
    pub fn atom_value(&self, id: &Hlc) -> Option<&SVal> {
        self.atoms.get(id).map(|a| &a.value)
    }

    /// Whether `id` is tombstoned.
    pub fn is_tombstoned(&self, id: &Hlc) -> bool {
        self.tombstones.contains(id)
    }

    /// Join with `other`: union of atoms and of tombstones; the order is recomputed by the rule
    /// above, so merge is order-independent (a join).
    pub fn merge(&mut self, other: &RgaSeq) {
        for (id, atom) in &other.atoms {
            self.atoms.insert(id.clone(), atom.clone());
        }
        for (id, atom) in &other.pending {
            if !self.atoms.contains_key(id) && !self.pending.iter().any(|(p, _)| p == id) {
                self.pending.push((id.clone(), atom.clone()));
            }
        }
        self.tombstones.extend(other.tombstones.iter().cloned());
        self.flush_pending();
    }
}

// ============================================================================================
// §4.8 movable tree (NEW)
// ============================================================================================

/// A cycle-safe movable tree (§4.8) — the one kind whose apply is **not** a per-op join.
///
/// Moves are retained and **replayed in ascending HLC order (oldest first)**. A move
/// `(node → new_parent)` would create a cycle iff `new_parent == node` or `new_parent` is a
/// descendant of `node` in the tree formed by all strictly-earlier moves already applied; such a
/// move is **skipped** (recorded as a no-op, never an error) and the tree stays acyclic.
///
/// Because each move is evaluated against the state of every lower-HLC move, the **later**-HLC move
/// of a colliding pair is the one skipped and the **earlier** applied. For the canonical swap —
/// `move(A → under B)` at `h1` and `move(B → under A)` at `h2 > h1` — replay applies `h1` (A
/// becomes a child of B), and when `h2` is evaluated A is already a descendant of B, so moving B
/// under A would close the cycle B→A→B and `h2` is skipped: B keeps its pre-swap parent.
///
/// This is deliberately **not** last-writer-wins for the colliding *pair*. Plain LWW governs only
/// repeated moves of the **same** node (there the greater HLC does win, which falls out of ordered
/// replay for free); the cycle rule governs the *interaction* between moves of *different* nodes,
/// and there the ordered replay — not the clock — decides, so no move is silently lost to a
/// numerically larger wall clock and every replica reaches the identical acyclic tree regardless of
/// arrival order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    /// Every move ever seen, keyed by `(hlc, node)` so the replay order is the HLC total order.
    moves: BTreeMap<(Hlc, String), (String, String)>,
}

/// The outcome of one replay: the winning edges, and which moves were applied vs skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeReplay {
    /// node → `(parent, ordering_key)` after the acyclic replay, in canonical node order.
    pub edges: BTreeMap<String, (String, String)>,
    /// The `(hlc, node)` of every move that took effect, in replay order.
    pub applied: Vec<(Hlc, String)>,
    /// The `(hlc, node)` of every move skipped as cycle-closing, in replay order. **Not** errors.
    pub skipped: Vec<(Hlc, String)>,
}

impl Tree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a move. The observable tree is always recomputed by [`replay`](Self::replay), so
    /// recording is order-independent even though applying is not.
    pub fn record(&mut self, hlc: Hlc, node: &str, parent: &str, ord: &str) {
        self.moves.insert((hlc, node.to_owned()), (parent.to_owned(), ord.to_owned()));
    }

    /// Replay every recorded move in ascending HLC order, skipping cycle-closing moves.
    pub fn replay(&self) -> TreeReplay {
        let mut out = TreeReplay::default();
        for ((hlc, node), (parent, ord)) in &self.moves {
            if would_cycle(&out.edges, node, parent) {
                out.skipped.push((hlc.clone(), node.clone()));
                continue;
            }
            out.edges.insert(node.clone(), (parent.clone(), ord.clone()));
            out.applied.push((hlc.clone(), node.clone()));
        }
        out
    }

    /// The winning `(parent, ordering_key)` edges after replay.
    pub fn edges(&self) -> BTreeMap<String, (String, String)> {
        self.replay().edges
    }

    /// Join with `other`: union of the recorded moves. The union is a join; determinism comes from
    /// the replay, not from the merge (§4.8).
    pub fn merge(&mut self, other: &Tree) {
        for (k, v) in &other.moves {
            self.moves.insert(k.clone(), v.clone());
        }
    }
}

/// Whether moving `node` under `new_parent` would close a cycle, given the edges formed by all
/// strictly-earlier moves: true iff `new_parent == node`, or walking up from `new_parent` reaches
/// `node` (i.e. `new_parent` is a descendant of `node`).
fn would_cycle(
    edges: &BTreeMap<String, (String, String)>,
    node: &str,
    new_parent: &str,
) -> bool {
    if new_parent == node {
        return true;
    }
    let mut cur = new_parent;
    // The walk is bounded by the edge count: an acyclic invariant is maintained inductively, but
    // the bound is belt-and-braces so a malformed state can never spin forever.
    for _ in 0..=edges.len() {
        if cur == TREE_ROOT {
            return false;
        }
        match edges.get(cur) {
            Some((parent, _)) => {
                if parent == node {
                    return true;
                }
                cur = parent;
            }
            None => return false, // cur is a root-level node with no recorded edge
        }
    }
    true // walked past the bound ⇒ treat as cyclic (fail-safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn h(counter: u32, author: u8) -> Hlc {
        Hlc { wall: 1_700_000_100_000, counter, author: a(author) }
    }

    fn tag(counter: u32, author: u8) -> AddTag {
        AddTag { author: a(author), hlc: h(counter, author) }
    }

    #[test]
    fn orset_is_add_wins() {
        let e = SVal::Text("e1".into());
        let mut s = OrSet::new();
        s.add("tags", &e, tag(0, 0xcc));
        s.add("tags", &e, tag(2, 0xcc));
        s.remove("tags", &e, &[tag(0, 0xcc)]); // remove observed only the first add
        assert!(s.contains("tags", &e));
        assert_eq!(s.surviving_tags("tags", &e), vec![tag(2, 0xcc)]);
    }

    #[test]
    fn lww_exact_tie_breaks_on_encoded_value_bytes() {
        let mut x = LwwMap::new();
        let mut y = LwwMap::new();
        // Same HLC, different values, opposite apply orders ⇒ identical winner.
        x.set("doc1", "title", h(5, 0xcc), SVal::Text("m".into()));
        x.set("doc1", "title", h(5, 0xcc), SVal::Text("n".into()));
        y.set("doc1", "title", h(5, 0xcc), SVal::Text("n".into()));
        y.set("doc1", "title", h(5, 0xcc), SVal::Text("m".into()));
        assert_eq!(x.get("doc1", "title"), Some(&SVal::Text("n".into())));
        assert_eq!(x, y);
    }

    #[test]
    fn death_dominates_and_ties_fail_safe() {
        let mut d = DeathReg::new();
        d.write("rec1", h(1, 0xcc), DeathState::Deleted(DeathClass::Redact));
        // An exact-HLC `Live` must NOT revive: Deleted > Live in the state order.
        d.write("rec2", h(7, 0xcc), DeathState::Deleted(DeathClass::Redact));
        d.write("rec2", h(7, 0xcc), DeathState::Live);
        assert!(d.is_deleted("rec1"));
        assert!(d.is_deleted("rec2"));
        // Only a strictly greater HLC revives.
        d.write("rec2", h(8, 0xcc), DeathState::Live);
        assert!(!d.is_deleted("rec2"));
    }

    #[test]
    fn pn_counter_totals_and_merge_is_an_idempotent_join() {
        let mut x = PnCounter::new();
        x.apply("stock1", "qty", &a(0xcc), b"op-1", 5);
        x.apply("stock1", "qty", &a(0xdd), b"op-2", -2);
        let mut y = x.clone();
        y.merge(&x); // idempotent: re-merging already-known state changes nothing
        assert_eq!(x, y);
        assert_eq!(x.total("stock1", "qty"), 3);
        assert_eq!(x.author_pn("stock1", "qty", &a(0xcc)), (5, 0));
        assert_eq!(x.author_pn("stock1", "qty", &a(0xdd)), (0, 2));
        // A redelivered delta (same op-id) cannot double-count...
        x.apply("stock1", "qty", &a(0xcc), b"op-1", 5);
        assert_eq!(x.total("stock1", "qty"), 3);
        // ...while a genuinely NEW delta from the same author accumulates.
        x.apply("stock1", "qty", &a(0xcc), b"op-3", 5);
        assert_eq!(x.total("stock1", "qty"), 8);
    }

    #[test]
    fn pn_counter_merge_of_partial_states_loses_nothing() {
        // The case per-author `max` would silently lose: two replicas each holding a DIFFERENT
        // subset of one author's deltas.
        let mut left = PnCounter::new();
        left.apply("stock1", "qty", &a(0xcc), b"op-1", 5);
        let mut right = PnCounter::new();
        right.apply("stock1", "qty", &a(0xcc), b"op-2", 5);
        left.merge(&right);
        assert_eq!(left.total("stock1", "qty"), 10);
    }

    #[test]
    fn rga_siblings_are_newer_first_and_tombstone_origins_resolve() {
        let mut s = RgaSeq::new();
        let root = h(0, 0xcc);
        s.insert(root.clone(), SVal::Text("atom0".into()), None).unwrap();
        s.insert(h(3, 0xcc), SVal::Text("X".into()), Some(root.clone())).unwrap();
        s.insert(h(4, 0xcc), SVal::Text("Y".into()), Some(root.clone())).unwrap();
        assert_eq!(
            s.values(),
            vec![SVal::Text("atom0".into()), SVal::Text("Y".into()), SVal::Text("X".into())]
        );
        // An insert after a tombstoned atom still resolves.
        s.remove(h(3, 0xcc));
        s.insert(h(5, 0xcc), SVal::Text("Z".into()), Some(h(3, 0xcc))).unwrap();
        assert_eq!(
            s.values(),
            vec![SVal::Text("atom0".into()), SVal::Text("Y".into()), SVal::Text("Z".into())]
        );
    }

    #[test]
    fn rga_buffers_an_unknown_origin_until_it_arrives() {
        let mut s = RgaSeq::new();
        let origin = h(1, 0xcc);
        s.insert(h(2, 0xcc), SVal::Text("late".into()), Some(origin.clone())).unwrap();
        assert!(s.values().is_empty(), "buffered, not applied and not rejected");
        s.insert(origin, SVal::Text("first".into()), None).unwrap();
        assert_eq!(s.values(), vec![SVal::Text("first".into()), SVal::Text("late".into())]);
    }

    #[test]
    fn tree_skips_the_later_move_of_a_colliding_pair() {
        let mut t = Tree::new();
        t.record(h(0, 0xcc), "A", "", "a");
        t.record(h(0, 0xdd), "B", "", "b");
        t.record(h(1, 0xcc), "A", "B", "1"); // h1: A under B
        t.record(h(2, 0xdd), "B", "A", "1"); // h2: B under A — would close the cycle
        let r = t.replay();
        assert_eq!(r.skipped, vec![(h(2, 0xdd), "B".to_string())]);
        assert_eq!(r.edges["A"], ("B".into(), "1".into()));
        assert_eq!(r.edges["B"], ("".into(), "b".into()));
    }

    #[test]
    fn tree_repeated_moves_of_the_same_node_are_lww() {
        // LWW *does* govern repeated moves of one node: ordered replay makes the greater HLC last.
        let mut t = Tree::new();
        t.record(h(0, 0xcc), "P", "", "p");
        t.record(h(0, 0xdd), "Q", "", "q");
        t.record(h(1, 0xcc), "A", "P", "1");
        t.record(h(2, 0xdd), "A", "Q", "2");
        let r = t.replay();
        assert!(r.skipped.is_empty());
        assert_eq!(r.edges["A"], ("Q".into(), "2".into()));
    }

    #[test]
    fn tree_self_parent_is_refused_by_the_cycle_rule() {
        let mut t = Tree::new();
        t.record(h(1, 0xcc), "A", "A", "x");
        assert_eq!(t.replay().skipped.len(), 1);
    }
}
