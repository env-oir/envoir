//! CRDT merge semantics for the cluster's mutable metadata (spec §5.6.4).
//!
//! Immutable objects (MOTEs, file chunks) need no merge — a content address means the same thing
//! whenever it arrives. **Mutable metadata** — folder/label membership, read/unread, stars, moves,
//! deletes — does, and §5.6.4 fixes the concrete CRDT primitives so two implementations converge
//! **byte-identically**:
//!
//! * **Benign label membership → Observed-Remove Set (OR-Set)** with tombstones (**add-wins**).
//!   Each add carries a globally-unique add-tag `{device, HLC}`; a remove tombstones the *specific*
//!   add-tags it observed. An element is present **iff it has ≥1 add-tag not covered by a
//!   tombstone** — so a concurrent add *wins over* a remove that never saw it. This add-wins bias
//!   is correct **only** for benign, many-valued labels, where a spuriously-resurrected tag is
//!   harmless.
//! * **Per-field flags & moves → Last-Writer-Wins register per field**, keyed by the HLC. The
//!   winner of two concurrent writes is the one with the greater HLC under the total order
//!   `(wall, counter, device)` — deterministic on every replica, never a wall-clock coin-flip.
//! * **Durable deletions → remove-wins HLC-keyed `deleted` flag** (a per-object "death
//!   certificate," an LWW register over `{live, deleted}`) that **dominates** the OR-Set. A
//!   `redact` (§6.7), a reached `expires` (§2.4), or a `sensitive`-marked removal sets it; once set
//!   with the greatest HLC, **no unobserved OR-Set add-tag can resurrect the object** — a
//!   concurrent benign re-label does not un-redact a message, closing the resurrection hole where
//!   an add-wins delete would let a concurrent label op revive redacted/expired/sensitive content.
//!   The delete/re-add tiebreak is explicit: because the flag is LWW-keyed by HLC, only a later
//!   **explicit un-delete** (a `live` write with a *greater* HLC than the certificate) supersedes
//!   it; a bare OR-Set add — which never writes the `deleted` field, so has no HLC on it — can
//!   **never** outrank a set death certificate.
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
use crate::wire::{
    AddTag, ClusterOp, DeleteClass, Hlc, DEATH_LIVE, OP_DELETE, OP_LWW_SET, OP_SET_ADD,
    OP_SET_REMOVE,
};
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
    if !matches!(op.kind, OP_SET_ADD | OP_SET_REMOVE | OP_LWW_SET | OP_DELETE) {
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
        OP_DELETE => {
            // A durable death-certificate write carries a **death token** in `field` and nothing
            // else: no LWW value (it does not write a scalar cell), no observed set (it is not an
            // OR-Set remove). The token is either a durable-delete class (`redact`/`expires`/
            // `sensitive`) or the explicit `live` un-delete; any other token is invalid.
            let field = op.field.as_deref().ok_or(SyncError::CrdtOpInvalid)?;
            if op.value.is_some() || op.observed.is_some() {
                return Err(SyncError::CrdtOpInvalid);
            }
            if field != DEATH_LIVE && DeleteClass::from_token(field).is_none() {
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

    /// **Stability-cut garbage collection (§5.6.5).** Drop every locally-dead add-tag (present in
    /// *both* `adds` and `tombstones`) whose HLC is `≤ cut`, where `cut` is the minimum per-device
    /// max-applied-HLC across all cluster members. Once a tombstone is stable — every member has
    /// applied at least up to it, and since add-tags are the globally-unique pair `{device, HLC}`
    /// no member can ever originate that tag again — the collapsed add+tombstone pair can never
    /// affect presence, so it is pure metadata bloat and is removed.
    ///
    /// This changes the *stored* representation but never the *observable* state
    /// ([`contains`](Self::contains) / [`elements`](Self::elements)): a dead tag contributes to
    /// presence neither before nor after. Because every replica derives the same `cut` from the same
    /// stability marks and drops the same tags, strong eventual consistency (byte-identical
    /// snapshots) is preserved. A tombstone whose matching add has not yet arrived locally is
    /// **kept** (it is still needed the instant the add lands) — only genuinely-collapsed pairs are
    /// reclaimed. Returns the number of tags reclaimed.
    pub fn prune_stable(&mut self, cut: &Hlc) -> usize {
        let mut pruned = 0usize;
        let elems: Vec<String> = self.tombstones.keys().cloned().collect();
        for elem in elems {
            // A tag is reclaimable iff it is tombstoned, its matching add is present locally, and
            // it is at/below the stability cut (so it can never again influence presence).
            let reclaim: Vec<AddTag> = {
                let dead = &self.tombstones[&elem];
                let adds = self.adds.get(&elem);
                dead.iter()
                    .filter(|t| t.hlc <= *cut && adds.is_some_and(|a| a.contains(*t)))
                    .cloned()
                    .collect()
            };
            if reclaim.is_empty() {
                continue;
            }
            if let Some(dead) = self.tombstones.get_mut(&elem) {
                for t in &reclaim {
                    dead.remove(t);
                }
                if dead.is_empty() {
                    self.tombstones.remove(&elem);
                }
            }
            if let Some(adds) = self.adds.get_mut(&elem) {
                for t in &reclaim {
                    adds.remove(t);
                }
                if adds.is_empty() {
                    self.adds.remove(&elem);
                }
            }
            pruned += reclaim.len();
        }
        pruned
    }
}

/// The state of a per-object **death certificate** (§5.6.4): the object is either `Live` or durably
/// `Deleted` under a [`DeleteClass`]. Ordered so that, at an exact HLC tie, `Deleted` beats `Live`
/// (remove-wins, fail-safe toward deletion) and a later class deterministically beats an earlier —
/// making the LWW join total and identical on every replica. In practice HLCs are globally unique
/// (the `device` field disambiguates), so the tie rule only guarantees determinism.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeathState {
    /// The object is live (never deleted, or explicitly un-deleted).
    Live,
    /// The object is durably deleted under this class.
    Deleted(DeleteClass),
}

impl DeathState {
    /// The durable-delete class if this certificate is `Deleted`.
    pub fn class(&self) -> Option<DeleteClass> {
        match self {
            DeathState::Live => None,
            DeathState::Deleted(c) => Some(*c),
        }
    }
}

/// The **remove-wins durable-delete dimension** (§5.6.4): a per-object HLC-keyed `deleted` flag —
/// an LWW register over the states `{live, deleted}` (a 2P-Set-style "death certificate"). Set with
/// the greatest HLC, it **dominates** the add-wins [`OrSet`]: a `Deleted` certificate makes the
/// object absent **regardless** of any un-tombstoned OR-Set add-tag, so a concurrent benign
/// re-label cannot resurrect a redacted/expired/sensitive object. Only an explicit un-delete (a
/// `Live` write with a *greater* HLC) supersedes a certificate; a bare OR-Set add never touches
/// this dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeathReg {
    /// object → the winning `(HLC, state)` of its death certificate.
    regs: BTreeMap<String, (Hlc, DeathState)>,
}

/// Whether a death write `(new_hlc, new_state)` beats the incumbent `(cur_hlc, cur_state)` — the
/// total, deterministic LWW join. Greater HLC wins; at an exact HLC tie the greater [`DeathState`]
/// wins (`Deleted` > `Live`), so an un-delete needs a *strictly greater* HLC to revive an object
/// and equal-HLC ties fail safe toward deletion.
fn death_wins(new_hlc: &Hlc, new_state: &DeathState, cur_hlc: &Hlc, cur_state: &DeathState) -> bool {
    match new_hlc.cmp(cur_hlc) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new_state > cur_state,
    }
}

impl DeathReg {
    /// An empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a death-certificate write to `object`; keeps it only if it beats the incumbent (LWW).
    pub fn write(&mut self, object: &str, hlc: Hlc, state: DeathState) {
        match self.regs.get(object) {
            Some((cur_hlc, cur_state)) if !death_wins(&hlc, &state, cur_hlc, cur_state) => {}
            _ => {
                self.regs.insert(object.to_owned(), (hlc, state));
            }
        }
    }

    /// The winning death state of `object` (default [`DeathState::Live`] if no certificate exists).
    pub fn state(&self, object: &str) -> DeathState {
        self.regs.get(object).map(|(_, s)| s.clone()).unwrap_or(DeathState::Live)
    }

    /// Whether `object` currently bears a `Deleted` death certificate (durably deleted).
    pub fn is_deleted(&self, object: &str) -> bool {
        matches!(self.regs.get(object), Some((_, DeathState::Deleted(_))))
    }

    /// The durable-delete class of `object`, if it is currently deleted.
    pub fn class(&self, object: &str) -> Option<DeleteClass> {
        self.regs.get(object).and_then(|(_, s)| s.class())
    }

    /// The sorted object ids currently bearing a `Deleted` certificate, each with its class — the
    /// observable output of the remove-wins dimension (used in [`ClusterState::snapshot`]).
    pub fn deleted(&self) -> Vec<(String, DeleteClass)> {
        self.regs
            .iter()
            .filter_map(|(o, (_, s))| s.class().map(|c| (o.clone(), c)))
            .collect()
    }

    /// Join with `other` (§5.6.4): per object, keep the winning certificate. HLC-max with the
    /// deterministic [`death_wins`] tiebreak is commutative, associative, and idempotent ⇒ a CvRDT.
    pub fn merge(&mut self, other: &DeathReg) {
        for (object, (hlc, state)) in &other.regs {
            match self.regs.get(object) {
                Some((cur_hlc, cur_state)) if !death_wins(hlc, state, cur_hlc, cur_state) => {}
                _ => {
                    self.regs.insert(object.clone(), (hlc.clone(), state.clone()));
                }
            }
        }
    }

    /// The maximum HLC across every death-certificate register — folded into the replica's §5.6.5
    /// stability watermark so a durable delete/un-delete advances GC like any other op.
    fn max_hlc(&self) -> Option<Hlc> {
        self.regs.values().map(|(h, _)| h.clone()).max()
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
    /// Benign, add-wins object / folder / label membership + benign label removes.
    pub set: OrSet,
    /// Per-field flags & moves (read/unread, star, current folder, …).
    pub lww: LwwMap,
    /// Remove-wins durable-delete death certificates; dominates [`set`](Self::set).
    pub deaths: DeathReg,
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
            OP_DELETE => {
                // The death token in `field` selects the certificate state: a class token ⇒ durable
                // `Deleted`, the `live` token ⇒ an explicit un-delete. (Validated by `validate_op`.)
                if let Some(field) = &op.field {
                    let state = match DeleteClass::from_token(field) {
                        Some(class) => DeathState::Deleted(class),
                        None => DeathState::Live, // `field == DEATH_LIVE`
                    };
                    self.deaths.write(&op.target, op.hlc.clone(), state);
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

    /// Join with `other` (§5.6.4): merge all three dimensions (OR-Set, LWW registers, remove-wins
    /// death certificates). Each is a CvRDT join ⇒ commutative, associative, idempotent.
    pub fn merge(&mut self, other: &ClusterState) {
        self.set.merge(&other.set);
        self.lww.merge(&other.lww);
        self.deaths.merge(&other.deaths);
    }

    /// Whether `target` is durably deleted — its death certificate is `Deleted` (§5.6.4). Dominates
    /// OR-Set membership.
    pub fn is_deleted(&self, target: &str) -> bool {
        self.deaths.is_deleted(target)
    }

    /// Whether `target` is **present**: the remove-wins death certificate is not `Deleted` **and**
    /// the add-wins OR-Set holds a live add-tag (§5.6.4). The durable-delete dimension dominates, so
    /// a concurrent benign re-label can never resurrect a redacted/expired/sensitive object.
    pub fn is_present(&self, target: &str) -> bool {
        !self.deaths.is_deleted(target) && self.set.contains(target)
    }

    /// The present OR-Set elements (§5.6.4), with any durably-deleted object filtered out.
    pub fn present_elements(&self) -> Vec<String> {
        self.set.elements().into_iter().filter(|e| !self.deaths.is_deleted(e)).collect()
    }

    /// Run the §5.6.5 stability-cut GC over the OR-Set half (see [`OrSet::prune_stable`]): reclaim
    /// collapsed add+tombstone pairs at/below `cut` without changing observable state. The LWW half
    /// is already bounded (one register per `(target, field)`), so it needs no tombstone GC. Returns
    /// the number of OR-Set tags reclaimed.
    pub fn prune_stable(&mut self, cut: &Hlc) -> usize {
        self.set.prune_stable(cut)
    }

    /// The maximum HLC this state has applied across every OR-Set add-tag / tombstone tag and every
    /// LWW register key — this replica's own §5.6.5 stability watermark (the mark it would advertise
    /// in a [`StabilityMark`](crate::wire::StabilityMark)). `None` if no op has been applied.
    pub fn max_hlc(&self) -> Option<Hlc> {
        let set_tags = self
            .set
            .adds
            .values()
            .chain(self.set.tombstones.values())
            .flat_map(|tags| tags.iter().map(|t| t.hlc.clone()));
        let lww_keys = self.lww.regs.values().map(|(h, _)| h.clone());
        set_tags.chain(lww_keys).chain(self.deaths.max_hlc()).max()
    }

    /// A canonical, order-independent snapshot of the *observable* state — present set elements and
    /// each cell's winning value — as deterministic CBOR bytes. Two replicas that have seen the same
    /// ops (in any order, with any duplication) produce **byte-identical** snapshots; this is the
    /// strong-eventual-consistency equality used by the convergence tests (§5.6.4).
    pub fn snapshot(&self) -> Vec<u8> {
        // Present members exclude durably-deleted objects (remove-wins death dimension dominates).
        let members: Vec<Cv> = self.present_elements().into_iter().map(Cv::Text).collect();
        let mut cells: Vec<Cv> = self
            .lww
            .regs
            .iter()
            .map(|((t, f), (_, v))| {
                Cv::Array(vec![Cv::Text(t.clone()), Cv::Text(f.clone()), v.clone()])
            })
            .collect();
        cells.sort_by(|a, b| cbor::encode(a).cmp(&cbor::encode(b)));
        // The observable output of the death dimension: each durably-deleted object with its class
        // token. A `Live` certificate contributes nothing (observationally identical to no cert), so
        // two replicas that converge on presence produce byte-identical snapshots.
        let deleted: Vec<Cv> = self
            .deaths
            .deleted()
            .into_iter()
            .map(|(o, c)| Cv::Array(vec![Cv::Text(o), Cv::Text(c.token().to_owned())]))
            .collect();
        cbor::encode(&Cv::Array(vec![Cv::Array(members), Cv::Array(cells), Cv::Array(deleted)]))
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
    /// A durable death-certificate (remove-wins) op of the given class.
    fn del(target: &str, class: DeleteClass, w: u64, d: u8) -> ClusterOp {
        ClusterOp::durable_delete(target, class, hlc(w, 0, d))
    }
    /// An explicit un-delete (write `live`) op.
    fn undel(target: &str, w: u64, d: u8) -> ClusterOp {
        ClusterOp::undelete(target, hlc(w, 0, d))
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
    fn stability_cut_prunes_stable_tombstones_without_changing_state() {
        // A delete: add "m"@(10,A), then remove it citing that add — a collapsed add+tombstone pair.
        let a_tag = AddTag { device: vec![0xA], hlc: hlc(10, 0, 0xA) };
        let mut s = state_of(&[add("m", 10, 0xA), remove("m", 11, 0xA, vec![a_tag.clone()])]);
        // A live element that must survive GC: add "keep"@(50,B), never removed.
        s.apply(&add("keep", 50, 0xB));

        assert!(!s.set.contains("m"), "the deleted element is absent");
        assert!(s.set.contains("keep"));
        let before = s.snapshot();
        // Metadata is present: "m" carries an add-tag and a tombstone.
        assert_eq!(s.set.adds.get("m").map(|t| t.len()), Some(1));
        assert_eq!(s.set.tombstones.get("m").map(|t| t.len()), Some(1));

        // Stability cut at (40,*) is above the delete's tags (≤ 11) but below "keep"'s live add (50).
        let cut = hlc(40, 0, 0);
        let reclaimed = s.prune_stable(&cut);
        assert_eq!(reclaimed, 1, "the one stable dead tag is reclaimed");
        // The dead element's metadata is gone entirely; the live element is untouched.
        assert!(s.set.adds.get("m").is_none() && s.set.tombstones.get("m").is_none());
        assert_eq!(s.set.adds.get("keep").map(|t| t.len()), Some(1));

        // Observable state is byte-identical before and after GC (SEC preserved).
        assert_eq!(s.snapshot(), before, "GC must not change observable state");
        assert!(!s.set.contains("m") && s.set.contains("keep"));

        // Merging an un-GC'd replica (still holding the dead pair) does not resurrect anything.
        let peer = state_of(&[add("m", 10, 0xA), remove("m", 11, 0xA, vec![a_tag])]);
        s.merge(&peer);
        assert!(!s.set.contains("m"), "a re-merged stable delete stays deleted");
        assert_eq!(s.snapshot(), before, "merge after GC leaves observable state unchanged");

        // A cut BELOW the tags reclaims nothing (fail-safe: nothing GC'd until proven stable).
        let mut s2 = state_of(&[add("x", 100, 1), remove("x", 101, 1, vec![AddTag { device: vec![1], hlc: hlc(100, 0, 1) }])]);
        assert_eq!(s2.prune_stable(&hlc(50, 0, 0)), 0);
        assert_eq!(s2.set.tombstones.get("x").map(|t| t.len()), Some(1));
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

    // ── D3: remove-wins durable delete (§5.6.4) ──────────────────────────────────────────────

    #[test]
    fn durable_delete_is_remove_wins_over_concurrent_benign_relabel() {
        // The resurrection hole an add-wins delete would leave open: A durably redacts a message
        // while B, never having seen the redaction, concurrently re-labels it (a benign OR-Set add
        // with a fresh, un-tombstoned add-tag). The death certificate DOMINATES the OR-Set, so the
        // message stays deleted — a concurrent re-label does not un-redact confidential content.
        let s = state_of(&[
            add("m1", 10, 0xA),                 // m1 was present (a live add-tag)
            del("m1", DeleteClass::Redact, 20, 0xA), // A redacts it (durable, remove-wins)
            add("m1", 21, 0xB),                 // B concurrently re-labels — a NEW, unseen add-tag
        ]);
        // The OR-Set alone would report it present (B's add-tag is un-tombstoned)...
        assert!(s.set.contains("m1"), "the OR-Set still holds a live add-tag");
        // ...but the remove-wins death certificate dominates: the object is absent.
        assert!(s.is_deleted("m1"));
        assert!(!s.is_present("m1"), "remove-wins: a concurrent benign re-label cannot resurrect it");
        assert!(!s.present_elements().contains(&"m1".to_string()));
        assert_eq!(s.deaths.class("m1"), Some(DeleteClass::Redact));

        // Order-independence: applying the same ops in any order converges identically.
        let reordered = state_of(&[add("m1", 21, 0xB), add("m1", 10, 0xA), del("m1", DeleteClass::Redact, 20, 0xA)]);
        assert_eq!(reordered.snapshot(), s.snapshot());
    }

    #[test]
    fn bare_orset_add_never_resurrects_a_durable_delete_even_with_greater_hlc() {
        // The exact delete/re-add tiebreak (§5.6.4): a bare OR-Set add — even one whose HLC is
        // GREATER than the death certificate's — never writes the `deleted` field, so it has no HLC
        // on that dimension and can NEVER outrank a set certificate. Only an explicit un-delete can.
        let s = state_of(&[
            del("m1", DeleteClass::Sensitive, 20, 0xA), // death certificate @ wall 20
            add("m1", 99, 0xB),                          // a bare add @ wall 99 (>> 20)
        ]);
        assert!(s.is_deleted("m1"), "a bare add, however late, does not un-delete");
        assert!(!s.is_present("m1"));
    }

    #[test]
    fn explicit_undelete_with_greater_hlc_readds_but_a_lesser_one_does_not() {
        // Only a genuine un-delete (a `live` write) with a *greater* HLC than the certificate
        // supersedes it (§5.6.4). Below/at the certificate's HLC it loses; above it, the object
        // reverts to its OR-Set membership (present again, since a live add-tag exists).
        let base = [add("m1", 5, 0xA), del("m1", DeleteClass::Expires, 20, 0xA)];

        // An un-delete BELOW the certificate loses ⇒ stays deleted.
        let mut lo = state_of(&base);
        lo.apply(&undel("m1", 15, 0xA));
        assert!(lo.is_deleted("m1"), "an un-delete with a lesser HLC cannot revive the object");

        // An un-delete ABOVE the certificate wins ⇒ live again (OR-Set add-tag makes it present).
        let mut hi = state_of(&base);
        hi.apply(&undel("m1", 25, 0xA));
        assert!(!hi.is_deleted("m1"));
        assert!(hi.is_present("m1"), "a greater-HLC un-delete re-adds the object");
        assert!(hi.present_elements().contains(&"m1".to_string()));
    }

    #[test]
    fn benign_label_remove_is_still_add_wins_alongside_the_death_dimension() {
        // Adding the remove-wins dimension must NOT change benign label semantics: a benign OR-Set
        // remove that did not observe a concurrent add still loses to it (add-wins), and no death
        // certificate is involved, so the label stays present.
        let a_tag = AddTag { device: vec![0xA], hlc: hlc(10, 0, 0xA) };
        let s = state_of(&[
            add("work", 10, 0xA),           // A labels "work"
            add("work", 11, 0xB),           // B concurrently re-labels "work" (unseen add-tag)
            remove("work", 12, 0xA, vec![a_tag]), // A un-labels, observing only its own tag
        ]);
        assert!(!s.is_deleted("work"), "a benign label remove is not a durable delete");
        assert!(s.is_present("work"), "add-wins: the concurrent unseen re-label survives the remove");
    }

    #[test]
    fn death_register_is_a_convergent_lww_commutative_and_idempotent() {
        // The death dimension is itself a CvRDT: concurrent delete/un-delete writes converge on the
        // greater-HLC winner regardless of order or duplication.
        let ops = [
            del("m", DeleteClass::Redact, 10, 0xA),
            undel("m", 20, 0xB),                 // greater HLC ⇒ live wins
            del("m", DeleteClass::Sensitive, 15, 0xC), // an intermediate delete
        ];
        let fwd = state_of(&ops);
        let mut rev: Vec<ClusterOp> = ops.iter().rev().cloned().collect();
        rev.push(ops[0].clone()); // duplicate one op (idempotency)
        let bwd = state_of(&rev);
        assert_eq!(fwd.snapshot(), bwd.snapshot(), "death register converges under any order");
        assert!(!fwd.is_deleted("m"), "the greatest-HLC write (un-delete @20) wins");

        // Merge of the two divergent replicas is the same fixed point (join).
        let mut merged = fwd.clone();
        merged.merge(&bwd);
        assert_eq!(merged.snapshot(), fwd.snapshot());
    }

    #[test]
    fn equal_hlc_tie_is_remove_wins_deleted_beats_live() {
        // Determinism at an exact HLC tie (pathological — HLCs are globally unique in practice):
        // `Deleted` beats `Live`, so ties fail safe toward deletion and merge stays commutative.
        let mut a = ClusterState::new();
        a.apply(&del("m", DeleteClass::Redact, 10, 0xA));
        a.apply(&undel("m", 10, 0xA)); // identical HLC ⇒ does not supersede
        assert!(a.is_deleted("m"), "an equal-HLC un-delete does not revive (remove-wins tie)");

        // Order-independent: live-then-delete lands identically.
        let mut b = ClusterState::new();
        b.apply(&undel("m", 10, 0xA));
        b.apply(&del("m", DeleteClass::Redact, 10, 0xA));
        assert_eq!(a.snapshot(), b.snapshot());
    }

    #[test]
    fn validate_durable_delete_and_undelete_ops() {
        // Well-formed durable-delete and un-delete ops validate.
        assert!(validate_op(&del("m", DeleteClass::Redact, 10, 1), 1_000_000).is_ok());
        assert!(validate_op(&undel("m", 10, 1), 1_000_000).is_ok());

        // A kind-4 op with no death token is invalid.
        let mut no_field = del("m", DeleteClass::Redact, 10, 1);
        no_field.field = None;
        assert_eq!(validate_op(&no_field, 1_000_000), Err(SyncError::CrdtOpInvalid));

        // A kind-4 op with an unknown token is invalid.
        let mut bad_token = del("m", DeleteClass::Redact, 10, 1);
        bad_token.field = Some("obliterate".into());
        assert_eq!(validate_op(&bad_token, 1_000_000), Err(SyncError::CrdtOpInvalid));

        // A kind-4 op may not smuggle an LWW value or an observed set.
        let mut with_value = del("m", DeleteClass::Redact, 10, 1);
        with_value.value = Some(Cv::Bool(true));
        assert_eq!(validate_op(&with_value, 1_000_000), Err(SyncError::CrdtOpInvalid));
        let mut with_obs = del("m", DeleteClass::Redact, 10, 1);
        with_obs.observed = Some(vec![AddTag { device: vec![1], hlc: hlc(5, 0, 1) }]);
        assert_eq!(validate_op(&with_obs, 1_000_000), Err(SyncError::CrdtOpInvalid));

        // The skew bound still applies to a durable delete.
        assert_eq!(validate_op(&del("m", DeleteClass::Redact, 300_000, 1), 0), Err(SyncError::CrdtOpInvalid));
    }

    // ── Property tests (§5.6.4): the merge is a CvRDT — commutative, associative, idempotent — so ──
    // ── over MANY random op sequences applied/merged in random orders every replica converges to a ──
    // ── byte-identical snapshot; and the D3 remove-wins invariant (a durable delete is never ──
    // ── resurrected by concurrent adds) holds across every random schedule. ──

    /// A tiny deterministic SplitMix64 PRNG — dependency-free, reproducible generative testing.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        /// A Fisher-Yates shuffle of `v`.
        fn shuffle<T>(&mut self, v: &mut [T]) {
            for i in (1..v.len()).rev() {
                let j = self.below(i + 1);
                v.swap(i, j);
            }
        }
    }

    /// Generate one random, well-formed op over small target/device alphabets so ops collide and
    /// concurrency is real (many ops touch the same object). Dense low `wall` values force HLC ties.
    fn gen_op(rng: &mut Rng) -> ClusterOp {
        let target = format!("o{}", rng.below(4));
        let wall = (rng.below(8)) as u64; // 0..=7 — heavy HLC collision
        let dev = rng.below(3) as u8;
        match rng.below(6) {
            0 | 1 => add(&target, wall, dev), // adds are common so removes/deletes have prey
            2 => {
                // A remove citing a causally-valid add-tag drawn from the same small space.
                let ow = wall.saturating_sub(rng.below(3) as u64);
                let od = rng.below(3) as u8;
                remove(&target, wall, dev, vec![AddTag { device: vec![od], hlc: hlc(ow, 0, od) }])
            }
            3 => lww(&target, &format!("f{}", rng.below(3)), wall, dev, Cv::U64(rng.next() % 5)),
            4 => {
                let class = match rng.below(3) {
                    0 => DeleteClass::Redact,
                    1 => DeleteClass::Expires,
                    _ => DeleteClass::Sensitive,
                };
                del(&target, class, wall, dev)
            }
            _ => undel(&target, wall, dev),
        }
    }

    #[test]
    fn crdt_merge_converges_under_random_schedules_and_d3_holds() {
        let mut rng = Rng(0xC0FFEE_5E6);
        for _ in 0..20_000 {
            let n = 1 + rng.below(24);
            let ops: Vec<ClusterOp> = (0..n).map(|_| gen_op(&mut rng)).collect();

            // The reference snapshot: all ops applied to a fresh state, in generation order.
            let reference = state_of(&ops).snapshot();

            // (1) Commutativity: a random permutation of the SAME ops converges identically.
            let mut permuted = ops.clone();
            rng.shuffle(&mut permuted);
            assert_eq!(reference, state_of(&permuted).snapshot(), "random-order apply must converge");

            // (2) Associativity via a per-op singleton fold, merged in a random order.
            let mut singletons: Vec<ClusterState> = ops
                .iter()
                .map(|op| {
                    let mut s = ClusterState::new();
                    s.apply(op);
                    s
                })
                .collect();
            rng.shuffle(&mut singletons);
            let mut folded = ClusterState::new();
            for s in &singletons {
                folded.merge(s);
            }
            assert_eq!(reference, folded.snapshot(), "singleton-merge fold must converge");

            // (3) Two independent replicas that each saw a random subset, then exchanged, converge —
            // and to the same fixed point as the full application (join = least upper bound).
            let mut ra = ClusterState::new();
            let mut rb = ClusterState::new();
            for op in &ops {
                if rng.next() & 1 == 0 {
                    ra.apply(op);
                } else {
                    rb.apply(op);
                }
                // Sprinkle in cross-merges at random points (anti-entropy at arbitrary times).
                if rng.next() % 5 == 0 {
                    ra.merge(&rb);
                }
            }
            let mut ab = ra.clone();
            ab.merge(&rb);
            let mut ba = rb.clone();
            ba.merge(&ra);
            assert_eq!(ab.snapshot(), ba.snapshot(), "A∨B == B∨A (commutative merge)");
            assert_eq!(reference, ab.snapshot(), "gossiping replicas reach the full-apply fixed point");

            // (4) Idempotence: merging the converged state with itself, and re-applying every op a
            // second time, changes nothing.
            let mut idem = state_of(&ops);
            let copy = idem.clone();
            idem.merge(&copy);
            for op in &ops {
                idem.apply(op);
            }
            assert_eq!(reference, idem.snapshot(), "merge(x,x)=x and re-applying seen ops is a no-op");

            // (5) D3 remove-wins invariant: in EVERY converged replica, a durably-deleted object is
            // never present — no concurrent OR-Set add-tag, at any HLC, resurrects it.
            let converged = state_of(&ops);
            for target in ["o0", "o1", "o2", "o3"] {
                if converged.is_deleted(target) {
                    assert!(!converged.is_present(target), "D3: a durable delete is never present");
                    assert!(!converged.present_elements().contains(&target.to_string()));
                    // The domination holds identically in the gossiped replica.
                    assert_eq!(ab.is_deleted(target), converged.is_deleted(target));
                    assert!(!ab.is_present(target));
                }
            }
        }
    }
}
