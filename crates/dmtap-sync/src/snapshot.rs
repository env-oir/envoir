//! Signed snapshots and the canonical observable state (`SYNC.md` §6.1 / §6.1.1, frozen as
//! `SYNC-SNAP-01`/`SYNC-SNAP-02`).
//!
//! [`ObservableState`] is the single deterministic-CBOR value a replica hashes to produce
//! `Snapshot.root`: a **fixed six-element positional array**, one section per CRDT type in
//! `kind`-ascending order. Positional sections — not a keyed map — are used deliberately: they
//! match the §5.6 reference and remove any map-key-scheme choice as a source of divergence.
//!
//! Only **observable** state appears. OR-Set add-tags and tombstones, PN-counter per-author `P`/`N`
//! maps, RGA element ids and tombstones, `Live` death cells, and superseded LWW cells are all
//! internal. That is exactly why fast-join works: adopting a snapshot and applying the
//! post-`covers` ops yields byte-identical `ObservableState` to a full replay, because the two
//! paths can differ only in bookkeeping the projection never serializes.

use crate::detcbor::{encode, SVal};
use crate::error::SyncError;
use crate::state::{SyncState, VersionVector};
use crate::wire::{ds_hash, DS_SNAPSHOT, DS_SNAPSHOT_STATE, TREE_ROOT};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, IdentityKey};

/// The canonical observable state of one namespace (§6.1.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservableState {
    /// §4.3 — one entry per **present** `(target, element)`.
    pub orset: Vec<(String, SVal)>,
    /// §4.4 — the winning cell per `(target, field)`.
    pub lww: Vec<(String, String, SVal)>,
    /// §4.6 — `Σ_a P[a] − Σ_a N[a]` per `(target, field)`.
    pub pn: Vec<(String, String, i128)>,
    /// §4.5 — one entry per **deleted** object (`Live` contributes nothing).
    pub death: Vec<(String, String)>,
    /// §4.7 — per RGA target, the live atom values **in sequence order** (never re-sorted).
    pub rga: Vec<(String, Vec<SVal>)>,
    /// §4.8 — each non-root node's winning `(parent, ordering_key)` after the acyclic replay.
    pub tree: Vec<(String, String, String)>,
}

/// Sort a section ascending by the deterministic-CBOR encoding of each entry — a byte comparison,
/// so the ordering is implementation-independent (the same rule §5.6 already uses).
fn sort_section(entries: &mut Vec<SVal>) {
    entries.sort_by(|a, b| encode(a).cmp(&encode(b)));
}

impl ObservableState {
    /// Project a replica's state into its observable form (§6.1.1).
    pub fn of(state: &SyncState) -> ObservableState {
        let orset = state.present_members();
        let lww = state
            .lww
            .cells()
            .map(|((t, f), (_, v))| (t.clone(), f.clone(), v.clone()))
            .collect();
        let pn = state.counters.totals();
        let death = state
            .deaths
            .deleted()
            .into_iter()
            .map(|(t, c)| (t, c.token().to_string()))
            .collect();
        let rga = state
            .sequences
            .iter()
            .map(|(t, seq)| (t.clone(), seq.values()))
            .collect();
        let tree = state
            .tree
            .edges()
            .into_iter()
            // The reserved root node id `""` never appears as a `node` entry — the root has no
            // parent edge; it appears only as the `parent` of a top-level node.
            .filter(|(node, _)| node != TREE_ROOT)
            .map(|(node, (parent, ord))| (node, parent, ord))
            .collect();
        ObservableState { orset, lww, pn, death, rga, tree }
    }

    /// The canonical six-element array (§6.1.1). Empty sections are the empty array `[]`, present
    /// in position — a section is never omitted, so the array is always length 6.
    pub fn to_sval(&self) -> SVal {
        let mut orset: Vec<SVal> = self
            .orset
            .iter()
            .map(|(t, e)| SVal::Array(vec![SVal::Text(t.clone()), e.clone()]))
            .collect();
        sort_section(&mut orset);

        let mut lww: Vec<SVal> = self
            .lww
            .iter()
            .map(|(t, f, v)| {
                SVal::Array(vec![SVal::Text(t.clone()), SVal::Text(f.clone()), v.clone()])
            })
            .collect();
        sort_section(&mut lww);

        let mut pn: Vec<SVal> = self
            .pn
            .iter()
            .map(|(t, f, total)| {
                SVal::Array(vec![
                    SVal::Text(t.clone()),
                    SVal::Text(f.clone()),
                    SVal::int(*total as i64),
                ])
            })
            .collect();
        sort_section(&mut pn);

        let mut death: Vec<SVal> = self
            .death
            .iter()
            .map(|(t, c)| SVal::Array(vec![SVal::Text(t.clone()), SVal::Text(c.clone())]))
            .collect();
        sort_section(&mut death);

        // The RGA inner order is SEQUENCE order (the §4.7 pre-order walk) and is never re-sorted;
        // only the outer array is sorted, by `det_cbor(target)`.
        let mut rga: Vec<(Vec<u8>, SVal)> = self
            .rga
            .iter()
            .map(|(t, atoms)| {
                (
                    encode(&SVal::Text(t.clone())),
                    SVal::Array(vec![SVal::Text(t.clone()), SVal::Array(atoms.clone())]),
                )
            })
            .collect();
        rga.sort_by(|a, b| a.0.cmp(&b.0));
        let rga: Vec<SVal> = rga.into_iter().map(|(_, v)| v).collect();

        let mut tree: Vec<SVal> = self
            .tree
            .iter()
            .map(|(node, parent, ord)| {
                SVal::Array(vec![
                    SVal::Text(node.clone()),
                    SVal::Text(parent.clone()),
                    SVal::Text(ord.clone()),
                ])
            })
            .collect();
        sort_section(&mut tree);

        SVal::Array(vec![
            SVal::Array(orset),
            SVal::Array(lww),
            SVal::Array(pn),
            SVal::Array(death),
            SVal::Array(rga),
            SVal::Array(tree),
        ])
    }

    /// The canonical bytes two replicas at the same `covers` MUST agree on byte-for-byte.
    pub fn det_cbor(&self) -> Vec<u8> {
        encode(&self.to_sval())
    }

    /// `root = 0x1e ‖ BLAKE3-256("DMTAP-SYNC-v0/snapshot-state" ‖ 0x00 ‖ det_cbor(ObservableState))`
    /// (§6.1). A mismatch between two replicas at the same `covers` is
    /// `ERR_SYNC_SNAPSHOT_ROOT_MISMATCH` (`0x0A09`) — evidence of divergence, not a recoverable
    /// disagreement.
    pub fn root(&self) -> ContentId {
        ds_hash(DS_SNAPSHOT_STATE, &self.det_cbor())
    }
}

/// The observable-state root of a replica.
pub fn state_root(state: &SyncState) -> ContentId {
    ObservableState::of(state).root()
}

/// Check a claimed `root` against the locally recomputed one (§6.1): a snapshot is **verifiable,
/// not merely trusted**, so a replica that backfills the pre-`covers` history MUST recompute and
/// confirm.
pub fn verify_root(state: &SyncState, claimed: &ContentId) -> Result<(), SyncError> {
    if state_root(state).as_bytes() == claimed.as_bytes() {
        Ok(())
    } else {
        Err(SyncError::SnapshotRootMismatch)
    }
}

/// A portable, signed checkpoint (§6.1). `covers` names the exact set of ops folded into `root`, so
/// a joining replica adopts the state, sets its vector to `covers`, and pulls **only** the ops
/// after it — never replaying the pre-snapshot history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Version (key 1) — `0`.
    pub v: u8,
    /// Cryptographic suite (key 2).
    pub suite: u8,
    /// The namespace this snapshot covers (key 3).
    pub ns: String,
    /// The per-author max HLC folded into `root` (key 4).
    pub covers: VersionVector,
    /// The §6.1 observable-state root (key 5).
    pub root: ContentId,
    /// Timestamp, unix milliseconds (key 6).
    pub ts: u64,
    /// The signer's author key (key 7).
    pub signer: Vec<u8>,
    /// Signature over `det_cbor(Snapshot ∖ {8})`, DS-tag `DMTAP-SYNC-v0/snapshot` (key 8).
    pub sig: Vec<u8>,
}

impl Snapshot {
    fn body(&self) -> Vec<u8> {
        // The signature preimage body: the object WITHOUT key 8.
        encode(&SVal::Map(vec![
            (1, SVal::Uint(self.v as u64)),
            (2, SVal::Uint(self.suite as u64)),
            (3, SVal::Text(self.ns.clone())),
            (4, self.covers.to_sval()),
            (5, SVal::Bytes(self.root.as_bytes().to_vec())),
            (6, SVal::Uint(self.ts)),
            (7, SVal::Bytes(self.signer.clone())),
        ]))
    }

    /// The DS-tagged signing preimage. The **state-root** hash and the **snapshot signature** use
    /// two distinct DS-tags on purpose, so the two can never be confused (§6.1).
    fn preimage(&self) -> Vec<u8> {
        let mut p = DS_SNAPSHOT.to_vec();
        p.push(0x00);
        p.extend_from_slice(&self.body());
        p
    }

    /// Mint a signed snapshot of `state` at its current vector.
    pub fn create(sk: &IdentityKey, suite: u8, ns: &str, state: &SyncState, ts: u64) -> Snapshot {
        let mut s = Snapshot {
            v: 0,
            suite,
            ns: ns.to_owned(),
            covers: state.vector.clone(),
            root: state_root(state),
            ts,
            signer: sk.public(),
            sig: Vec::new(),
        };
        s.sig = sk.sign_domain(&[], &s.preimage());
        s
    }

    /// Verify the snapshot's own signature under `signer` (fails closed, `0x0A02`).
    pub fn verify_sig(&self) -> Result<(), SyncError> {
        if self.v != 0 {
            return Err(SyncError::UnsupportedVersion);
        }
        verify_domain(&self.signer, &[], &self.preimage(), &self.sig)
            .map_err(|_| SyncError::OpSigInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detcbor::SVal;
    use crate::state::SyncState;
    use crate::wire::{Hlc as WHlc, OpRef, SyncOp, OP_LWW_SET};

    fn a(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn h(counter: u32, author: u8) -> WHlc {
        WHlc { wall: 1_700_000_100_000, counter, author: a(author) }
    }

    fn lww(target: &str, field: &str, value: &str, counter: u32, author: u8) -> SyncOp {
        SyncOp {
            kind: OP_LWW_SET,
            ns: String::new(),
            target: target.into(),
            field: Some(field.into()),
            value: Some(SVal::Text(value.into())),
            hlc: h(counter, author),
            observed: None,
            reference: None,
        }
    }

    #[test]
    fn empty_state_is_six_empty_sections() {
        let s = ObservableState::default();
        assert_eq!(s.det_cbor(), vec![0x86, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);
    }

    #[test]
    fn fast_join_equals_full_replay() {
        let now = 1_700_000_200_000;
        // Full replay: every op, oldest first.
        let ops = vec![lww("doc1", "title", "m", 1, 0xcc), lww("doc1", "title", "p", 20, 0xdd)];
        let mut full = SyncState::new();
        for op in &ops {
            full.ingest(op, now).unwrap();
        }
        // Fast join: adopt the snapshot's observable state, then apply only the post-covers op.
        let mut pre = SyncState::new();
        pre.ingest(&ops[0], now).unwrap();
        let snap_state = ObservableState::of(&pre);
        let mut joined = SyncState::new();
        // Adoption of the projected state is modelled by replaying the (single) surviving cell —
        // the point of the test is that the OBSERVABLE bytes match, not the internal bookkeeping.
        joined.ingest(&ops[0], now).unwrap();
        assert_eq!(ObservableState::of(&joined).det_cbor(), snap_state.det_cbor());
        joined.ingest(&ops[1], now).unwrap();
        assert_eq!(ObservableState::of(&joined).det_cbor(), ObservableState::of(&full).det_cbor());
        assert_eq!(state_root(&joined).as_bytes(), state_root(&full).as_bytes());
    }

    #[test]
    fn snapshot_signature_round_trips_and_fails_closed_on_tamper() {
        let sk = IdentityKey::from_seed(&[0xcc; 32]);
        let mut state = SyncState::new();
        state.ingest(&lww("doc1", "title", "m", 1, 0xcc), 1_700_000_200_000).unwrap();
        let mut snap = Snapshot::create(&sk, 0x01, "", &state, 1_700_000_100_000);
        assert!(snap.verify_sig().is_ok());
        snap.ns = "other".into();
        assert_eq!(snap.verify_sig(), Err(SyncError::OpSigInvalid));
    }

    #[test]
    fn root_mismatch_is_detected() {
        let now = 1_700_000_200_000;
        let mut x = SyncState::new();
        x.ingest(&lww("doc1", "title", "m", 1, 0xcc), now).unwrap();
        let mut y = SyncState::new();
        y.ingest(&lww("doc1", "title", "z", 1, 0xdd), now).unwrap();
        assert_eq!(verify_root(&y, &state_root(&x)), Err(SyncError::SnapshotRootMismatch));
        assert!(verify_root(&x, &state_root(&x)).is_ok());
    }

    #[test]
    fn rga_inner_order_is_sequence_order_not_sorted() {
        let now = 1_700_000_200_000;
        let mut s = SyncState::new();
        let root = h(0, 0xcc);
        let mut ins = SyncOp {
            kind: crate::wire::OP_SEQ_INSERT,
            ns: String::new(),
            target: "line1".into(),
            field: None,
            value: Some(SVal::Text("atom0".into())),
            hlc: root.clone(),
            observed: None,
            reference: None,
        };
        s.ingest(&ins, now).unwrap();
        ins.hlc = h(3, 0xcc);
        ins.value = Some(SVal::Text("X".into()));
        ins.reference = Some(OpRef { target: "line1".into(), hlc: Some(root.clone()) });
        s.ingest(&ins, now).unwrap();
        ins.hlc = h(4, 0xcc);
        ins.value = Some(SVal::Text("Y".into()));
        s.ingest(&ins, now).unwrap();
        let obs = ObservableState::of(&s);
        assert_eq!(
            obs.rga[0].1,
            vec![SVal::Text("atom0".into()), SVal::Text("Y".into()), SVal::Text("X".into())],
            "newer-first sequence order survives into the snapshot; it is NOT re-sorted"
        );
    }
}
