//! # dmtap-clustersync — DMTAP device-cluster sync (§5.6 / §18.6.3)
//!
//! An owner's devices (a laptop, a home box, a VPS) form a **personal cluster** that converges on
//! **every** mail, chat, and file — live and historical — with **no primary and no central
//! server** (spec §8.5 decentralization invariant, realised via §5.6). This crate is the reference
//! implementation of that convergence:
//!
//! * [`wire`] — the [`ClusterSyncFrame`] / [`ClusterOp`] / [`RangeFingerprint`] / [`JournalEntry`]
//!   / [`Hlc`] / [`AddTag`] / [`StabilityMark`] wire objects (§18.6.3), encoded in canonical §18.1
//!   CBOR through dmtap-core's single codec — round-tripping and **failing closed** on any
//!   non-canonical byte, unknown frame type, unknown key, or non-`ext-value` LWW value.
//! * [`crdt`] — the CRDT merge semantics (§5.6.4): an **OR-Set** for membership/labels/deletes and
//!   a **hybrid-logical-clock LWW register** per scalar field. The merge is **commutative,
//!   associative, and idempotent** ⇒ strong eventual consistency. `validate_op` rejects an
//!   out-of-skew HLC, an unknown kind, a causally-impossible remove, or an embedded
//!   `DeniablePayload` (`0x0413`).
//! * [`recon`] — **range-based Merkle set-reconciliation** (§5.6.3(a)): two devices diff their
//!   object-id sets in **O(differences · log n)**, exchanging only what differs, with
//!   **self-verifying** fingerprints (`0x0411`).
//! * [`journal`] — **append-only hash-chained journal replay** (§5.6.3(b)) for backfill, halting on
//!   a forked/rewritten own-log (`0x0412`).
//! * [`cluster`] — **mutually-authenticated membership** (§5.6.1) over a pinned `Identity`, plus the
//!   eager-replication + backfill engine ([`Replica`]) that brings a lagging or brand-new device to
//!   parity (`0x0410`).
//!
//! ## Why these CRDT primitives
//!
//! Mailbox metadata is concurrent, add-and-remove, coordinator-free. A grow-only set cannot
//! un-read or un-label; a plain last-writer-wins *set* loses the "a concurrent add beats a delete
//! that never saw it" property mail needs; a LWW register on *membership* would silently drop a
//! concurrent add. So §5.6.4 fixes **OR-Set** (add-wins membership with real, non-destructive
//! tombstone deletes) for set-valued data, and a **per-field HLC-LWW register** (a deterministic
//! single-value winner under the total order `(wall, counter, device)`) for scalar flags. Both are
//! state-based CvRDTs whose `merge` is a join — the algebraic guarantee behind convergence.
//!
//! ## Fail-closed posture
//!
//! Every ingest path authenticates the origin device (`0x0410`), validates structure and canonical
//! encoding (`0x18.1` errors), and rejects a forged reconciliation summary (`0x0411`), a forked
//! journal (`0x0412`), or an invalid/forbidden CRDT op (`0x0413`) **before** touching state. See
//! [`error::SyncError`] for the full taxonomy. This crate depends only on dmtap-core's public API,
//! `std`, and nothing else.

#![forbid(unsafe_code)]

pub mod cluster;
pub mod crdt;
pub mod error;
pub mod journal;
pub mod recon;
pub mod wire;

pub use cluster::{Cluster, Replica};
pub use crdt::{validate_op, ClusterState, LwwMap, OrSet, HLC_SKEW_MS};
pub use error::{Action, SyncError};
pub use journal::{genesis_prev, verify_segment, Journal};
pub use recon::{range_fingerprint, reconcile, verify_range, ReconConfig, ReconOutcome};
pub use wire::{
    AddTag, ClusterOp, ClusterSyncFrame, Hash, Hlc, JournalEntry, RangeFingerprint, StabilityMark,
    FRAME_ANNOUNCE, FRAME_FETCH, FRAME_JOURNAL, FRAME_RECON, FRAME_STABILITY, OP_LWW_SET,
    OP_SET_ADD, OP_SET_REMOVE,
};

#[cfg(test)]
mod convergence_tests {
    //! DMTAP-SYNC-05: two replicas applying the same concurrent OR-Set + LWW ops in **any order**
    //! reach the **identical** state — the strong-eventual-consistency conformance property.

    use super::*;
    use dmtap_core::cbor::Cv;

    fn hlc(wall: u64, counter: u32, device: u8) -> Hlc {
        Hlc { wall, counter, device: vec![device] }
    }

    /// Apply a list of ops to a fresh [`ClusterState`] in the given order (each validated first).
    fn apply_all(ops: &[ClusterOp]) -> ClusterState {
        let mut s = ClusterState::new();
        for op in ops {
            s.ingest(op, 10_000_000).expect("op must validate");
        }
        s
    }

    #[test]
    fn two_replicas_converge_under_any_order() {
        // A realistic concurrent history: two devices add and flag messages, one deletes what it
        // saw, the other concurrently re-labels and re-reads.
        let dev_a: u8 = 0xA;
        let dev_b: u8 = 0xB;

        let add_m1_a = ClusterOp {
            kind: OP_SET_ADD,
            target: "m1".into(),
            field: None,
            value: None,
            hlc: hlc(100, 0, dev_a),
            observed: None,
        };
        let add_m1_b = ClusterOp {
            kind: OP_SET_ADD,
            target: "m1".into(),
            field: None,
            value: None,
            hlc: hlc(101, 0, dev_b), // concurrent, distinct add-tag
            observed: None,
        };
        // A removes the add-tag it saw (its own), but NOT B's concurrent unseen add.
        let rm_m1_a = ClusterOp {
            kind: OP_SET_REMOVE,
            target: "m1".into(),
            field: None,
            value: None,
            hlc: hlc(102, 0, dev_a),
            observed: Some(vec![AddTag { device: vec![dev_a], hlc: hlc(100, 0, dev_a) }]),
        };
        let read_lo = ClusterOp {
            kind: OP_LWW_SET,
            target: "m1".into(),
            field: Some("read".into()),
            value: Some(Cv::Bool(false)),
            hlc: hlc(105, 0, dev_a),
            observed: None,
        };
        let read_hi = ClusterOp {
            kind: OP_LWW_SET,
            target: "m1".into(),
            field: Some("read".into()),
            value: Some(Cv::Bool(true)),
            hlc: hlc(106, 0, dev_b), // greater HLC ⇒ wins
            observed: None,
        };
        let folder = ClusterOp {
            kind: OP_LWW_SET,
            target: "m1".into(),
            field: Some("folder".into()),
            value: Some(Cv::Text("archive".into())),
            hlc: hlc(107, 1, dev_a),
            observed: None,
        };

        let ops = [add_m1_a, add_m1_b, rm_m1_a, read_lo, read_hi, folder];

        // Replica 1 applies them in declared order.
        let order1 = apply_all(&ops);
        // Replica 2 applies a shuffled order (reverse), plus a duplicate to exercise idempotency.
        let mut shuffled: Vec<ClusterOp> = ops.iter().rev().cloned().collect();
        shuffled.push(ops[0].clone()); // re-deliver an op
        shuffled.push(ops[4].clone()); // re-deliver the winning read
        let order2 = apply_all(&shuffled);

        // Strong eventual consistency: identical observable state regardless of order/duplication.
        assert_eq!(order1.snapshot(), order2.snapshot(), "replicas must converge byte-identically");

        // And the merge of the two divergent-intermediate replicas is the same fixed point.
        let mut merged = order1.clone();
        merged.merge(&order2);
        assert_eq!(merged.snapshot(), order1.snapshot());

        // Semantic checks on the converged state:
        // - add-wins: m1 present (B's unseen add survived A's remove).
        assert!(order1.set.contains("m1"));
        // - greater-HLC LWW: read = true (dev_b @106 beat dev_a @105).
        assert_eq!(order1.lww.get("m1", "read"), Some(&Cv::Bool(true)));
        // - folder set by the sole writer.
        assert_eq!(order1.lww.get("m1", "folder"), Some(&Cv::Text("archive".into())));
    }

    #[test]
    fn frames_carrying_ops_round_trip_and_apply_identically() {
        // The ops also converge when they travel as encoded ClusterSyncFrames (wire path).
        let ops = vec![
            ClusterOp {
                kind: OP_SET_ADD,
                target: "x".into(),
                field: None,
                value: None,
                hlc: hlc(1, 0, 1),
                observed: None,
            },
            ClusterOp {
                kind: OP_LWW_SET,
                target: "x".into(),
                field: Some("star".into()),
                value: Some(Cv::Bool(true)),
                hlc: hlc(2, 0, 1),
                observed: None,
            },
        ];
        let frame = ClusterSyncFrame::new(FRAME_ANNOUNCE, vec![1]).with_ops(ops.clone());
        let decoded = ClusterSyncFrame::from_det_cbor(&frame.det_cbor()).unwrap();
        assert_eq!(decoded.ops, ops);

        let direct = apply_all(&ops);
        let viawire = apply_all(&decoded.ops);
        assert_eq!(direct.snapshot(), viawire.snapshot());
    }
}
