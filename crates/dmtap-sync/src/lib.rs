//! # dmtap-sync — DMTAP substrate capability ③, **Sync** (`dmtap/substrate/SYNC.md`)
//!
//! The shared sync engine: a **signed, deterministic, multi-author CRDT operation algebra** with
//! range-Merkle reconciliation, first-class signed snapshots, and sparse namespace sync.
//!
//! ## What this adds over §5.6 (`dmtap-clustersync`)
//!
//! §5.6 is the normative home of the **single-owner device cluster**: every writer is a device of
//! one identity, and ops ride **unsigned** inside an MLS group, so authenticity is ambient group
//! membership. This crate is the **multi-author generalization**, and the whole difference is one
//! decision: **the operation itself is the unit of authenticity.** Each op is COSE-signed
//! ([`cose`], RFC 9052) by an author key that chains to an `IK`, so no shared secret group is
//! required and two products built by different parties can converge on any namespace they both
//! subscribe to. Where this crate and §5.6 overlap, the semantics are identical
//! (`tests/clustersync_parity.rs` proves it op-for-op).
//!
//! ## Modules
//!
//! * [`detcbor`] — deterministic CBOR over the `ext-value` domain (§2.2, §18.1.1), including the
//!   negative integers a PN-counter delta needs.
//! * [`wire`] — [`Hlc`](wire::Hlc) (§3), the [`SyncOp`](wire::SyncOp) envelope and the `op-id`
//!   content address (§4.1).
//! * [`cose`] — the frozen `COSE_Sign1` op envelope: `protected = {1: -8, 4: kid}`, empty
//!   unprotected, inline payload, and the DS-tag `DMTAP-SYNC-v0/op ‖ 0x00` carried in
//!   `external_aad` (§4.1, `SYNC-OP-02`).
//! * [`crdt`] — all six CRDT types (§4.3–§4.8) plus the state-free fail-closed validators.
//! * [`state`] — [`SyncState`](state::SyncState), the idempotent ingest path, the
//!   [`VersionVector`](state::VersionVector) (§5.1), sparse scoping (§7) and the stability cut
//!   (§6.2).
//! * [`snapshot`] — the canonical six-section [`ObservableState`](snapshot::ObservableState) and
//!   the signed [`Snapshot`](snapshot::Snapshot) (§6.1/§6.1.1).
//! * [`recon`] — the range-Merkle fingerprint fold and the recursive diff (§5.3).
//!
//! ## Fail-closed posture
//!
//! Every ingest path verifies the op signature (`0x0A02`), checks author admission (`0x0A01`), and
//! validates structure/causality/skew (`0x0A03`, `0x0A05`) **before** touching state; a
//! cross-namespace reference (`0x0A0A`), a foreign counter entry (`0x0A06`), or a recomputed
//! snapshot root that disagrees (`0x0A09`) is a refusal, never a silent degradation. See
//! [`error::SyncError`] for the full `0x0A` block.
//!
//! ## Honest limits
//!
//! Sync is **not** sealed-sender: every op carries its author and HLC, visible to every replica in
//! the namespace — multi-author convergence needs attributable ops. A compromised author key can
//! write ops until revoked, and because replicated history is durable a malicious write must be
//! *superseded* by a later op, not "deleted". A trusted-checkpoint snapshot trusts its signer for
//! pre-`covers` history until backfilled and recomputed.

#![forbid(unsafe_code)]

pub mod cose;
pub mod crdt;
pub mod detcbor;
pub mod error;
pub mod recon;
pub mod snapshot;
pub mod state;
pub mod wire;

pub use cose::{sign_op, verify_op, verify_op_bytes, CoseSign1};
pub use crdt::{
    check_admitted, check_counter_entry, check_ns_ref, validate_op, DeathClass, DeathReg,
    DeathState, LwwMap, OrSet, PnCounter, RgaSeq, Tree, TreeReplay, SEQ_BUFFER_LIMIT,
};
pub use detcbor::{DetCborError, SVal};
pub use error::{Action, SyncError};
pub use recon::{fingerprint, reconcile, summarize, OpEntry, RangeFingerprint, ReconConfig,
    ReconOutcome};
pub use snapshot::{state_root, verify_root, ObservableState, Snapshot};
pub use state::{scope_to_subscription, stability_cut, SyncState, VersionVector};
pub use wire::{
    ds_hash, op_id_of, AddTag, Hlc, OpRef, SyncOp, DEATH_LIVE, DS_OP, DS_OP_ID, DS_RECON_FP,
    DS_SNAPSHOT, DS_SNAPSHOT_STATE, HLC_SKEW_MS, OP_COUNTER, OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT,
    OP_SEQ_REMOVE, OP_SET_ADD, OP_SET_REMOVE, OP_TREE_MOVE, TREE_ROOT,
};
