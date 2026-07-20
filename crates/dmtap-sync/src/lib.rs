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
//! [`snapshot`] also carries the §5.2.1 fast-join path: [`FastJoin`] (the `pull` answer to a caller
//! below a §6.2 truncation floor), the responder predicate [`caller_is_below_floor`], and
//! [`FastJoin::adopt`], the fail-closed caller-side sequence. There is no fallback to the surviving
//! suffix on any failure there — that fallback is the silent lost-write §5.2.1 exists to prevent.
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

//! ## Mixed-deployment note: the `ext-value` widening (§14 C-08)
//!
//! [`SVal::is_ext_value`](detcbor::SVal::is_ext_value) now accepts the **whole** §18.3.6
//! `ext-value` — text-keyed maps and heterogeneous arrays included — where it previously
//! implemented §4.1's narrower prose. That is a **widening**, and a widening has a failure mode a
//! narrowing does not: **a mixed deployment diverges by *rejection*.** An engine on the old profile
//! refuses, with `0x0A03`, an op an updated engine accepts and applies; the two replicas then hold
//! different op sets and different roots, with an error raised on only one side. Nothing here can
//! detect that from the other end — a refusal is indistinguishable from an op that never arrived.
//!
//! So it is a **deployment** obligation, expressed where capability negotiation lives (the `sync-1`
//! capability, `envoir-node`'s `syncserve`), not a runtime check: see [`EXT_VALUE_PROFILE`] and
//! `SYNC.md` §4.1.2's `sync-1/ext-value-2` sub-token (correction C-13b — the mechanism this note
//! originally said the specification lacked). Until every engine in a namespace is confirmed on
//! profile `2`, a product SHOULD keep carrying structured content as an opaque payload (§4.1.1) —
//! which is exactly what the first adopter did, and why C-08 was found.

#![forbid(unsafe_code)]

/// This engine's accepted-`ext-value` profile.
///
/// * `1` — §4.1's pre-C-08 prose: scalars and **homogeneous** arrays only; no map arm.
/// * `2` — §18.3.6's full recursive `ext-value`: heterogeneous arrays **and** text-keyed maps,
///   bounded by [`detcbor::MAX_NESTING_DEPTH`]. **This crate is profile 2.**
///
/// The number is this implementation's handle on the widening; the wire form of the same fact is
/// now frozen by `SYNC.md` §4.1.2 (correction C-13b) as the `sync-1` sub-token `sync-1/ext-value-2`
/// — see `envoir-node`'s `syncserve::SYNC1_EXT_VALUE_2`, whose spelling the specification adopted
/// verbatim. It is carried in the `sync-1` capability token and/or the `GET /sync/vector` response's
/// OPTIONAL `profiles` member (key 4), and is specified **observational, never a gate**: absence
/// means "unknown", never "profile 1", and no node may refuse, downgrade or narrow its own
/// validation on it.
pub const EXT_VALUE_PROFILE: u8 = 2;

pub mod body;
pub mod cose;
pub mod crdt;
pub mod detcbor;
pub mod error;
pub mod recon;
pub mod snapshot;
pub mod state;
pub mod wire;

pub use body::{retention_set, AdoptedBody, SnapshotBody};
pub use cose::{sign_op, verify_op, verify_op_bytes, CoseSign1};
pub use crdt::{
    check_admitted, check_counter_entry, check_ns_ref, validate_op, DeathClass, DeathReg,
    DeathState, LwwMap, OrSet, PnCounter, RgaSeq, Tree, TreeReplay, SEQ_BUFFER_LIMIT,
};
pub use detcbor::{DetCborError, SVal};
pub use error::{Action, SyncError};
pub use recon::{fingerprint, reconcile, summarize, OpEntry, RangeFingerprint, ReconConfig,
    ReconOutcome};
pub use snapshot::{caller_is_below_floor, check_covers_closes_gap,
    covers_carries_mark_for_floor_author, state_root, state_root_of, verify_root, FastJoin,
    ObservableState, Snapshot, INLINE_STATE_CEILING};
pub use state::{scope_to_subscription, stability_cut, SyncState, VersionVector};
pub use wire::{
    ds_hash, op_id_of, AddTag, Hlc, OpRef, SyncOp, DEATH_LIVE, DS_OP, DS_OP_ID, DS_RECON_FP,
    DS_SNAPSHOT, DS_SNAPSHOT_STATE, HLC_SKEW_MS, OP_COUNTER, OP_DEATH, OP_LWW_SET, OP_SEQ_INSERT,
    OP_SEQ_REMOVE, OP_SET_ADD, OP_SET_REMOVE, OP_TREE_MOVE, TREE_ROOT,
};
