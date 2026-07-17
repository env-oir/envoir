//! Fail-closed error taxonomy for device-cluster sync (§5.6 / §21).
//!
//! Every rejection maps to one of the four normative device-cluster error codes (§21,
//! `0x0410`–`0x0413`). A structurally malformed frame surfaces as [`SyncError::Cbor`] wrapping the
//! core canonical-CBOR error — the same fail-closed posture §18.1.1 already enforces on decode.
//!
//! The impls here are hand-written (`Display`/`Error`) so this crate stays **std + dmtap-core
//! only** — no third-party error-derive dependency.

use dmtap_core::cbor::CborError;
use std::fmt;

/// The disposition a receiver MUST take on a rejection (§21 "action" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Refuse the peer / op; do not act on it (`0x0410`, `0x0411`, `0x0413`).
    FailClosedBlock,
    /// Stop replaying and alert the owner — a fork of the owner's *own* log (`0x0412`).
    HaltAlert,
}

/// A device-cluster sync failure. Decoding a malformed frame yields [`SyncError::Cbor`]; the four
/// domain variants are the §5.6 normative rejections a receiver MUST perform before acting.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    /// Malformed / non-canonical wire bytes — fail closed exactly as §18.1.1 requires.
    Cbor(CborError),

    /// `0x0410` — the origin device is not a current, non-revoked cluster member (§5.6.1).
    /// Replication is mutually authenticated; a non-member can neither inject nor pull.
    DeviceUnauthorized,

    /// `0x0411` — a `recon` summary is malformed, or a `RangeFingerprint.fp` does not recompute
    /// over the ids actually held in `[lo, hi)` (a forged Merkle fingerprint) (§5.6.3(a)).
    ReconSummaryInvalid,

    /// `0x0412` — a journal-replay segment's `prev` hash-chain does not verify: a fork or rewrite
    /// of the owner's own append-only log (§5.6.3(b)). Disposition is HALT_ALERT.
    JournalChainBroken,

    /// `0x0413` — a `ClusterOp` is invalid: unknown kind, a remove citing an unknown/causally
    /// impossible add-tag, an HLC `wall` beyond the skew bound, a missing kind-3 field/value, or an
    /// op embedding a `DeniablePayload`/its plaintext (forbidden, §5.2.1) (§5.6.4).
    CrdtOpInvalid,
}

impl SyncError {
    /// The numeric §21 error code for this rejection (`0x0000` for a wrapped CBOR error, which is
    /// itself the §18.1.1 fail-closed decode rejection rather than a §5.6 domain code).
    pub fn code(&self) -> u16 {
        match self {
            SyncError::Cbor(_) => 0x0000,
            SyncError::DeviceUnauthorized => 0x0410,
            SyncError::ReconSummaryInvalid => 0x0411,
            SyncError::JournalChainBroken => 0x0412,
            SyncError::CrdtOpInvalid => 0x0413,
        }
    }

    /// The disposition a receiver MUST take (§21). `None` for a wrapped decode error (drop the
    /// bytes); the four domain variants each carry their normative action.
    pub fn action(&self) -> Option<Action> {
        match self {
            SyncError::Cbor(_) => None,
            SyncError::JournalChainBroken => Some(Action::HaltAlert),
            _ => Some(Action::FailClosedBlock),
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Cbor(e) => write!(f, "malformed cluster-sync frame: {e}"),
            SyncError::DeviceUnauthorized => f.write_str(
                "ERR_CLUSTER_DEVICE_UNAUTHORIZED (0x0410): origin device is not a non-revoked cluster member",
            ),
            SyncError::ReconSummaryInvalid => f.write_str(
                "ERR_CLUSTER_RECON_SUMMARY_INVALID (0x0411): range fingerprint does not recompute over its ids",
            ),
            SyncError::JournalChainBroken => f.write_str(
                "ERR_CLUSTER_JOURNAL_CHAIN_BROKEN (0x0412): journal prev-chain does not verify (own-log fork)",
            ),
            SyncError::CrdtOpInvalid => f.write_str(
                "ERR_CLUSTER_CRDT_OP_INVALID (0x0413): malformed or forbidden CRDT op",
            ),
        }
    }
}

impl std::error::Error for SyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SyncError::Cbor(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CborError> for SyncError {
    fn from(e: CborError) -> Self {
        SyncError::Cbor(e)
    }
}
