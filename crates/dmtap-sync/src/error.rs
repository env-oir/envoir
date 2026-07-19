//! The proposed `0x0A` ("SYNC substrate") error block (`SYNC.md` §12), with each code's
//! fail-closed action. The owning clause governs; nothing here degrades silently.

use std::fmt;

/// A Sync substrate failure. Every variant is a **refusal**, never a downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// `0x0A01` — op author not admitted by the namespace policy (§8, §9).
    AuthorUnauthorized,
    /// `0x0A02` — `COSE_Sign1` fails under `hlc.author`, or the `DeviceCert` chain is broken (§4.1).
    OpSigInvalid,
    /// `0x0A03` — non-`ext-value` value, future-add remove, embedded deniable payload, or an
    /// otherwise malformed op (§4).
    OpInvalid,
    /// `0x0A04` — op/snapshot carries an unsupported `v`/`suite` (§4.1, §6.1). Never guess.
    UnsupportedVersion,
    /// `0x0A05` — op `wall` outside the ±`HLC_SKEW_MS` window (§3).
    HlcSkew,
    /// `0x0A06` — a PN-counter op mutates another author's `P`/`N` entry (§4.6).
    CounterForeign,
    /// `0x0A07` — an RGA insert's origin is absent and the causal buffer overflowed (§4.7).
    SeqOriginMissing,
    /// `0x0A08` — a `SyncFrame` op's `ref` back-link does not resolve to its predecessor (§4.1).
    FrameChainBroken,
    /// `0x0A09` — recomputed observable-state root ≠ `Snapshot.root` at the same `covers` (§6.1).
    SnapshotRootMismatch,
    /// `0x0A0A` — an op references a `target` in a different namespace (§7).
    NsLeak,
    /// `0x0A0B` — an open-namespace admission limit (rate/quota) exceeded (§9).
    AdmissionQuota,
}

/// The §10.7-class action a receiver takes for a given failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Refuse the input outright.
    FailClosedBlock,
    /// Stop and raise: this is evidence of divergence or a forked history.
    HaltAlert,
    /// Defer, then retry on a rotated path.
    DeferRequests,
    /// A policy deny — never a security gate, never a silent hole.
    DenyPolicy,
}

impl SyncError {
    /// The numeric `0x0A` code.
    pub fn code(self) -> u16 {
        match self {
            SyncError::AuthorUnauthorized => 0x0A01,
            SyncError::OpSigInvalid => 0x0A02,
            SyncError::OpInvalid => 0x0A03,
            SyncError::UnsupportedVersion => 0x0A04,
            SyncError::HlcSkew => 0x0A05,
            SyncError::CounterForeign => 0x0A06,
            SyncError::SeqOriginMissing => 0x0A07,
            SyncError::FrameChainBroken => 0x0A08,
            SyncError::SnapshotRootMismatch => 0x0A09,
            SyncError::NsLeak => 0x0A0A,
            SyncError::AdmissionQuota => 0x0A0B,
        }
    }

    /// The `0x0AXX` spelling used in the conformance vectors.
    pub fn code_hex(self) -> String {
        format!("0x{:04X}", self.code())
    }

    /// The registry name.
    pub fn name(self) -> &'static str {
        match self {
            SyncError::AuthorUnauthorized => "ERR_SYNC_AUTHOR_UNAUTHORIZED",
            SyncError::OpSigInvalid => "ERR_SYNC_OP_SIG_INVALID",
            SyncError::OpInvalid => "ERR_SYNC_OP_INVALID",
            SyncError::UnsupportedVersion => "ERR_SYNC_UNSUPPORTED_VERSION",
            SyncError::HlcSkew => "ERR_SYNC_HLC_SKEW",
            SyncError::CounterForeign => "ERR_SYNC_COUNTER_FOREIGN",
            SyncError::SeqOriginMissing => "ERR_SYNC_SEQ_ORIGIN_MISSING",
            SyncError::FrameChainBroken => "ERR_SYNC_FRAME_CHAIN_BROKEN",
            SyncError::SnapshotRootMismatch => "ERR_SYNC_SNAPSHOT_ROOT_MISMATCH",
            SyncError::NsLeak => "ERR_SYNC_NS_LEAK",
            SyncError::AdmissionQuota => "ERR_SYNC_ADMISSION_QUOTA",
        }
    }

    /// The fail-closed action (§12).
    pub fn action(self) -> Action {
        match self {
            SyncError::SeqOriginMissing => Action::DeferRequests,
            SyncError::FrameChainBroken | SyncError::SnapshotRootMismatch => Action::HaltAlert,
            SyncError::AdmissionQuota => Action::DenyPolicy,
            _ => Action::FailClosedBlock,
        }
    }

    /// The action spelling used in the conformance vectors.
    pub fn action_str(self) -> &'static str {
        match self.action() {
            Action::FailClosedBlock => "FAIL_CLOSED_BLOCK",
            Action::HaltAlert => "HALT_ALERT",
            Action::DeferRequests => "DEFER_REQUESTS",
            Action::DenyPolicy => "DENY_POLICY",
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code_hex())
    }
}

impl std::error::Error for SyncError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_actions_match_the_registry_table() {
        assert_eq!(SyncError::OpSigInvalid.code_hex(), "0x0A02");
        assert_eq!(SyncError::NsLeak.code_hex(), "0x0A0A");
        assert_eq!(SyncError::SnapshotRootMismatch.action(), Action::HaltAlert);
        assert_eq!(SyncError::AdmissionQuota.action(), Action::DenyPolicy);
        assert_eq!(SyncError::SeqOriginMissing.action(), Action::DeferRequests);
        assert_eq!(SyncError::CounterForeign.action(), Action::FailClosedBlock);
    }
}
