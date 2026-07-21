//! Metering seam — the OSS emits [`UsageEvent`]s at the real cost centers; an operator turns
//! them into billable line items. Self-host default ([`NullMetering`]) drops them.
//!
//! Only *operations* are metered (gateway egress, storage, relayed bytes, message counts).
//! Privacy/crypto features emit no meter and are never gated (see crate docs).

use crate::{AccountId, TimestampMs};

/// A single usage observation emitted by a node or gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageEvent {
    pub account: AccountId,
    pub kind: UsageKind,
    /// The metered amount in the kind's natural unit (bytes, or a count).
    pub amount: u64,
    pub ts_ms: TimestampMs,
}

/// The metered dimensions — the genuine cost centers (spec §7, §9). Deliberately small.
///
/// `Hash` is derived so an operator-side usage queue/accumulator (e.g. `dmtap-operator`) can key a
/// dedup set or a running-total map on `(account, kind, ...)` without redefining this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageKind {
    /// Legacy egress: one message bridged DMTAP → SMTP. Carries the IP-reputation cost.
    GatewaySend,
    /// Legacy ingress: one message accepted SMTP → DMTAP and delivered.
    InboundLegacy,
    /// Hosted storage, in bytes (mailbox + files) for a managed node.
    StorageBytes,
    /// Bytes relayed on behalf of the account (bandwidth).
    RelayBytes,
    /// Native DMTAP messages sent (count) — for plan tracking, not usually billed.
    MessagesSent,
    /// A vanity (tier C) domain under management, counted per billing period.
    VanityDomain,
}

impl UsageKind {
    /// True for dimensions that have real marginal cost and are typically billed.
    pub fn is_billable_by_default(self) -> bool {
        matches!(
            self,
            UsageKind::GatewaySend
                | UsageKind::InboundLegacy
                | UsageKind::StorageBytes
                | UsageKind::RelayBytes
                | UsageKind::VanityDomain
        )
    }
}

/// The metering sink. Implemented by an operator's billing pipeline; the OSS only calls
/// [`record`](Metering::record) and never inspects the result.
pub trait Metering: Send + Sync {
    fn record(&self, event: UsageEvent);
}

/// Self-host default: records nothing (self-host has no billing).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMetering;

impl Metering for NullMetering {
    fn record(&self, _event: UsageEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_metering_is_noop() {
        NullMetering.record(UsageEvent {
            account: "x".into(),
            kind: UsageKind::GatewaySend,
            amount: 1,
            ts_ms: 0,
        });
    }

    #[test]
    fn billable_classification() {
        assert!(UsageKind::GatewaySend.is_billable_by_default());
        assert!(!UsageKind::MessagesSent.is_billable_by_default());
    }
}
