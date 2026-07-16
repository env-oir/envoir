//! Outbound delivery — the sender-side retry state machine (spec §4.7, §19.3.3, §20.1).
//!
//! Durability in DMTAP lives *entirely* in this sender-side queue: the mixnet/relay middle holds
//! nothing (§0.5). An unacked MOTE is retried with backoff until the recipient's `ack(id)` comes
//! back (§19.3.2) or the 72 h deadline elapses (§16.1). This module implements that machine as a
//! **total** transition function ([`OutboundEntry::apply`]) — every `(state, event)` pair is
//! either an explicit transition from §20.1's table or a rejected [`InvalidTransition`], so the
//! machine can never wander into an undefined state.
//!
//! Timers are *modeled as events* (`retry_timer_fires`, `deadline_exceeded`) rather than driven
//! by a real clock inside this type: the owning [`Node`](crate::node::Node) decides when they
//! fire (from wall-clock or, in tests, an injected clock), which keeps the machine pure and
//! exhaustively testable. The backoff *schedule* itself (§16.1) is computed by [`backoff_ms`].

use dmtap_core::mote::Envelope;
use dmtap_core::{ContentId, TimestampMs};

/// The §16.1 retry deadline: 72 hours from `QUEUED` entry, after which an unacked MOTE `EXPIRED`s.
pub const RETRY_DEADLINE_MS: u64 = 72 * 60 * 60 * 1000;
/// §16.1 backoff base (30 s) and cap (1 h).
pub const BACKOFF_BASE_MS: u64 = 30 * 1000;
pub const BACKOFF_CAP_MS: u64 = 60 * 60 * 1000;

/// Exponential backoff for retry attempt `n` (0-based), base 30 s, cap 1 h (spec §16.1). Jitter
/// is applied by the scheduler, not here (kept deterministic for testing).
pub fn backoff_ms(attempt: u32) -> u64 {
    BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(12)).min(BACKOFF_CAP_MS)
}

/// Sender-side delivery state (spec §4.7, §20.1). `ACKED`/`EXPIRED` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutState {
    Queued,
    Sealed,
    InFlight,
    Retry,
    Acked,
    Expired,
}

impl OutState {
    /// Terminal states (§20.1: the queue slot may be GC'd once here).
    pub fn is_terminal(self) -> bool {
        matches!(self, OutState::Acked | OutState::Expired)
    }

    /// Stable discriminant for on-disk persistence (§19.3.3 durability). The mapping is fixed
    /// forever — appending new states is fine, renumbering an existing one corrupts old journals.
    pub fn as_u8(self) -> u8 {
        match self {
            OutState::Queued => 0,
            OutState::Sealed => 1,
            OutState::InFlight => 2,
            OutState::Retry => 3,
            OutState::Acked => 4,
            OutState::Expired => 5,
        }
    }

    /// Inverse of [`as_u8`](Self::as_u8); `None` for an unknown discriminant (a corrupt journal).
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => OutState::Queued,
            1 => OutState::Sealed,
            2 => OutState::InFlight,
            3 => OutState::Retry,
            4 => OutState::Acked,
            5 => OutState::Expired,
            _ => return None,
        })
    }
}

/// The events that drive the §20.1 machine (see its "Events" list). `Blocked`/`SealOk` cover the
/// resolve-and-seal branch; `DispatchOk`/`TierUnreachable` the transport attempt; the rest are
/// acks and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutEvent {
    /// `resolve_and_seal_ok`: recipient key resolved, envelope sealed; tier fixed.
    SealOk,
    /// `resolve_or_seal_blocked`: transient resolution/seal failure (DNS/DHT/KT lag, §3.3).
    Blocked,
    /// `dispatch_ok`: sealed object handed to the transport.
    DispatchOk,
    /// `tier_unreachable`: the transport rung failed (§19.2.3 `PEER_UNREACHABLE`).
    TierUnreachable,
    /// `ack_received`: recipient acked (or dedup-acked) `id` (§2.6).
    AckReceived,
    /// `retry_timer_fires`: backoff elapsed; re-dispatch the same sealed object.
    RetryTimerFires,
    /// `deadline_exceeded`: the 72 h deadline elapsed (§16.1); checked on every tick.
    DeadlineExceeded,
    /// `late_ack`: an ack arriving after `EXPIRED` (§20.1 fill) — corrects the UI, does not resurrect.
    LateAck,
}

impl OutEvent {
    fn name(self) -> &'static str {
        match self {
            OutEvent::SealOk => "resolve_and_seal_ok",
            OutEvent::Blocked => "resolve_or_seal_blocked",
            OutEvent::DispatchOk => "dispatch_ok",
            OutEvent::TierUnreachable => "tier_unreachable",
            OutEvent::AckReceived => "ack_received",
            OutEvent::RetryTimerFires => "retry_timer_fires",
            OutEvent::DeadlineExceeded => "deadline_exceeded",
            OutEvent::LateAck => "late_ack",
        }
    }
}

/// A `(state, event)` pair that §20.1's total table does not define — a bug in the driver, never
/// a network condition. Returned rather than panicking so the caller can assert the machine's
/// totality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTransition {
    pub state: OutState,
    pub event: &'static str,
}

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid transition: {:?} on event {}", self.state, self.event)
    }
}
impl std::error::Error for InvalidTransition {}

/// One tracked outbound MOTE: its stable content address, recipient, sealed envelope, and its
/// position in the §20.1 machine. Immutable `id`/`to`; the sealed [`Envelope`] is retained so a
/// retry re-dispatches the *same* object (same `id`) — the property that makes retry idempotent
/// against recipient dedup (§2.6).
#[derive(Debug, Clone)]
pub struct OutboundEntry {
    pub id: ContentId,
    pub to: Vec<u8>,
    pub state: OutState,
    /// The sealed envelope, present once `SEALED` is reached. Retained across `RETRY` so
    /// re-dispatch needs no re-sealing (§20.1: "no re-sealing needed; `id` is stable").
    pub sealed: Option<Envelope>,
    /// Number of failed in-flight attempts so far (indexes [`backoff_ms`]).
    pub attempts: u32,
    /// Absolute deadline (`queued_at + 72h`, bounded above by the MOTE's own `expires`, §16.1).
    pub deadline: TimestampMs,
    /// True once a late ack corrected an already-`EXPIRED` entry (UI hint, §20.1 fill).
    pub delivered_late: bool,
}

impl OutboundEntry {
    /// Admit a MOTE to the queue (`enqueue` → `QUEUED`). `queued_at` starts the 72 h deadline;
    /// `expires` (the MOTE's own requested expiry, §2.4) bounds it from above if smaller.
    pub fn enqueue(
        id: ContentId,
        to: Vec<u8>,
        queued_at: TimestampMs,
        expires: Option<TimestampMs>,
    ) -> Self {
        let default_deadline = queued_at.saturating_add(RETRY_DEADLINE_MS);
        let deadline = match expires {
            Some(e) => default_deadline.min(e),
            None => default_deadline,
        };
        OutboundEntry {
            id,
            to,
            state: OutState::Queued,
            sealed: None,
            attempts: 0,
            deadline,
            delivered_late: false,
        }
    }

    /// Apply one §20.1 event, mutating `state` (and bookkeeping) per the transition table, or
    /// rejecting an undefined pair. This is the whole machine; see §20.1 for the table.
    pub fn apply(&mut self, ev: OutEvent) -> Result<OutState, InvalidTransition> {
        use OutEvent::*;
        use OutState::*;
        let next = match (self.state, ev) {
            // QUEUED
            (Queued, SealOk) => Sealed,
            (Queued, Blocked) => Retry,
            (Queued, DeadlineExceeded) => Expired,
            // SEALED
            (Sealed, DispatchOk) => InFlight,
            (Sealed, DeadlineExceeded) => Expired,
            // IN_FLIGHT
            (InFlight, AckReceived) => Acked,
            (InFlight, TierUnreachable) => {
                self.attempts = self.attempts.saturating_add(1);
                Retry
            }
            (InFlight, DeadlineExceeded) => Expired,
            // RETRY
            (Retry, RetryTimerFires) => InFlight,
            (Retry, AckReceived) => Acked, // a duplicate in-flight copy landed first
            (Retry, DeadlineExceeded) => Expired,
            // Terminal idempotency
            (Acked, AckReceived) => Acked, // no-op, further acks ignored (§19.3.2)
            (Expired, LateAck) => {
                self.delivered_late = true; // UI correction only; does not resurrect (§20.1 fill)
                Expired
            }
            // Everything else is undefined by the (total) table.
            (state, ev) => return Err(InvalidTransition { state, event: ev.name() }),
        };
        self.state = next;
        Ok(next)
    }

    /// True if the deadline has elapsed in a non-terminal state (drives `deadline_exceeded`).
    pub fn deadline_passed(&self, now: TimestampMs) -> bool {
        !self.state.is_terminal() && now >= self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::OutState::*;
    use super::*;

    fn entry() -> OutboundEntry {
        OutboundEntry::enqueue(ContentId::of(b"m"), b"bob".to_vec(), 0, None)
    }

    #[test]
    fn happy_path_queued_to_acked() {
        let mut e = entry();
        assert_eq!(e.state, Queued);
        assert_eq!(e.apply(OutEvent::SealOk).unwrap(), Sealed);
        assert_eq!(e.apply(OutEvent::DispatchOk).unwrap(), InFlight);
        assert_eq!(e.apply(OutEvent::AckReceived).unwrap(), Acked);
        assert!(e.state.is_terminal());
    }

    #[test]
    fn retry_path_reenters_in_flight_then_acks() {
        let mut e = entry();
        e.apply(OutEvent::SealOk).unwrap();
        e.apply(OutEvent::DispatchOk).unwrap();
        assert_eq!(e.apply(OutEvent::TierUnreachable).unwrap(), Retry);
        assert_eq!(e.attempts, 1);
        assert_eq!(e.apply(OutEvent::RetryTimerFires).unwrap(), InFlight);
        assert_eq!(e.apply(OutEvent::AckReceived).unwrap(), Acked);
    }

    #[test]
    fn ack_in_retry_short_circuits() {
        let mut e = entry();
        e.apply(OutEvent::SealOk).unwrap();
        e.apply(OutEvent::DispatchOk).unwrap();
        e.apply(OutEvent::TierUnreachable).unwrap();
        assert_eq!(e.apply(OutEvent::AckReceived).unwrap(), Acked);
    }

    #[test]
    fn blocked_resolution_goes_to_retry() {
        let mut e = entry();
        assert_eq!(e.apply(OutEvent::Blocked).unwrap(), Retry);
        assert_eq!(e.apply(OutEvent::RetryTimerFires).unwrap(), InFlight);
    }

    #[test]
    fn deadline_expires_from_every_nonterminal_state() {
        for setup in [
            vec![],
            vec![OutEvent::SealOk],
            vec![OutEvent::SealOk, OutEvent::DispatchOk],
            vec![OutEvent::SealOk, OutEvent::DispatchOk, OutEvent::TierUnreachable],
        ] {
            let mut e = entry();
            for ev in setup {
                e.apply(ev).unwrap();
            }
            assert_eq!(e.apply(OutEvent::DeadlineExceeded).unwrap(), Expired);
        }
    }

    #[test]
    fn ack_is_idempotent_in_acked() {
        let mut e = entry();
        e.apply(OutEvent::SealOk).unwrap();
        e.apply(OutEvent::DispatchOk).unwrap();
        e.apply(OutEvent::AckReceived).unwrap();
        assert_eq!(e.apply(OutEvent::AckReceived).unwrap(), Acked);
        assert!(!e.delivered_late);
    }

    #[test]
    fn late_ack_after_expired_corrects_ui_but_stays_expired() {
        let mut e = entry();
        e.apply(OutEvent::DeadlineExceeded).unwrap();
        assert_eq!(e.apply(OutEvent::LateAck).unwrap(), Expired);
        assert!(e.delivered_late);
    }

    #[test]
    fn undefined_pairs_are_rejected_not_panicked() {
        // Can't ack a freshly QUEUED entry (never dispatched).
        let mut e = entry();
        assert_eq!(
            e.apply(OutEvent::AckReceived),
            Err(InvalidTransition { state: Queued, event: "ack_received" })
        );
        // Can't re-dispatch from ACKED.
        let mut e = entry();
        e.apply(OutEvent::SealOk).unwrap();
        e.apply(OutEvent::DispatchOk).unwrap();
        e.apply(OutEvent::AckReceived).unwrap();
        assert!(e.apply(OutEvent::DispatchOk).is_err());
    }

    #[test]
    fn expires_bounds_the_deadline() {
        let e = OutboundEntry::enqueue(ContentId::of(b"m"), b"bob".to_vec(), 1000, Some(2000));
        assert_eq!(e.deadline, 2000, "the smaller of expires and the 72h default governs");
        let e2 = OutboundEntry::enqueue(ContentId::of(b"m"), b"bob".to_vec(), 1000, None);
        assert_eq!(e2.deadline, 1000 + RETRY_DEADLINE_MS);
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_ms(0), BACKOFF_BASE_MS);
        assert_eq!(backoff_ms(1), 2 * BACKOFF_BASE_MS);
        assert_eq!(backoff_ms(2), 4 * BACKOFF_BASE_MS);
        assert_eq!(backoff_ms(100), BACKOFF_CAP_MS, "caps at 1 h");
    }
}
