//! Outbound anti-spam: keep the gateway from being used as a spam relay (spec §7.3, §9).
//!
//! Inbound abuse (legacy → DMTAP) is gated by [`crate::inbound::ColdSenderGate`] + DKIM/SPF/DMARC.
//! The **outbound** leg (DMTAP → legacy) has the opposite risk: if any authenticated self-hoster can
//! fire unlimited mail at the legacy world, the gateway's IP gets blacklisted and every other user's
//! deliverability collapses. So outbound relay is **authenticated-senders-only** (no open outbound
//! relay) and each authenticated sender is held to:
//!
//! - a **per-sender rate limit** (a short-window burst ceiling),
//! - a **volume cap** (a longer-window absolute message ceiling), and
//! - a **simple reputation / backoff**: a sender that accrues bad delivery signals (destination 5xx,
//!   bounces, spam complaints) is throttled with an exponentially-growing backoff, which decays as it
//!   sends cleanly again.
//!
//! Deterministic and testable: time comes from the injected [`Clock`] seam (production uses
//! [`crate::inbound::SystemClock`]; tests inject a manual clock), never a direct wall-clock read, so
//! a flood and its throttling are exercised without sleeping. State is in-memory operational
//! anti-abuse state (not message durability — the gateway stays stateless about mail, §7.4).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::inbound::{Clock, SystemClock};

/// The outbound guard's verdict for one send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderVerdict {
    /// The send may proceed.
    Allow,
    /// Defer: the sender is over a rate window or in reputation backoff. `retry_after_ms` is how long
    /// the node should wait before retrying (§19.3.3), `reason` the enhanced text.
    Throttle { retry_after_ms: u64, reason: String },
    /// Refuse outright: an unauthenticated sender, or one that has exhausted its volume cap for the
    /// window. A hard refusal, not a retry hint.
    Refuse { reason: String },
}

impl SenderVerdict {
    /// True iff the send may proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, SenderVerdict::Allow)
    }
}

/// Per-sender operational state (windows + reputation).
#[derive(Default)]
struct SenderState {
    /// Timestamps (ms) of recent sends within the rate window.
    rate_hits: Vec<u64>,
    /// Timestamps (ms) of sends within the (longer) volume window.
    volume_hits: Vec<u64>,
    /// Reputation strikes: each bad delivery signal +1, each clean send decays it by 1.
    strikes: u32,
    /// While `now < backoff_until`, the sender is throttled regardless of the rate window.
    backoff_until: u64,
}

/// Governs outbound sends per authenticated sender account (§7.3, §9). Authenticated-senders-only:
/// an account not in the configured registered set (when one is set) is refused, so the gateway is
/// never an open outbound relay. See the module docs for the rate / volume / reputation model.
pub struct OutboundSenderGuard {
    /// Max sends per `rate_window_ms` before deferring.
    rate_limit: u32,
    rate_window_ms: u64,
    /// Absolute sends per `volume_window_ms` before refusing (the anti-flood ceiling).
    volume_cap: u32,
    volume_window_ms: u64,
    /// Base backoff added on the first strike; doubles per additional strike (capped).
    backoff_base_ms: u64,
    /// Max doublings of the backoff (so it cannot grow without bound).
    backoff_max_shift: u32,
    /// The authenticated-senders allowlist. When `Some`, only these accounts are authenticated
    /// senders (anyone else is refused). When `None` the allowlist is **unset**, which is
    /// **fail-closed by default**: no account is authenticated until the operator configures the
    /// allowlist via [`Self::require_registered`]. An unset allowlist must never silently become an
    /// open outbound relay.
    registered: Option<Vec<String>>,
    clock: Box<dyn Clock>,
    state: Mutex<HashMap<String, SenderState>>,
}

impl OutboundSenderGuard {
    /// A guard with sensible defaults: 20 sends / 60 s burst, a 500-message / 24 h volume cap, and a
    /// reputation backoff starting at 5 min and doubling up to ~1 h. Tune via the builder methods.
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    /// As [`Self::new`] but with an explicit clock (tests inject a manual clock).
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        OutboundSenderGuard {
            rate_limit: 20,
            rate_window_ms: 60_000,
            volume_cap: 500,
            volume_window_ms: 24 * 3_600_000,
            backoff_base_ms: 300_000,
            backoff_max_shift: 3,
            registered: None,
            clock,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Set the per-sender burst rate limit (`max` sends per `window_ms`).
    pub fn with_rate_limit(mut self, max: u32, window_ms: u64) -> Self {
        self.rate_limit = max;
        self.rate_window_ms = window_ms;
        self
    }

    /// Set the per-sender volume cap (`max` sends per `window_ms`) — the absolute anti-flood ceiling.
    pub fn with_volume_cap(mut self, max: u32, window_ms: u64) -> Self {
        self.volume_cap = max;
        self.volume_window_ms = window_ms;
        self
    }

    /// Set the reputation backoff: `base_ms` on the first strike, doubling up to `max_shift` times.
    pub fn with_backoff(mut self, base_ms: u64, max_shift: u32) -> Self {
        self.backoff_base_ms = base_ms;
        self.backoff_max_shift = max_shift;
        self
    }

    /// Restrict outbound relay to this explicit set of authenticated accounts (the
    /// authenticated-senders-only allowlist). Until this is set the guard is fail-closed and
    /// authenticates **no** account, so the gateway is never an open outbound relay by default.
    pub fn require_registered(mut self, accounts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.registered = Some(accounts.into_iter().map(Into::into).collect());
        self
    }

    fn is_authenticated(&self, account: &str) -> bool {
        if account.trim().is_empty() {
            return false;
        }
        match &self.registered {
            Some(set) => set.iter().any(|a| a == account),
            // Fail-closed: an unset allowlist authenticates NO account (no open outbound relay).
            None => false,
        }
    }

    /// Decide whether `account` may send one message now (§7.3). Records the send against both
    /// windows when it returns [`SenderVerdict::Allow`]. Order: authentication → reputation backoff →
    /// volume cap (hard) → rate limit (defer). Uses the injected clock, so it is deterministic.
    pub fn authorize_send(&self, account: &str) -> SenderVerdict {
        if !self.is_authenticated(account) {
            return SenderVerdict::Refuse {
                reason: "5.7.1 outbound relay denied: sender is not an authenticated account".into(),
            };
        }
        let now = self.clock.now_ms();
        let mut states = self.state.lock().expect("outbound guard poisoned");
        let st = states.entry(account.to_string()).or_default();

        // 1. Reputation backoff dominates: a sender in penalty is throttled regardless of windows.
        if now < st.backoff_until {
            return SenderVerdict::Throttle {
                retry_after_ms: st.backoff_until - now,
                reason: "4.7.1 sender in reputation backoff after prior delivery failures".into(),
            };
        }

        // 2. Volume cap (hard refuse) — the absolute anti-flood ceiling over the long window.
        let vstart = now.saturating_sub(self.volume_window_ms);
        st.volume_hits.retain(|&t| t >= vstart);
        if st.volume_hits.len() as u32 >= self.volume_cap {
            return SenderVerdict::Refuse {
                reason: "5.7.1 outbound volume cap reached for this sender; relay refused".into(),
            };
        }

        // 3. Burst rate limit (defer) — smooths a short spike into the node's retry queue.
        let rstart = now.saturating_sub(self.rate_window_ms);
        st.rate_hits.retain(|&t| t >= rstart);
        if st.rate_hits.len() as u32 >= self.rate_limit {
            // Retry after the oldest hit in the window falls out.
            let retry_after = st
                .rate_hits
                .first()
                .map(|&oldest| (oldest + self.rate_window_ms).saturating_sub(now))
                .unwrap_or(self.rate_window_ms);
            return SenderVerdict::Throttle {
                retry_after_ms: retry_after.max(1),
                reason: "4.7.1 per-sender outbound rate limit exceeded; slow down".into(),
            };
        }

        // Allowed: record against both windows.
        st.rate_hits.push(now);
        st.volume_hits.push(now);
        SenderVerdict::Allow
    }

    /// Feed a delivery outcome back into the sender's reputation (§9). A failed/bounced/complained
    /// send raises the strike count and (re)arms an exponentially-growing backoff; a clean delivery
    /// decays one strike so a sender recovers over time. Uses the injected clock.
    pub fn report_outcome(&self, account: &str, delivered: bool) {
        let now = self.clock.now_ms();
        let mut states = self.state.lock().expect("outbound guard poisoned");
        let st = states.entry(account.to_string()).or_default();
        if delivered {
            st.strikes = st.strikes.saturating_sub(1);
        } else {
            st.strikes = st.strikes.saturating_add(1);
            let shift = (st.strikes - 1).min(self.backoff_max_shift);
            // `backoff_max_shift` is operator-set and unbounded; `1u64 << shift` panics (debug) or
            // wraps (release) once `shift >= 64`. `checked_shl` clamps to a saturated factor instead,
            // so an absurd config produces a very large but finite backoff, never a panic.
            let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
            let backoff = self.backoff_base_ms.saturating_mul(factor);
            st.backoff_until = now.saturating_add(backoff);
        }
    }

    /// The current reputation strike count for an account (for tests / operator introspection).
    pub fn strikes(&self, account: &str) -> u32 {
        self.state.lock().expect("outbound guard poisoned").get(account).map(|s| s.strikes).unwrap_or(0)
    }
}

impl Default for OutboundSenderGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicU64>);
    impl ManualClock {
        fn new(t: u64) -> Self {
            ManualClock(Arc::new(AtomicU64::new(t)))
        }
        fn advance(&self, d: u64) {
            self.0.fetch_add(d, Ordering::SeqCst);
        }
    }
    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn unauthenticated_sender_is_refused_no_open_outbound_relay() {
        let guard = OutboundSenderGuard::new().require_registered(["acct-alice"]);
        assert!(matches!(guard.authorize_send(""), SenderVerdict::Refuse { .. }));
        assert!(matches!(guard.authorize_send("acct-stranger"), SenderVerdict::Refuse { .. }));
        assert_eq!(guard.authorize_send("acct-alice"), SenderVerdict::Allow);
    }

    #[test]
    fn unset_allowlist_denies_by_default_not_open_relay() {
        // A guard with NO allowlist configured must DENY every account — an unset allowlist is
        // fail-closed, not an open outbound relay. (Old behavior authenticated any non-empty account.)
        let guard = OutboundSenderGuard::new();
        assert!(matches!(guard.authorize_send("anyone"), SenderVerdict::Refuse { .. }));
        assert!(matches!(guard.authorize_send("acct-whoever"), SenderVerdict::Refuse { .. }));

        // Only after the operator sets an allowlist is a listed account authenticated; others are
        // still refused (not merely rate-limited).
        let guard = OutboundSenderGuard::new().require_registered(["acct-alice"]);
        assert_eq!(guard.authorize_send("acct-alice"), SenderVerdict::Allow);
        assert!(matches!(guard.authorize_send("acct-bob"), SenderVerdict::Refuse { .. }));
    }

    #[test]
    fn oversized_backoff_max_shift_saturates_without_panicking() {
        // `backoff_max_shift` is operator-set and unbounded. With the old `1u64 << shift`, a shift
        // >= 64 panics in debug (overflow) / wraps in release. It must saturate sanely instead.
        let clock = ManualClock::new(0);
        let guard = OutboundSenderGuard::with_clock(Box::new(clock.clone()))
            .require_registered(["risky"])
            .with_backoff(1_000_000, u32::MAX);
        // Accrue enough strikes that the shift exceeds 64.
        for _ in 0..70 {
            guard.report_outcome("risky", false);
        }
        // No panic; the sender is throttled with a finite (saturated) backoff.
        match guard.authorize_send("risky") {
            SenderVerdict::Throttle { retry_after_ms, .. } => assert!(retry_after_ms > 0),
            other => panic!("expected throttle, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_throttles_a_flood_while_a_normal_sender_passes() {
        let clock = ManualClock::new(1_000_000);
        let guard = OutboundSenderGuard::with_clock(Box::new(clock.clone()))
            .require_registered(["flooder", "normal"])
            .with_rate_limit(3, 60_000)
            .with_volume_cap(1000, 24 * 3_600_000);

        // The flooder burns its 3-per-minute burst, then is throttled (deferred, not hard-refused).
        assert_eq!(guard.authorize_send("flooder"), SenderVerdict::Allow);
        assert_eq!(guard.authorize_send("flooder"), SenderVerdict::Allow);
        assert_eq!(guard.authorize_send("flooder"), SenderVerdict::Allow);
        match guard.authorize_send("flooder") {
            SenderVerdict::Throttle { retry_after_ms, .. } => assert!(retry_after_ms > 0),
            other => panic!("expected throttle, got {other:?}"),
        }

        // A different, normal sender is unaffected by the flooder's throttle (per-sender state).
        assert_eq!(guard.authorize_send("normal"), SenderVerdict::Allow);

        // After the window elapses, the flooder is allowed again.
        clock.advance(60_001);
        assert_eq!(guard.authorize_send("flooder"), SenderVerdict::Allow);
    }

    #[test]
    fn volume_cap_hard_refuses_a_sustained_flood() {
        let clock = ManualClock::new(0);
        let guard = OutboundSenderGuard::with_clock(Box::new(clock.clone()))
            .require_registered(["spammer"])
            .with_rate_limit(1000, 60_000) // rate not the limiter here
            .with_volume_cap(5, 3_600_000);

        for _ in 0..5 {
            assert_eq!(guard.authorize_send("spammer"), SenderVerdict::Allow);
            clock.advance(1000);
        }
        // The 6th within the volume window is a HARD refuse (not a mere defer).
        assert!(matches!(guard.authorize_send("spammer"), SenderVerdict::Refuse { .. }));
    }

    #[test]
    fn reputation_backoff_grows_on_failures_and_decays_on_clean_sends() {
        let clock = ManualClock::new(10_000_000);
        let guard = OutboundSenderGuard::with_clock(Box::new(clock.clone()))
            .require_registered(["risky"])
            .with_backoff(1000, 3);

        // First send is fine.
        assert_eq!(guard.authorize_send("risky"), SenderVerdict::Allow);

        // A failed delivery arms a backoff → the next send is throttled.
        guard.report_outcome("risky", false);
        assert_eq!(guard.strikes("risky"), 1);
        let first = match guard.authorize_send("risky") {
            SenderVerdict::Throttle { retry_after_ms, .. } => retry_after_ms,
            other => panic!("expected throttle, got {other:?}"),
        };
        assert_eq!(first, 1000, "first strike ⇒ base backoff");

        // A second failure doubles the backoff window.
        guard.report_outcome("risky", false);
        let second = match guard.authorize_send("risky") {
            SenderVerdict::Throttle { retry_after_ms, .. } => retry_after_ms,
            other => panic!("expected throttle, got {other:?}"),
        };
        assert_eq!(second, 2000, "second strike ⇒ doubled backoff");

        // Let the backoff elapse, then a clean delivery decays the strike count back toward zero.
        clock.advance(2001);
        assert_eq!(guard.authorize_send("risky"), SenderVerdict::Allow);
        guard.report_outcome("risky", true);
        assert_eq!(guard.strikes("risky"), 1);
        guard.report_outcome("risky", true);
        assert_eq!(guard.strikes("risky"), 0, "reputation recovers with clean sends");
    }
}
