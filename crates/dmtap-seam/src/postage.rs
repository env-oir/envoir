//! Postage seam — OPTIONAL, provider-agnostic PREPAID anti-spam credit for legacy gateway egress
//! (spec §9.5).
//!
//! Spec §9 gives a sender three alternative ways to be "anonymous but accountable" to a gateway:
//! an ARC rate-limit token, proof-of-work, or a **postage** stamp. This module is the seam for the
//! postage leg, and it is deliberately narrow:
//!
//! - **Prepaid, not per-message.** A sender tops up a credit balance *once*, through whatever
//!   payment rail the operator has wired in — a card processor, mobile money, their own ledger, or
//!   the optional `patala`-backed reference adapter (`dmtap-postage-patala`, a sibling crate, NOT a
//!   dependency of this one). [`GatewayAuthz`]'s per-send check then draws that balance down
//!   *locally* — there is no on-chain/processor settlement per email.
//! - **Provider-agnostic.** [`PostageProvider`] names no payment provider anywhere in its
//!   signature. `patala`, Stripe, M-Pesa, and "write your own" are all just implementors of the
//!   same three methods; this crate has zero dependency on any of them.
//! - **Non-custodial.** Envoir/this seam never holds funds. A provider's own custody model (if
//!   any — a card processor is custodial, patala's Stellar rail is not) is entirely the
//!   provider's concern, not this crate's.
//! - **Off by default.** [`NullPostage`] is the self-host default, mirroring
//!   [`crate::metering::NullMetering`] and [`crate::gateway_authz::OpenGatewayAuthz`]: no operator
//!   opts in ⇒ no postage, no gating, no billing. [`PostageGatedAuthz`] is the ONLY way postage
//!   reaches [`GatewayAuthz`], and it exists solely to be constructed by an operator who wants it
//!   — [`crate::gateway_authz::OpenGatewayAuthz`] and every other authz impl keep working
//!   unwrapped, exactly as before this module existed.
//! - **Never gates privacy.** This seam composes only with [`GatewayAuthz`] (spec §7.9's
//!   operations-only gate for legacy egress). There is no path from here to encryption, the
//!   mixnet, metadata privacy, or key recovery — see the crate's inviolable rule.
//!
//! ## No persistence here
//!
//! Exactly like every other seam trait ([`crate::metering::Metering`], [`crate::policy::Policy`]),
//! `dmtap-seam` does not persist a balance itself. An implementor of [`PostageProvider`] owns its
//! own storage — in-memory, a database, a payment provider's own ledger — the seam is only the
//! three calls a gateway makes against it.
//!
//! ## Reminders use envoir's OWN notification mechanism
//!
//! Envoir is itself a notification system (native DMTAP delivery, DSN/system messages over the
//! same mail path, content-free push wakes — see `dmtap-mail::smtp`'s `DsnReport` and
//! `dmtap-core::push`). When a sender's postage credit runs low, the right way to tell them is
//! through that existing path, addressed to the sender's own mailbox — never a new side-channel.
//! `dmtap-seam` is a std-only, dependency-free contract crate: it cannot construct a MOTE or a DSN
//! itself (that needs `dmtap-core`/`dmtap-mail`, which this crate deliberately does not depend
//! on). So [`PostageReminderSink::notify`] is, like [`crate::metering::Metering::record`], a plain
//! "here is the event" hand-off — the operator's implementation is expected to turn it into an
//! ordinary message on envoir's existing send path, not invent a parallel one.

use crate::gateway_authz::{GatewayAuthz, GatewayDecision, SendCredential};
use crate::AccountId;

// ── Money, requests, and results ────────────────────────────────────────────────────────────

/// Money as an integer count of `currency`'s smallest unit — **never a float**, anywhere in this
/// module. `currency` is an opaque short code the provider defines (an ISO-4217 code for a fiat
/// rail, an asset ticker such as `"USDC"` for a crypto rail); this seam never interprets it beyond
/// carrying it through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    pub minor_units: u64,
    pub currency: String,
}

impl Money {
    pub fn new(minor_units: u64, currency: impl Into<String>) -> Self {
        Money { minor_units, currency: currency.into() }
    }
}

/// A request to add prepaid postage credit for `account`, through whatever payment provider the
/// operator has wired in behind [`PostageProvider::top_up`].
#[derive(Debug, Clone)]
pub struct TopUpRequest {
    pub account: AccountId,
    pub amount: Money,
    /// Caller-supplied idempotency/correlation key. A provider that needs one (e.g. to make a
    /// retried top-up idempotent) uses this; a provider that doesn't may ignore it.
    pub reference: String,
}

/// The outcome of a top-up attempt. Settlement detail beyond the resulting balance is opaque
/// (`reference` / `reason`) — this seam never interprets or depends on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopUpResult {
    /// Credited immediately (a synchronous rail: a card charge, or a fast-finality crypto rail).
    Credited { new_balance: Money, reference: String },
    /// Initiated but not yet settled (e.g. awaiting confirmations); the caller should not treat
    /// the sender as topped up until a later [`PostageProvider::balance`] reflects it.
    Pending { reference: String },
    /// The top-up did not happen — includes "postage isn't enabled here" ([`NullPostage`]) as
    /// well as a genuine provider failure.
    Failed { reason: String },
}

/// A point-in-time balance snapshot for one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostageBalance {
    pub account: AccountId,
    pub balance: Money,
}

/// The outcome of drawing down postage for one gateway send. This is **local bookkeeping only** —
/// spending never talks to the payment provider; only [`PostageProvider::top_up`] does that
/// (the "prepaid, not per-message" rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendResult {
    /// Spent; the account's balance after this send, in the account's configured currency.
    Spent { remaining_minor_units: u64 },
    /// Not enough credit for this send (spec §9.5's "insufficient postage").
    Insufficient { balance_minor_units: u64, required_minor_units: u64 },
}

// ── The seam trait + self-host default ──────────────────────────────────────────────────────

/// Provider-agnostic PREPAID postage (spec §9.5). Implemented entirely by the operator; this
/// trait names no provider — not `patala`, not Stripe, not M-Pesa — and this crate depends on
/// none of them. An operator picks whatever rail they like and writes ~3 methods; see the sibling
/// `dmtap-postage-patala` adapter crate for one optional, isolated reference implementation.
pub trait PostageProvider: Send + Sync {
    /// Begin/complete a prepaid top-up through this operator's chosen payment provider. Settles
    /// **once** per top-up — never per message.
    fn top_up(&self, req: TopUpRequest) -> TopUpResult;

    /// Current balance for `account` (`None` if postage isn't tracked for this account at all,
    /// e.g. it has never topped up).
    fn balance(&self, account: &AccountId) -> Option<PostageBalance>;

    /// Draw down `amount_minor_units` from `account`'s prepaid balance for one gateway send.
    fn spend(&self, account: &AccountId, amount_minor_units: u64) -> SpendResult;
}

/// Self-host / disabled default: postage is off. `spend` always succeeds trivially — there is
/// nothing to gate on, so a self-hoster's own sends are never denied for lack of postage — and
/// `top_up`/`balance` honestly report the feature is not enabled rather than faking a ledger.
/// Mirrors [`crate::metering::NullMetering`] and [`crate::gateway_authz::OpenGatewayAuthz`]: no
/// operator opts in ⇒ no postage, no billing, nothing gated.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullPostage;

impl PostageProvider for NullPostage {
    fn top_up(&self, _req: TopUpRequest) -> TopUpResult {
        TopUpResult::Failed { reason: "postage is not enabled on this gateway".into() }
    }

    fn balance(&self, _account: &AccountId) -> Option<PostageBalance> {
        None
    }

    fn spend(&self, _account: &AccountId, _amount_minor_units: u64) -> SpendResult {
        SpendResult::Spent { remaining_minor_units: u64::MAX }
    }
}

// ── Reminders — envoir's own notification mechanism, never a parallel one ──────────────────

/// Why a [`PostageReminder`] is firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReminderKind {
    /// Balance is at or below the operator's configured low-balance threshold, but not yet zero.
    LowBalance,
    /// Balance has hit zero — the very next gated send will be denied.
    Exhausted,
}

/// A reminder that a sender's prepaid postage credit needs attention. This is plain data — see
/// the module docs' "reminders use envoir's own notification mechanism" section for why
/// `dmtap-seam` stops here rather than constructing an actual DMTAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostageReminder {
    pub account: AccountId,
    pub kind: ReminderKind,
    pub balance_minor_units: u64,
    pub currency: String,
}

/// Delivers a [`PostageReminder`]. An implementation is expected to hand this to envoir's
/// existing notification path (e.g. a system message addressed to the account's own mailbox, or a
/// content-free push wake) — never a new side-channel. Fire-and-forget from this crate's point of
/// view, exactly like [`crate::metering::Metering::record`].
pub trait PostageReminderSink: Send + Sync {
    fn notify(&self, reminder: PostageReminder);
}

/// Self-host / disabled default: drops reminders. Mirrors [`NullPostage`] — no postage enabled,
/// nothing to remind anyone about.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullReminders;

impl PostageReminderSink for NullReminders {
    fn notify(&self, _reminder: PostageReminder) {}
}

/// Decide whether a reminder is due for a post-spend balance, given an operator-configured
/// `threshold_minor_units`. Pure and deterministic, so it is trivially testable and reusable
/// outside [`PostageGatedAuthz`] (e.g. from a periodic balance sweep, not just the send path).
/// Returns `None` when the balance is healthy.
pub fn reminder_for_balance(
    account: &AccountId,
    balance_minor_units: u64,
    currency: &str,
    threshold_minor_units: u64,
) -> Option<PostageReminder> {
    if balance_minor_units == 0 {
        Some(PostageReminder {
            account: account.clone(),
            kind: ReminderKind::Exhausted,
            balance_minor_units,
            currency: currency.to_string(),
        })
    } else if balance_minor_units <= threshold_minor_units {
        Some(PostageReminder {
            account: account.clone(),
            kind: ReminderKind::LowBalance,
            balance_minor_units,
            currency: currency.to_string(),
        })
    } else {
        None
    }
}

// ── Wiring into GatewayAuthz — optional, off by default ─────────────────────────────────────

/// Wraps an existing [`GatewayAuthz`] with an OPTIONAL prepaid-postage gate (spec §9.5).
///
/// **Off by default in the strongest possible sense: nothing constructs one of these unless an
/// operator explicitly does.** Self-host, and any operator who never builds a
/// [`PostageGatedAuthz`], keep using [`crate::gateway_authz::OpenGatewayAuthz`] (or their own
/// [`GatewayAuthz`]) bare and unwrapped — postage is not in their authorization path at all.
///
/// An operator who DOES want it wraps their inner authz:
/// `PostageGatedAuthz::new(inner, my_provider, cost_per_send, threshold, currency)`, optionally
/// adding [`PostageGatedAuthz::with_reminders`] to also emit low-balance notifications.
///
/// Two things keep this from ever double-gating or double-charging a send:
/// - Only credentials naming an `account` are gated at all — anonymous ARC-token/PoW senders
///   ([`SendCredential::token`] / [`SendCredential::pow_bits`]) keep their existing, untouched
///   accountable path (spec §9's ARC/PoW/postage triad is *alternative*, not additive).
/// - A credential that already carries an inline per-message postage voucher
///   ([`SendCredential::postage`] `> 0`, the existing spec §9.5 mechanism) skips the prepaid
///   draw-down entirely, so the two postage mechanisms can never charge the same send twice.
pub struct PostageGatedAuthz<A, P, R = NullReminders> {
    inner: A,
    postage: P,
    reminders: R,
    cost_per_send_minor_units: u64,
    low_balance_threshold_minor_units: u64,
    currency: String,
}

impl<A: GatewayAuthz, P: PostageProvider> PostageGatedAuthz<A, P, NullReminders> {
    /// A postage gate with no reminder delivery wired in.
    pub fn new(
        inner: A,
        postage: P,
        cost_per_send_minor_units: u64,
        low_balance_threshold_minor_units: u64,
        currency: impl Into<String>,
    ) -> Self {
        PostageGatedAuthz {
            inner,
            postage,
            reminders: NullReminders,
            cost_per_send_minor_units,
            low_balance_threshold_minor_units,
            currency: currency.into(),
        }
    }
}

impl<A: GatewayAuthz, P: PostageProvider, R: PostageReminderSink> PostageGatedAuthz<A, P, R> {
    /// A postage gate that also emits low-balance/exhausted reminders through `reminders` —
    /// envoir's own notification mechanism (see [`PostageReminderSink`] docs).
    pub fn with_reminders(
        inner: A,
        postage: P,
        cost_per_send_minor_units: u64,
        low_balance_threshold_minor_units: u64,
        currency: impl Into<String>,
        reminders: R,
    ) -> Self {
        PostageGatedAuthz {
            inner,
            postage,
            reminders,
            cost_per_send_minor_units,
            low_balance_threshold_minor_units,
            currency: currency.into(),
        }
    }
}

impl<A: GatewayAuthz, P: PostageProvider, R: PostageReminderSink> GatewayAuthz
    for PostageGatedAuthz<A, P, R>
{
    fn authorize(&self, cred: &SendCredential) -> GatewayDecision {
        if let Some(account) = &cred.account {
            // A voucher already attached to this send is the existing, separate spec §9.5
            // mechanism — never double-charge by also drawing down the prepaid balance.
            if cred.postage == 0 {
                match self.postage.spend(account, self.cost_per_send_minor_units) {
                    SpendResult::Insufficient { .. } => {
                        return GatewayDecision::Deny { reason: "insufficient postage".into() };
                    }
                    SpendResult::Spent { remaining_minor_units } => {
                        if let Some(reminder) = reminder_for_balance(
                            account,
                            remaining_minor_units,
                            &self.currency,
                            self.low_balance_threshold_minor_units,
                        ) {
                            self.reminders.notify(reminder);
                        }
                    }
                }
            }
        }
        // Privacy/crypto is never reachable from here: this composes only with GatewayAuthz, the
        // operations-only legacy-egress gate — never encryption, the mixnet, or key recovery.
        self.inner.authorize(cred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_authz::OpenGatewayAuthz;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // A minimal in-memory PostageProvider for tests: caller-owned storage, exactly the shape a
    // real operator implementation takes (see module docs).
    struct TestProvider {
        balances: Mutex<HashMap<AccountId, u64>>,
        spends: Mutex<u32>,
    }

    impl TestProvider {
        fn with_balance(account: &str, minor_units: u64) -> Self {
            let mut m = HashMap::new();
            m.insert(account.to_string(), minor_units);
            TestProvider { balances: Mutex::new(m), spends: Mutex::new(0) }
        }
    }

    impl PostageProvider for TestProvider {
        fn top_up(&self, req: TopUpRequest) -> TopUpResult {
            let mut b = self.balances.lock().unwrap();
            let entry = b.entry(req.account).or_insert(0);
            *entry += req.amount.minor_units;
            TopUpResult::Credited {
                new_balance: Money::new(*entry, req.amount.currency),
                reference: req.reference,
            }
        }

        fn balance(&self, account: &AccountId) -> Option<PostageBalance> {
            self.balances.lock().unwrap().get(account).map(|&minor_units| PostageBalance {
                account: account.clone(),
                balance: Money::new(minor_units, "USD"),
            })
        }

        fn spend(&self, account: &AccountId, amount_minor_units: u64) -> SpendResult {
            *self.spends.lock().unwrap() += 1;
            let mut b = self.balances.lock().unwrap();
            let bal = b.entry(account.clone()).or_insert(0);
            if *bal < amount_minor_units {
                SpendResult::Insufficient {
                    balance_minor_units: *bal,
                    required_minor_units: amount_minor_units,
                }
            } else {
                *bal -= amount_minor_units;
                SpendResult::Spent { remaining_minor_units: *bal }
            }
        }
    }

    #[derive(Default)]
    struct TestReminders {
        seen: Mutex<Vec<PostageReminder>>,
    }

    impl PostageReminderSink for TestReminders {
        fn notify(&self, reminder: PostageReminder) {
            self.seen.lock().unwrap().push(reminder);
        }
    }

    // ── NullPostage: postage disabled = no gating ───────────────────────────────────────────

    #[test]
    fn null_postage_top_up_is_honestly_disabled() {
        let result = NullPostage.top_up(TopUpRequest {
            account: "acct".into(),
            amount: Money::new(500, "USD"),
            reference: "ref-1".into(),
        });
        assert!(matches!(result, TopUpResult::Failed { .. }));
    }

    #[test]
    fn null_postage_balance_is_untracked() {
        assert_eq!(NullPostage.balance(&"acct".to_string()), None);
    }

    #[test]
    fn null_postage_spend_never_gates() {
        // Even an absurd amount always succeeds — self-host's own sends are never denied.
        assert_eq!(
            NullPostage.spend(&"acct".to_string(), u64::MAX / 2),
            SpendResult::Spent { remaining_minor_units: u64::MAX }
        );
    }

    #[test]
    fn null_postage_gated_authz_stays_open() {
        // Even wrapping OpenGatewayAuthz with a disabled provider never denies (defense in
        // depth: NullPostage's own semantics already guarantee this).
        let authz = PostageGatedAuthz::new(OpenGatewayAuthz, NullPostage, 100, 10, "USD");
        assert_eq!(
            authz.authorize(&SendCredential::none("acct")),
            GatewayDecision::Allow
        );
    }

    // ── Prepaid spend-down logic ─────────────────────────────────────────────────────────────

    #[test]
    fn spend_draws_down_balance() {
        let p = TestProvider::with_balance("acct", 1_000);
        assert_eq!(
            p.spend(&"acct".to_string(), 300),
            SpendResult::Spent { remaining_minor_units: 700 }
        );
        assert_eq!(
            p.balance(&"acct".to_string()).unwrap().balance.minor_units,
            700
        );
    }

    #[test]
    fn top_up_then_spend_round_trip() {
        let p = TestProvider::with_balance("acct", 0);
        let top_up = p.top_up(TopUpRequest {
            account: "acct".into(),
            amount: Money::new(1_000, "USD"),
            reference: "ref-1".into(),
        });
        assert!(matches!(top_up, TopUpResult::Credited { .. }));
        assert_eq!(
            p.spend(&"acct".to_string(), 250),
            SpendResult::Spent { remaining_minor_units: 750 }
        );
    }

    // ── Insufficient-postage rejection ──────────────────────────────────────────────────────

    #[test]
    fn spend_beyond_balance_is_insufficient() {
        let p = TestProvider::with_balance("acct", 50);
        assert_eq!(
            p.spend(&"acct".to_string(), 100),
            SpendResult::Insufficient { balance_minor_units: 50, required_minor_units: 100 }
        );
    }

    #[test]
    fn postage_gated_authz_denies_on_insufficient_balance() {
        let p = TestProvider::with_balance("acct", 10);
        let authz = PostageGatedAuthz::new(OpenGatewayAuthz, p, 100, 20, "USD");
        let decision = authz.authorize(&SendCredential::none("acct"));
        assert_eq!(decision, GatewayDecision::Deny { reason: "insufficient postage".into() });
    }

    #[test]
    fn postage_gated_authz_allows_when_balance_covers_cost() {
        let p = TestProvider::with_balance("acct", 1_000);
        let authz = PostageGatedAuthz::new(OpenGatewayAuthz, p, 100, 20, "USD");
        assert_eq!(authz.authorize(&SendCredential::none("acct")), GatewayDecision::Allow);
    }

    #[test]
    fn postage_gated_authz_defers_to_inner_deny() {
        struct AlwaysDeny;
        impl GatewayAuthz for AlwaysDeny {
            fn authorize(&self, _cred: &SendCredential) -> GatewayDecision {
                GatewayDecision::Deny { reason: "rate limited".into() }
            }
        }
        let p = TestProvider::with_balance("acct", 1_000);
        let authz = PostageGatedAuthz::new(AlwaysDeny, p, 100, 20, "USD");
        // Postage is fine, but the inner authz still gets the final say.
        assert_eq!(
            authz.authorize(&SendCredential::none("acct")),
            GatewayDecision::Deny { reason: "rate limited".into() }
        );
    }

    #[test]
    fn anonymous_credential_bypasses_prepaid_gate() {
        // No account ⇒ no postage account to charge; ARC/PoW accountability is untouched.
        let p = TestProvider::with_balance("acct", 0);
        let authz = PostageGatedAuthz::new(OpenGatewayAuthz, p, 100, 20, "USD");
        let cred = SendCredential {
            account: None,
            token: Some("arc-token".into()),
            postage: 0,
            pow_bits: 20,
        };
        assert_eq!(authz.authorize(&cred), GatewayDecision::Allow);
    }

    #[test]
    fn inline_postage_voucher_skips_prepaid_double_charge() {
        // A credential arriving with its own attached voucher (the existing, separate spec
        // §9.5 mechanism) must not ALSO draw down the prepaid balance.
        let p = TestProvider::with_balance("acct", 0); // would be insufficient if charged
        let authz = PostageGatedAuthz::new(OpenGatewayAuthz, p, 100, 20, "USD");
        let cred = SendCredential {
            account: Some("acct".into()),
            token: None,
            postage: 500, // inline voucher already covers this send
            pow_bits: 0,
        };
        assert_eq!(authz.authorize(&cred), GatewayDecision::Allow);
    }

    // ── Reminders ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn reminder_none_when_balance_healthy() {
        assert_eq!(reminder_for_balance(&"acct".to_string(), 1_000, "USD", 100), None);
    }

    #[test]
    fn reminder_low_balance_at_threshold() {
        let r = reminder_for_balance(&"acct".to_string(), 100, "USD", 100).unwrap();
        assert_eq!(r.kind, ReminderKind::LowBalance);
        assert_eq!(r.balance_minor_units, 100);
        assert_eq!(r.currency, "USD");
    }

    #[test]
    fn reminder_exhausted_at_zero() {
        let r = reminder_for_balance(&"acct".to_string(), 0, "USD", 100).unwrap();
        assert_eq!(r.kind, ReminderKind::Exhausted);
    }

    #[test]
    fn low_balance_reminder_fires_through_sink_on_send() {
        let p = TestProvider::with_balance("acct", 120);
        let reminders = TestReminders::default();
        // Spending 100 of 120 leaves 20, at/under the threshold of 20 ⇒ a reminder should fire.
        let authz = PostageGatedAuthz::with_reminders(
            OpenGatewayAuthz,
            p,
            100,
            20,
            "USD",
            reminders,
        );
        assert_eq!(authz.authorize(&SendCredential::none("acct")), GatewayDecision::Allow);
        let seen = authz.reminders.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].kind, ReminderKind::LowBalance);
        assert_eq!(seen[0].balance_minor_units, 20);
    }

    #[test]
    fn healthy_balance_never_triggers_a_reminder() {
        let p = TestProvider::with_balance("acct", 10_000);
        let reminders = TestReminders::default();
        let authz = PostageGatedAuthz::with_reminders(
            OpenGatewayAuthz,
            p,
            100,
            20,
            "USD",
            reminders,
        );
        assert_eq!(authz.authorize(&SendCredential::none("acct")), GatewayDecision::Allow);
        assert!(authz.reminders.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn insufficient_balance_denies_before_any_reminder_check() {
        // Below zero cost: the deny path returns early and never even calls reminder_for_balance
        // (there is no post-spend balance to reminder about).
        let p = TestProvider::with_balance("acct", 5);
        let reminders = TestReminders::default();
        let authz = PostageGatedAuthz::with_reminders(
            OpenGatewayAuthz,
            p,
            100,
            20,
            "USD",
            reminders,
        );
        assert_eq!(
            authz.authorize(&SendCredential::none("acct")),
            GatewayDecision::Deny { reason: "insufficient postage".into() }
        );
        assert!(authz.reminders.seen.lock().unwrap().is_empty());
    }
}
