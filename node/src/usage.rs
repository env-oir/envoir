//! Hosted-node **storage** seam — the node side of the operator seam (spec §12.2, §12.3, §12.4).
//!
//! The private control-plane (`envoir-cloud`, a **separate repo**) sells three usage meters:
//! *alias*, *gateway*, and *node*. "Node usage" is **hosted-mailbox storage** — the durable bytes a
//! node holds on an account's behalf. This module is the OSS half of that meter, and it mirrors the
//! shape the gateway already uses ([`GatewayAuthz`] + [`GatewayMeter`], §7.9): the whole cloud
//! relationship reduces to exactly **two traits** —
//!
//! 1. [`StorageQuota`] — a **Policy** decision (§12.2): given an account and a proposed storage
//!    delta, may the node durably accept it, and what allowance remains? The self-host default
//!    ([`UnlimitedStorage`]) is **unlimited** and never denies.
//! 2. [`NodeUsageMeter`] — a **Metering** sink (§12.2): an append-only stream of usage events
//!    (stored-bytes delta / eviction / message-accepted) the operator turns into a bill. The
//!    self-host default ([`NullUsageMeter`]) is a no-op.
//!
//! ## No money, no plans, no pricing here
//! The seam carries **events and a yes/no** — nothing about currency, plans, or prices. The node
//! links **no** cloud or billing crate; a cloud impl *drops into* these traits from the outside. The
//! OSS defaults make the node run **identically with the cloud off**: self-host stores everything and
//! bills no one (§12.2 "self-host default is unlimited/no-op").
//!
//! ## The inviolable rule (§12.3) — this seam gates operations, never protection
//! A denied store refuses to **durably add new inbound** to the mailbox. It does **not** — and MUST
//! never — touch encryption, decryption, the mixnet, metadata privacy, recovery, or a user's access
//! to keys or to already-stored mail. It is a storage **operation** limit on new writes, exactly the
//! "operations and organizational concerns only" the seam is allowed to meter and cap. Everything the
//! node already holds stays fully readable regardless of any quota verdict.
//!
//! ## Fail-closed enforcement vs. the impl's own fallback (§12.2)
//! The node **enforces a `Deny` faithfully**: a store the quota does not admit is **not** written and
//! **not** acked (fail-closed — the node never silently ignores a deny and stores anyway). What to do
//! when a *remote* operator is unreachable is the **impl's** concern, not the node's: per §12.2 an
//! operator's Policy SHOULD fall back to `Allow` there (a billing concern, not a security one). The
//! OSS default simply never denies, so this file's behavior on self-host is: admit everything.
//!
//! [`GatewayAuthz`]: crate — see `gateway` crate `provenance::GatewayAuthz`
//! [`GatewayMeter`]: crate — see `gateway` crate `provenance::GatewayMeter`

use std::cell::RefCell;
use std::rc::Rc;

use dmtap_core::TimestampMs;

// ── Storage Policy seam (§12.2 Policy: storage caps) ──────────────────────────────────────────

/// The verdict for a proposed durable storage write (§12.2 Policy). `remaining_bytes` is the
/// allowance left for this account **after** the decision would apply: `None` means *unlimited*
/// (the self-host default), `Some(n)` means at most `n` further bytes may be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// The write is admitted. `remaining_bytes` is the allowance left afterwards (`None` = unlimited).
    Allow { remaining_bytes: Option<u64> },
    /// The write is refused — the account's storage cap would be exceeded. `remaining_bytes` is what
    /// the account may still store (`< delta_bytes`, possibly `0`); `reason` is safe to surface.
    Deny { reason: String, remaining_bytes: u64 },
}

impl QuotaDecision {
    /// Whether the write is admitted. The node stores + meters **iff** this is true (fail-closed).
    pub fn is_allowed(&self) -> bool {
        matches!(self, QuotaDecision::Allow { .. })
    }

    /// The allowance remaining after this decision would apply: `None` = unlimited, `Some(n)` = at
    /// most `n` further bytes. Uniform accessor across both variants.
    pub fn remaining_bytes(&self) -> Option<u64> {
        match self {
            QuotaDecision::Allow { remaining_bytes } => *remaining_bytes,
            QuotaDecision::Deny { remaining_bytes, .. } => Some(*remaining_bytes),
        }
    }
}

/// The **Policy** capability for hosted-mailbox storage (§12.2). Given the mailbox owner's account
/// (`account` — the node's root identity public bytes, §1.2, which a hosted deployment maps to its
/// billing account) and a proposed `delta_bytes` of new durable storage, decide [`QuotaDecision`]
/// and expose the remaining allowance.
///
/// The node consults this **before** durably accepting a stored MOTE/file. The OSS ships
/// [`UnlimitedStorage`] (never denies); a cloud impl drops in from the outside. No pricing, no plans
/// — only a yes/no and how much room is left. The trait carries no `Send + Sync` bound, matching the
/// node's other injected seams ([`crate::Journal`], the name-chain client): the node is a single
/// current-thread actor.
pub trait StorageQuota {
    /// May `account` durably store `delta_bytes` more? Returns the verdict and remaining allowance.
    fn admit(&self, account: &[u8], delta_bytes: u64) -> QuotaDecision;
}

/// The self-host default: **unlimited** (§12.2 "self-host default is unlimited/no-op"). Every write is
/// [`QuotaDecision::Allow`] with `remaining_bytes: None`, so a node with no operator stores everything
/// and self-host is byte-for-byte unaffected by the seam.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnlimitedStorage;

impl StorageQuota for UnlimitedStorage {
    fn admit(&self, _account: &[u8], _delta_bytes: u64) -> QuotaDecision {
        QuotaDecision::Allow { remaining_bytes: None }
    }
}

// ── Metering seam (§12.2 Metering: storage / message counts) ──────────────────────────────────

/// One appended node-usage event — the raw material the operator's billing (a **separate repo**)
/// turns into a bill. It carries **no** money, plan, or price: just what happened, to which account,
/// and when. Emitted by the node at the real storage cost centers only (§12.2, §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageEvent {
    /// A MOTE/file was durably accepted into the mailbox: `delta_bytes` were added. This is the
    /// primary "node usage" (hosted-mailbox storage) signal a cloud samples into GB-month (§12.4).
    Stored { account: Vec<u8>, delta_bytes: u64, at: TimestampMs },
    /// Durably-stored bytes were released (expunge/retention eviction): `delta_bytes` were freed. The
    /// running signed sum of `Stored − Evicted` is the current stored-bytes level a GB-month sample
    /// reads. (The reference node has no eviction call site yet; the variant completes the seam so a
    /// cloud impl — or a future expunge path — can bill storage as a *level*, not a monotone total.)
    Evicted { account: Vec<u8>, delta_bytes: u64, at: TimestampMs },
    /// A message was accepted into the inbox (a unit count, independent of its size) — the optional
    /// message-count meter (§12.2 "message counts").
    MessageAccepted { account: Vec<u8>, at: TimestampMs },
}

impl UsageEvent {
    /// The account this event bills against (the mailbox owner's identity bytes).
    pub fn account(&self) -> &[u8] {
        match self {
            UsageEvent::Stored { account, .. }
            | UsageEvent::Evicted { account, .. }
            | UsageEvent::MessageAccepted { account, .. } => account,
        }
    }

    /// The signed contribution of this event to the account's stored-bytes level: `Stored` adds,
    /// `Evicted` subtracts, `MessageAccepted` is size-neutral (`0`). Summing this over the stream
    /// yields the current GB-month sample input.
    pub fn stored_delta(&self) -> i64 {
        match self {
            UsageEvent::Stored { delta_bytes, .. } => *delta_bytes as i64,
            UsageEvent::Evicted { delta_bytes, .. } => -(*delta_bytes as i64),
            UsageEvent::MessageAccepted { .. } => 0,
        }
    }
}

/// The **Metering** capability envoir-cloud consumes (§12.2). The node calls [`Self::record`] once per
/// real storage cost event; the sink is append-only and holds no policy. Like [`StorageQuota`], it
/// carries no `Send + Sync` bound (single-threaded node actor) and no cloud dependency — a billing
/// backend implements it from the outside.
pub trait NodeUsageMeter {
    /// Append `event` to the usage stream. Best-effort and non-blocking: metering MUST NOT break
    /// user-facing storage (§12.2 "fail-open to function") — an unrecordable event is dropped/queued
    /// by the impl, never surfaced to the store path.
    fn record(&self, event: &UsageEvent);
}

/// The self-host default: a no-op meter (§12.2 "self-host default is unlimited/no-op"). A node with no
/// operator bills no one and holds nothing after emitting.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullUsageMeter;

impl NodeUsageMeter for NullUsageMeter {
    fn record(&self, _event: &UsageEvent) {}
}

/// An in-memory counting meter for tests and single-node deployments: it records every event and
/// exposes the running stored-bytes level, so a test can prove the node meters **exactly** the
/// storage it durably accepts. Cloning shares the same underlying log (via [`Rc`]), so a clone handed
/// to a [`crate::Node`] and a clone retained by the caller observe the **same** counter.
#[derive(Debug, Default, Clone)]
pub struct CountingUsageMeter {
    events: Rc<RefCell<Vec<UsageEvent>>>,
}

impl CountingUsageMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of usage events recorded so far.
    pub fn count(&self) -> usize {
        self.events.borrow().len()
    }

    /// The current stored-bytes level for `account`: the signed sum of its `Stored − Evicted`
    /// contributions. This is the value a GB-month sample reads (§12.4).
    pub fn stored_bytes(&self, account: &[u8]) -> i64 {
        self.events
            .borrow()
            .iter()
            .filter(|e| e.account() == account)
            .map(UsageEvent::stored_delta)
            .sum()
    }

    /// A snapshot of the recorded events (for audit / assertions).
    pub fn events(&self) -> Vec<UsageEvent> {
        self.events.borrow().clone()
    }
}

impl NodeUsageMeter for CountingUsageMeter {
    fn record(&self, event: &UsageEvent) {
        self.events.borrow_mut().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_admits_everything_with_no_bound() {
        let q = UnlimitedStorage;
        let d = q.admit(b"acct", u64::MAX);
        assert!(d.is_allowed());
        assert_eq!(d.remaining_bytes(), None, "unlimited exposes no finite allowance");
    }

    #[test]
    fn null_meter_is_a_noop() {
        // A no-op meter simply must not panic; it records nothing observable.
        NullUsageMeter.record(&UsageEvent::Stored {
            account: b"acct".to_vec(),
            delta_bytes: 42,
            at: 1_700_000_000_000,
        });
    }

    #[test]
    fn counting_meter_tracks_signed_stored_level_per_account() {
        let m = CountingUsageMeter::new();
        let a = b"account-a".to_vec();
        let b = b"account-b".to_vec();

        m.record(&UsageEvent::Stored { account: a.clone(), delta_bytes: 1000, at: 1 });
        m.record(&UsageEvent::Stored { account: a.clone(), delta_bytes: 500, at: 2 });
        m.record(&UsageEvent::MessageAccepted { account: a.clone(), at: 3 }); // size-neutral
        m.record(&UsageEvent::Evicted { account: a.clone(), delta_bytes: 200, at: 4 });
        m.record(&UsageEvent::Stored { account: b.clone(), delta_bytes: 7, at: 5 });

        assert_eq!(m.count(), 5);
        assert_eq!(m.stored_bytes(&a), 1000 + 500 - 200, "signed level, message-count is neutral");
        assert_eq!(m.stored_bytes(&b), 7, "levels are per-account");
    }

    #[test]
    fn counting_meter_clone_shares_the_log() {
        let m = CountingUsageMeter::new();
        let handed_off = m.clone();
        handed_off.record(&UsageEvent::Stored {
            account: b"acct".to_vec(),
            delta_bytes: 9,
            at: 1,
        });
        assert_eq!(m.count(), 1, "a clone and the original observe the same underlying log");
    }
}
