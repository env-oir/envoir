//! Caller-policy predicates for recipient MOTE handling — spec §2.6/§2.7, §16.1.
//!
//! Several checks in the recipient pipeline (§2.7) are **caller policy**, not part of the
//! anonymous cryptographic validation in [`crate::mote::validate`]: they depend on caller-owned
//! state (a dedup set, the pinned-identity table) or the caller's wall clock (skew, expiry), which
//! [`crate::mote::validate`] deliberately does not touch (§16.1: nodes MUST NOT rely on
//! synchronized clocks for correctness). This module gives those checks **explicit, deterministic,
//! testable** helpers so a caller — and the conformance runner's VAL cases — can enforce them the
//! same way everywhere, each mapped to its normative §21 code.
//!
//! It is strictly **additive**: [`crate::mote::validate`]'s signature is unchanged. A caller runs
//! [`crate::mote::validate`] for the cryptographic gate, then applies these predicates around it.
//!
//! | Helper | Concern | §21 code |
//! |--------|---------|----------|
//! | [`is_duplicate`] / [`CallerPolicy::check_duplicate`] | dedup by `Envelope.id` (§2.6) | `STATUS_DUPLICATE_ID` `0x020E` |
//! | [`within_skew`] / [`CallerPolicy::check_skew`] | `Envelope.ts` vs receiver clock (§16.1) | `ERR_TIMESTAMP_OUT_OF_SKEW` `0x020C` |
//! | [`is_expired`] / [`CallerPolicy::check_expiry`] | `Payload.expires` (§2.4, §16.1) | `ERR_EXPIRED_MOTE` `0x020B` |
//! | [`repin_allowed`] / [`CallerPolicy::check_repin`] | pinned-identity re-pin (§2.7 step 8, §3.4) | `ERR_FROM_PIN_MISMATCH` `0x0209` |

use std::collections::BTreeSet;

use crate::id::ContentId;

/// The ±120 s clock-skew tolerance for `Envelope.ts` (spec §16.1), in milliseconds.
pub const SKEW_TOLERANCE_MS: u64 = 120_000;

/// A caller-policy verdict, each variant carrying its normative §21 wire code. `DuplicateId` is a
/// **status** (`ACK_DEDUP`, §2.6), not a failure — the recipient already holds the MOTE and acks
/// it — but is modelled as an `Err` so a caller can branch on it uniformly.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// The recipient already holds this `Envelope.id` — `STATUS_DUPLICATE_ID` (`0x020E`,
    /// ACK_DEDUP, §2.6). Content-addressed dedup is what makes a bare MOTE replay a no-op.
    #[error("recipient already holds this id (STATUS_DUPLICATE_ID 0x020E)")]
    DuplicateId,
    /// `Envelope.ts` falls outside the ±120 s skew tolerance — `ERR_TIMESTAMP_OUT_OF_SKEW`
    /// (`0x020C`, §16.1). DROP_SILENT for cold senders; a caller MAY be lenient toward known
    /// contacts.
    #[error("timestamp outside ±120 s skew tolerance (ERR_TIMESTAMP_OUT_OF_SKEW 0x020C)")]
    TimestampOutOfSkew,
    /// `Payload.expires` has passed at receipt time — `ERR_EXPIRED_MOTE` (`0x020B`, DROP_SILENT,
    /// §2.4). A cooperative hint (§6.6 item 8), not a security guarantee.
    #[error("client-requested expiry has passed (ERR_EXPIRED_MOTE 0x020B)")]
    ExpiredMote,
    /// The authenticated `Payload.from` does not match the pinned identity for a known contact —
    /// `ERR_FROM_PIN_MISMATCH` (`0x0209`, HALT_ALERT, §2.7 step 8, §3.4). MUST NOT silently repin;
    /// surface a security warning.
    #[error("decrypted `from` does not match the pinned identity (ERR_FROM_PIN_MISMATCH 0x0209)")]
    FromPinMismatch,
}

impl PolicyError {
    /// The normative DMTAP wire code (§21) for this verdict.
    pub fn code(&self) -> u16 {
        match self {
            PolicyError::DuplicateId => 0x020E,
            PolicyError::TimestampOutOfSkew => 0x020C,
            PolicyError::ExpiredMote => 0x020B,
            PolicyError::FromPinMismatch => 0x0209,
        }
    }
}

// ── Standalone predicates (pure; no owned state) ────────────────────────────────────────────

/// Whether `id` is already in the recipient's `seen` set — the §2.6 dedup test. A `true` verdict
/// is `STATUS_DUPLICATE_ID` (`0x020E`): the recipient acks without re-processing.
pub fn is_duplicate(seen: &BTreeSet<Vec<u8>>, id: &ContentId) -> bool {
    seen.contains(id.as_bytes())
}

/// Whether `sender_ts` is within `tolerance_ms` of the receiver's clock `receiver_now` (§16.1),
/// symmetric in both directions (future- and past-skew). Pass [`SKEW_TOLERANCE_MS`] for the spec
/// default. A `false` verdict is `ERR_TIMESTAMP_OUT_OF_SKEW` (`0x020C`).
pub fn within_skew(sender_ts: u64, receiver_now: u64, tolerance_ms: u64) -> bool {
    let delta = sender_ts.abs_diff(receiver_now);
    delta <= tolerance_ms
}

/// Whether a MOTE whose `Payload.expires` is `expires` has expired at receipt time `now` (§2.4,
/// §16.1). Absent `expires` never expires. A `true` verdict is `ERR_EXPIRED_MOTE` (`0x020B`).
pub fn is_expired(expires: Option<u64>, now: u64) -> bool {
    matches!(expires, Some(e) if now > e)
}

/// Whether pinning `observed` as this contact's identity key is allowed (§2.7 step 8, §3.4).
///
/// - `pinned = None` ⇒ first contact: allowed (TOFU-pin the observed key).
/// - `pinned = Some(k)` ⇒ known contact: allowed **iff** `observed == k`. A different key is a
///   silent-repin attempt and MUST be refused — `ERR_FROM_PIN_MISMATCH` (`0x0209`).
pub fn repin_allowed(pinned: Option<&[u8]>, observed: &[u8]) -> bool {
    match pinned {
        None => true,
        Some(k) => k == observed,
    }
}

// ── Stateful helper that owns the dedup set + tolerance ─────────────────────────────────────

/// A caller-owned bundle of the recipient-side policy state: the seen-`id` dedup set and the skew
/// tolerance. Deterministic (no internal clock — the caller passes `now`), so it is reproducible
/// across runs and suitable for the conformance VAL cases. Persist it across calls to retain dedup
/// state; the pinned-identity table is passed per-call to [`CallerPolicy::check_repin`] since it is
/// keyed by contact and typically lives elsewhere.
#[derive(Debug, Clone)]
pub struct CallerPolicy {
    seen: BTreeSet<Vec<u8>>,
    tolerance_ms: u64,
}

impl Default for CallerPolicy {
    fn default() -> Self {
        CallerPolicy { seen: BTreeSet::new(), tolerance_ms: SKEW_TOLERANCE_MS }
    }
}

impl CallerPolicy {
    /// A fresh policy with the spec-default ±120 s skew tolerance and an empty dedup set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the skew tolerance (e.g. to be lenient toward a known contact, §16.1).
    pub fn with_tolerance_ms(mut self, tolerance_ms: u64) -> Self {
        self.tolerance_ms = tolerance_ms;
        self
    }

    /// Dedup check **without** recording — [`PolicyError::DuplicateId`] (`0x020E`) if `id` is
    /// already held.
    pub fn check_duplicate(&self, id: &ContentId) -> Result<(), PolicyError> {
        if is_duplicate(&self.seen, id) {
            Err(PolicyError::DuplicateId)
        } else {
            Ok(())
        }
    }

    /// Dedup check **and** record: `Ok(())` the first time `id` is seen (now recorded), then
    /// [`PolicyError::DuplicateId`] (`0x020E`) on every later presentation of the same `id`.
    pub fn check_and_record(&mut self, id: &ContentId) -> Result<(), PolicyError> {
        if self.seen.insert(id.as_bytes().to_vec()) {
            Ok(())
        } else {
            Err(PolicyError::DuplicateId)
        }
    }

    /// Skew check against the configured tolerance — [`PolicyError::TimestampOutOfSkew`]
    /// (`0x020C`) when `sender_ts` is too far from `now` (§16.1).
    pub fn check_skew(&self, sender_ts: u64, now: u64) -> Result<(), PolicyError> {
        if within_skew(sender_ts, now, self.tolerance_ms) {
            Ok(())
        } else {
            Err(PolicyError::TimestampOutOfSkew)
        }
    }

    /// Expiry check — [`PolicyError::ExpiredMote`] (`0x020B`) when `expires` has passed at `now`
    /// (§2.4). Absent `expires` never expires.
    pub fn check_expiry(&self, expires: Option<u64>, now: u64) -> Result<(), PolicyError> {
        if is_expired(expires, now) {
            Err(PolicyError::ExpiredMote)
        } else {
            Ok(())
        }
    }

    /// Pinned-identity re-pin check — [`PolicyError::FromPinMismatch`] (`0x0209`) when a known
    /// contact's authenticated `from` differs from the pinned key (§2.7 step 8, §3.4). First
    /// contact (`pinned = None`) is accepted (TOFU).
    pub fn check_repin(&self, pinned: Option<&[u8]>, observed: &[u8]) -> Result<(), PolicyError> {
        if repin_allowed(pinned, observed) {
            Ok(())
        } else {
            Err(PolicyError::FromPinMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_predicate_and_stateful() {
        let id = ContentId::of(b"m1");
        let mut seen = BTreeSet::new();
        assert!(!is_duplicate(&seen, &id));
        seen.insert(id.as_bytes().to_vec());
        assert!(is_duplicate(&seen, &id));

        let mut pol = CallerPolicy::new();
        assert!(pol.check_and_record(&id).is_ok(), "first sight accepted");
        let err = pol.check_and_record(&id).unwrap_err();
        assert_eq!(err, PolicyError::DuplicateId);
        assert_eq!(err.code(), 0x020E);
        // A different id is not a duplicate.
        assert!(pol.check_and_record(&ContentId::of(b"m2")).is_ok());
    }

    #[test]
    fn skew_within_and_outside_tolerance() {
        let now = 1_700_000_000_000u64;
        assert!(within_skew(now, now, SKEW_TOLERANCE_MS));
        assert!(within_skew(now + 120_000, now, SKEW_TOLERANCE_MS)); // exactly at bound
        assert!(within_skew(now - 120_000, now, SKEW_TOLERANCE_MS)); // symmetric
        assert!(!within_skew(now + 120_001, now, SKEW_TOLERANCE_MS));

        let pol = CallerPolicy::new();
        assert!(pol.check_skew(now + 5_000, now).is_ok());
        let err = pol.check_skew(now + 200_000, now).unwrap_err();
        assert_eq!(err, PolicyError::TimestampOutOfSkew);
        assert_eq!(err.code(), 0x020C);
        // Past-skew beyond tolerance also rejected.
        assert!(pol.check_skew(now - 200_000, now).is_err());
    }

    #[test]
    fn lenient_tolerance_override() {
        let now = 1_000_000u64;
        let pol = CallerPolicy::new().with_tolerance_ms(10_000_000);
        assert!(pol.check_skew(now + 5_000_000, now).is_ok(), "known-contact leniency");
    }

    #[test]
    fn expiry_check() {
        let now = 1_700_000_000_000u64;
        assert!(!is_expired(None, now), "no expiry never expires");
        assert!(!is_expired(Some(now), now), "exactly-now is not yet passed");
        assert!(!is_expired(Some(now + 1), now));
        assert!(is_expired(Some(now - 1), now));

        let pol = CallerPolicy::new();
        assert!(pol.check_expiry(Some(now + 60_000), now).is_ok());
        let err = pol.check_expiry(Some(now - 60_000), now).unwrap_err();
        assert_eq!(err, PolicyError::ExpiredMote);
        assert_eq!(err.code(), 0x020B);
    }

    #[test]
    fn repin_tofu_then_pin_mismatch() {
        let pinned = vec![0xAAu8; 32];
        let same = pinned.clone();
        let other = vec![0xBBu8; 32];

        assert!(repin_allowed(None, &pinned), "first contact TOFU-pins");
        assert!(repin_allowed(Some(&pinned), &same), "same key re-pins fine");
        assert!(!repin_allowed(Some(&pinned), &other), "different key refused");

        let pol = CallerPolicy::new();
        assert!(pol.check_repin(None, &pinned).is_ok());
        assert!(pol.check_repin(Some(&pinned), &same).is_ok());
        let err = pol.check_repin(Some(&pinned), &other).unwrap_err();
        assert_eq!(err, PolicyError::FromPinMismatch);
        assert_eq!(err.code(), 0x0209);
    }
}
