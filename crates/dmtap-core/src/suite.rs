//! Algorithm suites & crypto-agility — spec §1.1, §16.7.
//!
//! Every signed/encrypted object carries a `suite` identifier. Implementations MUST reject
//! unknown suites (**fail closed**) and never guess. `suites` on an [`crate::identity::Identity`]
//! is a *set* (§1.3), so an identity can hold classical and PQ keys simultaneously during
//! migration.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A DMTAP algorithm suite (spec §1.1).
///
/// | `suite` | Sign | KEM | AEAD | Hash | Status |
/// |--------:|------|-----|------|------|--------|
/// | `0x01`  | Ed25519 | X25519 (HPKE) | ChaCha20-Poly1305 | BLAKE3-256 | v0 REQUIRED |
/// | `0x02`  | Ed25519+ML-DSA-65 | X-Wing (X25519+ML-KEM-768) | ChaCha20-Poly1305 | BLAKE3-256 | RESERVED (PQ) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Suite {
    /// v0 REQUIRED: Ed25519 sign, HPKE DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305.
    Classical = 0x01,
    /// PQ HYBRID: Ed25519+ML-DSA-65 sign, X-Wing (X25519 + ML-KEM-768) KEM.
    ///
    /// The **MOTE layer** implements this suite for real — hybrid sealing/signing live in
    /// [`crate::pq`], and [`mote_supported`](Suite::mote_supported) returns `true`. The multi-suite
    /// [`crate::identity::Identity`] object machinery, however, is still classical-only, so
    /// [`is_supported`](Suite::is_supported) returns `false` and a `0x02`-only `Identity` fails
    /// closed (see [`crate::identity::Identity::verify`]).
    PqHybrid = 0x02,
}

impl Suite {
    /// Decode a suite byte, **failing closed** on any unknown value (spec §1.1).
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Suite::Classical),
            0x02 => Some(Suite::PqHybrid),
            _ => None, // unknown suite — reject, never guess
        }
    }

    /// The on-the-wire byte for this suite.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the reference core supports this suite for the **multi-suite [`Identity`] object**
    /// (§18.4.1): a full per-suite key set + one signature per suite. Only `0x01` is wired at that
    /// layer, so `0x02` returns `false` (a `0x02`-only `Identity` fails closed). This is distinct
    /// from [`mote_supported`](Suite::mote_supported) — the MOTE envelope/payload layer implements
    /// `0x02` for real (see [`crate::pq`]).
    ///
    /// [`Identity`]: crate::identity::Identity
    pub fn is_supported(self) -> bool {
        matches!(self, Suite::Classical)
    }

    /// Whether the **MOTE envelope/payload layer** (§2.2, §2.4) can seal, sign, and validate an
    /// object under this suite. Both `0x01` (classical) and `0x02` (X-Wing + Ed25519∧ML-DSA-65
    /// hybrid, see [`crate::pq`]) are implemented, so both return `true`. A future, still-unassigned
    /// suite byte cannot even decode ([`from_u8`](Suite::from_u8) fails closed), so this predicate
    /// enumerates exactly the suites the MOTE machinery can handle.
    pub fn mote_supported(self) -> bool {
        matches!(self, Suite::Classical | Suite::PqHybrid)
    }
}

// Serialize as a single CBOR unsigned integer (the suite byte), and fail closed on decode.
impl Serialize for Suite {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for Suite {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = u8::deserialize(d)?;
        Suite::from_u8(b).ok_or_else(|| serde::de::Error::custom(format!("unknown suite 0x{b:02x}")))
    }
}

// --- Suite negotiation / intersection (§1.1, §1.3) -----------------------------------------

/// A [`negotiate_suite`] failure (`ERR_SUITE_INTERSECTION_EMPTY`, §21.3 `0x0102`).
///
/// Disposition per §21.3: `REJECT_NOTIFY` — the sender's and recipient's supported-suite sets do
/// not intersect, so there is **no common suite** to encrypt/sign under. Delivery fails closed;
/// there is **no silent downgrade** to a suite one side does not support (§1.3).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SuiteNegotiationError {
    /// The sender's and recipient's supported-suite sets are disjoint — no suite both can use.
    #[error(
        "sender and recipient supported-suite sets do not intersect — no common suite \
         (ERR_SUITE_INTERSECTION_EMPTY, §21.3 0x0102)"
    )]
    IntersectionEmpty,
}

impl SuiteNegotiationError {
    /// The normative DMTAP wire error code (§21.3).
    pub fn code(&self) -> u16 {
        match self {
            SuiteNegotiationError::IntersectionEmpty => 0x0102,
        }
    }
}

/// Select the negotiated cipher-suite for delivery from a `sender` and a `recipient`
/// supported-suite set (spec §1.1, §1.3).
///
/// `suites` is a *set* (§1.3): the two argument lists are the sender's supported suites and the
/// recipient's `Identity.suites`. The rule is normative — a **sender MUST use the highest suite
/// both parties support** (the intersection). "Highest" is the strongest suite, i.e. the greatest
/// [`Suite`] byte (`PqHybrid` `0x02` > `Classical` `0x01`), so a pair that has both migrated to the
/// PQ suite negotiates it in preference to the classical one. Duplicate or unordered inputs do not
/// matter — only set membership and the byte ordering do.
///
/// If the intersection is **empty** there is no common suite and this **fails closed** with
/// [`SuiteNegotiationError::IntersectionEmpty`] (`0x0102`): delivery is refused rather than silently
/// downgraded to a suite one side cannot validate (§1.1 "reject unknown suites, never guess";
/// §1.3 "no silent downgrade").
pub fn negotiate_suite(
    sender: &[Suite],
    recipient: &[Suite],
) -> Result<Suite, SuiteNegotiationError> {
    sender
        .iter()
        .filter(|s| recipient.contains(s))
        .copied()
        .max() // highest (strongest) suite both parties support
        .ok_or(SuiteNegotiationError::IntersectionEmpty)
}

// --- Suite high-water-mark ratchet (§1.3, §2.7 step 8) -------------------------------------

/// A [`SuiteRatchet`] downgrade rejection (`ERR_SUITE_DOWNGRADE`, §21.3 `0x020F`).
///
/// Disposition per §21.3: `DEFER_REQUESTS + USER_WARN` — a below-high-water-mark MOTE MUST NOT be
/// accepted and the high-water-mark MUST NOT ratchet down (§10.7.1, §2.7 step 8).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SuiteRatchetError {
    /// `Envelope.suite` is **below** the sender-contact's pinned suite high-water-mark — a
    /// downgrade attempt (e.g. a broken classical suite offered after both parties migrated to PQ).
    #[error(
        "Envelope.suite is below the contact's pinned suite high-water-mark — suite downgrade \
         (ERR_SUITE_DOWNGRADE, §21.3 0x020F)"
    )]
    SuiteDowngrade,
}

impl SuiteRatchetError {
    /// The normative DMTAP wire error code (§21.3).
    pub fn code(&self) -> u16 {
        match self {
            SuiteRatchetError::SuiteDowngrade => 0x020F,
        }
    }
}

/// Per-contact suite **high-water-mark ratchet** (spec §1.3, §2.7 step 8, §10.7.1).
///
/// A receiver tracks, per pinned contact (keyed by identity public key), the highest
/// `Envelope.suite` ever accepted from them. Once a peer is seen at suite epoch `N`, any later
/// object asserting a suite below that mark is a **downgrade** and is rejected with
/// [`SuiteRatchetError::SuiteDowngrade`] (`0x020F`). The mark ratchets **up only** — [`observe`]
/// never lowers it — so a global active adversary cannot replay a weaker suite past two peers who
/// have already migrated upward.
///
/// Suite ordering is the [`Suite`] byte order (`Classical = 0x01` < `PqHybrid = 0x02`), matching
/// the spec's "suite epoch" monotonicity. This is pure, deterministic state: the ratchet observes a
/// suite regardless of whether the reference core can *validate* it, because pinning is a distinct
/// concern from suite support (`mote::validate`'s §2.7 step 1 support check).
///
/// [`observe`]: SuiteRatchet::observe
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SuiteRatchet {
    /// contact identity key → highest suite byte accepted from that contact.
    floors: BTreeMap<Vec<u8>, u8>,
}

impl SuiteRatchet {
    /// A ratchet with no pinned contacts.
    pub fn new() -> Self {
        SuiteRatchet { floors: BTreeMap::new() }
    }

    /// The current high-water-mark for `contact`, or `None` if never seen.
    pub fn high_water_mark(&self, contact: &[u8]) -> Option<Suite> {
        self.floors.get(contact).and_then(|b| Suite::from_u8(*b))
    }

    /// Check `suite` against `contact`'s high-water-mark **without** mutating state: a suite below
    /// the pinned floor fails closed with `0x020F`. A first-contact (unpinned) suite always passes.
    pub fn check(&self, contact: &[u8], suite: Suite) -> Result<(), SuiteRatchetError> {
        match self.floors.get(contact) {
            Some(&floor) if suite.as_u8() < floor => Err(SuiteRatchetError::SuiteDowngrade),
            _ => Ok(()),
        }
    }

    /// Ratchet the high-water-mark for `contact` **up** to `suite` (never down). Idempotent for a
    /// suite at or below the current mark.
    pub fn observe(&mut self, contact: &[u8], suite: Suite) {
        let e = self.floors.entry(contact.to_vec()).or_insert(0);
        if suite.as_u8() > *e {
            *e = suite.as_u8();
        }
    }

    /// [`check`](SuiteRatchet::check) then, on success, [`observe`](SuiteRatchet::observe): accept a
    /// suite from `contact`, rejecting a downgrade below the pinned floor (`0x020F`) and otherwise
    /// ratcheting the mark up. A rejected downgrade leaves the mark untouched (never ratchets down).
    pub fn accept(&mut self, contact: &[u8], suite: Suite) -> Result<(), SuiteRatchetError> {
        self.check(contact, suite)?;
        self.observe(contact, suite);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_fails_closed() {
        assert_eq!(Suite::from_u8(0x01), Some(Suite::Classical));
        assert_eq!(Suite::from_u8(0x02), Some(Suite::PqHybrid));
        // Every other byte MUST be rejected.
        for b in [0x00u8, 0x03, 0x7f, 0xff] {
            assert_eq!(Suite::from_u8(b), None, "byte 0x{b:02x} must fail closed");
        }
    }

    #[test]
    fn cbor_rejects_unknown_suite() {
        // A CBOR integer 0x05 must not deserialize into a Suite.
        let mut buf = Vec::new();
        ciborium::into_writer(&5u8, &mut buf).unwrap();
        let r: Result<Suite, _> = ciborium::from_reader(&buf[..]);
        assert!(r.is_err(), "unknown suite byte must fail closed on decode");
    }

    #[test]
    fn only_classical_is_supported() {
        // Identity-object (multi-suite) support is classical-only.
        assert!(Suite::Classical.is_supported());
        assert!(!Suite::PqHybrid.is_supported());
    }

    #[test]
    fn both_suites_are_mote_supported() {
        // The MOTE envelope/payload layer implements both the classical and the PQ-hybrid suite.
        assert!(Suite::Classical.mote_supported());
        assert!(Suite::PqHybrid.mote_supported());
    }

    #[test]
    fn negotiate_picks_highest_common_suite() {
        // Both support both suites — pick the highest (PQ).
        assert_eq!(
            negotiate_suite(&[Suite::Classical, Suite::PqHybrid], &[Suite::Classical, Suite::PqHybrid]),
            Ok(Suite::PqHybrid)
        );
        // Overlap is classical only (sender is PQ-capable, recipient classical-only) — pick classical.
        assert_eq!(
            negotiate_suite(&[Suite::Classical, Suite::PqHybrid], &[Suite::Classical]),
            Ok(Suite::Classical)
        );
        // Order of the input lists is irrelevant; only set membership + strength ordering matter.
        assert_eq!(
            negotiate_suite(&[Suite::PqHybrid, Suite::Classical], &[Suite::PqHybrid]),
            Ok(Suite::PqHybrid)
        );
    }

    #[test]
    fn negotiate_disjoint_sets_fail_closed() {
        // Sender only PQ, recipient only classical — no common suite, fail closed 0x0102.
        let err = negotiate_suite(&[Suite::PqHybrid], &[Suite::Classical]).unwrap_err();
        assert_eq!(err, SuiteNegotiationError::IntersectionEmpty);
        assert_eq!(err.code(), 0x0102);
        // Empty recipient set (nothing published) also fails closed — never guess a suite.
        assert_eq!(
            negotiate_suite(&[Suite::Classical], &[]),
            Err(SuiteNegotiationError::IntersectionEmpty)
        );
        assert_eq!(
            negotiate_suite(&[], &[Suite::Classical]),
            Err(SuiteNegotiationError::IntersectionEmpty)
        );
    }

    #[test]
    fn ratchet_rejects_downgrade_below_high_water_mark() {
        let mut r = SuiteRatchet::new();
        let peer = b"peer-key".to_vec();
        // First contact at the higher (PQ) suite pins the mark.
        assert!(r.accept(&peer, Suite::PqHybrid).is_ok());
        assert_eq!(r.high_water_mark(&peer), Some(Suite::PqHybrid));
        // A later classical (0x01 < 0x02) MOTE is a downgrade — reject with 0x020F.
        let err = r.check(&peer, Suite::Classical).unwrap_err();
        assert_eq!(err, SuiteRatchetError::SuiteDowngrade);
        assert_eq!(err.code(), 0x020F);
        // The rejected downgrade MUST NOT ratchet the mark down.
        assert_eq!(r.high_water_mark(&peer), Some(Suite::PqHybrid));
        assert_eq!(r.accept(&peer, Suite::Classical), Err(SuiteRatchetError::SuiteDowngrade));
        assert_eq!(r.high_water_mark(&peer), Some(Suite::PqHybrid));
    }

    #[test]
    fn ratchet_first_contact_and_upgrade_are_accepted() {
        let mut r = SuiteRatchet::new();
        let peer = b"peer".to_vec();
        // Unpinned first contact at classical is fine.
        assert!(r.accept(&peer, Suite::Classical).is_ok());
        assert_eq!(r.high_water_mark(&peer), Some(Suite::Classical));
        // Ratcheting UP to PQ is allowed and sticks.
        assert!(r.accept(&peer, Suite::PqHybrid).is_ok());
        assert_eq!(r.high_water_mark(&peer), Some(Suite::PqHybrid));
        // Distinct contacts are tracked independently.
        let other = b"other".to_vec();
        assert!(r.check(&other, Suite::Classical).is_ok());
    }
}
