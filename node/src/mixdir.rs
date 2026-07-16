//! Mix-directory anti-rollback — the node's per-authority monotonic high-water-mark (spec §4.4.2,
//! §18.5.3).
//!
//! A [`MixDirectory`](dmtap_core::mixnet::MixDirectory) is the signed, versioned mix-fleet snapshot a
//! node consumes to route through the mixnet. Its `version` (and `epoch`) are **monotonic — an
//! older-or-equal directory MUST be rejected** (see the field docs in `dmtap_core::mixnet`), so a
//! network adversary cannot replay a *stale* fleet (e.g. one whose mixes it has since compromised, or
//! that omits nodes added later) past a node that has already seen a newer one.
//!
//! `dmtap_core` gives the node the primitive — [`MixDirectory::verify`] (authority signature) plus the
//! authenticated `authority`/`epoch`/`version` — but **no tracker**: enforcing monotonicity is the
//! *stateful* concern the crate deliberately leaves to the caller (like the per-contact
//! [`SuiteRatchet`](dmtap_core::suite::SuiteRatchet) for suite downgrades). This module is that
//! caller: it stores the per-authority high-water-mark in the node's state so a rollback is rejected
//! **at the node**, not merely rejectable in the crate.
//!
//! The high-water-mark is the `(epoch, version)` pair, ordered lexicographically (a newer epoch
//! always wins; within an epoch a higher version wins). Held inside the [`Node`](crate::node::Node);
//! see [`Node::ingest_mix_directory`](crate::node::Node::ingest_mix_directory).

use std::collections::HashMap;

use dmtap_core::mixnet::MixDirectory;

/// Why a node refused to accept an inbound [`MixDirectory`] (fail-closed, §4.4.2 / §18.5.3).
#[derive(Debug, PartialEq, Eq)]
pub enum MixDirError {
    /// The bytes did not decode as a canonical §18.5.3 directory (bad CBOR, empty fleet, …).
    Malformed,
    /// The directory-authority signature did not verify (or its suite is unsupported) — the
    /// authority did not attest this fleet ([`MixDirectory::verify`]).
    Unverified,
    /// The directory is **older-or-equal** to the authority's pinned high-water-mark — a rollback.
    /// `pinned` / `offered` are the `(epoch, version)` pairs. The pinned mark is left untouched.
    Stale { pinned: (u64, u64), offered: (u64, u64) },
}

impl std::fmt::Display for MixDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MixDirError::Malformed => f.write_str("mix directory is malformed (§18.5.3)"),
            MixDirError::Unverified => {
                f.write_str("mix directory authority signature did not verify (§18.9.9)")
            }
            MixDirError::Stale { pinned, offered } => write!(
                f,
                "mix directory rollback: offered (epoch {}, ver {}) ≤ pinned (epoch {}, ver {})",
                offered.0, offered.1, pinned.0, pinned.1
            ),
        }
    }
}
impl std::error::Error for MixDirError {}

/// Per-authority monotonic mix-directory tracker (spec §4.4.2, §18.5.3). Keyed by the
/// directory-authority identity key, it retains the highest `(epoch, version)` accepted from each
/// authority (and the accepted directory itself), rejecting any older-or-equal snapshot as a
/// rollback. Pure, deterministic state (no wall clock); persist it across restarts to keep the
/// high-water-mark. This is the node-layer half of the crate's monotonic-`version` contract.
#[derive(Debug, Default, Clone)]
pub struct MixDirectoryTracker {
    /// authority IK → the latest accepted directory from that authority. Its `(epoch, version)` is
    /// the high-water-mark; the directory itself is retained so the node can route on the fleet.
    latest: HashMap<Vec<u8>, MixDirectory>,
}

impl MixDirectoryTracker {
    /// A tracker with no pinned authorities.
    pub fn new() -> Self {
        MixDirectoryTracker { latest: HashMap::new() }
    }

    /// The pinned high-water-mark `(epoch, version)` for `authority`, or `None` if never seen.
    pub fn high_water_mark(&self, authority: &[u8]) -> Option<(u64, u64)> {
        self.latest.get(authority).map(|d| (d.epoch, d.version))
    }

    /// The latest accepted directory from `authority`, if any.
    pub fn latest(&self, authority: &[u8]) -> Option<&MixDirectory> {
        self.latest.get(authority)
    }

    /// Verify `dir` (authority signature) and enforce the per-authority monotonic high-water-mark,
    /// **fail-closed** (§4.4.2, §18.5.3):
    ///
    /// 1. [`MixDirectory::verify`] — the authority signed this fleet (else [`MixDirError::Unverified`]).
    /// 2. `(epoch, version)` must be **strictly greater** than the authority's pinned mark; an
    ///    older-or-equal directory is a rollback ([`MixDirError::Stale`]) and the mark is left
    ///    untouched (never ratchets down).
    ///
    /// On success the mark ratchets up and the directory is retained. First contact with an authority
    /// establishes the mark at the directory's `(epoch, version)`.
    pub fn accept(&mut self, dir: &MixDirectory) -> Result<(), MixDirError> {
        dir.verify().map_err(|_| MixDirError::Unverified)?;
        let offered = (dir.epoch, dir.version);
        if let Some(pinned) = self.high_water_mark(&dir.authority) {
            if offered <= pinned {
                return Err(MixDirError::Stale { pinned, offered });
            }
        }
        self.latest.insert(dir.authority.clone(), dir.clone());
        Ok(())
    }

    /// Decode `bytes` as a §18.5.3 directory then [`accept`](Self::accept) it. The single entry point
    /// a node's inbound path uses to admit a mix-directory from the wire, fail-closed at every stage.
    pub fn ingest(&mut self, bytes: &[u8]) -> Result<(), MixDirError> {
        let dir = MixDirectory::from_det_cbor(bytes).map_err(|_| MixDirError::Malformed)?;
        self.accept(&dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::id::ContentId;
    use dmtap_core::identity::IdentityKey;
    use dmtap_core::mixnet::{MixKeyEntry, MixNodeDescriptor};

    fn directory(authority: &IdentityKey, epoch: u64, version: u64) -> MixDirectory {
        let node = IdentityKey::from_seed(&[0x55; 32]);
        let desc = MixNodeDescriptor::issue(
            &node,
            vec!["/ip4/198.51.100.7/udp/443/quic-v1".into()],
            vec![MixKeyEntry { epoch, mix_key: vec![0x11; 32], valid_until: 1_700_000_600_000 }],
            1,
            1_700_000_000_000,
            None,
            None,
        );
        MixDirectory::issue(
            authority,
            epoch,
            version,
            vec![desc],
            ContentId::of(b"genesis"),
            1_700_000_000_000,
        )
    }

    #[test]
    fn first_contact_pins_and_upgrade_ratchets() {
        let auth = IdentityKey::from_seed(&[0x01; 32]);
        let mut t = MixDirectoryTracker::new();
        assert!(t.accept(&directory(&auth, 5, 1)).is_ok());
        assert_eq!(t.high_water_mark(&auth.public()), Some((5, 1)));
        // Same epoch, higher version — ratchets up.
        assert!(t.accept(&directory(&auth, 5, 2)).is_ok());
        assert_eq!(t.high_water_mark(&auth.public()), Some((5, 2)));
        // New epoch — always wins.
        assert!(t.accept(&directory(&auth, 6, 1)).is_ok());
        assert_eq!(t.high_water_mark(&auth.public()), Some((6, 1)));
    }

    #[test]
    fn rollback_is_rejected_and_mark_untouched() {
        let auth = IdentityKey::from_seed(&[0x02; 32]);
        let mut t = MixDirectoryTracker::new();
        assert!(t.accept(&directory(&auth, 9, 4)).is_ok());
        // Older version, same epoch — a rollback.
        assert_eq!(
            t.accept(&directory(&auth, 9, 3)),
            Err(MixDirError::Stale { pinned: (9, 4), offered: (9, 3) })
        );
        // Equal — also rejected (monotonic = strictly greater).
        assert!(matches!(t.accept(&directory(&auth, 9, 4)), Err(MixDirError::Stale { .. })));
        // Older epoch even with a higher version — still a rollback (epoch dominates).
        assert!(matches!(t.accept(&directory(&auth, 8, 99)), Err(MixDirError::Stale { .. })));
        // The mark never ratcheted down.
        assert_eq!(t.high_water_mark(&auth.public()), Some((9, 4)));
    }

    #[test]
    fn a_forged_authority_signature_fails_closed() {
        let auth = IdentityKey::from_seed(&[0x03; 32]);
        let mut dir = directory(&auth, 1, 1);
        dir.sig[0] ^= 0xff; // tamper the authority signature
        let mut t = MixDirectoryTracker::new();
        assert_eq!(t.accept(&dir), Err(MixDirError::Unverified));
        assert_eq!(t.high_water_mark(&auth.public()), None, "an unverified dir pins nothing");
    }

    #[test]
    fn distinct_authorities_are_tracked_independently() {
        let a = IdentityKey::from_seed(&[0x04; 32]);
        let b = IdentityKey::from_seed(&[0x05; 32]);
        let mut t = MixDirectoryTracker::new();
        assert!(t.accept(&directory(&a, 7, 7)).is_ok());
        // A first-contact directory from a *different* authority is not gated by a's mark.
        assert!(t.accept(&directory(&b, 1, 1)).is_ok());
        assert_eq!(t.high_water_mark(&a.public()), Some((7, 7)));
        assert_eq!(t.high_water_mark(&b.public()), Some((1, 1)));
    }

    #[test]
    fn ingest_round_trips_through_the_wire() {
        let auth = IdentityKey::from_seed(&[0x06; 32]);
        let bytes = directory(&auth, 3, 3).det_cbor();
        let mut t = MixDirectoryTracker::new();
        assert!(t.ingest(&bytes).is_ok());
        assert_eq!(t.high_water_mark(&auth.public()), Some((3, 3)));
        // A replay of the same wire bytes is a rollback (equal mark).
        assert!(matches!(t.ingest(&bytes), Err(MixDirError::Stale { .. })));
        // Garbage bytes fail closed as malformed.
        assert_eq!(t.ingest(b"not cbor"), Err(MixDirError::Malformed));
    }
}
