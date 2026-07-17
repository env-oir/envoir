//! Range-based Merkle set-reconciliation (spec §5.6.3(a)).
//!
//! Two devices reconcile their sets of object ids **without re-downloading everything**. Objects
//! are ordered by content address; the id-space is split into ranges; each range carries a
//! **fingerprint** = the suite hash over the sorted ids it contains ([`RangeFingerprint`]). The
//! exchange (Meyer / Auvolat–Taïani / Minsky–Trachtenberg, §15.5):
//!
//! 1. Each side summarises the whole id-space as a handful of top-level range fingerprints.
//! 2. A range whose fingerprint **matches** on both sides is skipped — the two hold the identical
//!    ids there, *proven by one hash comparison*, with no further traffic.
//! 3. A range whose fingerprint **differs** is **drilled down**: re-split into `b` sub-ranges
//!    (fan-out §16.10) and recurse, until a divergent range is small enough (≤ the leaf threshold,
//!    §16.10) to **enumerate** its ids directly.
//! 4. Each side then **fetches only the ids the other holds that it lacks** — never the matching
//!    bulk.
//!
//! The cost is **O(differences · log n)**, not O(n): matching subtrees vanish in a single hash
//! comparison. A [`RangeFingerprint`] is **self-verifying** — a receiver recomputes it over the
//! ids it holds in the range ([`verify_range`]) — so a peer cannot forge a "we match" claim to
//! suppress objects; a summary whose `fp` does not recompute is rejected
//! (`ERR_CLUSTER_RECON_SUMMARY_INVALID`, `0x0411`, §5.6.3(a)).

use crate::error::SyncError;
use crate::wire::{Hash, RangeFingerprint};
use dmtap_core::cbor::{self, Cv};
use dmtap_core::ContentId;
use std::collections::BTreeSet;

/// Reconciliation tuning (§16.10). `fanout` is the branching factor of the range summary;
/// `leaf_threshold` is the id count at or below which a divergent range is enumerated directly.
#[derive(Debug, Clone, Copy)]
pub struct ReconConfig {
    /// Branching factor `b`: each divergent range re-splits into this many sub-ranges (§16.10 = 16).
    pub fanout: usize,
    /// Enumerate a divergent range once it holds ≤ this many ids (§16.10 = 8).
    pub leaf_threshold: usize,
}

impl Default for ReconConfig {
    fn default() -> Self {
        ReconConfig { fanout: 16, leaf_threshold: 8 }
    }
}

/// The suite hash over a range's **sorted** ids (§5.6.3(a)). Computed as the content address of the
/// canonical CBOR array of the ids — reusing the §18.1 codec makes it deterministic and
/// unambiguous (length-prefixed byte strings can't be confused across a boundary), and identical on
/// any implementation. The caller MUST pass the ids **already sorted** by content address.
pub fn range_fingerprint(sorted_ids: &[Hash]) -> Hash {
    let arr = Cv::Array(sorted_ids.iter().map(|h| Cv::Bytes(h.clone())).collect());
    ContentId::of(&cbor::encode(&arr)).0
}

/// The 16-byte big-endian numeric view of a content address's leading bytes, used only to derive
/// **range boundaries** both sides agree on. Ids are still compared and fingerprinted by their full
/// bytes; this prefix merely partitions the key-space deterministically (blake3 ids are uniform, so
/// the split is balanced).
fn key_prefix(k: &[u8]) -> u128 {
    let mut buf = [0u8; 16];
    for (i, b) in k.iter().take(16).enumerate() {
        buf[i] = *b;
    }
    u128::from_be_bytes(buf)
}

/// A 16-byte content-address bound from a numeric boundary (for a wire [`RangeFingerprint`]).
fn bound_bytes(n: u128) -> Hash {
    n.to_be_bytes().to_vec()
}

/// The sorted ids of `set` whose key-prefix lies in `[lo, hi)`.
fn ids_in_range(sorted: &[Hash], lo: u128, hi: u128) -> Vec<Hash> {
    sorted.iter().filter(|id| (lo..hi).contains(&key_prefix(id))).cloned().collect()
}

/// **Self-verify** a peer's [`RangeFingerprint`] against the ids `own_sorted` a receiver holds:
/// recompute the count and `fp` over the ids in `[lo, hi)` and reject a mismatch
/// (`ERR_CLUSTER_RECON_SUMMARY_INVALID`, `0x0411`). When the peer has revealed (enumerated) the ids
/// it claims for the range, pass those; a forged fingerprint that does not equal the hash of the
/// sorted ids in the range is caught here (§5.6.3(a)).
pub fn verify_range(rf: &RangeFingerprint, own_sorted: &[Hash]) -> Result<(), SyncError> {
    let lo = key_prefix(&rf.lo);
    let hi = key_prefix(&rf.hi);
    if lo > hi {
        return Err(SyncError::ReconSummaryInvalid); // inverted range is malformed
    }
    let ids = ids_in_range(own_sorted, lo, hi);
    if ids.len() as u64 != rf.count || range_fingerprint(&ids) != rf.fp {
        return Err(SyncError::ReconSummaryInvalid);
    }
    Ok(())
}

/// Build the `fanout` top-level range fingerprints spanning the whole id-space for `sorted_ids` —
/// the coarse `recon` summary a device sends first (§5.6.3(a)). Each carries the sender's `fp` over
/// its own ids in the sub-range, which the receiver self-verifies once the ids are revealed.
pub fn top_summary(sorted_ids: &[Hash], cfg: &ReconConfig) -> Vec<RangeFingerprint> {
    subranges(0, u128::MAX, cfg.fanout)
        .into_iter()
        .map(|(lo, hi)| {
            let ids = ids_in_range(sorted_ids, lo, hi);
            RangeFingerprint {
                lo: bound_bytes(lo),
                hi: bound_bytes(hi),
                count: ids.len() as u64,
                fp: range_fingerprint(&ids),
            }
        })
        .collect()
}

/// Split `[lo, hi)` into up to `b` contiguous sub-ranges. Returns fewer (a single `[lo, hi)`) when
/// the interval is too narrow to divide, so recursion always terminates.
fn subranges(lo: u128, hi: u128, b: usize) -> Vec<(u128, u128)> {
    let width = hi - lo;
    let b = b.max(2) as u128;
    if width <= b {
        return vec![(lo, hi)]; // indivisible — the caller enumerates it
    }
    let step = width / b;
    let mut out = Vec::with_capacity(b as usize);
    let mut cur = lo;
    for i in 0..b {
        let next = if i == b - 1 { hi } else { lo + step * (i + 1) };
        out.push((cur, next));
        cur = next;
    }
    out
}

/// The result of reconciling two id sets (§5.6.3(a)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconOutcome {
    /// Ids the peer holds that the local side lacks — the local side pulls these (§5.6.2).
    pub local_missing: Vec<Hash>,
    /// Ids the local side holds that the peer lacks — the local side pushes these (§5.6.2).
    pub peer_missing: Vec<Hash>,
    /// Number of range fingerprints compared — the reconciliation cost. For near-identical sets
    /// this is a handful (matching subtrees are eliminated by one comparison each), demonstrating
    /// the O(differences · log n) bound rather than O(n).
    pub ranges_compared: usize,
}

/// Reconcile `local` against `peer` by range-based Merkle set-reconciliation (§5.6.3(a)), returning
/// the minimal id differences each side must fetch and the number of range comparisons it took.
/// This drives the same drill-down the two devices would run over the wire: matching ranges are
/// skipped by a single fingerprint comparison; only divergent ranges are refined and, at the leaf,
/// enumerated.
pub fn reconcile(local: &BTreeSet<Hash>, peer: &BTreeSet<Hash>, cfg: &ReconConfig) -> ReconOutcome {
    let lsorted: Vec<Hash> = local.iter().cloned().collect();
    let psorted: Vec<Hash> = peer.iter().cloned().collect();
    let mut out =
        ReconOutcome { local_missing: Vec::new(), peer_missing: Vec::new(), ranges_compared: 0 };
    recon_range(local, peer, &lsorted, &psorted, 0, u128::MAX, cfg, &mut out);
    out.local_missing.sort();
    out.peer_missing.sort();
    out
}

#[allow(clippy::too_many_arguments)]
fn recon_range(
    local: &BTreeSet<Hash>,
    peer: &BTreeSet<Hash>,
    lsorted: &[Hash],
    psorted: &[Hash],
    lo: u128,
    hi: u128,
    cfg: &ReconConfig,
    out: &mut ReconOutcome,
) {
    out.ranges_compared += 1;
    let lids = ids_in_range(lsorted, lo, hi);
    let pids = ids_in_range(psorted, lo, hi);
    // One hash comparison decides a whole subtree: equal fingerprints ⇒ identical ids here ⇒ skip.
    if range_fingerprint(&lids) == range_fingerprint(&pids) {
        return;
    }
    // Divergent: enumerate if small enough on both sides or if the interval can't be split further.
    let subs = subranges(lo, hi, cfg.fanout);
    let indivisible = subs.len() == 1 && subs[0] == (lo, hi);
    if (lids.len() <= cfg.leaf_threshold && pids.len() <= cfg.leaf_threshold) || indivisible {
        for id in &pids {
            if !local.contains(id) {
                out.local_missing.push(id.clone());
            }
        }
        for id in &lids {
            if !peer.contains(id) {
                out.peer_missing.push(id.clone());
            }
        }
        return;
    }
    // Otherwise drill down into the sub-ranges (fan-out b).
    for (slo, shi) in subs {
        recon_range(local, peer, lsorted, psorted, slo, shi, cfg, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic content address for a test object numbered `n` (byte0 = 0x1e, like a real
    /// `ContentId`), so ids distribute across the key-space the way blake3 hashes do.
    fn oid(n: u64) -> Hash {
        ContentId::of(&n.to_be_bytes()).0
    }

    fn set(ids: impl IntoIterator<Item = u64>) -> BTreeSet<Hash> {
        ids.into_iter().map(oid).collect()
    }

    #[test]
    fn identical_sets_reconcile_with_no_differences_and_minimal_comparisons() {
        let a = set(0..500);
        let b = a.clone();
        let out = reconcile(&a, &b, &ReconConfig::default());
        assert!(out.local_missing.is_empty() && out.peer_missing.is_empty());
        // The whole space matches at the very top: a single fingerprint comparison suffices.
        assert_eq!(out.ranges_compared, 1, "matching sets must cost exactly one comparison");
    }

    #[test]
    fn divergent_sets_reconcile_to_convergence_with_minimal_exchange() {
        // Two large, nearly-identical replicas: A lacks 3 ids B has, B lacks 2 ids A has.
        let common: Vec<u64> = (0..5000).collect();
        let mut a = set(common.iter().copied());
        let mut b = set(common.iter().copied());
        // ids only B holds:
        for n in [10_001, 10_002, 10_003] {
            b.insert(oid(n));
        }
        // ids only A holds:
        for n in [20_001, 20_002] {
            a.insert(oid(n));
        }
        let out = reconcile(&a, &b, &ReconConfig::default());
        assert_eq!(out.local_missing, {
            let mut v = vec![oid(10_001), oid(10_002), oid(10_003)];
            v.sort();
            v
        });
        assert_eq!(out.peer_missing, {
            let mut v = vec![oid(20_001), oid(20_002)];
            v.sort();
            v
        });
        // Minimal exchange: O(diff · log n) ≪ O(n). Far fewer comparisons than the ~5000 ids —
        // matching subtrees are eliminated by a single fingerprint comparison each.
        assert!(
            out.ranges_compared < 500,
            "exchange must be sublinear in set size, got {} comparisons over ~5000 ids",
            out.ranges_compared
        );
        // Convergence: after each side fetches its missing ids, both hold the identical union.
        let mut a2 = a.clone();
        let mut b2 = b.clone();
        for id in &out.local_missing {
            a2.insert(id.clone());
        }
        for id in &out.peer_missing {
            b2.insert(id.clone());
        }
        assert_eq!(a2, b2, "both replicas must converge to the union");
    }

    #[test]
    fn backfill_empty_device_reaches_parity() {
        // A brand-new device (empty) reconciling against a full peer must learn *every* id.
        let full = set(0..300);
        let empty = BTreeSet::new();
        let out = reconcile(&empty, &full, &ReconConfig::default());
        assert!(out.peer_missing.is_empty());
        let learned: BTreeSet<Hash> = out.local_missing.into_iter().collect();
        assert_eq!(learned, full, "empty device must backfill to full parity");
    }

    #[test]
    fn range_fingerprint_self_verifies() {
        let ids: Vec<Hash> = (0..50).map(oid).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let rf = &top_summary(&sorted, &ReconConfig::default())[0];
        // Honest recomputation over the same ids passes.
        verify_range(rf, &sorted).expect("honest fingerprint must self-verify");
    }

    #[test]
    fn forged_fingerprint_is_rejected_fail_closed() {
        let ids: Vec<Hash> = (0..50).map(oid).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let mut rf = top_summary(&sorted, &ReconConfig::default())[0].clone();
        // Tamper the fingerprint — a peer forging "we match" to suppress objects.
        rf.fp[5] ^= 0xff;
        assert_eq!(verify_range(&rf, &sorted), Err(SyncError::ReconSummaryInvalid));
        // A lied-about count is equally rejected.
        let mut rf2 = top_summary(&sorted, &ReconConfig::default())[0].clone();
        rf2.count += 1;
        assert_eq!(verify_range(&rf2, &sorted), Err(SyncError::ReconSummaryInvalid));
    }
}
