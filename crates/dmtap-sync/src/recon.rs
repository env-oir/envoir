//! Range-based Merkle reconciliation (`SYNC.md` §5.3, fold frozen as `SYNC-RECON-01`).
//!
//! The §5.2 baseline `pull` scans all ops after a version vector — fine for small states, O(history)
//! to *find* a small difference between two large ones. Range-Merkle finds it in
//! O(log n · divergence) by recursively fingerprinting HLC-ordered ranges: equal `(fp, count)` ⇒
//! the ranges are identical and **no data is exchanged**; on mismatch the range is split and the
//! sub-range fingerprints are compared recursively, until a range small enough to ship directly.
//!
//! **The fold is deliberately not homomorphic.** `fp` is one DS-tagged BLAKE3 hash over the
//! deterministic-CBOR array of the range's op ids in ascending-HLC order — a collapse to a single
//! digest, matching the §5.6 `recon` reference. An incremental/homomorphic combiner (XOR- or
//! addition-of-hashes) would buy O(1) range updates but admits **cancellation** (an even number of
//! identical insertions vanishes) and adds an integer-arithmetic corner to the wire. A changed
//! range is simply re-hashed instead. `count` guards the degenerate empty-vs-empty and duplicate
//! cases a digest alone could not distinguish.
//!
//! Range-Merkle is a **discovery optimization only**: every op it surfaces is applied through the
//! same §4 verify + merge path. It changes *how the difference is found*, never *what converges*.

use crate::detcbor::{encode, SVal};
use crate::wire::{ds_hash, Hlc, DS_RECON_FP};
use dmtap_core::id::ContentId;

/// One op as reconciliation sees it: its HLC (the range key, a total order) and its `op-id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpEntry {
    /// The op's HLC — the §3 total order the ranges are canonical in.
    pub hlc: Hlc,
    /// The op's §4.1 content address.
    pub id: ContentId,
}

impl Ord for OpEntry {
    /// The §3 HLC total order, with the op id as a final tiebreak so the sort is total even if two
    /// distinct ops somehow carried the same HLC (only possible from a forging author).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hlc.cmp(&other.hlc).then_with(|| self.id.as_bytes().cmp(other.id.as_bytes()))
    }
}

impl PartialOrd for OpEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A range summary exchanged by `POST /sync/fingerprint` (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeFingerprint {
    /// Range start, inclusive.
    pub lo: Hlc,
    /// Range end, exclusive.
    pub hi: Hlc,
    /// The §5.3 fold over the range's op ids.
    pub fp: ContentId,
    /// The number of ops in the range — the guard the digest alone cannot provide.
    pub count: u64,
}

/// The §5.3 fold:
/// `fp = 0x1e ‖ BLAKE3-256("DMTAP-SYNC-v0/recon-fp" ‖ 0x00 ‖ det_cbor([* op-id]))`
/// over the range's op ids sorted **ascending by HLC**. Distinct authors never tie, so the order is
/// total and identical on both sides.
pub fn fingerprint(entries: &[OpEntry]) -> (ContentId, u64) {
    let mut sorted: Vec<&OpEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.hlc.cmp(&b.hlc));
    let body = encode(&SVal::Array(
        sorted.iter().map(|e| SVal::Bytes(e.id.as_bytes().to_vec())).collect(),
    ));
    (ds_hash(DS_RECON_FP, &body), sorted.len() as u64)
}

/// The entries of `all` whose HLC lies in `[lo, hi)`.
pub fn in_range<'a>(all: &'a [OpEntry], lo: &Hlc, hi: &Hlc) -> Vec<OpEntry> {
    let mut v: Vec<OpEntry> =
        all.iter().filter(|e| e.hlc >= *lo && e.hlc < *hi).cloned().collect();
    v.sort();
    v
}

/// Summarize `[lo, hi)` of `all` as a wire fingerprint.
pub fn summarize(all: &[OpEntry], lo: &Hlc, hi: &Hlc) -> RangeFingerprint {
    let entries = in_range(all, lo, hi);
    let (fp, count) = fingerprint(&entries);
    RangeFingerprint { lo: lo.clone(), hi: hi.clone(), fp, count }
}

/// The result of a reconciliation round.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconOutcome {
    /// Op ids the responder holds that the caller lacks.
    pub missing_here: Vec<ContentId>,
    /// Op ids the caller holds that the responder lacks.
    pub missing_there: Vec<ContentId>,
    /// How many ranges were fingerprinted — the work the optimization is measured in.
    pub ranges_compared: usize,
}

/// Tuning for [`reconcile`] (§5.3: "a small fixed fan-out"; "a range that shrinks below a threshold
/// ships its ops directly").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconConfig {
    /// How many sub-ranges a mismatched range splits into.
    pub fanout: usize,
    /// At or below this many ops, a mismatched range ships its ops instead of splitting further.
    pub direct_threshold: usize,
}

impl Default for ReconConfig {
    fn default() -> Self {
        ReconConfig { fanout: 2, direct_threshold: 1 }
    }
}

/// Reconcile two replicas' op sets over `[lo, hi)`, exchanging only what differs.
///
/// Equal `(fp, count)` short-circuits the whole subtree with **no ops exchanged** — the property
/// that makes this O(divergence) rather than O(history).
pub fn reconcile(
    local: &[OpEntry],
    remote: &[OpEntry],
    lo: &Hlc,
    hi: &Hlc,
    cfg: ReconConfig,
) -> ReconOutcome {
    let mut out = ReconOutcome::default();
    recurse(&in_range(local, lo, hi), &in_range(remote, lo, hi), cfg, &mut out);
    out
}

fn recurse(local: &[OpEntry], remote: &[OpEntry], cfg: ReconConfig, out: &mut ReconOutcome) {
    out.ranges_compared += 1;
    let (lfp, lcount) = fingerprint(local);
    let (rfp, rcount) = fingerprint(remote);
    if lfp.as_bytes() == rfp.as_bytes() && lcount == rcount {
        return; // identical range: nothing exchanged, no recursion
    }
    if local.len().max(remote.len()) <= cfg.direct_threshold.max(1) {
        for e in remote {
            if !local.iter().any(|l| l.id.as_bytes() == e.id.as_bytes()) {
                out.missing_here.push(e.id.clone());
            }
        }
        for e in local {
            if !remote.iter().any(|r| r.id.as_bytes() == e.id.as_bytes()) {
                out.missing_there.push(e.id.clone());
            }
        }
        return;
    }
    // Split by op count on the union of both sides' HLC boundaries, so the split points are
    // canonical on both replicas (the HLC total order is shared).
    let mut boundaries: Vec<Hlc> =
        local.iter().chain(remote.iter()).map(|e| e.hlc.clone()).collect();
    boundaries.sort();
    boundaries.dedup();
    let fanout = cfg.fanout.max(2);
    let chunk = boundaries.len().div_ceil(fanout).max(1);
    let mut start = 0usize;
    while start < boundaries.len() {
        let end = (start + chunk).min(boundaries.len());
        let lo = &boundaries[start];
        let hi = boundaries.get(end);
        let pick = |set: &[OpEntry]| -> Vec<OpEntry> {
            set.iter()
                .filter(|e| e.hlc >= *lo && hi.map_or(true, |h| e.hlc < *h))
                .cloned()
                .collect()
        };
        recurse(&pick(local), &pick(remote), cfg, out);
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn entry(counter: u32, tag: u8) -> OpEntry {
        OpEntry {
            hlc: Hlc { wall: 1_700_000_100_000, counter, author: a(0xcc) },
            id: ContentId::of(&[tag]),
        }
    }

    #[test]
    fn equal_ranges_exchange_nothing() {
        let set: Vec<OpEntry> = (1..=3).map(|i| entry(i, i as u8)).collect();
        let lo = Hlc { wall: 1_700_000_100_000, counter: 0, author: a(0xcc) };
        let hi = Hlc { wall: 1_700_000_100_000, counter: 10, author: a(0xcc) };
        let out = reconcile(&set, &set, &lo, &hi, ReconConfig::default());
        assert!(out.missing_here.is_empty() && out.missing_there.is_empty());
        assert_eq!(out.ranges_compared, 1, "an equal top-level range short-circuits immediately");
    }

    #[test]
    fn one_differing_op_is_surfaced() {
        let a_set: Vec<OpEntry> = (1..=3).map(|i| entry(i, i as u8)).collect();
        let b_set: Vec<OpEntry> = (1..=2).map(|i| entry(i, i as u8)).collect();
        let lo = Hlc { wall: 1_700_000_100_000, counter: 0, author: a(0xcc) };
        let hi = Hlc { wall: 1_700_000_100_000, counter: 10, author: a(0xcc) };
        // From B's point of view, A holds one op B lacks.
        let out = reconcile(&b_set, &a_set, &lo, &hi, ReconConfig::default());
        assert_eq!(out.missing_here.len(), 1);
        assert_eq!(out.missing_here[0].as_bytes(), ContentId::of(&[3u8]).as_bytes());
        assert!(out.missing_there.is_empty());
    }

    #[test]
    fn fingerprint_is_not_homomorphic_duplicates_do_not_cancel() {
        // A cancelling (XOR-style) fold would make an even number of identical ids vanish; this
        // fold does not — the count and the ordered array both change.
        let one = vec![entry(1, 1)];
        let two = vec![entry(1, 1), entry(2, 1)];
        assert_ne!(fingerprint(&one).0.as_bytes(), fingerprint(&two).0.as_bytes());
        assert_eq!(fingerprint(&two).1, 2);
    }

    #[test]
    fn fingerprint_is_order_independent_because_it_sorts_by_hlc() {
        let mut forward: Vec<OpEntry> = (1..=3).map(|i| entry(i, i as u8)).collect();
        let backward: Vec<OpEntry> = forward.iter().rev().cloned().collect();
        forward.rotate_left(1);
        assert_eq!(fingerprint(&forward).0.as_bytes(), fingerprint(&backward).0.as_bytes());
    }
}
