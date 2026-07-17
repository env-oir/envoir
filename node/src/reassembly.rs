//! Bounded multi-cell reassembly (spec §4.4.1 fragment reliability, §16.3).
//!
//! A `private` MOTE padded to a top-of-ladder bucket fragments into as many as **32
//! independently-pathed Sphinx cells** (§4.4.1). The recipient peels each cell at the exit and must
//! hold the received fragments until the MOTE is complete. Left unbounded, a lost cell would pin
//! reassembly state forever and an adversary could exhaust memory with endless half-MOTEs.
//!
//! This module implements the **safety** part of §4.4.1's fragment reliability: a **bounded**
//! partial-reassembly cache keyed by the fragment [`msg_id`](dmtap_core::sphinx::SphinxFragmentHeader)
//! with an explicit **reassembly timeout** (§16.3: ≤ 15 min, distinct from the 72 h send deadline of
//! §16.1). A partial MOTE that does not complete within the window is discarded; the cache is also
//! capped in the number of concurrent partial MOTEs and in total buffered cells, so memory is bounded
//! regardless of the clock.
//!
//! ## Scope — what is deliberately NOT here (the larger follow-up)
//! Full per-cell **recovery** is §4.4.1's larger feature and is **not** implemented in this pass:
//! - **per-cell SURB-ARQ** — the recipient returns a still-missing-cell bitmap over a sender-supplied
//!   Single-Use Reply Block and the sender re-onion-wraps and re-dispatches **only** the missing
//!   cells; and
//! - **FEC** — the sender ships `n > k` erasure-coded cells so the recipient reconstructs from any `k`.
//!
//! This cache is the memory-safety substrate those build on: it bounds and times out partial state so
//! a lost cell cannot leak reassembly memory. ARQ/FEC (the retransmit/coded-recovery machinery) are
//! tracked as the follow-up.
//!
//! Reassembly operates on the **peeled** δ plaintext of each cell — the fixed
//! [`SphinxFragmentHeader`] followed by that fragment's data bytes — not the on-wire ciphertext.

use std::collections::BTreeMap;
use std::collections::HashMap;

use dmtap_core::sphinx::{SphinxFragmentHeader, FRAGMENT_DATA_LEN};
use dmtap_core::TimestampMs;

/// The multi-cell reassembly timeout (§16.3): ≤ 15 min, ≈ 3× the `private`-tier delivery latency
/// budget. **Distinct** from the §16.1 72 h send deadline — this bounds *recipient* memory against
/// half-MOTE flooding, not sender retry.
pub const REASSEMBLY_TIMEOUT_MS: u64 = 15 * 60 * 1000;
/// Max concurrent partial MOTEs held. Beyond this the oldest-started partial is evicted (bounded).
pub const MAX_PARTIAL_MOTES: usize = 4_096;
/// Max total buffered fragment cells across all partials — an absolute memory ceiling.
pub const MAX_PARTIAL_CELLS: usize = 32 * 1_024;
/// The bucket-ladder fragment counts (§4.4.1, §16.3). A frame asserting any other `frag_count` is
/// malformed.
const LADDER: [u16; 4] = [1, 4, 16, 32];

/// The outcome of accepting one fragment cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reassembled {
    /// The last missing cell arrived — the full padded MOTE, truncated to its true length. The
    /// partial has been evicted from the cache.
    Complete(Vec<u8>),
    /// Stored; still awaiting more cells.
    Pending,
    /// The cell was malformed, inconsistent with the partial already held, or over a hard cap — it
    /// was dropped and no state changed (fail-closed).
    Rejected,
}

/// One in-flight partial MOTE.
struct Partial {
    frag_count: u16,
    total_len: u32,
    /// Received fragments, keyed by index (dedup + ordered reassembly).
    cells: BTreeMap<u16, Vec<u8>>,
    started_at: TimestampMs,
}

/// A bounded partial-reassembly cache (§4.4.1 safety part). Keyed by the 8-byte fragment `msg_id`.
pub struct ReassemblyCache {
    partials: HashMap<[u8; 8], Partial>,
    timeout_ms: u64,
    max_motes: usize,
    max_cells: usize,
}

impl ReassemblyCache {
    /// A cache with the production timeout + caps.
    pub fn new() -> Self {
        Self::with_bounds(REASSEMBLY_TIMEOUT_MS, MAX_PARTIAL_MOTES, MAX_PARTIAL_CELLS)
    }

    /// A cache with explicit bounds (tests exercise small timeouts/caps).
    pub fn with_bounds(timeout_ms: u64, max_motes: usize, max_cells: usize) -> Self {
        ReassemblyCache { partials: HashMap::new(), timeout_ms, max_motes, max_cells }
    }

    /// Accept one peeled fragment (`hdr` + `data`, exactly [`FRAGMENT_DATA_LEN`] bytes) at receive
    /// clock `now`. Prunes timed-out partials first, then stores the cell — returning
    /// [`Reassembled::Complete`] with the reconstructed MOTE when the final missing cell arrives,
    /// [`Reassembled::Pending`] while incomplete, or [`Reassembled::Rejected`] on a malformed /
    /// inconsistent / over-cap cell.
    pub fn accept(
        &mut self,
        hdr: &SphinxFragmentHeader,
        data: &[u8],
        now: TimestampMs,
    ) -> Reassembled {
        self.prune(now);

        // Structural validation (fail-closed): ladder frag_count, in-range index, fixed data length.
        if !LADDER.contains(&hdr.frag_count)
            || hdr.frag_index >= hdr.frag_count
            || data.len() != FRAGMENT_DATA_LEN
        {
            return Reassembled::Rejected;
        }
        // total_len must fit the claimed cell count and exceed the previous rung (so frag_count is the
        // genuine ladder rung for this length — a mismatch is a malformed/adversarial frame).
        let cap = hdr.frag_count as usize * FRAGMENT_DATA_LEN;
        if hdr.total_len as usize > cap {
            return Reassembled::Rejected;
        }

        // A single-cell MOTE completes immediately with no caching (nothing to reassemble).
        if hdr.frag_count == 1 {
            let mut out = data.to_vec();
            out.truncate(hdr.total_len as usize);
            self.partials.remove(&hdr.msg_id); // any stray partial under this id is superseded
            return Reassembled::Complete(out);
        }

        // Consistency against a partial already held for this msg_id.
        if let Some(p) = self.partials.get(&hdr.msg_id) {
            if p.frag_count != hdr.frag_count || p.total_len != hdr.total_len {
                return Reassembled::Rejected; // an attacker mixing fragments across MOTEs
            }
        } else {
            // A new partial — enforce the concurrent-MOTE and total-cell caps before inserting.
            if self.partials.len() >= self.max_motes {
                self.evict_oldest();
            }
            if self.total_cells() >= self.max_cells {
                return Reassembled::Rejected;
            }
        }

        let entry = self.partials.entry(hdr.msg_id).or_insert_with(|| Partial {
            frag_count: hdr.frag_count,
            total_len: hdr.total_len,
            cells: BTreeMap::new(),
            started_at: now,
        });
        // A duplicate cell index is a no-op (idempotent); a new one is stored.
        entry.cells.entry(hdr.frag_index).or_insert_with(|| data.to_vec());

        if entry.cells.len() as u16 == entry.frag_count {
            // Complete: concatenate fragments in index order, truncate to the true length, evict.
            let p = self.partials.remove(&hdr.msg_id).expect("just present");
            let mut out = Vec::with_capacity(p.frag_count as usize * FRAGMENT_DATA_LEN);
            for (_, cell) in p.cells {
                out.extend_from_slice(&cell);
            }
            out.truncate(p.total_len as usize);
            Reassembled::Complete(out)
        } else {
            Reassembled::Pending
        }
    }

    /// Drop every partial whose reassembly timeout has elapsed at `now` (§16.3). Returns how many
    /// were discarded. Called periodically by the node so a lost cell cannot pin memory.
    pub fn prune(&mut self, now: TimestampMs) -> usize {
        let timeout = self.timeout_ms;
        let before = self.partials.len();
        self.partials.retain(|_, p| now.saturating_sub(p.started_at) < timeout);
        before - self.partials.len()
    }

    /// The number of partial MOTEs currently held.
    pub fn len(&self) -> usize {
        self.partials.len()
    }

    /// `true` iff no partial is held.
    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    fn total_cells(&self) -> usize {
        self.partials.values().map(|p| p.cells.len()).sum()
    }

    /// Evict the oldest-started partial to make room (bounded concurrent-MOTE cap).
    fn evict_oldest(&mut self) {
        if let Some(key) = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.started_at)
            .map(|(k, _)| *k)
        {
            self.partials.remove(&key);
        }
    }
}

impl Default for ReassemblyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(msg_id: [u8; 8], idx: u16, count: u16, total_len: u32) -> SphinxFragmentHeader {
        SphinxFragmentHeader { msg_id, frag_index: idx, frag_count: count, total_len }
    }

    fn cell(fill: u8) -> Vec<u8> {
        vec![fill; FRAGMENT_DATA_LEN]
    }

    #[test]
    fn single_cell_completes_immediately() {
        let mut c = ReassemblyCache::new();
        let mut data = cell(0);
        data[..5].copy_from_slice(b"hello");
        let out = c.accept(&hdr([1; 8], 0, 1, 5), &data, 0);
        assert_eq!(out, Reassembled::Complete(b"hello".to_vec()));
        assert!(c.is_empty(), "a single-cell MOTE is not cached");
    }

    #[test]
    fn multi_cell_reassembles_in_order() {
        let mut c = ReassemblyCache::new();
        let id = [7u8; 8];
        let total = FRAGMENT_DATA_LEN + 3; // spans 2 of the 4-cell rung; the rest is padding
        // Distinguishable payload across the first two cells.
        let mut c0 = cell(0xA0);
        let mut c1 = cell(0xB0);
        c0[0] = 1;
        c1[0] = 2;
        assert_eq!(c.accept(&hdr(id, 0, 4, total as u32), &c0, 0), Reassembled::Pending);
        assert_eq!(c.accept(&hdr(id, 2, 4, total as u32), &cell(0xC0), 0), Reassembled::Pending);
        assert_eq!(c.accept(&hdr(id, 3, 4, total as u32), &cell(0xD0), 0), Reassembled::Pending);
        assert_eq!(c.len(), 1);
        // The last missing cell completes it.
        let out = match c.accept(&hdr(id, 1, 4, total as u32), &c1, 0) {
            Reassembled::Complete(b) => b,
            other => panic!("expected Complete, got {other:?}"),
        };
        assert_eq!(out.len(), total, "reassembled MOTE truncated to its true length");
        assert_eq!(out[0], 1, "cell 0 first");
        assert_eq!(out[FRAGMENT_DATA_LEN], 2, "cell 1 second");
        assert!(c.is_empty(), "the completed partial is evicted");
    }

    #[test]
    fn incomplete_reassembly_is_evicted_after_the_timeout() {
        let mut c = ReassemblyCache::with_bounds(1_000, 16, 64);
        let id = [9u8; 8];
        assert_eq!(c.accept(&hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.len(), 1);
        // Still held just before the timeout...
        assert_eq!(c.prune(999), 0);
        assert_eq!(c.len(), 1);
        // ...evicted once it elapses (bounded — a lost cell cannot pin memory).
        assert_eq!(c.prune(1_000), 1);
        assert!(c.is_empty());
        // A late cell after eviction starts a fresh partial, never resurrecting the timed-out one.
        assert_eq!(c.accept(&hdr(id, 1, 4, 100), &cell(2), 1_000), Reassembled::Pending);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn accept_prunes_timed_out_partials() {
        let mut c = ReassemblyCache::with_bounds(1_000, 16, 64);
        c.accept(&hdr([1; 8], 0, 4, 100), &cell(1), 0);
        // A later accept for a different MOTE prunes the stale one first.
        c.accept(&hdr([2; 8], 0, 4, 100), &cell(1), 2_000);
        assert_eq!(c.len(), 1, "the timed-out partial was pruned on the next accept");
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let mut c = ReassemblyCache::new();
        // Non-ladder frag_count.
        assert_eq!(c.accept(&hdr([1; 8], 0, 3, 10), &cell(0), 0), Reassembled::Rejected);
        // Index out of range.
        assert_eq!(c.accept(&hdr([1; 8], 4, 4, 10), &cell(0), 0), Reassembled::Rejected);
        // Wrong data length.
        assert_eq!(c.accept(&hdr([1; 8], 0, 4, 10), &vec![0u8; 10], 0), Reassembled::Rejected);
        // total_len larger than the cell count can hold.
        assert_eq!(
            c.accept(&hdr([1; 8], 0, 4, (5 * FRAGMENT_DATA_LEN) as u32), &cell(0), 0),
            Reassembled::Rejected
        );
        assert!(c.is_empty());
    }

    #[test]
    fn inconsistent_fragments_for_a_msg_id_are_rejected() {
        let mut c = ReassemblyCache::new();
        let id = [5u8; 8];
        assert_eq!(c.accept(&hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        // Same msg_id but a different frag_count/total_len — an attacker mixing MOTEs.
        assert_eq!(c.accept(&hdr(id, 1, 16, 100), &cell(2), 0), Reassembled::Rejected);
        assert_eq!(c.accept(&hdr(id, 1, 4, 999), &cell(2), 0), Reassembled::Rejected);
        assert_eq!(c.len(), 1, "the original partial is untouched");
    }

    #[test]
    fn concurrent_partial_motes_are_bounded() {
        let mut c = ReassemblyCache::with_bounds(REASSEMBLY_TIMEOUT_MS, 2, 64);
        c.accept(&hdr([1; 8], 0, 4, 100), &cell(1), 0);
        c.accept(&hdr([2; 8], 0, 4, 100), &cell(1), 1);
        assert_eq!(c.len(), 2);
        // A third partial evicts the oldest-started — the cap holds.
        c.accept(&hdr([3; 8], 0, 4, 100), &cell(1), 2);
        assert_eq!(c.len(), 2, "never exceeds the concurrent-MOTE cap");
    }

    #[test]
    fn duplicate_cell_index_is_idempotent() {
        let mut c = ReassemblyCache::new();
        let id = [4u8; 8];
        assert_eq!(c.accept(&hdr(id, 0, 4, 100), &cell(1), 0), Reassembled::Pending);
        assert_eq!(c.accept(&hdr(id, 0, 4, 100), &cell(9), 0), Reassembled::Pending);
        assert_eq!(c.len(), 1);
    }
}
