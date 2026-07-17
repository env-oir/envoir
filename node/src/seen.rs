//! Bounded dedup / replay set (spec §2.6, §19.3.1 step 9).
//!
//! The node re-acks a redelivered MOTE `id` without reprocessing it (§2.6). The set that backs that
//! is **bounded** two ways so a long-running (or flooded) node cannot grow it — and the durable
//! snapshot it feeds (§19.3.3) — without limit:
//!
//! - a **sliding TTL window**: an entry older than [`DEDUP_WINDOW_MS`] is dropped. The window is the
//!   §16.10 **durable seen-id / tombstone horizon** = `max(72 h retry, 20 d offline-buffer)` = **20
//!   days**: a *late duplicate* of a since-deleted MOTE can re-arrive not only from a sender's 72 h
//!   retry (§16.1) but from an **offline / peer buffer** up to the offline-buffer horizon (§16.6), so
//!   the dedup entry MUST outlive the longer of the two — otherwise a stale duplicate would slip past
//!   an expired dedup entry and **resurrect a deleted object** (§2.6, §5.6.4, §5.6.5). The window is
//!   keyed on the node's **receive clock**, not the attacker-controlled `Envelope.ts` — a forged
//!   future timestamp must never be able to evict a genuine peer's still-live dedup entry, and the
//!   receive clock is monotonic in the daemon.
//! - a hard **LRU cap** ([`MAX_SEEN`]): an absolute ceiling regardless of the clock, evicting the
//!   oldest-received entry first. Fail-safe against clock stalls / adversarial timestamps.
//!
//! Restart-correctness (§19.3.3): the set round-trips through the journal as `(id, from)` pairs; a
//! restored entry is stamped with the restore-time receive clock, so it lives a fresh window (never
//! shorter) and re-ack-on-redelivery keeps working across a restart.

use std::collections::{HashMap, VecDeque};

use dmtap_core::TimestampMs;

use crate::outbound::RETRY_DEADLINE_MS;

/// The §16.10 offline / peer-buffer horizon (20 days): the longest a MOTE may sit in an offline or
/// peer buffer (§16.6) before it is redelivered. A late duplicate can re-arrive this far out, so a
/// deleted object's tombstone / seen-id must survive at least this long or the duplicate resurrects
/// it (§2.6, §5.6.5).
pub const TOMBSTONE_HORIZON_MS: u64 = 20 * 24 * 60 * 60 * 1000;

/// The durable dedup window (§16.10): `max(72 h retry, 20 d offline-buffer)` = **20 days**. Past this
/// neither a sender's own EXPIREd retry (§16.1) nor an offline/peer buffer (§16.6) can legitimately
/// redeliver, so the dedup entry is no longer needed (§2.6). Keyed on the receive clock; a hard LRU
/// cap ([`MAX_SEEN`]) still bounds the set independently of the clock.
pub const DEDUP_WINDOW_MS: u64 = if RETRY_DEADLINE_MS > TOMBSTONE_HORIZON_MS {
    RETRY_DEADLINE_MS
} else {
    TOMBSTONE_HORIZON_MS
};

/// Absolute upper bound on tracked dedup entries — a hard memory/journal-size ceiling independent of
/// the clock. Oldest-received entries are evicted first once exceeded.
pub const MAX_SEEN: usize = 100_000;

/// Per-entry dedup metadata: the sender return path (persisted for parity with the pre-bound set) and
/// the node's receive clock at record time (the window/eviction key).
#[derive(Clone)]
struct SeenMeta {
    from: Vec<u8>,
    received_at: TimestampMs,
}

/// A bounded dedup/replay set (§2.6). Entries expire out of a sliding receive-time window and are
/// hard-capped by count; both bounds evict from the oldest-received end.
pub struct SeenSet {
    entries: HashMap<Vec<u8>, SeenMeta>,
    /// Insertion order (ids), monotonic by `received_at` since the receive clock only advances — so
    /// both the window prune and the LRU cap pop from the front.
    order: VecDeque<Vec<u8>>,
    window_ms: u64,
    cap: usize,
}

impl SeenSet {
    /// A set with the production window + cap.
    pub fn new() -> Self {
        Self::with_bounds(DEDUP_WINDOW_MS, MAX_SEEN)
    }

    /// A set with explicit bounds (tests exercise small caps/windows).
    pub fn with_bounds(window_ms: u64, cap: usize) -> Self {
        SeenSet { entries: HashMap::new(), order: VecDeque::new(), window_ms, cap }
    }

    /// Record an accepted MOTE `id` with its sender return path, stamped at receive clock `now`.
    /// Prunes the window and enforces the cap so the set can never exceed its bounds.
    pub fn record(&mut self, id: Vec<u8>, from: Vec<u8>, now: TimestampMs) {
        self.prune(now);
        if self.entries.insert(id.clone(), SeenMeta { from, received_at: now }).is_none() {
            // A genuinely new id: extend the ordering. (A re-record — which the dedup fast path makes
            // unreachable — just refreshes `from`/`received_at` in place without duplicating order.)
            self.order.push_back(id);
        }
        self.enforce_cap();
    }

    /// Whether `id` is a still-valid (in-window) dedup entry at receive clock `now`. An entry past the
    /// window reads as absent (it is physically pruned on the next `record`).
    pub fn contains(&self, id: &[u8], now: TimestampMs) -> bool {
        match self.entries.get(id) {
            Some(meta) => !self.expired(meta.received_at, now),
            None => false,
        }
    }

    /// The number of tracked entries (test/inspection aid).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `(id, from)` pairs for the durable snapshot (§19.3.3). Bounded, so the persisted set is too.
    pub fn persist_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.order
            .iter()
            .filter_map(|id| self.entries.get(id).map(|m| (id.clone(), m.from.clone())))
            .collect()
    }

    /// Restore a persisted `(id, from)` pair at restore-time clock `now` (a fresh window; §19.3.3).
    pub fn restore(&mut self, id: Vec<u8>, from: Vec<u8>, now: TimestampMs) {
        self.record(id, from, now);
    }

    fn expired(&self, received_at: TimestampMs, now: TimestampMs) -> bool {
        now.saturating_sub(received_at) >= self.window_ms
    }

    /// Drop every entry whose window has elapsed. `order` is monotonic in `received_at`, so this pops
    /// from the front until the head is still in-window (amortized O(1) per record).
    fn prune(&mut self, now: TimestampMs) {
        while let Some(front) = self.order.front() {
            match self.entries.get(front) {
                // A stale ordering slot (already cap-evicted): drop it and continue.
                None => {
                    self.order.pop_front();
                }
                Some(meta) if self.expired(meta.received_at, now) => {
                    let id = self.order.pop_front().expect("front just peeked");
                    self.entries.remove(&id);
                }
                Some(_) => break,
            }
        }
    }

    /// Enforce the hard cap by evicting oldest-received entries.
    fn enforce_cap(&mut self) {
        while self.entries.len() > self.cap {
            match self.order.pop_front() {
                Some(id) => {
                    self.entries.remove(&id);
                }
                None => break,
            }
        }
    }
}

impl Default for SeenSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_bounds_the_set_evicting_oldest_first() {
        let cap = 8;
        let mut s = SeenSet::with_bounds(DEDUP_WINDOW_MS, cap);
        for i in 0..(cap as u64 + 20) {
            s.record(vec![i as u8], vec![0xAA], 1_000);
        }
        assert!(s.len() <= cap, "set never exceeds the cap ({} > {cap})", s.len());
        // The oldest ids were evicted; the most-recent `cap` remain.
        assert!(!s.contains(&[0], 1_000), "oldest entry evicted under the cap");
        let newest = (cap as u64 + 20 - 1) as u8;
        assert!(s.contains(&[newest], 1_000), "newest entry retained");
    }

    #[test]
    fn window_prunes_entries_past_the_ttl() {
        let window = 10_000;
        let mut s = SeenSet::with_bounds(window, MAX_SEEN);
        s.record(vec![1], vec![0xAA], 0);
        assert!(s.contains(&[1], 5_000), "in-window entry is a dedup hit");
        // Past the window it reads as absent...
        assert!(!s.contains(&[1], window), "at/after the window the entry is expired");
        // ...and a later record physically prunes it (set does not grow with stale entries).
        s.record(vec![2], vec![0xBB], window + 1);
        assert_eq!(s.len(), 1, "the expired entry was pruned, only the fresh one remains");
        assert!(!s.contains(&[1], window + 1));
        assert!(s.contains(&[2], window + 1));
    }

    #[test]
    fn dedup_horizon_covers_twenty_days_not_just_72h() {
        // §16.10: the durable seen-id/tombstone horizon is max(72 h, 20 d) = 20 days. A late duplicate
        // of a since-deleted MOTE — re-arriving from a retry (§16.1) or an offline/peer buffer (§16.6)
        // — must still be deduped so it cannot resurrect the deleted object. Under the old 72 h window
        // a 10-day-late duplicate was evicted and would have re-delivered.
        assert_eq!(DEDUP_WINDOW_MS, TOMBSTONE_HORIZON_MS, "the 20-day horizon governs (> 72 h)");
        let mut s = SeenSet::new();
        s.record(vec![1], vec![0xAA], 0);
        let ten_days = 10 * 24 * 60 * 60 * 1000;
        assert!(s.contains(&[1], ten_days), "still deduped at 10 days (was evicted under 72 h)");
        let seventy_two_h = 72 * 60 * 60 * 1000;
        assert!(s.contains(&[1], seventy_two_h + 1), "still deduped just past the old 72 h window");
        // It finally ages out only past the 20-day horizon.
        assert!(!s.contains(&[1], TOMBSTONE_HORIZON_MS + 1));
    }

    #[test]
    fn persist_pairs_round_trip_in_order() {
        let mut s = SeenSet::with_bounds(DEDUP_WINDOW_MS, MAX_SEEN);
        s.record(vec![1], vec![0x11], 0);
        s.record(vec![2], vec![0x22], 0);
        let pairs = s.persist_pairs();
        assert_eq!(pairs, vec![(vec![1], vec![0x11]), (vec![2], vec![0x22])]);
    }
}
