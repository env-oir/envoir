//! Journal-replay backfill (spec §5.6.3(b)).
//!
//! Each account maintains an **append-only, hash-chained per-account journal**: an ordered log
//! where each entry commits to the object id (or CRDT op hash, §5.6.4) it records **and** to the
//! hash of the prior entry (`prev`) — the same append-only discipline as the committer log (§5.1)
//! and the KT log (§3.5). A rejoining device MAY replay the journal from its last-seen entry,
//! applying each referenced object/op in order, instead of running range reconciliation.
//!
//! A journal whose `prev` chain does not verify is a **fork or rewrite of the owner's own log** and
//! is rejected fail-closed with HALT_ALERT (`ERR_CLUSTER_JOURNAL_CHAIN_BROKEN`, `0x0412`) — the
//! same fork-detection posture as a committer fork (`0x0404`). Replay is only a way to *learn* the
//! missing ids/ops; they are fed into the same §5.6.2 / §5.6.4 apply path as any other backfill.

use crate::error::SyncError;
use crate::wire::{Hash, JournalEntry};
use dmtap_core::id::MH_BLAKE3_256;

/// The genesis `prev` value: the all-zero v0-prefixed digest (§18.6.3) — a BLAKE3-256 multihash
/// prefix (`0x1e`) followed by 32 zero bytes. The first entry of a journal chains to this.
pub fn genesis_prev() -> Hash {
    let mut v = vec![0u8; 33];
    v[0] = MH_BLAKE3_256;
    v
}

/// An append-only, hash-chained journal (§5.6.3(b)). Appending links each entry to the previous by
/// content address; [`verify`] re-checks the whole chain fail-closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journal {
    entries: Vec<JournalEntry>,
}

impl Journal {
    /// An empty journal (its first appended entry chains to [`genesis_prev`]).
    pub fn new() -> Self {
        Journal { entries: Vec::new() }
    }

    /// The entries, in order.
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// The `prev` value the *next* appended entry must carry: the hash of the last entry, or the
    /// genesis value for an empty journal.
    pub fn head_prev(&self) -> Hash {
        self.entries.last().map_or_else(genesis_prev, JournalEntry::entry_hash)
    }

    /// The `seq` the next appended entry will carry (0-based, strictly increasing).
    pub fn next_seq(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.seq + 1)
    }

    /// Append a record of `reference` (an object id or op hash), linking it to the current head.
    /// Returns the new entry.
    pub fn append(&mut self, reference: Hash) -> JournalEntry {
        let entry = JournalEntry { seq: self.next_seq(), prev: self.head_prev(), reference };
        self.entries.push(entry.clone());
        entry
    }

    /// Verify the entire chain from genesis, fail-closed (`0x0412`). Equivalent to
    /// [`verify_segment`] with `expected_first_prev = genesis_prev()` and a genesis `seq` of 0.
    pub fn verify(&self) -> Result<(), SyncError> {
        verify_segment(&self.entries, &genesis_prev(), Some(0))
    }

    /// The ordered references (object ids / op hashes) to feed the apply path (§5.6.2 / §5.6.4).
    /// Verifies the chain first; a fork is rejected before any replay (`0x0412`).
    pub fn replay(&self) -> Result<Vec<Hash>, SyncError> {
        self.verify()?;
        Ok(self.entries.iter().map(|e| e.reference.clone()).collect())
    }
}

/// Verify a journal **segment** (a contiguous run a rejoining device replays, §5.6.3(b)) fail-closed:
///
/// * the first entry's `prev` MUST equal `expected_first_prev` (the hash of the entry just before
///   the segment, or [`genesis_prev`] for a from-scratch replay);
/// * each subsequent entry's `prev` MUST equal the **hash of the prior entry**;
/// * `seq` MUST increase by exactly 1 across the segment (and equal `expected_first_seq` at the
///   start, when known).
///
/// Any deviation is a fork/rewrite of the owner's own log ⇒ [`SyncError::JournalChainBroken`]
/// (HALT_ALERT, `0x0412`). An empty segment verifies trivially.
pub fn verify_segment(
    entries: &[JournalEntry],
    expected_first_prev: &Hash,
    expected_first_seq: Option<u64>,
) -> Result<(), SyncError> {
    let mut prev_hash = expected_first_prev.clone();
    let mut expected_seq = expected_first_seq;
    for entry in entries {
        if entry.prev != prev_hash {
            return Err(SyncError::JournalChainBroken); // broken back-link ⇒ fork
        }
        if let Some(want) = expected_seq {
            if entry.seq != want {
                return Err(SyncError::JournalChainBroken); // non-contiguous seq ⇒ fork/rewrite
            }
        }
        prev_hash = entry.entry_hash();
        expected_seq = Some(entry.seq + 1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::ContentId;

    fn oid(n: u64) -> Hash {
        ContentId::of(&n.to_be_bytes()).0
    }

    #[test]
    fn honest_journal_verifies_and_replays_in_order() {
        let mut j = Journal::new();
        for n in 0..5 {
            j.append(oid(n));
        }
        // First entry chains to genesis.
        assert_eq!(j.entries()[0].prev, genesis_prev());
        assert_eq!(j.entries()[0].seq, 0);
        j.verify().expect("honest chain must verify");
        assert_eq!(j.replay().unwrap(), (0..5).map(oid).collect::<Vec<_>>());
    }

    #[test]
    fn broken_prev_link_is_rejected_fail_closed() {
        let mut j = Journal::new();
        for n in 0..5 {
            j.append(oid(n));
        }
        // Rewrite entry 3's back-link — a fork of the owner's own log.
        let mut tampered = j.entries().to_vec();
        tampered[3].prev = oid(999);
        assert_eq!(
            verify_segment(&tampered, &genesis_prev(), Some(0)),
            Err(SyncError::JournalChainBroken)
        );
        // The HALT_ALERT disposition is carried by the error.
        assert_eq!(
            SyncError::JournalChainBroken.action(),
            Some(crate::error::Action::HaltAlert)
        );
    }

    #[test]
    fn rewritten_reference_breaks_the_chain() {
        // Changing a recorded reference changes that entry's hash, so the *next* entry's prev no
        // longer matches — a silent rewrite is caught downstream in the chain.
        let mut j = Journal::new();
        for n in 0..5 {
            j.append(oid(n));
        }
        let mut tampered = j.entries().to_vec();
        tampered[2].reference = oid(777);
        assert_eq!(
            verify_segment(&tampered, &genesis_prev(), Some(0)),
            Err(SyncError::JournalChainBroken)
        );
    }

    #[test]
    fn segment_replay_from_a_midpoint_verifies_against_the_prior_hash() {
        let mut j = Journal::new();
        for n in 0..6 {
            j.append(oid(n));
        }
        // A device that already has entries 0..3 replays the segment 3..6.
        let segment = &j.entries()[3..];
        let prior_hash = j.entries()[2].entry_hash();
        verify_segment(segment, &prior_hash, Some(3)).expect("valid mid-journal segment");
        // Presenting the segment with the wrong anchor (claiming it follows entry 0) is rejected.
        let wrong_anchor = j.entries()[0].entry_hash();
        assert_eq!(
            verify_segment(segment, &wrong_anchor, Some(3)),
            Err(SyncError::JournalChainBroken)
        );
    }
}
