//! The [`Committer`] — DMTAP's epoch-ordering seam over MLS (spec §5.1).
//!
//! MLS trusts the Delivery Service for exactly **one** thing: a *total order on epochs* — Commits
//! must be applied in one agreed order per group. On a leaderless mesh that ordering is the hard
//! part (not the crypto), so DMTAP puts a **committer** on top of MLS: the node that serializes
//! handshake messages into an **append-only, hash-chained per-group log** (§5.1). Every member
//! knows the committer; a malicious committer can *stall* but not *forge* (every handshake is
//! member-signed), and the hash chain makes a fork detectable.
//!
//! This is the lightweight **in-process** committer: an ordered log with a running hash chain.
//! It stands in for the ordering *contract* — the real mesh committer's deterministic succession,
//! `> n/2` takeover, liveness timeouts, and fork recovery (§5.1) are a separate concern and are
//! **not** modeled here. A member [submits](Committer::submit) a Commit to get its sequence
//! position, then all members [`advance`](crate::Session::advance) by applying the log in order.

use crate::session::Handshake;

/// One entry in the committer's ordered log: a [`Handshake`] at a total-order `seq`, chained to the
/// previous entry by a hash so a fork (two entries at one position with the same predecessor) is
/// detectable (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// 1-based total-order position of this handshake in the group's log.
    pub seq: u64,
    /// The member-signed handshake (Commit + optional Welcome) being ordered.
    pub handshake: Handshake,
    /// Hash chaining this entry to its predecessor: `BLAKE3(prev_link ‖ seq ‖ commit)`. Two
    /// entries claiming the same `seq` with a different `link` is fork evidence (§5.1).
    pub link: [u8; 32],
}

/// The append-only, hash-chained per-group handshake log (spec §5.1) — the ordering authority MLS
/// delegates to the DS. In-process and single-writer; the real mesh committer is out of scope.
#[derive(Debug, Default, Clone)]
pub struct Committer {
    log: Vec<LogEntry>,
    /// Running chain link (hash of the last entry); the genesis link is all-zero.
    head_link: [u8; 32],
}

impl Committer {
    /// A fresh, empty committer log (genesis; no epochs ordered yet).
    pub fn new() -> Self {
        Committer::default()
    }

    /// **Order** a handshake: append it at the next sequence position, extend the hash chain, and
    /// return its assigned `seq` (1-based). The author records this `seq` via
    /// [`Session::note_authored`](crate::Session::note_authored) so it later merges its own pending
    /// commit instead of re-processing it.
    pub fn submit(&mut self, handshake: Handshake) -> u64 {
        let seq = self.log.len() as u64 + 1;
        let link = chain_link(&self.head_link, seq, &handshake.commit);
        self.head_link = link;
        self.log.push(LogEntry { seq, handshake, link });
        seq
    }

    /// The current log head sequence (0 = empty).
    pub fn head(&self) -> u64 {
        self.log.len() as u64
    }

    /// Every log entry ordered **after** `seq` (i.e. `entry.seq > seq`), in order — what a member
    /// at `applied_seq == seq` still needs to apply to catch up (spec §5.1).
    pub fn entries_after(&self, seq: u64) -> impl Iterator<Item = &LogEntry> {
        self.log.iter().filter(move |e| e.seq > seq)
    }

    /// The full ordered log (for audit/inspection — the group's handshake history, §5.8.2).
    pub fn log(&self) -> &[LogEntry] {
        &self.log
    }
}

/// Extend the committer's hash chain: `BLAKE3(prev_link ‖ u64be(seq) ‖ commit_bytes)`. Uses the
/// same BLAKE3 primitive DMTAP uses for content addressing (§2.2), so the log's fork-evidence
/// hashing matches the rest of the protocol.
fn chain_link(prev: &[u8; 32], seq: u64, commit: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(&seq.to_be_bytes());
    h.update(commit);
    *h.finalize().as_bytes()
}
