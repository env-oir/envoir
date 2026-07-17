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
//! It stands in for the ordering *contract* — the real mesh committer's deterministic succession
//! and full liveness timers (§5.1) are a separate concern. A member [submits](Committer::submit) a
//! Commit to get its sequence position, then all members [`advance`](crate::Session::advance) by
//! applying the log in order.
//!
//! ## Commit-confirmation quorum & self-suspend (spec §5.1, D7)
//!
//! A live but **partitioned** incumbent committer that keeps serializing Commits for a **minority**
//! of members would deterministically build a divergent log branch — healing later into a *fork*,
//! group HALT, and manual recovery. DMTAP bounds this with two coupled rules, both modeled here:
//!
//! - A committer's Commit is **`confirmed`** only once a **`> n/2` apply-ack quorum** (the §16.8
//!   roster quorum) of current members has acknowledged applying it. An **`unconfirmed`** Commit is
//!   provisional and, if later **superseded** by a quorum-confirmed Commit at the same log position,
//!   is **rolled back by its own author without raising a fork** ([`Committer::adopt_confirmed`]).
//!   A superseded-*unconfirmed* Commit is explicitly **not** the two-confirmed-Commits-at-one-
//!   position condition that is fork evidence ([`ForkEvidence`], `0x0404`).
//! - A committer that cannot observe **`> n/2` member heartbeats** within the liveness window MUST
//!   **self-suspend** — stop ordering new Commits and hold pending Proposals
//!   ([`Committer::observe_heartbeats`] / [`Committer::try_order`]) — so a partitioned minority
//!   committer stops manufacturing a branch to reconcile. Only one partition can ever hold the
//!   `> n/2` quorum, so at most one branch is ever confirmed.
//!
//! **Boundary (test double for the roster).** The in-process committer cannot observe real mesh
//! roster acks or heartbeats; those arrive as network events in a live node. This module therefore
//! models the **confirmation state machine and supersede rule** with an explicit, caller-driven
//! roster: the caller feeds apply-acks ([`Committer::record_ack`]) and the live heartbeat set
//! ([`Committer::observe_heartbeats`]), and this crate derives confirmation, suspension, supersede,
//! and fork evidence from the `> n/2` quorum. The quorum arithmetic, the unconfirmed-supersede rule,
//! and the "two *confirmed* at one position = fork" distinction are the load-bearing logic and are
//! real; the transport that would deliver acks/heartbeats is out of scope for an in-process seam.

use std::collections::{BTreeMap, BTreeSet};

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

/// The confirmation status of a Commit at a log position (spec §5.1 commit-confirmation quorum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStatus {
    /// Provisional: fewer than a `> n/2` apply-ack quorum of current members have acked applying it.
    /// May still be **superseded** by a quorum-confirmed Commit at the same position, rolled back by
    /// its author **without** raising a fork.
    Unconfirmed,
    /// A `> n/2` apply-ack quorum has acknowledged applying it: canonical, and can no longer be
    /// superseded. A *different* confirmed Commit at the same position is fork evidence.
    Confirmed,
}

/// The result of reconciling a healing peer's quorum-confirmed Commit into this committer's branch
/// ([`Committer::adopt_confirmed`], spec §5.1 partition heal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderOutcome {
    /// The position was empty here; the confirmed Commit was installed (no local Commit to roll
    /// back).
    Installed,
    /// The confirmed Commit was already the entry at this position (idempotent heal / re-delivery).
    AlreadyPresent,
    /// This branch held a **different, still-unconfirmed** Commit at the position; it is **superseded**
    /// by the quorum-confirmed one and **rolled back by its author without raising a fork** (§5.1).
    /// The rolled-back handshake is returned so the author can re-derive and resubmit its change
    /// against the new epoch.
    Superseded {
        /// The unconfirmed handshake that lost the position and must be re-proposed by its author.
        rolled_back: Handshake,
    },
}

/// **Fork evidence** (spec §5.1, `ERR_COMMITTER_FORK_DETECTED` `0x0404`): two **different** Commits,
/// **both quorum-confirmed**, occupy the same log position with the same predecessor. This is the
/// genuine equivocation condition; members MUST `HALT_ALERT`. A *superseded-unconfirmed* Commit is
/// explicitly **not** this — the whole point of the confirmation quorum is that a partitioned
/// minority's unconfirmed branch heals by supersede, not by fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvidence {
    /// The log position at which two confirmed Commits disagree.
    pub seq: u64,
    /// The confirmed handshake this branch holds at `seq`.
    pub ours: Handshake,
    /// The confirmed handshake the healing peer holds at `seq`.
    pub theirs: Handshake,
}

impl ForkEvidence {
    /// The normative DMTAP wire error code (§21.6): `0x0404` `ERR_COMMITTER_FORK_DETECTED`
    /// (`HALT_ALERT`).
    pub fn code(&self) -> u16 {
        0x0404
    }
}

impl std::fmt::Display for ForkEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "two confirmed Commits at log position {} — committer fork \
             (ERR_COMMITTER_FORK_DETECTED, §21.6 0x0404)",
            self.seq
        )
    }
}

impl std::error::Error for ForkEvidence {}

/// A committer that has **self-suspended** refused to order a new Commit (spec §5.1 self-suspend):
/// it cannot observe a `> n/2` heartbeat quorum, so it MUST hold pending Proposals rather than
/// manufacture a divergent minority branch (`ERR_COMMITTER_UNREACHABLE` `0x0405` at the members
/// awaiting it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuspendedError;

impl SuspendedError {
    /// The related DMTAP wire code (§21.6): `0x0405` `ERR_COMMITTER_UNREACHABLE` (`ROTATE_RETRY` —
    /// the majority partition proceeds via deterministic takeover, §5.1).
    pub fn code(&self) -> u16 {
        0x0405
    }
}

impl std::fmt::Display for SuspendedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "committer self-suspended: cannot observe a > n/2 heartbeat quorum, so it MUST NOT order \
             new Commits (spec §5.1 self-suspend; ERR_COMMITTER_UNREACHABLE 0x0405)",
        )
    }
}

impl std::error::Error for SuspendedError {}

/// The append-only, hash-chained per-group handshake log (spec §5.1) — the ordering authority MLS
/// delegates to the DS. In-process and single-writer; the real mesh committer's transport is out of
/// scope, but the **commit-confirmation quorum / supersede / self-suspend** state machine (§5.1, D7)
/// is modeled here over a caller-driven roster (see the module docs).
#[derive(Debug, Default, Clone)]
pub struct Committer {
    log: Vec<LogEntry>,
    /// Running chain link (hash of the last entry); the genesis link is all-zero.
    head_link: [u8; 32],
    /// Current roster size `n` (0 until set): the denominator of the `> n/2` quorum (§16.8).
    roster_size: usize,
    /// seq → set of member ids that have acked **applying** the entry currently at that position.
    acks: BTreeMap<u64, BTreeSet<Vec<u8>>>,
    /// Positions whose entry has reached a `> n/2` apply-ack quorum (canonical / confirmed).
    confirmed: BTreeSet<u64>,
    /// Whether this committer has self-suspended (cannot see a `> n/2` heartbeat quorum, §5.1).
    suspended: bool,
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
    ///
    /// This is the raw ordering primitive and does **not** consult self-suspension; use
    /// [`try_order`](Committer::try_order) for the confirmation-aware path that honors the §5.1
    /// self-suspend rule.
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

    /// The entry at 1-based position `seq`, if any.
    pub fn entry(&self, seq: u64) -> Option<&LogEntry> {
        seq.checked_sub(1).and_then(|i| self.log.get(i as usize))
    }

    // --- commit-confirmation quorum (spec §5.1, D7) -----------------------------------------

    /// Set the current roster size `n` — the denominator of the `> n/2` quorum (§16.8). Membership
    /// changes (Add/Remove) change `n`, so the caller updates it as the roster evolves.
    pub fn set_roster_size(&mut self, n: usize) {
        self.roster_size = n;
    }

    /// The current roster size `n`.
    pub fn roster_size(&self) -> usize {
        self.roster_size
    }

    /// The strict-majority **roster quorum** `> n/2` = ⌈(n+1)/2⌉ = `n / 2 + 1` (spec §16.8). Two
    /// partitions can never each assemble it, so at most one branch is ever confirmed.
    pub fn quorum(&self) -> usize {
        self.roster_size / 2 + 1
    }

    /// Record that `member` has **acked applying** the Commit ordered at `seq` (spec §5.1). Reaching
    /// a `> n/2` quorum flips the Commit from [`Unconfirmed`](CommitStatus::Unconfirmed) to
    /// [`Confirmed`](CommitStatus::Confirmed) — canonical, and no longer superseasible. Returns the
    /// Commit's status **after** recording the ack. Idempotent per `(seq, member)`.
    pub fn record_ack(&mut self, seq: u64, member: impl Into<Vec<u8>>) -> CommitStatus {
        self.acks.entry(seq).or_default().insert(member.into());
        if self.roster_size > 0 && self.acks[&seq].len() >= self.quorum() {
            self.confirmed.insert(seq);
        }
        self.status(seq)
    }

    /// The number of distinct apply-acks recorded for the Commit at `seq`.
    pub fn ack_count(&self, seq: u64) -> usize {
        self.acks.get(&seq).map_or(0, |a| a.len())
    }

    /// The confirmation status of the Commit at `seq` (spec §5.1). An unknown/empty position reads
    /// [`Unconfirmed`](CommitStatus::Unconfirmed).
    pub fn status(&self, seq: u64) -> CommitStatus {
        if self.confirmed.contains(&seq) {
            CommitStatus::Confirmed
        } else {
            CommitStatus::Unconfirmed
        }
    }

    /// Whether the Commit at `seq` has reached the `> n/2` apply-ack quorum (spec §5.1).
    pub fn is_confirmed(&self, seq: u64) -> bool {
        self.confirmed.contains(&seq)
    }

    // --- committer self-suspend (spec §5.1) -------------------------------------------------

    /// Observe the set of current members whose **heartbeats** this committer can presently see
    /// (spec §5.1 self-suspend, §16.8 committer-liveness). If that live set is **below** the `> n/2`
    /// quorum, the committer **self-suspends** — subsequent [`try_order`](Committer::try_order) calls
    /// refuse to order new Commits and hold pending Proposals — so a partitioned **minority**
    /// committer stops manufacturing a divergent branch. Observing a quorum again lifts suspension.
    ///
    /// The liveness *window* itself is the caller's timer; this records the observed live set and
    /// derives suspension from the quorum (the test-double boundary noted in the module docs).
    pub fn observe_heartbeats<T: AsRef<[u8]>>(&mut self, live_members: &[T]) {
        let live: BTreeSet<&[u8]> = live_members.iter().map(|m| m.as_ref()).collect();
        self.suspended = self.roster_size > 0 && live.len() < self.quorum();
    }

    /// Whether this committer has self-suspended (cannot see a `> n/2` heartbeat quorum, §5.1).
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Order a handshake **subject to the self-suspend rule** (spec §5.1): if the committer has
    /// self-suspended ([`is_suspended`](Committer::is_suspended)) it MUST NOT order new Commits — it
    /// returns [`SuspendedError`] and holds the pending Proposal. Otherwise behaves like
    /// [`submit`](Committer::submit), returning the assigned `seq`.
    pub fn try_order(&mut self, handshake: Handshake) -> Result<u64, SuspendedError> {
        if self.suspended {
            return Err(SuspendedError);
        }
        Ok(self.submit(handshake))
    }

    // --- partition heal: supersede-unconfirmed vs. fork (spec §5.1, D7) ---------------------

    /// Reconcile a healing peer's quorum-**confirmed** `confirmed` Commit (which that peer holds at
    /// position `seq`) into this committer's branch (spec §5.1 partition heal). The caller passes a
    /// Commit the *other* side has already confirmed via its own `> n/2` quorum; this side decides
    /// how it lands against whatever it holds at `seq`:
    ///
    /// - **Empty position** here → the confirmed Commit is [`Installed`](OrderOutcome::Installed).
    /// - **Same Commit** already here → [`AlreadyPresent`](OrderOutcome::AlreadyPresent) (idempotent).
    /// - **Different, still-unconfirmed** Commit here → it is
    ///   [`Superseded`](OrderOutcome::Superseded): rolled back by its author **without raising a
    ///   fork**, this branch adopts the confirmed Commit, and (having healed into the majority) the
    ///   committer clears its self-suspension.
    /// - **Different, already-confirmed** Commit here → **[`ForkEvidence`]** (`0x0404`): two confirmed
    ///   Commits at one position is genuine equivocation; the caller MUST `HALT_ALERT`.
    ///
    /// Only one partition can ever hold the `> n/2` quorum, so in a real partition the fork branch is
    /// reached only if a committer confirmed a Commit it had no quorum for — which the quorum rule
    /// prevents. The fork arm is retained as the fail-closed check, not an expected path.
    pub fn adopt_confirmed(
        &mut self,
        seq: u64,
        confirmed: Handshake,
    ) -> Result<OrderOutcome, ForkEvidence> {
        match self.entry(seq).cloned() {
            None => {
                self.install_confirmed(seq, confirmed);
                Ok(OrderOutcome::Installed)
            }
            Some(existing) if existing.handshake.commit == confirmed.commit => {
                // Same Commit — just record that it is confirmed here too.
                self.confirmed.insert(seq);
                Ok(OrderOutcome::AlreadyPresent)
            }
            Some(existing) => {
                if self.is_confirmed(seq) {
                    // Two DIFFERENT confirmed Commits at one position: genuine fork (§5.1, 0x0404).
                    Err(ForkEvidence { seq, ours: existing.handshake, theirs: confirmed })
                } else {
                    // Our entry is UNCONFIRMED → superseded by the quorum-confirmed one, rolled back
                    // by its author WITHOUT raising a fork (§5.1). Adopt the confirmed Commit and,
                    // having healed into the majority branch, lift self-suspension.
                    self.install_confirmed(seq, confirmed);
                    self.suspended = false;
                    Ok(OrderOutcome::Superseded { rolled_back: existing.handshake })
                }
            }
        }
    }

    /// Install `confirmed` at position `seq` (replacing any existing entry), mark it confirmed, and
    /// re-derive the hash chain from `seq` to the head so the log stays a consistent chain after a
    /// supersede. Old apply-acks for the position are voided (the confirmed Commit carries the quorum
    /// that matters).
    fn install_confirmed(&mut self, seq: u64, confirmed: Handshake) {
        let idx = (seq - 1) as usize;
        let prev = if idx == 0 { [0u8; 32] } else { self.log[idx - 1].link };
        let link = chain_link(&prev, seq, &confirmed.commit);
        let entry = LogEntry { seq, handshake: confirmed, link };
        if idx < self.log.len() {
            self.log[idx] = entry;
        } else {
            // seq beyond the current head: pad is not expected for the heal path, but stay safe.
            self.log.push(entry);
        }
        self.confirmed.insert(seq);
        self.acks.remove(&seq);
        // Re-chain any entries after the replaced position so links stay consistent.
        let mut prev_link = self.log[idx].link;
        for i in (idx + 1)..self.log.len() {
            let s = self.log[i].seq;
            let relinked = chain_link(&prev_link, s, &self.log[i].handshake.commit);
            self.log[i].link = relinked;
            prev_link = relinked;
        }
        self.head_link = self.log.last().map(|e| e.link).unwrap_or([0u8; 32]);
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
