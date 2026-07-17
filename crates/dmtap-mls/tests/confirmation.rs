//! Commit-confirmation quorum + self-suspend + supersede-vs-fork (spec §5.1, D7).
//!
//! A live but **partitioned** incumbent committer that keeps serializing Commits for a **minority**
//! would build a divergent branch that heals into a fork + group HALT. DMTAP bounds this: a Commit is
//! **confirmed** only on a `> n/2` apply-ack quorum; an **unconfirmed** minority Commit is cleanly
//! **superseded** (rolled back by its author, no fork) by the majority's quorum-confirmed Commit at
//! the same position; and a committer that cannot see a `> n/2` heartbeat quorum **self-suspends**.
//!
//! These tests drive the confirmation state machine over a **test-double roster** (the caller feeds
//! apply-acks and the live heartbeat set) — the boundary noted in `committer.rs`: the in-process
//! committer cannot observe real mesh acks/heartbeats, so the caller stands in for the roster while
//! the quorum arithmetic, supersede rule, and "two *confirmed* at one position = fork" distinction
//! are exercised for real.

use dmtap_mls::{CommitStatus, Committer, ForkEvidence, Handshake, OrderOutcome, SuspendedError};

/// A distinct handshake whose `commit` bytes identify it (the confirmation logic is byte-opaque —
/// it cares only about which Commit occupies a position, not its MLS internals).
fn hs(tag: &str, author: &str) -> Handshake {
    Handshake { commit: tag.as_bytes().to_vec(), welcome: None, author: author.as_bytes().to_vec() }
}

/// Build the shared base branch both partitions agree on: `base_len` confirmed entries in a 5-member
/// group, so `head == base_len` and the next ordered Commit lands at `base_len + 1`. Returns a
/// committer with roster size 5 (quorum 3) and every base entry confirmed by the full roster.
fn confirmed_base(base_len: u64) -> Committer {
    let members = ["a", "b", "c", "d", "e"];
    let mut c = Committer::new();
    c.set_roster_size(members.len());
    for i in 1..=base_len {
        let seq = c.submit(hs(&format!("base-{i}"), "a"));
        for m in members {
            c.record_ack(seq, m);
        }
        assert!(c.is_confirmed(seq), "base entries are fully acked → confirmed");
    }
    c
}

// --- plain confirmation: acks flip Unconfirmed → Confirmed at the > n/2 quorum ---------------

#[test]
fn a_commit_is_confirmed_only_once_a_strict_majority_acks() {
    let mut c = Committer::new();
    c.set_roster_size(5); // n = 5 → quorum > n/2 = 3
    assert_eq!(c.quorum(), 3);

    let seq = c.submit(hs("commit-1", "a"));
    assert_eq!(c.status(seq), CommitStatus::Unconfirmed, "no acks yet");

    assert_eq!(c.record_ack(seq, "a"), CommitStatus::Unconfirmed, "1/5 acked");
    assert_eq!(c.record_ack(seq, "b"), CommitStatus::Unconfirmed, "2/5 — still a minority");
    // Duplicate ack does not count twice.
    assert_eq!(c.record_ack(seq, "b"), CommitStatus::Unconfirmed);
    assert_eq!(c.ack_count(seq), 2);
    // The third distinct ack crosses > n/2 → Confirmed.
    assert_eq!(c.record_ack(seq, "c"), CommitStatus::Confirmed, "3/5 is a strict majority");
    assert!(c.is_confirmed(seq));
}

// --- self-suspend: a minority committer stops ordering new Commits ---------------------------

#[test]
fn committer_self_suspends_without_a_majority_heartbeat_quorum() {
    let mut c = confirmed_base(2);

    // The committer can still see the full roster: it orders freely.
    c.observe_heartbeats(&["a", "b", "c", "d", "e"]);
    assert!(!c.is_suspended());
    let seq = c.try_order(hs("while-healthy", "a")).expect("a healthy committer orders");
    assert_eq!(seq, 3);

    // A partition drops it to a minority {a, b} (2 < quorum 3): it MUST self-suspend.
    c.observe_heartbeats(&["a", "b"]);
    assert!(c.is_suspended(), "a minority-partition committer self-suspends (§5.1)");
    assert_eq!(
        c.try_order(hs("minority-branch", "a")),
        Err(SuspendedError),
        "a suspended committer MUST NOT order new Commits — it holds pending Proposals"
    );
    assert_eq!(c.head(), 3, "no minority branch was manufactured");

    // When it re-observes a majority heartbeat the suspension lifts and ordering resumes.
    c.observe_heartbeats(&["a", "c", "d"]);
    assert!(!c.is_suspended());
    assert!(c.try_order(hs("after-heal", "a")).is_ok());
}

// --- the core D7 property: unconfirmed minority Commit is SUPERSEDED on heal, no fork ---------

#[test]
fn unconfirmed_minority_commit_is_superseded_on_heal_without_a_fork() {
    // Shared base: 2 confirmed entries; the contested position is seq = 3.
    let seq = 3;

    // MINORITY partition {a, b}: incumbent committer orders its own Commit at seq 3 but can only
    // gather minority acks — it stays UNCONFIRMED. It then notices the partition and self-suspends.
    let mut minority = confirmed_base(2);
    let c_min = hs("minority-commit", "a");
    assert_eq!(minority.submit(c_min.clone()), seq);
    minority.record_ack(seq, "a");
    minority.record_ack(seq, "b");
    assert_eq!(minority.status(seq), CommitStatus::Unconfirmed, "only 2/5 acked — no quorum");
    minority.observe_heartbeats(&["a", "b"]);
    assert!(minority.is_suspended());

    // MAJORITY partition {c, d, e}: the deterministic takeover successor orders a DIFFERENT Commit
    // at the same position 3, and its majority acks CONFIRM it.
    let mut majority = confirmed_base(2);
    let c_maj = hs("majority-commit", "c");
    assert_eq!(majority.submit(c_maj.clone()), seq);
    majority.record_ack(seq, "c");
    majority.record_ack(seq, "d");
    majority.record_ack(seq, "e");
    assert!(majority.is_confirmed(seq), "3/5 is a > n/2 quorum → the majority Commit STANDS");

    // HEAL: the minority reconciles the majority's quorum-confirmed Commit at position 3. Its own
    // unconfirmed Commit is SUPERSEDED — rolled back by its author, with NO fork / NO HALT.
    let outcome = minority
        .adopt_confirmed(seq, c_maj.clone())
        .expect("a supersede of an UNCONFIRMED entry is not a fork");
    assert_eq!(
        outcome,
        OrderOutcome::Superseded { rolled_back: c_min },
        "the minority's unconfirmed Commit is rolled back by its author, not forked"
    );

    // Post-heal: both branches hold the SAME confirmed Commit at position 3 (a single canonical
    // head that a strict majority endorsed), and the minority is no longer suspended.
    assert_eq!(minority.entry(seq).unwrap().handshake, c_maj);
    assert_eq!(majority.entry(seq).unwrap().handshake, c_maj);
    assert_eq!(minority.entry(seq).unwrap().link, majority.entry(seq).unwrap().link, "chains agree");
    assert!(minority.is_confirmed(seq), "the majority Commit is confirmed on the healed branch too");
    assert!(!minority.is_suspended(), "healed back into the majority branch");
}

// --- idempotent heal + the majority's confirmed Commit stands --------------------------------

#[test]
fn a_quorum_confirmed_commit_stands_and_heal_is_idempotent() {
    let seq = 3;
    let mut majority = confirmed_base(2);
    let c_maj = hs("majority-commit", "c");
    majority.submit(c_maj.clone());
    for m in ["c", "d", "e"] {
        majority.record_ack(seq, m);
    }
    assert!(majority.is_confirmed(seq));

    // Re-delivering the same confirmed Commit at the same position is a no-op, never a fork.
    assert_eq!(
        majority.adopt_confirmed(seq, c_maj.clone()),
        Ok(OrderOutcome::AlreadyPresent)
    );
    assert_eq!(majority.entry(seq).unwrap().handshake, c_maj, "the confirmed Commit still stands");

    // A peer that had NOTHING at the position simply installs the confirmed Commit (no rollback).
    let mut fresh = confirmed_base(2);
    assert_eq!(fresh.adopt_confirmed(seq, c_maj.clone()), Ok(OrderOutcome::Installed));
    assert!(fresh.is_confirmed(seq));
    assert_eq!(fresh.entry(seq).unwrap().handshake, c_maj);
}

// --- the fork arm: TWO different CONFIRMED Commits at one position is genuine fork evidence ---

#[test]
fn two_confirmed_commits_at_one_position_is_fork_evidence_halt() {
    let seq = 3;
    // A misbehaving/equivocating committer confirms its OWN Commit at position 3 (a real partition
    // could never assemble this quorum, but a Byzantine committer might claim it) ...
    let mut branch = confirmed_base(2);
    let ours = hs("our-confirmed", "a");
    branch.submit(ours.clone());
    for m in ["a", "b", "c"] {
        branch.record_ack(seq, m);
    }
    assert!(branch.is_confirmed(seq));

    // ... and a healing peer presents a DIFFERENT, also-confirmed Commit at the same position. This
    // is the two-confirmed-at-one-position condition — genuine equivocation, NOT a benign supersede.
    let theirs = hs("their-confirmed", "d");
    let fork = branch
        .adopt_confirmed(seq, theirs.clone())
        .expect_err("two CONFIRMED Commits at one position MUST be fork evidence, not a supersede");
    assert_eq!(fork, ForkEvidence { seq, ours, theirs });
    assert_eq!(fork.code(), 0x0404, "committer fork → ERR_COMMITTER_FORK_DETECTED (HALT_ALERT)");
}
