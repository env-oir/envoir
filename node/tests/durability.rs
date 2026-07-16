//! Node durability — the outbound retry queue survives restart (spec §19.3.3, §0.5, §4.7).
//!
//! DMTAP's *only* durability mechanism is the sender's outbound queue; a node that loses
//! queued-but-unacked MOTEs when its process restarts violates the §4.7 invariant. These tests
//! drop a node mid-retry and rebuild it against the same journal, then prove the pending send
//! resumes and ultimately delivers + acks.

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};
use dmtap::{FileJournal, Journal, MemoryJournal};

/// Rebuild a sender node on the shared fabric with the same identity address + the given journal,
/// resuming whatever it persisted.
fn resume_sender(
    net: &InMemoryNetwork,
    seed: [u8; 32],
    journal: Box<dyn Journal>,
) -> Node<InMemoryTransport> {
    let ik = IdentityKey::from_seed(&seed);
    // The seal keypair matters only for *decrypting inbound*; a resumed sender re-dispatches an
    // already-sealed envelope and only needs its address to receive the ack, so a fresh seal is fine.
    let transport = net.endpoint(ik.public());
    Node::with_journal(ik, SealKeypair::generate(), transport, journal).expect("resume")
}

#[test]
fn memory_journal_resumes_a_pending_send_across_restart() {
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();

    // Bob is a normal node on the fabric.
    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    let alice_seed = [11u8; 32];
    let id;
    {
        // Alice v1: Bob is offline, so her send lands in RETRY — and is journaled.
        let mut alice = resume_sender(&net, alice_seed, Box::new(journal.clone()));
        alice.add_contact(&bob_ik_pub, bob_seal_pub);
        bob.add_contact(&IdentityKey::from_seed(&alice_seed).public(), [0u8; 32]);

        net.set_down(&bob_ik_pub, true);
        id = alice.send_mail(&bob_ik_pub, "survive me", b"queued before the crash").unwrap();
        assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "unreachable ⇒ RETRY");

        // The journal captured the pending entry.
        let snap = journal.snapshot().expect("checkpointed");
        assert_eq!(snap.outbound.len(), 1, "one pending MOTE persisted");
        assert_eq!(snap.outbound[0].state, OutState::Retry.as_u8());
        // Alice v1 is dropped here — simulating the process exiting mid-retry.
    }

    // Alice v2: fresh process, same identity + journal. The pending send comes back.
    let mut alice = resume_sender(&net, alice_seed, Box::new(journal.clone()));
    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::Retry),
        "the queued-but-unacked MOTE resumed from the journal after restart"
    );

    // Bob comes back; the resumed retry re-dispatches the SAME immutable envelope and delivers.
    net.set_down(&bob_ik_pub, false);
    assert_eq!(alice.retry_pending(), 1, "resumed entry re-dispatched");
    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "delivered after restart");
    assert_eq!(bob.inbox().exists(), 1);
    let raw = &bob.inbox().messages[0].raw;
    assert!(raw.windows(23).any(|w| w == b"queued before the crash"), "correct plaintext");

    // Alice consumes the ack; the resumed send reaches ACKED.
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked), "resumed send delivered + acked");
    // And the terminal ACKED state was itself checkpointed.
    assert_eq!(journal.snapshot().unwrap().outbound[0].state, OutState::Acked.as_u8());
}

#[test]
fn file_journal_resumes_across_an_actual_reopen() {
    let net = InMemoryNetwork::new();
    let path = std::env::temp_dir().join(format!(
        "envoir-node-journal-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    let alice_seed = [22u8; 32];
    // Bob pins Alice so her (resumed) MOTE is accepted to the inbox, not deferred as a cold sender.
    bob.add_contact(&IdentityKey::from_seed(&alice_seed).public(), [0u8; 32]);

    let id;
    {
        let mut alice = resume_sender(&net, alice_seed, Box::new(FileJournal::new(&path)));
        alice.add_contact(&bob_ik_pub, bob_seal_pub);
        net.set_down(&bob_ik_pub, true);
        id = alice.send_mail(&bob_ik_pub, "disk-durable", b"persisted to a file").unwrap();
        assert_eq!(alice.outbound_state(&id), Some(OutState::Retry));
    }

    // The JSON file exists on disk and holds the pending entry.
    let on_disk = FileJournal::new(&path).load().unwrap();
    assert_eq!(on_disk.outbound.len(), 1, "queue persisted to the JSON file");

    // Reopen from the same path — a genuine restart — and finish delivery.
    let mut alice = resume_sender(&net, alice_seed, Box::new(FileJournal::new(&path)));
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "resumed from file");
    net.set_down(&bob_ik_pub, false);
    assert_eq!(alice.retry_pending(), 1);
    assert!(matches!(bob.poll()[0], InboundOutcome::Stored { .. }));
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("tmp"));
}

// --- Anti-rollback / anti-abuse high-water-marks survive restart -----------------------------
//
// node-hardening added three in-memory security marks: the per-contact suite high-water-mark, the
// per-authority mix-directory `(epoch, version)` mark, and the deniable-init admission buckets. If
// they reset on restart, a restart re-pins on first contact and a downgrade/rollback/flood that WAS
// rejected slips through. These tests pin a mark, simulate a restart (reload from the journal), and
// prove the downgrade/rollback/throttle is STILL enforced afterwards. Fail-closed on corruption too.

use dmtap::dmtap_core::deniable::DeniablePayload;
use dmtap::dmtap_core::mixnet::{MixDirectory, MixKeyEntry, MixNodeDescriptor};
use dmtap::journal::{PersistedSuiteMark, Snapshot};
use dmtap::mixdir::MixDirError;
use dmtap::mote::{Headers, Kind};
use dmtap::{ContentId, DeniableAcceptLimits, DeniableRouteError, Suite};

/// A signed mix-directory from `authority` at `(epoch, version)` (mirrors the mixdir unit harness).
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
    MixDirectory::issue(authority, epoch, version, vec![desc], ContentId::of(b"genesis"), 1_700_000_000_000)
}

/// Rebuild a node with a fixed identity seed + a NEW sealing key against `journal` (the seal key is
/// not the journal's concern; a peer seals to whatever key the node now advertises).
fn resume_node(
    net: &InMemoryNetwork,
    seed: [u8; 32],
    journal: Box<dyn Journal>,
) -> Node<InMemoryTransport> {
    let ik = IdentityKey::from_seed(&seed);
    let pubk = ik.public();
    Node::with_journal(ik, SealKeypair::generate(), net.endpoint(pubk), journal).expect("resume")
}

#[test]
fn suite_high_water_mark_still_rejects_a_downgrade_after_restart() {
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice =
        Node::with_identity(alice_ik, SealKeypair::generate(), net.endpoint(alice_ik_pub.clone()));

    let bob_seed = [77u8; 32];
    let bob_ik_pub = IdentityKey::from_seed(&bob_seed).public();

    // Bob v1 pins Alice's suite floor at the PQ-hybrid suite (out-of-band knowledge that she has
    // migrated up), so a later classical MOTE from her is a downgrade. This is journaled.
    {
        let mut bob = resume_node(&net, bob_seed, Box::new(journal.clone()));
        bob.add_contact(&alice_ik_pub, [0u8; 32]);
        bob.pin_suite_floor(&alice_ik_pub, Suite::PqHybrid);
        assert_eq!(bob.suite_high_water_mark(&alice_ik_pub), Some(Suite::PqHybrid));
    }

    // The mark was persisted.
    let snap = journal.snapshot().expect("checkpointed");
    assert_eq!(snap.suite_marks.len(), 1, "suite mark persisted");
    assert_eq!(snap.suite_marks[0].suite, Suite::PqHybrid.as_u8());

    // Bob v2: fresh process, same identity + journal. The authoritative mark comes back — first
    // contact did NOT re-pin it down to classical.
    let mut bob = resume_node(&net, bob_seed, Box::new(journal.clone()));
    assert_eq!(
        bob.suite_high_water_mark(&alice_ik_pub),
        Some(Suite::PqHybrid),
        "the PQ high-water-mark survived the restart"
    );

    // Bob re-pins Alice as a known contact so her classical MOTE would be ACCEPTED if the floor had
    // reset. Alice learns Bob's new seal key and sends a classical mail — a downgrade below the mark.
    bob.add_contact(&alice_ik_pub, [0u8; 32]);
    alice.add_contact(&bob_ik_pub, bob.seal_public());
    alice.send_mail(&bob_ik_pub, "sneaky downgrade", b"a classical MOTE below the pinned floor").unwrap();

    let outcomes = bob.poll();
    assert!(
        matches!(outcomes.as_slice(), [InboundOutcome::Deferred { .. }]),
        "the downgrade is DEFERRED (rejected), not stored — got {outcomes:?}"
    );
    assert_eq!(bob.inbox().exists(), 0, "the downgraded MOTE never reached the inbox after restart");
    assert_eq!(bob.requests().exists(), 1, "held in the requests area (§21.3 DEFER_REQUESTS)");
}

#[test]
fn suite_downgrade_control_no_floor_accepts_classical() {
    // Control: a known sender with NO pinned suite floor has the same classical MOTE ACCEPTED —
    // proving the test above exercises the persisted mark, not some unrelated defer.
    let net = InMemoryNetwork::new();
    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice =
        Node::with_identity(alice_ik, SealKeypair::generate(), net.endpoint(alice_ik_pub.clone()));

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    bob.add_contact(&alice_ik_pub, [0u8; 32]); // known sender, but NO pinned suite floor
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    alice.send_mail(&bob_ik_pub, "first contact", b"a classical MOTE, no floor pinned").unwrap();

    assert!(
        matches!(bob.poll().as_slice(), [InboundOutcome::Stored { .. }]),
        "without a pinned floor the classical MOTE is accepted"
    );
    assert_eq!(bob.inbox().exists(), 1);
}

#[test]
fn mix_directory_high_water_mark_still_rejects_a_rollback_after_restart() {
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();
    let seed = [0xA1u8; 32];
    let authority = IdentityKey::from_seed(&[0x01; 32]);
    let auth_pub = authority.public();

    // Node v1 accepts a directory at (epoch 9, version 4); the mark is journaled.
    {
        let mut node = resume_node(&net, seed, Box::new(journal.clone()));
        node.ingest_mix_directory(&directory(&authority, 9, 4).det_cbor()).unwrap();
        assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((9, 4)));
    }
    assert_eq!(journal.snapshot().unwrap().mix_directories.len(), 1, "mix directory persisted");

    // Node v2: fresh process, same journal. The high-water-mark comes back authoritative.
    let mut node = resume_node(&net, seed, Box::new(journal.clone()));
    assert_eq!(
        node.mix_directory_high_water_mark(&auth_pub),
        Some((9, 4)),
        "the mix-directory high-water-mark survived the restart"
    );

    // A stale/replayed directory is STILL a rollback after restart — not re-pinned on first contact.
    assert_eq!(
        node.ingest_mix_directory(&directory(&authority, 9, 3).det_cbor()),
        Err(MixDirError::Stale { pinned: (9, 4), offered: (9, 3) }),
        "an older directory is rejected as a rollback after restart"
    );
    assert!(
        matches!(
            node.ingest_mix_directory(&directory(&authority, 9, 4).det_cbor()),
            Err(MixDirError::Stale { .. })
        ),
        "a replay of the exact pinned directory is also rejected"
    );
    // A genuinely newer directory still ratchets up (the mark is live, not frozen).
    assert!(node.ingest_mix_directory(&directory(&authority, 10, 1).det_cbor()).is_ok());
    assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((10, 1)));
}

#[test]
fn a_corrupt_suite_byte_in_the_journal_is_refused_not_defaulted() {
    // Fail-closed: a restored mark is authoritative, so a persisted mark with an unknown suite byte
    // is corruption and MUST be refused — never silently defaulted to a weaker suite.
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();
    journal
        .save(&Snapshot {
            suite_marks: vec![PersistedSuiteMark { contact: vec![1, 2, 3], suite: 0x00 }],
            ..Snapshot::default()
        })
        .unwrap();

    let seed = [0xB2u8; 32];
    let ik = IdentityKey::from_seed(&seed);
    let pubk = ik.public();
    let res = Node::with_journal(ik, SealKeypair::generate(), net.endpoint(pubk), Box::new(journal));
    assert!(
        matches!(res, Err(dmtap::JournalError::Corrupt(_))),
        "an unknown persisted suite byte is refused as corruption"
    );
}

#[test]
fn a_corrupt_mix_directory_in_the_journal_is_refused_not_dropped() {
    // Fail-closed: a persisted mix directory that no longer decodes/verifies is corruption and is
    // refused, not silently dropped (dropping would default the rollback floor away).
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();
    journal
        .save(&Snapshot { mix_directories: vec![b"not a valid directory".to_vec()], ..Snapshot::default() })
        .unwrap();

    let seed = [0xC3u8; 32];
    let ik = IdentityKey::from_seed(&seed);
    let pubk = ik.public();
    let res = Node::with_journal(ik, SealKeypair::generate(), net.endpoint(pubk), Box::new(journal));
    assert!(
        matches!(res, Err(dmtap::JournalError::Corrupt(_))),
        "an undecodable persisted mix directory is refused as corruption"
    );
}

#[test]
fn deniable_admission_buckets_survive_restart() {
    // The deniable-init admission gate's token buckets are persisted so a restart does not refill
    // them to a fresh full burst against the OPK pool (audit #4). Drain the global bucket via a real
    // accept in v1, restart, and confirm a fresh init is STILL throttled (RateLimited) — not admitted.
    let net = InMemoryNetwork::new();
    let journal = MemoryJournal::new();
    let bob_seed = [0xD4u8; 32];

    // Two initiators (distinct root IKs) so the global bucket — not per-source — is the binding limit.
    let alice1 = IdentityKey::generate();
    let alice1_ik = alice1.public();
    let mut alice1 = Node::with_identity(alice1, SealKeypair::generate(), net.endpoint(alice1_ik.clone()));
    let alice2 = IdentityKey::generate();
    let alice2_ik = alice2.public();
    let mut alice2 = Node::with_identity(alice2, SealKeypair::generate(), net.endpoint(alice2_ik.clone()));

    let bob_ik_pub = IdentityKey::from_seed(&bob_seed).public();
    let stale_init;
    {
        let mut bob = resume_node(&net, bob_seed, Box::new(journal.clone()));
        // A tight gate: a single global token, effectively no refill within the test.
        bob.configure_deniable_accept_gate(DeniableAcceptLimits {
            global_burst: 1,
            global_refill_ms: 1_000_000_000,
            source_burst: 100,
            source_refill_ms: 1_000_000_000,
        });
        let bundle = bob.deniable_publish_bundle();

        let p1 = deniable_payload(&alice1_ik, "one", b"first init");
        let init1 = alice1.deniable_open(&bob_ik_pub, &bundle, &p1).unwrap();
        // First accept: admitted (drains the only global token) and delivered.
        assert!(bob.deniable_accept(&alice1_ik, &init1).is_ok());

        let p2 = deniable_payload(&alice2_ik, "two", b"second init");
        stale_init = alice2.deniable_open(&bob_ik_pub, &bundle, &p2).unwrap();
        // Second accept (distinct source): the global bucket is empty ⇒ throttled BEFORE any OPK.
        assert!(
            matches!(bob.deniable_accept(&alice2_ik, &stale_init), Err(DeniableRouteError::RateLimited)),
            "the second init is throttled in v1 — the global burst is spent"
        );
    }

    assert!(journal.snapshot().unwrap().deniable_admission.is_some(), "admission gate persisted");

    // Bob v2: same journal, drained gate restored. Replaying alice2's init still trips the gate
    // (RateLimited) rather than reaching the responder — if the buckets had reset to full it would
    // instead have passed admission and failed later as NotResponder. So RateLimited proves the
    // drained anti-abuse state survived the restart.
    let mut bob = resume_node(&net, bob_seed, Box::new(journal.clone()));
    assert!(
        matches!(bob.deniable_accept(&alice2_ik, &stale_init), Err(DeniableRouteError::RateLimited)),
        "the drained admission buckets survived the restart — no fresh burst"
    );
}

/// A deniable payload (a MOTE with its signature removed, §18.3.10) for the admission test.
fn deniable_payload(from: &[u8], subject: &str, body: &[u8]) -> DeniablePayload {
    DeniablePayload {
        from: from.to_vec(),
        kind: Kind::Chat,
        headers: Headers { subject: Some(subject.into()), ..Headers::default() },
        body: body.to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}
