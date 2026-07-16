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
