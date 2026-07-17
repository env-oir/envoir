//! End-to-end delivery integration tests (spec §2, §19.3, §20).
//!
//! The milestone: two in-process [`Node`]s exchange a **real** end-to-end-encrypted MOTE over the
//! in-memory transport — node A resolves B's keys, builds + HPKE-seals a MOTE, sends it; node B
//! runs the §2.7 validation pipeline, decrypts, stores, and acks; A's outbound queue advances to
//! `ACKED`. The remaining tests cover the adversarial (tamper/forge/wrong-key), retry, dedup/late-
//! ack idempotency, and cold-sender (defer / challenge) paths.

use dmtap::identity::IdentityKey;
use dmtap::inbound::{DropReason, InboundOutcome};
use dmtap::mote::{
    build_mote, ChallengeResponse, Envelope, Hpke, Kind, MoteDraft, PowSolution, SealKeypair,
};
use dmtap::node::Node;
use dmtap::outbound::{OutState, TERMINAL_GRACE_MS};
use dmtap::seen::DEDUP_WINDOW_MS;
use dmtap::transport::{Frame, InMemoryNetwork, InMemoryTransport, Transport};

/// Build a node whose transport address equals its identity key (the in-process addressing model),
/// returning it alongside its identity public key and sealing public key for wiring peers.
fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    let transport = net.endpoint(ik_pub.clone());
    (Node::with_identity(ik, seal, transport), ik_pub, seal_pub)
}

/// Build a sealed envelope addressed to `to_ik`/`to_seal` from a fresh sender identity, returning
/// the wire bytes plus the sender's identity public key (its transport return path). The sender is
/// registered on `net` so any ack the recipient emits has somewhere to route (and is counted by
/// [`InMemoryNetwork::in_flight`]).
fn sealed_to(
    net: &InMemoryNetwork,
    to_ik: &[u8],
    to_seal: &[u8; 32],
    body: &[u8],
    challenge: Option<ChallengeResponse>,
) -> (Vec<u8>, Vec<u8>) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let mut draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, body.to_vec());
    draft.challenge = challenge;
    let env = build_mote(&Hpke, &sender, &eph, to_ik, to_seal, draft).unwrap();
    net.endpoint(sender.public()); // register the sender's return path
    (env.det_cbor(), sender.public())
}

// --- THE milestone -------------------------------------------------------------------------

#[test]
fn two_nodes_exchange_a_real_encrypted_mote_and_ack() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    // Mutual pinning (known contacts): each learns the other's identity + sealing key.
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    // Alice seals a real HPKE MOTE to Bob and dispatches it.
    let secret = b"the atomic unit of DMTAP is the MOTE";
    let id = alice.send_mail(&bob_ik, "hello", secret).expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "sealed + dispatched");
    assert_eq!(net.in_flight(), 1, "one MOTE frame is waiting for Bob");

    // Bob receives: validates (§2.7), decrypts, stores to INBOX, and acks.
    let outcomes = bob.poll();
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0] {
        InboundOutcome::Stored { id: got, uid } => {
            assert_eq!(got, &id, "stored the exact MOTE id");
            assert_eq!(*uid, 1);
        }
        other => panic!("expected Stored, got {other:?}"),
    }

    // The decrypted plaintext is exactly what Alice sent, visible in Bob's JMAP store view.
    assert_eq!(bob.inbox().exists(), 1, "delivered MOTE is retrievable in Bob's INBOX");
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the exact plaintext body is present in the rendered RFC 5322 message"
    );

    // Bob's ack is now in flight back to Alice; Alice consumes it and the queue reaches ACKED.
    assert_eq!(net.in_flight(), 1, "Bob's ack is waiting for Alice");
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked), "sender queue reaches ACKED");
    assert_eq!(net.in_flight(), 0, "nothing left in flight");
}

// --- adversarial: forged/tampered MOTEs are rejected BEFORE decryption ---------------------

#[test]
fn tampered_ciphertext_is_dropped_before_decryption() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    let (bytes, sender_addr) = sealed_to(&net, &bob_ik, &bob_seal, b"tamper me", None);
    bob.add_contact(&sender_addr, [7u8; 32]); // known sender, so only the tamper stops it

    // Flip a byte of the ciphertext field itself so the content address no longer matches (a
    // whole-wire tamper would more likely corrupt a trailing field and trip the sig check first).
    let mut env = Envelope::from_det_cbor(&bytes).unwrap();
    env.ciphertext[0] ^= 0xff;
    let outcome = bob.receive_mote(&sender_addr, &env.det_cbor());
    assert_eq!(
        outcome,
        InboundOutcome::Dropped(DropReason::BadContentAddress),
        "id ≠ content-address ⇒ dropped at §2.7 step 2, before any decryption"
    );
    assert!(!outcome.acked(), "a dropped MOTE is never acked (§2.7a)");
    assert_eq!(bob.inbox().exists(), 0, "nothing stored");
    assert_eq!(net.in_flight(), 0, "no ack emitted");
}

#[test]
fn forged_sender_sig_is_dropped() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    let (bytes, sender_addr) = sealed_to(&net, &bob_ik, &bob_seal, b"forge me", None);
    bob.add_contact(&sender_addr, [7u8; 32]);

    // Re-decode, corrupt the envelope sender_sig, re-encode — keeps `id` matching the ciphertext
    // so the drop is specifically the signature check (§2.7 step 3), not the address check.
    let mut env = Envelope::from_det_cbor(&bytes).unwrap();
    if let Some(sig) = env.sender_sig.as_mut() {
        sig[0] ^= 0xff;
    }
    let outcome = bob.receive_mote(&sender_addr, &env.det_cbor());
    assert_eq!(outcome, InboundOutcome::Dropped(DropReason::BadPayloadSig));
    assert!(!outcome.acked());
    assert_eq!(bob.inbox().exists(), 0);
}

#[test]
fn wrong_recipient_key_fails_to_decrypt() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, _bob_seal) = make_node(&net);

    // Seal to a DIFFERENT sealing key than Bob actually holds: passes address + sig, fails decrypt.
    let stranger_seal = *SealKeypair::generate().public();
    let (bytes, sender_addr) = sealed_to(&net, &bob_ik, &stranger_seal, b"not for bob's key", None);
    bob.add_contact(&sender_addr, [7u8; 32]);

    let outcome = bob.receive_mote(&sender_addr, &bytes);
    assert_eq!(outcome, InboundOutcome::Dropped(DropReason::DecryptFailed));
    assert!(!outcome.acked());
    assert_eq!(bob.inbox().exists(), 0);
}

#[test]
fn malformed_bytes_are_dropped() {
    let net = InMemoryNetwork::new();
    let (mut bob, _ik, _seal) = make_node(&net);
    let outcome = bob.receive_mote(b"someone", b"\xff\xff not cbor \x00");
    assert_eq!(outcome, InboundOutcome::Dropped(DropReason::Malformed));
    assert!(!outcome.acked());
}

// --- retry path: unreachable → RETRY → deliver on retry → ACKED ----------------------------

#[test]
fn unreachable_peer_retries_then_delivers_and_acks() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    // Bob is offline when Alice first tries.
    net.set_down(&bob_ik, true);
    let body = b"delivered on the second attempt";
    let id = alice.send_mail(&bob_ik, "retry", body).unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "unreachable ⇒ RETRY");
    assert_eq!(net.in_flight(), 0, "nothing was actually sent");

    // Bob comes back; the retry timer fires and re-dispatches the SAME sealed envelope.
    net.set_down(&bob_ik, false);
    assert_eq!(alice.retry_pending(), 1, "one entry re-dispatched");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    // Bob validates + stores + acks; Alice reaches ACKED.
    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }));
    assert_eq!(bob.inbox().exists(), 1);
    let raw = &bob.inbox().messages[0].raw;
    assert!(raw.windows(body.len()).any(|w| w == body), "correct plaintext delivered on retry");
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));
}

// --- dedup + late-ack idempotency ----------------------------------------------------------

#[test]
fn duplicate_delivery_is_deduped_and_reacked_without_reprocessing() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    let (bytes, sender_addr) = sealed_to(&net, &bob_ik, &bob_seal, b"exactly once", None);
    bob.add_contact(&sender_addr, [7u8; 32]);

    // First delivery: stored + acked.
    let first = bob.receive_mote(&sender_addr, &bytes);
    assert!(matches!(first, InboundOutcome::Stored { .. }));
    assert_eq!(bob.inbox().exists(), 1);
    let acks_after_first = net.in_flight();
    assert_eq!(acks_after_first, 1, "one ack for the first delivery");

    // Re-deliver the identical envelope: dedup shortcut → acked again, NOT stored twice (§2.6).
    let second = bob.receive_mote(&sender_addr, &bytes);
    assert!(matches!(second, InboundOutcome::Duplicate { .. }));
    assert!(second.acked(), "duplicates are re-acked (§19.3.1 step 9)");
    assert_eq!(bob.inbox().exists(), 1, "still exactly one message — no reprocessing");
    assert_eq!(net.in_flight(), 2, "a second ack was emitted for the duplicate");
}

#[test]
fn ack_is_idempotent_and_late_ack_does_not_resurrect() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    let id = alice.send_mail(&bob_ik, "slow", b"took too long").unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    // Alice gives up first: advance her clock past the 72 h deadline and expire the entry.
    alice.set_now(1_700_000_000_000 + 72 * 3_600_000 + 1);
    let expired = alice.tick_deadlines();
    assert_eq!(expired, vec![id.clone()]);
    assert_eq!(alice.outbound_state(&id), Some(OutState::Expired));

    // Bob only now processes and acks the (still valid, immutable) MOTE.
    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "Bob still delivers it");
    alice.poll(); // consumes the late ack

    // The late ack corrects the UI but MUST NOT resurrect the send (§20.1 fill).
    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::Expired),
        "terminal EXPIRED absorbs a late ack; it does not become ACKED"
    );
    // A further duplicate ack (from the real recipient) is a harmless no-op.
    alice.receive_ack(&bob_ik, id.as_bytes());
    assert_eq!(alice.outbound_state(&id), Some(OutState::Expired));
}

// --- H-C: a forged ack from a non-recipient must NOT suppress retries ------------------------

#[test]
fn forged_ack_from_non_recipient_does_not_advance_the_send() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    let id = alice.send_mail(&bob_ik, "hi", b"deliver me for real").unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    // An on-path relay learns the ack `id` (= BLAKE3(ciphertext), visible on the wire) and injects a
    // forged `Ack(id)` back to Alice from ITS OWN address — not Bob's. If honored, Alice would stop
    // retrying and falsely report the send delivered (silent non-delivery).
    let mallory = net.endpoint(b"mallory-relay".to_vec());
    mallory.send(&alice_ik, Frame::Ack(id.as_bytes().to_vec())).unwrap();
    alice.poll(); // consume the forged ack

    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::InFlight),
        "a forged ack whose `from` != the tracked recipient is ignored — retries continue"
    );

    // The genuine ack from Bob (from == entry.to) still advances the entry to ACKED.
    bob.poll(); // Bob stores + acks
    alice.poll(); // Alice consumes Bob's real ack
    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::Acked),
        "a legitimate ack from the real recipient still delivers"
    );
}

// --- H-A: the dedup `seen` set is bounded by a sliding window --------------------------------

#[test]
fn dedup_window_expires_so_seen_does_not_grow_forever() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    let (bytes, sender_addr) = sealed_to(&net, &bob_ik, &bob_seal, b"windowed", None);
    bob.add_contact(&sender_addr, [7u8; 32]);

    // First delivery stores + records the id in the dedup set.
    assert!(matches!(bob.receive_mote(&sender_addr, &bytes), InboundOutcome::Stored { .. }));
    assert_eq!(bob.inbox().exists(), 1);
    // An immediate redelivery is within the window ⇒ deduped (re-acked, not reprocessed).
    assert!(matches!(bob.receive_mote(&sender_addr, &bytes), InboundOutcome::Duplicate { .. }));
    assert_eq!(bob.inbox().exists(), 1, "still one — deduped inside the window");

    // Advance the receive clock PAST the dedup window: the entry ages out of `seen` (the set is a
    // recent window, not an unbounded log), so the same id is no longer a dedup hit.
    bob.set_now(1_700_000_000_000 + DEDUP_WINDOW_MS + 1);
    let after = bob.receive_mote(&sender_addr, &bytes);
    assert!(
        matches!(after, InboundOutcome::Stored { .. }),
        "past the window the id is no longer retained in `seen` — reprocessed, not a Duplicate: {after:?}"
    );
}

// --- H-A: terminal outbound entries are garbage-collected after a grace window ---------------

#[test]
fn terminal_outbound_entries_are_gc_d_after_the_grace() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    let id = alice.send_mail(&bob_ik, "gc", b"reach a terminal state").unwrap();
    bob.poll(); // Bob stores + acks
    alice.poll(); // Alice reaches ACKED (terminal)
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));
    assert_eq!(alice.outbound_len(), 1, "the terminal entry is still tracked (within grace)");

    // A tick stamps the terminal entry's grace-window start; it is not yet removed.
    alice.tick_deadlines();
    assert_eq!(alice.outbound_len(), 1, "still retained during the grace window");

    // Advance past the grace window and tick again: the terminal slot is garbage-collected, so the
    // outbound queue (and the durable snapshot it feeds) cannot accumulate terminal entries forever.
    alice.set_now(1_700_000_000_000 + TERMINAL_GRACE_MS + 1);
    alice.tick_deadlines();
    assert_eq!(alice.outbound_len(), 0, "the terminal entry was GC'd past the grace");
    assert_eq!(alice.outbound_state(&id), None, "no longer tracked");
}

// --- cold-sender paths (§2.7a) -------------------------------------------------------------

#[test]
fn cold_sender_without_challenge_is_deferred_and_unacked() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    // Alice can reach Bob (knows his key) but Bob has NOT pinned Alice ⇒ she is a cold sender.
    alice.learn_key(&bob_ik, bob_seal);
    let id = alice.send_mail(&bob_ik, "cold", b"do you know me?").unwrap();

    let outcomes = bob.poll();
    assert_eq!(outcomes[0], InboundOutcome::Deferred { id: id.clone() });
    assert!(!outcomes[0].acked(), "a deferred cold MOTE is NOT acked (§2.7a, §19.3.1 step 9, §20.2)");
    assert_eq!(bob.inbox().exists(), 0, "never the inbox (§2.7a)");
    assert_eq!(bob.requests().exists(), 1, "held in the requests area");

    // Because Bob sent no ack, Alice's queue does NOT reach ACKED — it stays in flight and her own
    // retry ultimately EXPIREs (the ack axis is binary: ack iff delivered to the inbox).
    alice.poll();
    assert_ne!(alice.outbound_state(&id), Some(OutState::Acked),
        "no ack ⇒ sender never sees ACKED for a merely-deferred cold MOTE");
    // Silence the unused warning for alice_ik (kept for symmetry/readability).
    let _ = alice_ik;
}

#[test]
fn cold_sender_with_valid_challenge_is_accepted() {
    let net = InMemoryNetwork::new();
    let (mut alice, _alice_ik, _alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.learn_key(&bob_ik, bob_seal);

    let mut draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, b"here is my proof".to_vec());
    draft.challenge = Some(ChallengeResponse::Pow(PowSolution {
        algo: "argon2id".into(),
        params: [65536, 3, 1],
        epoch_nonce: vec![1, 2, 3],
        solution: vec![4, 5, 6],
        difficulty: 20,
    }));
    let id = alice.send_with_draft(&bob_ik, draft).unwrap();

    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "challenge clears the §9 gate");
    assert_eq!(bob.inbox().exists(), 1);
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));
}

#[test]
fn unresolved_recipient_cannot_be_sent() {
    let net = InMemoryNetwork::new();
    let (mut alice, _ik, _seal) = make_node(&net);
    let (_bob, bob_ik, _bob_seal) = make_node(&net);
    // Alice never learned Bob's sealing key.
    assert_eq!(alice.send_mail(&bob_ik, "x", b"y"), Err(dmtap::SendError::Unresolved));
}
