//! §6.7 `sensitive` — decrypt, show once, never store.
//!
//! Kept in its own integration file rather than folded into `crate_integration.rs`: this is one
//! self-contained normative rule with two halves that pull against each other (never persist, but
//! still ack and still show), and it reads better as a unit than scattered among the general
//! delivery tests.

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::{Kind, MoteDraft, SealKeypair};
use dmtap::node::Node;
use dmtap::transport::InMemoryNetwork;

/// §6.7 `sensitive` (MAY-send / MUST-honor), end-to-end across two real nodes: the message is
/// delivered and ACKED, is readable exactly once, and never enters the recipient's durable store.
///
/// The three requirements pull against each other, which is why they are asserted together:
///
///   - NOT PERSISTED is the point of the flag.
///   - STILL ACKED is what keeps it usable. The ack axis is "was this delivered", not "is it still
///     on disk"; withholding it would make the sender retry to EXPIRED and report a delivery
///     failure for a message the recipient actually read.
///   - STILL READABLE is what keeps it a message. "Never stored" without an ephemeral view would
///     mean the sender is told it arrived while the recipient can never see it — both parties
///     misinformed, which is worse than simply storing it.
#[test]
fn a_sensitive_message_is_delivered_acked_readable_once_and_never_stored() {
    let net = InMemoryNetwork::new();
    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));
    bob.add_contact(&alice_ik_pub, alice.seal_public());
    alice.add_contact(&bob_ik_pub, bob_seal_pub);

    // Positive control: an ordinary message IS stored, so the assertions below are about the flag
    // and not about a delivery path that never worked in this fixture.
    let mut plain = MoteDraft::new(Kind::Mail, 1_700_000_000_000, b"ordinary".to_vec());
    plain.headers.subject = Some("ordinary".into());
    alice.send_with_draft(&bob_ik_pub, plain).expect("send ordinary");
    assert!(matches!(bob.poll()[0], InboundOutcome::Stored { .. }));
    assert_eq!(bob.inbox().exists(), 1);

    let mut secret = MoteDraft::new(Kind::Mail, 1_700_000_000_001, b"burn after reading".to_vec());
    secret.headers.subject = Some("private".into());
    secret.headers.sensitive = Some(true);
    alice.send_with_draft(&bob_ik_pub, secret).expect("send sensitive");

    let out = bob.poll();
    assert!(
        matches!(out[0], InboundOutcome::EphemeralDelivered { .. }),
        "a sensitive MOTE must be surfaced ephemerally, got {:?}",
        out[0]
    );
    assert!(out[0].acked(), "it WAS delivered — withholding the ack would retry it to EXPIRED");
    assert_eq!(
        bob.inbox().exists(),
        1,
        "the inbox must still hold only the ordinary message — the sensitive one was never stored"
    );

    // Readable exactly once.
    assert_eq!(bob.ephemeral_pending(), 1);
    let held = bob.take_ephemeral();
    assert_eq!(held.len(), 1);
    assert!(
        held[0].1.windows(18).any(|w| w == b"burn after reading"),
        "the ephemeral view must carry the real plaintext"
    );
    assert_eq!(bob.ephemeral_pending(), 0, "an ephemeral view is dropped once taken");
    assert!(bob.take_ephemeral().is_empty());
    assert_eq!(bob.inbox().exists(), 1, "reading it must not file it into the store either");
}

/// §6.7: the ephemeral buffer holds the message readably, and its contents never reach the durable
/// snapshot.
///
/// A buffer that survived a restart would be a durable copy of a message the sender asked not to be
/// retained — the very thing the flag forbids, reintroduced through the back door. The snapshot is
/// exactly the value handed to the journal, so asserting against it is asserting against what a
/// restart would restore.
#[test]
fn the_ephemeral_view_is_readable_once_and_never_persisted() {
    let net = InMemoryNetwork::new();
    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();
    let mut bob = Node::with_identity(bob_ik, bob_seal, net.endpoint(bob_ik_pub.clone()));

    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));
    bob.add_contact(&alice_ik_pub, alice.seal_public());
    alice.add_contact(&bob_ik_pub, bob_seal_pub);

    for i in 0..3u32 {
        let mut d =
            MoteDraft::new(Kind::Mail, 1_700_000_000_000 + i as u64, format!("s{i}").into_bytes());
        d.headers.sensitive = Some(true);
        alice.send_with_draft(&bob_ik_pub, d).expect("send");
    }
    let out = bob.poll();
    assert_eq!(out.len(), 3);
    assert!(out.iter().all(|o| matches!(o, InboundOutcome::EphemeralDelivered { .. })));
    assert_eq!(bob.ephemeral_pending(), 3);
    assert_eq!(bob.inbox().exists(), 0, "none of them may reach the store");

    // The load-bearing check, asserted directly rather than implied.
    let persisted = format!("{:?}", bob.snapshot());
    for marker in ["s0", "s1", "s2"] {
        assert!(
            !persisted.contains(marker),
            "sensitive plaintext {marker:?} must never appear in the durable snapshot"
        );
    }

    // Sanity in the other direction, so the assertion above cannot pass merely because nothing was
    // ever held: the content really is retained, readable, and cleared by the read.
    let held = bob.take_ephemeral();
    assert_eq!(held.len(), 3, "all three were held for an ephemeral view");
    assert!(
        held.iter().any(|(_, raw)| raw.windows(2).any(|w| w == b"s0")),
        "the held bytes must carry the real plaintext"
    );
    assert_eq!(bob.ephemeral_pending(), 0);
}
