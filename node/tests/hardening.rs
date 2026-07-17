//! Node-layer hardening integration tests (audit #4 + monotonic downgrade enforcement).
//!
//! 1. **OPK-depletion admission gate (§5.2.1, audit #4).** X3DH `accept` consumes a one-time prekey
//!    *before* a `DeniableInit` authenticates, and the init's `idk_a_cert` is self-signable — so an
//!    unsolicited flood of throwaway inits could burn the responder's OPK pool and force the weak
//!    last-resort prekey. The node throttles inbound inits (per-source + global token bucket) BEFORE a
//!    prekey is touched: a Sybil flood is capped and the pool preserved, while a genuine init's own
//!    retry still succeeds once the bucket refills.
//! 2. **Suite high-water-mark (§2.7 step 8, §10.7.1).** The node feeds its per-contact
//!    [`SuiteRatchet`] on the inbound path (`validate_pinned`), so an authenticated sender that later
//!    asserts a *lower* suite is rejected as a downgrade at the node (disposition DEFER, §21.3 0x020F).
//! 3. **Mix-directory anti-rollback (§4.4.2, §18.5.3).** The node pins a per-authority monotonic
//!    `(epoch, version)` high-water-mark, rejecting a replayed/stale mix-fleet snapshot.

use dmtap::deniable::DeniableAcceptLimits;
use dmtap::dmtap_core::deniable::DeniablePayload;
use dmtap::dmtap_core::mixnet::{MixDirectory, MixKeyEntry, MixNodeDescriptor};
use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::{Headers, Kind, SealKeypair};
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};
use dmtap::{CertifiedInit, ContentId, DeniableRouteError, Journal, JournalError, Snapshot, Suite};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000_000;

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    (Node::with_identity(ik, seal, net.endpoint(ik_pub.clone())), ik_pub, seal_pub)
}

fn deniable_payload(from: &[u8], body: &[u8]) -> DeniablePayload {
    DeniablePayload {
        from: from.to_vec(),
        kind: Kind::Chat,
        headers: Headers { subject: Some("x".into()), ..Headers::default() },
        body: body.to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}

/// A journal that counts `save` calls, so a test can assert *which* code paths persist. Backs a
/// shared snapshot so `load`/restart still works like [`MemoryJournal`].
#[derive(Clone, Default)]
struct CountingJournal {
    saves: Arc<AtomicUsize>,
    snap: Arc<Mutex<Option<Snapshot>>>,
}

impl CountingJournal {
    fn saves(&self) -> usize {
        self.saves.load(Ordering::SeqCst)
    }
}

impl Journal for CountingJournal {
    fn save(&self, snapshot: &Snapshot) -> Result<(), JournalError> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        *self.snap.lock().unwrap() = Some(snapshot.clone());
        Ok(())
    }
    fn load(&self) -> Result<Snapshot, JournalError> {
        Ok(self.snap.lock().unwrap().clone().unwrap_or_default())
    }
}

// ============================================================================================
// 1. OPK-depletion admission gate (audit #4)
// ============================================================================================

/// A burst of unsolicited inits — each a throwaway identity referencing a distinct published OPK
/// (the wire-level depletion vector: `accept` burns the referenced prekey before the init can be
/// authenticated) — is capped by the node's global admission bucket, so the OPK pool is preserved and
/// the weak last-resort prekey is never forced.
#[test]
fn unsolicited_init_flood_is_throttled_and_opk_pool_preserved() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let opks: Vec<Vec<u8>> = bundle.bundle.opks.clone();
    assert_eq!(bob.deniable_opks_remaining(), Some(opks.len()), "8 OPKs published");
    assert!(opks.len() >= 8, "reference bundle offers a real pool of one-time prekeys");

    // Global burst 3 caps a Sybil flood at 3 accepts; per-source is deliberately generous so the
    // *global* bucket (the real pool protector against throwaway identities) is what binds.
    bob.configure_deniable_accept_gate(DeniableAcceptLimits {
        global_burst: 3,
        global_refill_ms: 60_000,
        source_burst: 100,
        source_refill_ms: 60_000,
    });

    let mut admitted = 0;
    let mut throttled = 0;
    for (i, opk) in opks.iter().enumerate() {
        // A fresh throwaway attacker identity per init (Sybil): a valid self-signed CertifiedInit.
        let (mut mallory, mallory_ik, _) = make_node(&net);
        let first = deniable_payload(&mallory_ik, b"burn a prekey");
        let stock = mallory.deniable_open(&bob_ik, &bundle, &first).unwrap();
        // A wire attacker points each init at a DISTINCT published OPK so every admitted accept burns
        // a different prekey (swapping opk_ref leaves ik_a — hence the root-IK binding — intact).
        let mut init = stock.init.clone();
        init.opk_ref = Some(ContentId::of(opk));
        let certified = CertifiedInit { init, cert: stock.cert };

        match bob.deniable_accept(&mallory_ik, &certified) {
            Err(DeniableRouteError::RateLimited) => throttled += 1,
            _ => admitted += 1, // passed the gate (and burned opks[i], success or later decrypt-fail)
        }
        let _ = i;
    }

    assert_eq!(admitted, 3, "the global burst capped the flood at 3 accepts");
    assert_eq!(throttled, opks.len() - 3, "every further unsolicited init was throttled");

    let remaining = bob.deniable_opks_remaining().unwrap();
    assert_eq!(remaining, opks.len() - 3, "at most `global_burst` OPKs were consumed");
    assert!(remaining >= 5, "OPK pool preserved ({remaining} left) — last-resort NOT forced");
}

/// A genuine init that arrives while the gate is drained is throttled (no prekey consumed), and the
/// initiator's own retry succeeds once the bucket refills — legitimate flow is never permanently
/// denied. Directly exercises the retry semantics the gate is designed to allow.
#[test]
fn a_throttled_genuine_init_succeeds_on_retry_after_refill() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, _) = make_node(&net);
    let (mut alice, alice_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let opks: Vec<Vec<u8>> = bundle.bundle.opks.clone();
    bob.set_now(NOW);
    bob.configure_deniable_accept_gate(DeniableAcceptLimits {
        global_burst: 1,
        global_refill_ms: 30_000,
        source_burst: 10,
        source_refill_ms: 30_000,
    });

    // An attacker spends the single global token, burning a DIFFERENT opk than the one a genuine
    // initiator will pick (the reference initiator always chooses opks[0]).
    let (mut mallory, mallory_ik, _) = make_node(&net);
    let mstock = mallory
        .deniable_open(&bob_ik, &bundle, &deniable_payload(&mallory_ik, b"noise"))
        .unwrap();
    let mut minit = mstock.init.clone();
    minit.opk_ref = Some(ContentId::of(opks.last().unwrap()));
    let mcert = CertifiedInit { init: minit, cert: mstock.cert };
    let _ = bob.deniable_accept(&mallory_ik, &mcert); // admitted; drains the token, burns opks[last]
    assert_eq!(bob.deniable_opks_remaining(), Some(opks.len() - 1));

    // Alice opens a genuine session; her first delivery lands while the gate is empty ⇒ throttled,
    // with NO prekey consumed (the gate returns before X3DH touches the pool).
    let first = deniable_payload(&alice_ik, b"a real hello you cannot prove I wrote");
    let init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();
    assert!(matches!(
        bob.deniable_accept(&alice_ik, &init),
        Err(DeniableRouteError::RateLimited)
    ));
    assert_eq!(
        bob.deniable_opks_remaining(),
        Some(opks.len() - 1),
        "a throttled init consumes no prekey"
    );

    // The bucket refills; Alice's own retry (the same init) is admitted and the MOTE round-trips.
    bob.set_now(NOW + 30_000);
    let got = bob.deniable_accept(&alice_ik, &init).expect("genuine init admitted after refill");
    assert_eq!(got, first, "the genuine first MOTE round-trips once admitted");
    assert_eq!(bob.deniable_opks_remaining(), Some(opks.len() - 2), "now the genuine OPK is consumed");
}

/// A rejected (throttled) init performs NO checkpoint, while an admitted init still persists. This
/// closes the amplification vector where every self-signed `CertifiedInit` — even one the gate
/// throttles before touching a prekey — forced a full-node-Snapshot disk write (audit #4). We count
/// journal saves: the throttled flood adds none; the one admitted accept adds exactly one.
#[test]
fn a_throttled_init_performs_no_checkpoint_while_an_admitted_one_persists() {
    let net = InMemoryNetwork::new();
    let journal = CountingJournal::default();

    let bob_id = IdentityKey::generate();
    let bob_ik = bob_id.public();
    let mut bob = Node::with_journal(
        bob_id,
        SealKeypair::generate(),
        net.endpoint(bob_ik.clone()),
        Box::new(journal.clone()),
    )
    .expect("build bob on a counting journal");

    // A single global token: the first accept is admitted, every later distinct-source init throttled.
    bob.configure_deniable_accept_gate(DeniableAcceptLimits {
        global_burst: 1,
        global_refill_ms: 1_000_000_000,
        source_burst: 100,
        source_refill_ms: 1_000_000_000,
    });
    let bundle = bob.deniable_publish_bundle();

    // Baseline taken AFTER configure/publish so their (legitimate, admin-path) writes don't count.
    let baseline = journal.saves();

    // One genuine, admitted init — drains the token, accepts, and MUST persist (drained bucket +
    // delivered state survive a restart).
    let (mut alice, alice_ik, _) = make_node(&net);
    let hello = deniable_payload(&alice_ik, b"a real hello");
    let init = alice.deniable_open(&bob_ik, &bundle, &hello).unwrap();
    assert!(bob.deniable_accept(&alice_ik, &init).is_ok(), "genuine init admitted");
    assert_eq!(journal.saves(), baseline + 1, "an admitted accept persists exactly once");

    // A burst of throwaway (Sybil) inits: the global bucket is spent, so each is throttled BEFORE a
    // prekey is touched — and, post-fix, WITHOUT any checkpoint. The save count must not move.
    let after_admit = journal.saves();
    for _ in 0..200 {
        let (mut mallory, mallory_ik, _) = make_node(&net);
        let noise = deniable_payload(&mallory_ik, b"flood");
        let flood = mallory.deniable_open(&bob_ik, &bundle, &noise).unwrap();
        assert!(matches!(
            bob.deniable_accept(&mallory_ik, &flood),
            Err(DeniableRouteError::RateLimited)
        ));
    }
    assert_eq!(
        journal.saves(),
        after_admit,
        "a throttled/rejected init must perform NO checkpoint (no disk-write amplification)"
    );
}

// ============================================================================================
// 2. Suite high-water-mark downgrade rejection at the node (§2.7 step 8, §10.7.1, §21.3)
// ============================================================================================

/// A genuine inbound MOTE feeds the node's per-contact suite ratchet, and a subsequent object below
/// that established high-water-mark is rejected as a downgrade *at the node* (deferred, unacked, and
/// the mark is not ratcheted down). The only wire-supported suite is Classical, so the floor is
/// pinned to the higher PqHybrid out-of-band to make the on-the-wire downgrade expressible.
#[test]
fn suite_downgrade_is_rejected_at_the_node() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    // A genuine Classical MOTE is delivered and ratchets Bob's mark for Alice up to Classical.
    let id = alice.send_mail(&bob_ik, "hi", b"a real message").expect("send");
    let outcomes = bob.poll();
    assert!(matches!(&outcomes[0], InboundOutcome::Stored { id: got, .. } if got == &id));
    assert_eq!(bob.suite_high_water_mark(&alice_ik), Some(Suite::Classical), "mark fed on the wire");

    // Out-of-band, Bob learns Alice has migrated to the stronger PqHybrid suite (pin the floor up).
    bob.pin_suite_floor(&alice_ik, Suite::PqHybrid);
    assert_eq!(bob.suite_high_water_mark(&alice_ik), Some(Suite::PqHybrid));

    // Alice now (adversary-forced) sends a Classical MOTE — below the pinned PqHybrid floor. It
    // authenticates but is a downgrade: Bob DEFERS it (requests area, not inbox), does NOT ack, and
    // the high-water-mark is NOT ratcheted down.
    let inbox_before = bob.inbox().exists();
    let requests_before = bob.requests().exists();
    let _ = alice.send_mail(&bob_ik, "downgrade", b"weaker suite please").expect("send");
    let outcomes = bob.poll();
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(&outcomes[0], InboundOutcome::Deferred { .. }), "downgrade → DEFER (§21.3)");
    assert!(!outcomes[0].acked(), "a downgrade is not acked");
    assert_eq!(bob.inbox().exists(), inbox_before, "downgrade never reaches the inbox");
    assert_eq!(bob.requests().exists(), requests_before + 1, "held in the requests area");
    assert_eq!(bob.suite_high_water_mark(&alice_ik), Some(Suite::PqHybrid), "mark not lowered");
}

// ============================================================================================
// 3. Mix-directory anti-rollback wired into the node (§4.4.2, §18.5.3)
// ============================================================================================

fn signed_directory(authority: &IdentityKey, epoch: u64, version: u64) -> MixDirectory {
    let node = IdentityKey::from_seed(&[0x99; 32]);
    let desc = MixNodeDescriptor::issue(
        &node,
        vec!["/ip4/198.51.100.7/udp/443/quic-v1".into()],
        vec![MixKeyEntry { epoch, mix_key: vec![0x22; 32], valid_until: NOW + 600_000 }],
        1,
        NOW,
        None,
        None,
    );
    MixDirectory::issue(authority, epoch, version, vec![desc], ContentId::of(b"genesis"), NOW)
}

#[test]
fn node_rejects_a_stale_mix_directory_but_accepts_a_newer_one() {
    let net = InMemoryNetwork::new();
    let (mut node, _ik, _) = make_node(&net);
    let authority = IdentityKey::from_seed(&[0x77; 32]);
    let auth_pub = authority.public();

    // First accepted directory pins the (epoch, version) high-water-mark.
    assert!(node.ingest_mix_directory(&signed_directory(&authority, 10, 2).det_cbor()).is_ok());
    assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((10, 2)));

    // A replay/rollback (older-or-equal) is rejected and the mark is untouched.
    assert!(node.ingest_mix_directory(&signed_directory(&authority, 10, 1).det_cbor()).is_err());
    assert!(node.ingest_mix_directory(&signed_directory(&authority, 10, 2).det_cbor()).is_err());
    assert!(node.ingest_mix_directory(&signed_directory(&authority, 9, 99).det_cbor()).is_err());
    assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((10, 2)), "mark not rolled back");

    // A genuinely newer directory ratchets the mark up and is retained.
    assert!(node.ingest_mix_directory(&signed_directory(&authority, 11, 0).det_cbor()).is_ok());
    assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((11, 0)));
    assert_eq!(node.mix_directory(&auth_pub).map(|d| d.version), Some(0));

    // A forged authority signature fails closed.
    let mut forged = signed_directory(&authority, 12, 0);
    forged.sig[0] ^= 0xff;
    assert!(node.ingest_mix_directory(&forged.det_cbor()).is_err());
    assert_eq!(node.mix_directory_high_water_mark(&auth_pub), Some((11, 0)), "forgery pins nothing");
}

// ============================================================================================
// 4. Checkpoint write-amplification: a poll() batch persists once, not once-per-accept (H-A)
// ============================================================================================

/// The receive path checkpointed the FULL snapshot after every accepted MOTE (and every ack), so a
/// tick draining K frames performed K full-snapshot writes — O(n²) disk I/O over a node's lifetime.
/// A `poll()` batch now coalesces its per-frame checkpoints into a SINGLE durable write, so N accepts
/// across a tick cost one snapshot, not N. (Combined with the bounded `seen`/outbound state, each
/// snapshot is itself bounded, so total delivery I/O is linear.)
#[test]
fn a_poll_batch_of_many_accepts_checkpoints_once() {
    let net = InMemoryNetwork::new();
    let journal = CountingJournal::default();

    let bob_id = IdentityKey::generate();
    let bob_ik = bob_id.public();
    let mut bob = Node::with_journal(
        bob_id,
        SealKeypair::generate(),
        net.endpoint(bob_ik.clone()),
        Box::new(journal.clone()),
    )
    .expect("build bob on a counting journal");
    let bob_seal = bob.seal_public();

    // Queue K real end-to-end-sealed MOTEs from K distinct KNOWN senders onto Bob's transport (each is
    // accepted, so each would have triggered its own checkpoint on the old per-frame path).
    const K: usize = 16;
    for i in 0..K {
        let (mut sender, sender_ik, sender_seal) = make_node(&net);
        bob.add_contact(&sender_ik, sender_seal); // known ⇒ accepted (not deferred)
        sender.add_contact(&bob_ik, bob_seal);
        sender.send_mail(&bob_ik, "batch", format!("mote {i}").as_bytes()).unwrap();
    }

    let baseline = journal.saves();
    let outcomes = bob.poll();
    assert_eq!(outcomes.len(), K, "all {K} MOTEs were processed in one poll");
    assert!(
        outcomes.iter().all(|o| matches!(o, InboundOutcome::Stored { .. })),
        "every MOTE was accepted (each would have checkpointed on the old path)"
    );
    assert_eq!(bob.inbox().exists(), K);
    assert_eq!(
        journal.saves(),
        baseline + 1,
        "the whole batch persisted with exactly ONE snapshot write, not one per accept"
    );
}
