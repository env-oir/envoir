//! Hosted-node storage seam — end-to-end wiring tests (spec §12.2, §12.3, §12.4).
//!
//! Proves the OSS "node usage" (hosted-mailbox storage) seam behaves correctly **through the real
//! delivery path** ([`Node::receive_mote`]):
//!
//! 1. the self-host default admits everything and bills no one — a node with **no** injected seam
//!    stores + acks exactly as before (self-host is unaffected);
//! 2. an injected quota that denies past a cap is enforced **fail-closed** — a refused MOTE is
//!    neither stored nor acked, and a redelivery is re-evaluated (not fast-acked);
//! 3. an injected meter records the durable-storage delta of exactly the MOTEs the node accepts.
//!
//! The quota/meter doubles live here; the node links no cloud or billing crate.

use std::cell::RefCell;
use std::rc::Rc;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::{build_mote, Hpke, Kind, MoteDraft, SealKeypair};
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};
use dmtap::usage::{CountingUsageMeter, QuotaDecision, StorageQuota, UsageEvent};

// --- harness ------------------------------------------------------------------------------------

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    let transport = net.endpoint(ik_pub.clone());
    (Node::with_identity(ik, seal, transport), ik_pub, seal_pub)
}

/// Seal a real HPKE MOTE to `to_ik`/`to_seal` from a fresh sender, register the sender's return path,
/// and return `(wire_bytes, sender_ik)`. The caller pins the sender so the MOTE reaches the durable
/// accept path (a cold/unpinned sender would only *defer*, which the quota deliberately never gates).
fn sealed_to(net: &InMemoryNetwork, to_ik: &[u8], to_seal: &[u8; 32], body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sender = IdentityKey::generate();
    let eph = IdentityKey::generate();
    let draft = MoteDraft::new(Kind::Mail, 1_700_000_000_000, body.to_vec());
    let env = build_mote(&Hpke, &sender, &eph, to_ik, to_seal, draft).unwrap();
    net.endpoint(sender.public());
    (env.det_cbor(), sender.public())
}

/// A test-double storage quota that admits durable writes until a running total reaches `cap` bytes,
/// then denies — the shape a cloud Policy impl drops into. `used` is shared via [`Rc`] so a clone
/// injected into a node and a clone retained by the test observe the same committed total.
#[derive(Clone)]
struct LimitedStorageQuota {
    cap: u64,
    used: Rc<RefCell<u64>>,
}

impl LimitedStorageQuota {
    fn new(cap: u64) -> Self {
        Self { cap, used: Rc::new(RefCell::new(0)) }
    }
    fn used(&self) -> u64 {
        *self.used.borrow()
    }
}

impl StorageQuota for LimitedStorageQuota {
    fn admit(&self, _account: &[u8], delta_bytes: u64) -> QuotaDecision {
        let used = *self.used.borrow();
        if used.saturating_add(delta_bytes) <= self.cap {
            // Admitted ⇒ the node WILL store these bytes; commit them to the running total.
            *self.used.borrow_mut() = used + delta_bytes;
            QuotaDecision::Allow { remaining_bytes: Some(self.cap - used - delta_bytes) }
        } else {
            QuotaDecision::Deny {
                reason: format!("storage cap {} bytes exceeded", self.cap),
                remaining_bytes: self.cap.saturating_sub(used),
            }
        }
    }
}

// --- 1. self-host default: admits everything, self-host unchanged -------------------------------

#[test]
fn default_unlimited_quota_admits_and_self_host_is_unchanged() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    // No quota and no meter injected: the node uses its UnlimitedStorage + NullUsageMeter defaults.
    let (bytes, sender) = sealed_to(&net, &bob_ik, &bob_seal, b"self-host stores everything");
    bob.add_contact(&sender, [7u8; 32]);

    let outcome = bob.receive_mote(&sender, &bytes);
    assert!(matches!(outcome, InboundOutcome::Stored { .. }), "default admits the store");
    assert!(outcome.acked(), "an accepted MOTE is acked exactly as before");
    assert_eq!(bob.inbox().exists(), 1, "delivered to INBOX unchanged by the seam");
    assert_eq!(net.in_flight(), 1, "one ack in flight — the no-op meter did not break the path");
}

// --- 2. injected quota denies past N bytes, fail-closed -----------------------------------------

#[test]
fn quota_denies_past_cap_fail_closed() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    let (bytes1, s1) = sealed_to(&net, &bob_ik, &bob_seal, b"first message fits");
    let (bytes2, s2) = sealed_to(&net, &bob_ik, &bob_seal, b"second message overflows the cap");
    bob.add_contact(&s1, [7u8; 32]);
    bob.add_contact(&s2, [7u8; 32]);

    // Cap = exactly the first MOTE's wire size ⇒ room for one, then the cap is full.
    let cap = bytes1.len() as u64;
    let quota = LimitedStorageQuota::new(cap);
    bob.set_storage_quota(Box::new(quota.clone()));

    // First: admitted, stored, acked; the double committed the bytes.
    let o1 = bob.receive_mote(&s1, &bytes1);
    assert!(matches!(o1, InboundOutcome::Stored { .. }), "within cap ⇒ stored");
    assert!(o1.acked());
    assert_eq!(bob.inbox().exists(), 1);
    assert_eq!(quota.used(), cap, "the admitted store consumed the whole allowance");
    let acks_after_first = net.in_flight();
    assert_eq!(acks_after_first, 1, "one ack for the first, admitted MOTE");

    // Second: over cap ⇒ fail-closed. Not stored, not acked; the sender's retry holds it.
    let o2 = bob.receive_mote(&s2, &bytes2);
    match &o2 {
        InboundOutcome::StorageDenied { id, reason } => {
            assert_eq!(id.as_bytes().len(), 33, "the denied MOTE's id is surfaced");
            assert!(reason.contains("cap"), "a human-safe reason is surfaced: {reason}");
        }
        other => panic!("expected StorageDenied, got {other:?}"),
    }
    assert!(!o2.acked(), "a denied store is never acked (§12.3 fail-closed)");
    assert_eq!(bob.inbox().exists(), 1, "the denied MOTE was NOT durably written");
    assert_eq!(net.in_flight(), acks_after_first, "no new ack was emitted for the denied MOTE");

    // A redelivery of the denied MOTE is re-evaluated (not added to `seen`), and denied again — so a
    // later cap increase could admit it, rather than it being silently dedup-acked as already held.
    let again = bob.receive_mote(&s2, &bytes2);
    assert!(matches!(again, InboundOutcome::StorageDenied { .. }), "redelivery re-evaluated, still denied");
    assert_eq!(bob.inbox().exists(), 1);
}

// --- 3. injected meter records the durable-storage delta of accepted MOTEs ----------------------

#[test]
fn meter_records_stored_deltas_for_accepted_motes() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    let meter = CountingUsageMeter::new();
    bob.set_usage_meter(Box::new(meter.clone())); // default UnlimitedStorage quota ⇒ all admitted

    let (bytes1, s1) = sealed_to(&net, &bob_ik, &bob_seal, b"alpha");
    let (bytes2, s2) = sealed_to(&net, &bob_ik, &bob_seal, b"a much longer beta body than alpha");
    bob.add_contact(&s1, [7u8; 32]);
    bob.add_contact(&s2, [7u8; 32]);

    assert!(matches!(bob.receive_mote(&s1, &bytes1), InboundOutcome::Stored { .. }));
    assert!(matches!(bob.receive_mote(&s2, &bytes2), InboundOutcome::Stored { .. }));

    // Exactly one Stored event per accept, each billing the MOTE's durable wire size, attributed to
    // this node's own identity (the hosted-mailbox account).
    assert_eq!(meter.count(), 2, "one usage event per durable accept");
    let expected = (bytes1.len() + bytes2.len()) as i64;
    assert_eq!(
        meter.stored_bytes(&bob_ik),
        expected,
        "metered stored bytes == the exact bytes the node durably accepted",
    );
    // Every recorded event is a Stored delta for bob's account.
    for ev in meter.events() {
        match ev {
            UsageEvent::Stored { account, delta_bytes, .. } => {
                assert_eq!(account, bob_ik, "billed to the mailbox owner's account");
                assert!(delta_bytes > 0);
            }
            other => panic!("expected only Stored events, got {other:?}"),
        }
    }
}

// --- a dropped/deferred MOTE is neither stored nor metered --------------------------------------

#[test]
fn deferred_cold_sender_is_not_metered_or_quota_gated() {
    let net = InMemoryNetwork::new();
    let (mut bob, bob_ik, bob_seal) = make_node(&net);

    let meter = CountingUsageMeter::new();
    bob.set_usage_meter(Box::new(meter.clone()));
    // A quota with zero allowance — if the deferred path wrongly consulted/metered it, this would show.
    bob.set_storage_quota(Box::new(LimitedStorageQuota::new(0)));

    // Cold sender (NOT pinned) ⇒ deferred to the requests area, never the inbox accept path.
    let (bytes, sender) = sealed_to(&net, &bob_ik, &bob_seal, b"cold, unproven");
    let outcome = bob.receive_mote(&sender, &bytes);
    assert!(matches!(outcome, InboundOutcome::Deferred { .. }), "unpinned cold sender defers");
    assert_eq!(bob.inbox().exists(), 0);
    assert_eq!(meter.count(), 0, "a deferred (non-inbox) MOTE is never metered as stored usage");
}
