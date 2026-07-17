//! Node-runtime reliability/anti-abuse integration tests for the perfected-spec changes:
//!
//! - **D1 (§20.1 `RETRY (private)`).** A `private`-tier retry MUST **re-onion-wrap** — a fresh
//!   Sphinx path/`α`/current-epoch keys — so its per-hop tags differ from the first attempt's
//!   (§4.4.6); re-sending the identical onion would be dropped by every honest first hop as a replay
//!   and could never deliver. A `fast`-tier send ships the identical immutable sealed bytes.
//! - **S3 (§9.4/§16.5).** Cold-sender memory-hard PoW verifications are **bounded per delivering
//!   connection**; past the budget a bogus-PoW cold MOTE is deferred to the requests area **without**
//!   the Argon2id verifier ever running.
//! - **D6 (§4.4.1/§16.3).** The bounded multi-cell reassembly cache times out an incomplete MOTE and
//!   reassembles a complete one (the safety part; per-cell ARQ/FEC is the follow-up).

use dmtap::dmtap_core::sphinx::{SphinxFragmentHeader, FRAGMENT_DATA_LEN};
use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::{build_mote, ChallengeResponse, Hpke, Kind, MoteDraft, PowSolution, SealKeypair};
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::reassembly::REASSEMBLY_TIMEOUT_MS;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};
use dmtap::{MixHop, MixPath, Reassembled};

const NOW: u64 = 1_700_000_000_000;

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    (Node::with_identity(ik, seal, net.endpoint(ik_pub.clone())), ik_pub, seal_pub)
}

fn three_hop_path(entry_mix: &[u8], epoch: u64) -> MixPath {
    MixPath::new(
        vec![
            MixHop { node_ik: entry_mix.to_vec(), mix_key: [1u8; 32], delay_ms: 5000 },
            MixHop { node_ik: b"middle-mix".to_vec(), mix_key: [2u8; 32], delay_ms: 5000 },
            MixHop { node_ik: b"exit-mix".to_vec(), mix_key: [3u8; 32], delay_ms: 5000 },
        ],
        epoch,
    )
}

/// D1 — a `private`-tier RETRY re-onion-wraps to a DIFFERENT onion (distinct per-hop tags) for the
/// same stable `id` (§20.1 `RETRY (private)`, §4.4.6).
#[test]
fn private_retry_re_onion_wraps_distinct_per_hop_tags() {
    let net = InMemoryNetwork::new();
    let (mut alice, _a_pub, _a_seal) = make_node(&net);

    // A recipient whose sealing key Alice knows (so the MOTE seals), and an entry-mix address on the
    // fabric that we can toggle up/down to drive a retry.
    let bob = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    alice.add_contact(&bob.public(), *bob_seal.public());
    let entry_mix = b"entry-mix-endpoint".to_vec();
    let _mix_ep = net.endpoint(entry_mix.clone());

    // Entry mix DOWN → the first dispatch builds a fresh onion (stored) but cannot deliver → RETRY.
    net.set_down(&entry_mix, true);
    let path = three_hop_path(&entry_mix, 7);
    let id = alice.send_mail_private(&bob.public(), "subject", b"a private mail body", path).unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "unreachable entry mix ⇒ RETRY");
    let first = alice.outbound_onion(&id).expect("private send built an onion");

    // Entry mix UP → the RETRY re-onion-wraps with a FRESH α and re-dispatches (→ IN_FLIGHT).
    net.set_down(&entry_mix, false);
    assert_eq!(alice.retry_pending(), 1, "the private RETRY re-dispatched");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));
    let second = alice.outbound_onion(&id).expect("the retry rebuilt the onion");

    // The stable envelope id is unchanged, but the onion — and specifically its per-hop tags — differ,
    // so an honest first hop does NOT drop the retry as a per-hop-tag replay (§4.4.6).
    assert_ne!(
        first.replay_tags(),
        second.replay_tags(),
        "a private retry MUST produce distinct per-hop tags (re-onion-wrap), not a replay"
    );
    assert_ne!(first.to_bytes(), second.to_bytes(), "the whole onion is freshly drawn");
    // Nothing about the inner MOTE changed: same stable content-addressed id (§2.2).
    assert!(alice.outbound_sealed(&id).is_some(), "the inner sealed envelope is retained for re-wrap");
}

/// D1 — a `fast`-tier retry re-dispatches the IDENTICAL immutable sealed bytes (no per-hop mix tag to
/// refresh), and carries no onion (§20.1 `RETRY (fast)`).
#[test]
fn fast_retry_reuses_identical_sealed_bytes() {
    let net = InMemoryNetwork::new();
    let (mut alice, _a_pub, _a_seal) = make_node(&net);
    let (bob, bob_pub, _bob_seal) = make_node(&net);
    let _ = bob; // keep bob's endpoint registered on the fabric
    let bob_seal = SealKeypair::generate();
    alice.add_contact(&bob_pub, *bob_seal.public());

    // Bob DOWN → the fast send cannot deliver → RETRY (no onion is ever built for the fast tier).
    net.set_down(&bob_pub, true);
    let id = alice.send_mail(&bob_pub, "subject", b"a fast mail body").unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry));
    assert!(alice.outbound_onion(&id).is_none(), "the fast tier is not onion-wrapped");

    // Bob UP → the RETRY re-dispatches the identical sealed envelope bytes (a pure retransmission).
    net.set_down(&bob_pub, false);
    assert_eq!(alice.retry_pending(), 1);
    let delivered = bob_endpoint_drain(&net, &bob_pub);
    let sealed_cbor = alice.outbound_sealed(&id).expect("sealed").det_cbor();
    assert_eq!(
        delivered,
        vec![dmtap::transport::Frame::Mote(sealed_cbor)],
        "a fast retry ships the identical immutable sealed bytes, not a re-wrapped object"
    );
}

/// Drain whatever was delivered to `addr` on the shared fabric (a fresh endpoint handle onto the same
/// queue), returning just the frames.
fn bob_endpoint_drain(net: &InMemoryNetwork, addr: &[u8]) -> Vec<dmtap::transport::Frame> {
    use dmtap::transport::Transport;
    net.endpoint(addr.to_vec()).drain().into_iter().map(|(_from, f)| f).collect()
}

/// S3 — the number of memory-hard PoW verifications is bounded per delivering connection: past the
/// budget, extra cold-PoW MOTEs are DEFERRED to the requests area WITHOUT invoking Argon2id (§9.4,
/// §16.5). Within budget the verification is spent and the MOTE proceeds through normal validation
/// (the node bounds verification *cost*, it does not newly gate delivery on PoW validity — §9.4's
/// reference limit treats a present challenge as meeting threshold).
#[test]
fn cold_pow_flood_defers_past_budget_without_verifying() {
    let net = InMemoryNetwork::new();
    let (mut recip, recip_pub, recip_seal) = make_node(&net);
    // Budget: 2 memory-hard verifications per window, per delivering connection.
    recip.set_pow_budget(1_000, 2);

    // Four cold-sender MOTEs, each carrying a memory-hard Argon2id PoW, all delivered over the SAME
    // connection/relay `from`. Each sender IK is distinct and none is pinned, so every MOTE is a cold
    // sender (§2.7 step 5) whose PoW would otherwise be verified.
    let from = b"delivering-relay-A".to_vec();
    let mut deferred = 0;
    let mut stored = 0;
    for i in 0..4u8 {
        let sender = IdentityKey::generate();
        let eph = IdentityKey::generate();
        let mut draft = MoteDraft::new(Kind::Mail, NOW, vec![i]);
        draft.challenge = Some(ChallengeResponse::Pow(PowSolution {
            algo: "argon2id".into(),
            params: [8, 1, 1], // tiny/fast; the point under test is the budget, not any solution
            epoch_nonce: b"epoch-nonce".to_vec(),
            solution: vec![i],
            difficulty: 4,
        }));
        let env = build_mote(&Hpke, &sender, &eph, &recip_pub, &recip_seal, draft).unwrap();
        match recip.receive_mote(&from, &env.det_cbor()) {
            InboundOutcome::Deferred { .. } => deferred += 1,
            InboundOutcome::Stored { .. } => stored += 1,
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    // The first two (within budget) were verified and delivered; the flood past the budget was
    // DEFERRED without spending any memory-hard work — the whole point of the bound.
    assert_eq!(stored, 2, "within-budget cold-PoW MOTEs verify and proceed");
    assert_eq!(deferred, 2, "over-budget cold-PoW MOTEs are deferred to the requests area");
    assert_eq!(
        recip.pow_verifications(),
        2,
        "only the within-budget MOTEs invoked Argon2id — the over-budget tail was never verified"
    );
    assert_eq!(recip.requests().exists(), 2, "the deferred tail sits in the requests area");
}

/// S3 — the budget is per delivering connection: a second relay gets its own budget.
#[test]
fn pow_budget_is_per_connection() {
    let net = InMemoryNetwork::new();
    let (mut recip, recip_pub, recip_seal) = make_node(&net);
    recip.set_pow_budget(1_000, 1); // one verification per window per connection
    let sender = IdentityKey::generate();

    let cold_pow = |recip: &mut Node<InMemoryTransport>, from: &[u8], tag: u8| {
        let eph = IdentityKey::generate();
        let mut draft = MoteDraft::new(Kind::Mail, NOW, vec![tag]);
        draft.challenge = Some(ChallengeResponse::Pow(PowSolution {
            algo: "argon2id".into(),
            params: [8, 1, 1],
            epoch_nonce: b"n".to_vec(),
            solution: vec![tag],
            difficulty: 8,
        }));
        let env = build_mote(&Hpke, &sender, &eph, &recip_pub, &recip_seal, draft).unwrap();
        recip.receive_mote(from, &env.det_cbor())
    };

    // Relay A spends its single slot, then is over budget; relay B still has its own slot.
    cold_pow(&mut recip, b"relay-A", 1);
    cold_pow(&mut recip, b"relay-A", 2); // over A's budget → not verified
    cold_pow(&mut recip, b"relay-B", 3); // B's own budget → verified
    assert_eq!(recip.pow_verifications(), 2, "A spent 1, B spent 1; A's overflow was not verified");
}

/// D6 — the bounded reassembly cache evicts an incomplete MOTE after the timeout and reassembles a
/// complete one (§4.4.1 safety part, §16.3). Per-cell ARQ/FEC recovery is the tracked follow-up.
#[test]
fn node_reassembly_times_out_incomplete_and_completes_full() {
    let net = InMemoryNetwork::new();
    let (mut node, _pub, _seal) = make_node(&net);

    // An incomplete multi-cell MOTE: 1 of 4 cells. Held pending.
    let partial = SphinxFragmentHeader { msg_id: [1; 8], frag_index: 0, frag_count: 4, total_len: 100 };
    assert_eq!(
        node.accept_fragment(&partial, &vec![0u8; FRAGMENT_DATA_LEN]),
        Reassembled::Pending
    );
    assert_eq!(node.reassembly_pending(), 1);

    // Advance past the reassembly timeout: the deadline tick evicts the incomplete partial (bounded —
    // a lost cell cannot pin recipient memory).
    node.set_now(NOW + REASSEMBLY_TIMEOUT_MS);
    node.tick_deadlines();
    assert_eq!(node.reassembly_pending(), 0, "an incomplete reassembly is evicted after the timeout");

    // A complete (single-cell) MOTE reassembles to its true length.
    let mut data = vec![0u8; FRAGMENT_DATA_LEN];
    data[..3].copy_from_slice(b"abc");
    let full = SphinxFragmentHeader { msg_id: [2; 8], frag_index: 0, frag_count: 1, total_len: 3 };
    assert_eq!(node.accept_fragment(&full, &data), Reassembled::Complete(b"abc".to_vec()));
    assert_eq!(node.reassembly_pending(), 0);
}
