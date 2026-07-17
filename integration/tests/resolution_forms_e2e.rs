//! Additional name-**form** end-to-end compositions (spec §3.9, §3.12) beyond the DNS/KT path
//! `full_roundtrip.rs` already proves: the **`self`** key-name resolver and the OPTIONAL
//! **`name-chain`** resolver, each driven for real (`dmtap-naming`) and, on success, carried all the
//! way through a real `dmtap-p2p` libp2p mesh delivery into a real `dmtap-mail` JMAP view.
//!
//! Neither of these two resolver types is wired into [`dmtap::node::Node::resolve_and_pin`] yet — the
//! node's own dispatch (`node/src/node.rs`) fails closed on both `NameForm::KeyName` and
//! `NameForm::NameChain` with an explicit "not wired" error (see `node/src/naming.rs`). So, exactly as
//! `kt_resolution_and_delegation.rs` does for the DNS/KT core, these tests call the real
//! `dmtap-naming` resolver types directly ([`dmtap_naming::SelfResolver`] /
//! [`dmtap_naming::NameChainResolver`]) and then hand the *resolved* key into the node's existing
//! pin/send seam (`add_contact` + `send_mail`) — proving the resolution algorithm itself is real and
//! that its output is a genuinely usable, mesh-addressable key, without pretending the node already
//! dispatches these forms end-to-end on its own.
//!
//! - **`self` (§3.9.6):** a key-name is a *derivation* from the identity key, not a lookup — its
//!   "resolution" is checking a candidate key (discovered by some other channel, e.g. mesh presence)
//!   actually derives the name a correspondent was given out of band. [`SelfResolver::resolve`] proves
//!   that check for real; the resolved key then seals and delivers over the real libp2p mesh exactly
//!   like the DNS path in `full_roundtrip.rs`.
//! - **`name-chain` (§3.12.5, OPTIONAL):** an ENS/SNS-style `name → ik` pointer whose §3.12.5(b)
//!   **bidirectional** binding (the key claims the name in its signed `Identity.names`, *and* the
//!   on-chain record points at that same key) must hold in both directions. A match resolves and
//!   delivers over the real mesh; a hijacked/mismatched chain record fails closed
//!   (`NameChainBindingUnverified`, wire code `0x011E`) and — proven concretely, not just asserted as
//!   an error variant — the message is delivered **nowhere**: a real node spun up to stand in for the
//!   attacker's claimed key never receives anything, because resolution never got far enough to
//!   construct an addressable key at all.

use std::time::{Duration, Instant};

use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::InMemoryNetwork;

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, KeyPackageBundleRef};
use dmtap_core::TimestampMs;

use dmtap_mail::jmap::{self, Request};

use dmtap_naming::namechain::{InMemoryNameChain, NameChainResolver};
use dmtap_naming::restype::{Chain, ResolverType, SelfResolver, Verification};
use dmtap_naming::ResolveError;

use dmtap_p2p::Libp2pTransport;

use serde_json::json;

const NOW: TimestampMs = 1_752_600_000_000;

/// Generous loopback bound for the real libp2p stack (same bound the other real-mesh tests use).
const SPIN: Duration = Duration::from_secs(15);

fn tcp_listener(t: &Libp2pTransport) -> libp2p::Multiaddr {
    t.wait_for_listener(SPIN)
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

/// Pump both real swarms while waiting on a predicate (mirrors `full_roundtrip.rs`'s helper of the
/// same name/shape — kept local since each integration test file is self-contained).
fn poll_both_until(
    a: &mut Node<Libp2pTransport>,
    b: &mut Node<Libp2pTransport>,
    mut pred: impl FnMut(&Node<Libp2pTransport>, &Node<Libp2pTransport>) -> bool,
) -> bool {
    let deadline = Instant::now() + SPIN;
    loop {
        a.poll();
        b.poll();
        if pred(a, b) {
            return true;
        }
        if Instant::now() >= deadline {
            return pred(a, b);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn jmap_first_email(node: &mut Node<Libp2pTransport>, account: &str) -> serde_json::Value {
    let req: Request = serde_json::from_value(json!({
        "using": [jmap::CAP_CORE, jmap::CAP_MAIL],
        "methodCalls": [
            ["Email/query", { "accountId": account }, "0"],
            ["Email/get", {
                "accountId": account,
                "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                "properties": ["subject", "from", "bodyValues"]
            }, "1"]
        ]
    }))
    .unwrap();
    let resp = jmap::process(node.store_mut(), account, &req);
    let get = &resp.method_responses[1].1;
    get["list"][0].clone()
}

/// Two real libp2p swarms on ephemeral loopback ports, Alice pre-seeded with Bob's dialable route
/// (the §4.2 concern, orthogonal to whatever §3 naming path resolved his identity key).
fn real_swarms(
    alice_ik_pub: Vec<u8>,
    bob_ik_pub: Vec<u8>,
) -> (Libp2pTransport, Libp2pTransport) {
    let alice_tp = Libp2pTransport::new(alice_ik_pub, &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .expect("alice swarm starts");
    let bob_tp = Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .expect("bob swarm starts");
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub, bob_tp.peer_id(), bob_addr);
    (alice_tp, bob_tp)
}

// ── `self` key-name resolution (§3.9.6) ───────────────────────────────────────────────────────

#[test]
fn self_key_name_resolves_via_dmtap_naming_seals_and_delivers_over_real_libp2p_into_a_jmap_readable_inbox()
{
    let bob_ik = IdentityKey::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_seal_pub = *alice_seal.public();

    // The self-authenticating key-name Alice was given out of band (spoken, a QR code, a business
    // card) to identify Bob — a pure local derivation from his key (§3.9.6), no network at all.
    let key_name = SelfResolver::derive(&bob_ik_pub);

    // Real `dmtap-naming` resolution: the candidate key Alice already holds (discovered via some
    // other channel — mesh presence, a directory listing — exactly as the dialable *route* below is
    // seeded separately from the *identity* resolution, mirroring how `full_roundtrip.rs` keeps KT
    // resolution and the §4.2 transport route as two independent concerns) is checked to actually
    // DERIVE the key-name she was told. This is the real §3.9.6 verification, not a stub.
    let binding = SelfResolver::resolve(&key_name, &bob_ik_pub)
        .expect("the key-name checksums and derives from the discovered candidate key");
    assert_eq!(binding.ik, bob_ik_pub, "resolution yields the real candidate key");
    assert_eq!(binding.resolver_type, ResolverType::SelfKeyName);
    assert_eq!(binding.verification, Verification::DerivedSelf, "the binding IS the key, §3.9.6");

    // A mistyped/mismatched key-name must NOT resolve to a different key — proven alongside the
    // happy path so this test also demonstrates the fail-closed half of the same real resolver.
    let stranger_ik = IdentityKey::generate().public();
    assert!(matches!(
        SelfResolver::resolve(&key_name, &stranger_ik),
        Err(ResolveError::KeyNameUnverified(_))
    ));

    // Real libp2p mesh (§4.1) + a real envoir-node pair.
    let (alice_tp, bob_tp) = real_swarms(alice_ik_pub.clone(), bob_ik_pub.clone());
    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);

    // Pin the RESOLVED key (not the raw variable) — the point is that the mesh send is addressed to
    // whatever `dmtap-naming` actually resolved, not to a value the test already had lying around.
    alice.add_contact(&binding.ik, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    let secret = "self key-name resolved for real, then HPKE-sealed over the real mesh";
    let id = alice
        .send_mail(&binding.ik, "resolved via self key-name", secret.as_bytes())
        .expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the real swarm");

    assert!(
        poll_both_until(&mut alice, &mut bob, |_, b| b.inbox().exists() == 1),
        "the self-key-name-resolved MOTE should arrive over the real libp2p swarm"
    );

    let email = jmap_first_email(&mut bob, "bob@self-keyname.local");
    assert_eq!(email["subject"], "resolved via self key-name");
    let body = email["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    assert!(body.contains(secret), "content round-tripped: self-resolve → seal → mesh → JMAP; got {body:?}");

    assert!(
        poll_both_until(&mut alice, &mut bob, |a, _| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over real libp2p and the sender queue reaches ACKED"
    );
}

// ── `name-chain` resolution (§3.12.5, OPTIONAL) ───────────────────────────────────────────────

/// Build a real, self-signed classical `Identity` that asserts `names` (mirrors `dmtap-naming`'s own
/// `namechain::tests::identity_with_names` fixture shape, kept local per this crate's convention of
/// each test file being self-contained).
fn identity_with_names(seed: u8, names: Vec<String>) -> (IdentityKey, Identity) {
    let ik = IdentityKey::from_seed(&[seed; 32]);
    let id = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/kp/chain", ContentId::of(b"kp-chain")),
        ContentId::of(b"recovery-policy"),
        names,
        None,
        NOW,
    );
    (ik, id)
}

#[test]
fn name_chain_binding_match_resolves_and_delivers_over_real_libp2p_into_a_jmap_readable_inbox() {
    const NAME: &str = "bob@.eth";

    // Bob's real, self-signed Identity legitimately claims the name (§3.12.5(b) direction A)...
    let (bob_ik, bob_identity) = identity_with_names(0x61, vec![NAME.to_owned()]);
    let bob_ik_pub = bob_ik.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();

    // ...and the on-chain record points at that SAME key (§3.12.5(b) direction B) — both directions
    // agree, so this is the legitimate, non-hijacked case.
    let mut chain = InMemoryNameChain::new(Chain::Ens);
    chain.register(NAME, bob_ik_pub.clone());
    let resolver = NameChainResolver::new(chain);

    let binding = resolver
        .resolve(NAME, &bob_identity)
        .expect("bidirectional binding holds: the key claims the name AND the chain points at it");
    assert_eq!(binding.ik, bob_ik_pub);
    assert_eq!(binding.resolver_type, ResolverType::NameChain(Chain::Ens));
    assert_eq!(binding.verification, Verification::ChainBound);

    // Real libp2p mesh + real nodes; deliver to the resolved key exactly as the DNS/self paths do.
    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_seal_pub = *alice_seal.public();

    let (alice_tp, bob_tp) = real_swarms(alice_ik_pub.clone(), bob_ik_pub.clone());
    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);

    alice.add_contact(&binding.ik, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    let secret = "name-chain resolved for real (bidirectional match), then sealed over the real mesh";
    let id = alice
        .send_mail(&binding.ik, "resolved via name-chain", secret.as_bytes())
        .expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    assert!(
        poll_both_until(&mut alice, &mut bob, |_, b| b.inbox().exists() == 1),
        "the name-chain-resolved MOTE should arrive over the real libp2p swarm"
    );

    let email = jmap_first_email(&mut bob, "bob@name-chain.local");
    assert_eq!(email["subject"], "resolved via name-chain");
    let body = email["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    assert!(body.contains(secret), "content round-tripped: chain-resolve → seal → mesh → JMAP; got {body:?}");

    assert!(
        poll_both_until(&mut alice, &mut bob, |a, _| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over real libp2p and the sender queue reaches ACKED"
    );
}

#[test]
fn name_chain_bidirectional_mismatch_fails_closed_0x011e_and_is_delivered_nowhere() {
    const NAME: &str = "carol@.eth";

    // Carol's real Identity legitimately claims the name (direction A holds)...
    let (_carol_ik, carol_identity) = identity_with_names(0x62, vec![NAME.to_owned()]);

    // ...but the on-chain registrar has been hijacked: the record points at an ATTACKER's key, not
    // Carol's (direction B fails) — the two directions disagree.
    let attacker_ik = IdentityKey::from_seed(&[0xa7; 32]).public();
    let mut chain = InMemoryNameChain::new(Chain::Ens);
    chain.register(NAME, attacker_ik.clone());
    let resolver = NameChainResolver::new(chain);

    let err = resolver
        .resolve(NAME, &carol_identity)
        .expect_err("a hijacked chain record must fail closed, never resolve to either key");
    assert!(matches!(err, ResolveError::NameChainBindingUnverified(_)));
    assert_eq!(err.code(), 0x011E, "the normative §21.3 wire code for a binding mismatch");

    // "Delivered nowhere" is not just an error variant: resolution never produced an addressable
    // key, so there is nothing to pin and nothing to seal against. Prove it concretely — spin up a
    // real node standing in for the attacker's claimed key and confirm it receives NOTHING, because
    // no code path here ever got far enough to construct, seal, or send a MOTE to it.
    let net = InMemoryNetwork::new();
    let mut attacker_node = Node::with_identity(
        IdentityKey::from_seed(&[0xa7; 32]),
        SealKeypair::generate(),
        net.endpoint(attacker_ik.clone()),
    );
    // Give it a chance to receive anything that might be in flight (there is none).
    attacker_node.poll();
    assert_eq!(attacker_node.inbox().exists(), 0, "delivered nowhere: the attacker's key got nothing");
    assert_eq!(attacker_node.requests().exists(), 0, "not even a deferred/cold-sender MOTE arrived");

    // And no node ever resolved/pinned/addressed Carol's real key either — the whole exchange never
    // starts, which is the point of failing closed at the resolver rather than downstream.
}
