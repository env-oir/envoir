//! Integration tests for the crates wired into the node (spec §3, §5.2.1, §13, §4).
//!
//! These prove the four subsystems are *really* wired end-to-end — types flow from the shared
//! crates through the [`Node`] API, not `todo!()`:
//!
//! 1. **Resolution (§3):** a KT-verified `name@domain` resolve pins the recipient and an outbound
//!    MOTE round-trips to them; an unverifiable KT fails closed and pins nothing (no TOFU).
//! 2. **Deniable 1:1 (§5.2.1):** a deniable session opens and a MOTE round-trips through it
//!    (distinct from the MLS group path); a tampered message fails closed.
//! 3. **Auth (§13):** the node runs its own login ceremony, the RP establishes a key-bound session,
//!    and a DPoP-style request round-trips; a stolen assertion without the session key is useless.
//! 4. **Transport (§4):** the mesh transport is *selectable* — a `Node` drives delivery over both
//!    the [`SelectableTransport`] enum and a `Box<dyn Transport>` (the seam the out-of-tree
//!    `dmtap_p2p::Libp2pTransport` plugs into).

use dmtap::auth::{
    verify_login, AuthError, Challenge, Clock, DeviceCertAuthorizer, InMemoryReplayCache,
    SessionKey, SystemClock, TrustedClientStub,
};
use dmtap::dmtap_core::deniable::DeniablePayload;
use dmtap::identity::{DeviceCert, Identity, IdentityKey};
use dmtap::inbound::InboundOutcome;
use dmtap::mote::{Headers, Kind, SealKeypair};
use dmtap::names::{DmtapTxtRecord, InMemoryKeyPackages, InMemoryKtLog, InMemoryResolver};
use dmtap::naming::{seal_key_bundle, ResolveError};
use dmtap::node::Node;
use dmtap::outbound::OutState;
use dmtap::transport::{
    Frame, InMemoryNetwork, InMemoryTransport, SelectableTransport, Transport, TransportError,
};
use dmtap::{ContentId, SendError};

const NOW: u64 = 1_700_000_000_000;

// ============================================================================================
// 1. Resolution (§3): KT-verified resolve → pin → deliver, and fail-closed on unverifiable KT.
// ============================================================================================

/// A recipient whose DMTAP identity + DNS + KT are all consistent, publishable into an
/// [`InMemoryResolver`]. The node built from the same seed decrypts what the resolver's key seals.
struct Recipient {
    seed: [u8; 32],
    node_seal: SealKeypair,
    seal_pub: [u8; 32],
    identity: Identity,
    txt: String,
}

impl Recipient {
    fn new(name: &str, seed: u8) -> Self {
        let seed = [seed; 32];
        let id_key = IdentityKey::from_seed(&seed);
        let node_seal = SealKeypair::generate();
        let seal_pub = *node_seal.public();

        // The recipient advertises its SEALING key as its (content-addressed) KeyPackage bundle.
        let mut kps = InMemoryKeyPackages::new();
        let bref = kps.publish(format!("/mesh/kp/{name}"), seal_key_bundle(&seal_pub));

        let identity = Identity::create_classical(
            &id_key,
            0,
            vec![],
            bref.clone(),
            ContentId::of(b"recovery"),
            vec![name.to_owned()],
            None,
            NOW,
        );
        let txt = DmtapTxtRecord {
            version: "dmtap1".into(),
            suite: 1,
            ik: id_key.public(),
            id: identity.content_id(),
            kt: vec!["https://kt.example/log".into()],
            keypkgs: bref.loc.clone(),
        }
        .to_txt();
        Recipient { seed, node_seal, seal_pub, identity, txt }
    }

    fn ik_public(&self) -> Vec<u8> {
        IdentityKey::from_seed(&self.seed).public()
    }
}

/// A [`KeyPackageSource`] seeded with a recipient's sealing bundle so the node can fetch + verify it.
fn kps_for(name: &str, seal_pub: &[u8; 32]) -> InMemoryKeyPackages {
    let mut kps = InMemoryKeyPackages::new();
    kps.publish(format!("/mesh/kp/{name}"), seal_key_bundle(seal_pub));
    kps
}

#[test]
fn kt_verified_resolution_pins_and_delivers() {
    let net = InMemoryNetwork::new();

    // Bob: identity + DNS + KT, plus a live node built from the SAME identity seed so his transport
    // address equals the resolved `ik` and his seal secret opens what the resolved key seals.
    let bob = Recipient::new("bob@example.com", 3);
    let bob_ik = bob.ik_public();
    let bob_node_ik = IdentityKey::from_seed(&bob.seed);
    let mut bob_node = Node::with_identity(bob_node_ik, bob.node_seal, net.endpoint(bob_ik.clone()));

    // A resolver with Bob's identity published, DNS TXT set, and a single honest KT log pinned.
    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("bob._dmtap.example.com", &bob.txt);
    resolver.publish_identity(bob.identity.clone());
    let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
    log.append_identity("bob@example.com", &bob.identity).unwrap();
    resolver.pin_log(log);
    let kps = kps_for("bob@example.com", &bob.seal_pub);

    // Alice resolves Bob by NAME — KT-verified — and it pins the binding.
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));
    bob_node.add_contact(&alice_ik_pub, alice_seal_pub); // Bob knows Alice (so she is not cold)

    let resolved = alice.resolve_and_pin("bob@example.com", &resolver, &kps).expect("KT-verified");
    assert_eq!(resolved, bob_ik, "resolution returns the KT-verified identity key");

    // A one-call name-addressed send: resolve (fail-closed) + seal + dispatch, round-tripping.
    let body = b"resolved you by name, KT-verified";
    let id = alice
        .send_mail_to_name("bob@example.com", &resolver, &kps, "hi", body)
        .expect("name-addressed send");

    let outcomes = bob_node.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "delivered to the resolved key");
    assert_eq!(bob_node.inbox().exists(), 1);
    let raw = &bob_node.inbox().messages[0].raw;
    assert!(raw.windows(body.len()).any(|w| w == body), "correct plaintext delivered");

    alice.poll(); // consume Bob's ack
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked), "sender queue reaches ACKED");
}

#[test]
fn kt_unreachable_fails_closed_and_pins_nothing() {
    let net = InMemoryNetwork::new();
    let bob = Recipient::new("bob@example.com", 4);
    let bob_ik = bob.ik_public();

    // A resolver with a REACHABLE identity/DNS but only an UNREACHABLE KT log pinned — the §3.3
    // fail-closed condition: it MUST NOT TOFU-pin.
    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("bob._dmtap.example.com", &bob.txt);
    resolver.publish_identity(bob.identity.clone());
    resolver.pin_log(dmtap::names::UnreachableLog {
        log_id: IdentityKey::from_seed(&[7; 32]).public(),
    });
    let kps = kps_for("bob@example.com", &bob.seal_pub);

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice =
        Node::with_identity(alice_ik, SealKeypair::generate(), net.endpoint(alice_ik_pub));

    // Resolution fails closed with the KT-unreachable code, pinning nothing.
    let err = alice.resolve_and_pin("bob@example.com", &resolver, &kps).unwrap_err();
    assert_eq!(err, ResolveError::KtUnreachable, "unreachable KT ⇒ BLOCK, never TOFU (§3.3)");
    assert_eq!(err.code(), 0x0106, "the normative ERR_KT_UNREACHABLE code");

    // Nothing was pinned: a subsequent direct send to Bob's ik is still Unresolved.
    assert_eq!(
        alice.send_mail(&bob_ik, "x", b"y"),
        Err(SendError::Unresolved),
        "a failed KT resolve leaves the recipient unpinned"
    );
}

#[test]
fn tampered_dns_pointer_fails_closed() {
    let net = InMemoryNetwork::new();
    let bob = Recipient::new("bob@example.com", 5);

    // A TXT whose `ik=` is swapped for an attacker key: the DNS pointer and the signed Identity
    // disagree ⇒ resolution fails closed before anything is trusted.
    let evil_ik = IdentityKey::from_seed(&[0xee; 32]).public();
    let tampered = DmtapTxtRecord {
        version: "dmtap1".into(),
        suite: 1,
        ik: evil_ik,
        id: bob.identity.content_id(),
        kt: vec!["https://kt.example/log".into()],
        keypkgs: format!("/mesh/kp/{}", "bob@example.com"),
    }
    .to_txt();
    let mut resolver = InMemoryResolver::new(NOW);
    resolver.set_txt("bob._dmtap.example.com", &tampered);
    resolver.publish_identity(bob.identity.clone());
    let mut log = InMemoryKtLog::new(IdentityKey::from_seed(&[9; 32]));
    log.append_identity("bob@example.com", &bob.identity).unwrap();
    resolver.pin_log(log);
    let kps = kps_for("bob@example.com", &bob.seal_pub);

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice =
        Node::with_identity(alice_ik, SealKeypair::generate(), net.endpoint(alice_ik_pub));
    assert!(matches!(
        alice.resolve_and_pin("bob@example.com", &resolver, &kps),
        Err(ResolveError::DnsIdentityMismatch(_))
    ));
}

#[test]
fn non_dns_name_forms_dispatch_and_fail_closed_at_the_node() {
    // The node delegates form dispatch to `dmtap-naming`'s resolver-type registry (§3.12): a name is
    // routed by FORM and gated against the types this node implements *before* the DNS resolver is
    // consulted. The DNS resolver here has NOTHING published, so if a non-DNS form leaked into the
    // DNS path it would surface a DNS/KT error; instead each fails closed on the registry/dispatch,
    // pinning nothing — proving the crate's dispatch runs first.
    let net = InMemoryNetwork::new();
    let empty = InMemoryResolver::new(NOW);
    let kps = InMemoryKeyPackages::new();

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let mut alice =
        Node::with_identity(alice_ik, SealKeypair::generate(), net.endpoint(alice_ik_pub));

    // A self-authenticating key-name (§3.9.6) routes to the crate's real `SelfResolver`; with no such
    // key known to this node it is a fail-closed NameResolution miss (never a guess), not a DNS error.
    let key_name = dmtap::keyname::encode(&IdentityKey::from_seed(&[21u8; 32]).public());
    let err = alice.resolve_and_pin(&key_name, &empty, &kps).unwrap_err();
    assert!(
        matches!(err, ResolveError::NameResolution(m) if m.contains("key-name")),
        "an unknown key-name fails closed via SelfResolver, got {err:?}"
    );

    // A name-chain name is the OPTIONAL `name-chain` type — off by default (§3.12.5(a)), so the
    // registry rejects it as unsupported (`0x011F`), never guessing an on-chain binding.
    let err = alice.resolve_and_pin("vitalik.eth", &empty, &kps).unwrap_err();
    assert!(
        matches!(err, ResolveError::ResolverTypeUnsupported(_)),
        "an .eth name is unsupported until name-chain is enabled, got {err:?}"
    );
    assert_eq!(err.code(), 0x011F, "the normative ERR_RESOLVER_TYPE_UNSUPPORTED code");

    // A bare label that is neither a key-name nor a chain name classifies as a local petname; the
    // by-name send path carries no petname book, so it fails closed (pins nothing, not coerced to DNS).
    let err = alice.resolve_and_pin("not-a-known-name", &empty, &kps).unwrap_err();
    assert!(
        matches!(err, ResolveError::NameResolution(_)),
        "an unresolvable petname fails closed, got {err:?}"
    );
}

#[test]
fn key_name_really_resolves_end_to_end_at_the_node() {
    // A key-name (§3.9.6) is a one-way derivation of an identity key. Once the node has learned a
    // recipient's key, resolving that recipient's key-name really binds — via the crate's real
    // `SelfResolver` (checksum + full derivation) — and the resolved key is then addressable.
    let net = InMemoryNetwork::new();
    let empty = InMemoryResolver::new(NOW);
    let kps = InMemoryKeyPackages::new();

    let bob = Recipient::new("bob@example.com", 22);
    let bob_ik = bob.ik_public();
    let bob_node = Node::with_identity(
        IdentityKey::from_seed(&bob.seed),
        bob.node_seal,
        net.endpoint(bob_ik.clone()),
    );

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_seal_pub = *alice_seal.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));
    // Alice has learned Bob's sealing key out of band (e.g. an earlier exchange / mesh discovery).
    alice.learn_key(&bob_ik, bob.seal_pub);

    // Bob's key-name is the derivation of his identity key; resolving it returns exactly that key.
    let bobs_key_name = dmtap::naming::SelfResolver::derive(&bob_ik);
    let resolved = alice
        .resolve_and_pin(&bobs_key_name, &empty, &kps)
        .expect("a known key-name really resolves via SelfResolver");
    assert_eq!(resolved, bob_ik, "key-name resolves to the exact derived identity key");

    // And it is now a pinned, addressable contact — a real by-key-name send round-trips + acks.
    let mut bob_node = bob_node;
    bob_node.add_contact(&alice_ik_pub, alice_seal_pub); // Bob knows Alice (so she is not cold)
    let id = alice.send_mail(&bob_ik, "hi", b"reached you by key-name").expect("send to pinned key");
    assert!(matches!(bob_node.poll()[0], InboundOutcome::Stored { .. }), "delivered to the key-name'd key");
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));

    // A well-formed key-name for a key this node does NOT know fails closed — never a guess.
    let stranger = dmtap::naming::SelfResolver::derive(&IdentityKey::from_seed(&[99u8; 32]).public());
    assert!(
        matches!(alice.resolve_and_pin(&stranger, &empty, &kps), Err(ResolveError::NameResolution(_))),
        "an unknown key-name is a fail-closed miss"
    );
}

#[test]
fn name_chain_resolves_via_injected_client_and_enforces_binding() {
    // The OPTIONAL `name-chain` type (§3.12.5): a test injects an in-memory chain client, and the
    // node enforces the crate's §3.12.5(b) bidirectional key↔name binding against the owner's signed
    // Identity — accepting an agreeing binding and failing closed (`0x011E`) on a mismatch.
    let net = InMemoryNetwork::new();
    let chain_name = "vitalik@.eth";

    // Bob claims the chain name in his signed Identity, and the chain record points back at his key.
    let bob_key = IdentityKey::from_seed(&[42u8; 32]);
    let bob_ik = bob_key.public();
    let bob_seal = SealKeypair::generate();
    let bob_seal_pub = *bob_seal.public();
    let mut bob_kps = InMemoryKeyPackages::new();
    let bref = bob_kps.publish("/mesh/kp/vitalik", seal_key_bundle(&bob_seal_pub));
    let bob_identity = Identity::create_classical(
        &bob_key,
        0,
        vec![],
        bref,
        ContentId::of(b"recovery"),
        vec![chain_name.to_owned()],
        None,
        NOW,
    );

    let alice_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal = SealKeypair::generate();
    let alice_seal_pub = *alice_seal.public();
    let mut alice = Node::with_identity(alice_ik, alice_seal, net.endpoint(alice_ik_pub.clone()));

    // Off by default: even with the owner's Identity in hand, a chain name is unsupported (`0x011F`).
    let err = alice.resolve_name_chain(chain_name, &bob_identity, bob_seal_pub).unwrap_err();
    assert_eq!(err.code(), 0x011F, "name-chain is OPTIONAL and off until enabled");

    // Inject the chain client (the registrant's one on-chain claim), opting into name-chain.
    let mut chain = dmtap::naming::InMemoryNameChain::new(dmtap::naming::Chain::Ens);
    chain.register(chain_name, bob_ik.clone());
    alice.enable_name_chain(chain);

    // Both directions agree ⇒ the binding verifies and the classical IK is pinned + returned.
    let resolved = alice
        .resolve_name_chain(chain_name, &bob_identity, bob_seal_pub)
        .expect("agreeing bidirectional binding resolves");
    assert_eq!(resolved, bob_ik, "name-chain resolves to the classical identity key");

    // The pinned key is addressable — a real send to the name-chain'd key round-trips + acks.
    let mut bob_node = Node::with_identity(bob_key, bob_seal, net.endpoint(bob_ik.clone()));
    bob_node.add_contact(&alice_ik_pub, alice_seal_pub); // Bob knows Alice (so she is not cold)
    let id = alice.send_mail(&bob_ik, "hi", b"reached you by name-chain").expect("send to pinned key");
    assert!(matches!(bob_node.poll()[0], InboundOutcome::Stored { .. }));
    alice.poll();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Acked));

    // A captured registrar points the chain record at an ATTACKER key the identity never claims —
    // the two directions disagree ⇒ fail closed with ERR_NAMECHAIN_BINDING_UNVERIFIED (`0x011E`).
    let attacker_ik = IdentityKey::from_seed(&[0xee; 32]).public();
    let mut evil_chain = dmtap::naming::InMemoryNameChain::new(dmtap::naming::Chain::Ens);
    evil_chain.register(chain_name, attacker_ik);
    let mut mallory = Node::with_identity(
        IdentityKey::generate(),
        SealKeypair::generate(),
        net.endpoint(b"mallory".to_vec()),
    );
    mallory.enable_name_chain(evil_chain);
    let err = mallory.resolve_name_chain(chain_name, &bob_identity, bob_seal_pub).unwrap_err();
    assert!(matches!(err, ResolveError::NameChainBindingUnverified(_)));
    assert_eq!(err.code(), 0x011E, "a chain/identity binding mismatch fails closed");
}

#[test]
fn key_derived_gateway_alias_is_stable_and_stateless_decodable() {
    // Two independently-built nodes for the SAME identity yield the SAME gateway alias — the alias
    // is a pure function of the key with no per-node/per-gateway state.
    let net = InMemoryNetwork::new();
    let seed = [33u8; 32];
    let node_a = Node::with_identity(
        IdentityKey::from_seed(&seed),
        SealKeypair::generate(),
        net.endpoint(IdentityKey::from_seed(&seed).public()),
    );
    let node_b = Node::with_identity(
        IdentityKey::from_seed(&seed),
        SealKeypair::generate(),
        net.endpoint(b"a-different-transport-address".to_vec()),
    );
    assert_eq!(
        node_a.gateway_alias(),
        node_b.gateway_alias(),
        "the alias is identical at every gateway (key-derived, stateless)"
    );

    // Any gateway decodes the alias straight back to the node's identity key — no registration.
    let alias = node_a.gateway_alias();
    let recovered = dmtap::naming::ik_from_gateway_alias(&alias).expect("decodes back to a key");
    assert_eq!(recovered, node_a.ik_public(), "the alias round-trips to the exact key");
    assert!(alias.len() <= 64, "fits an RFC 5321 local-part");
}

// ============================================================================================
// 2. Deniable 1:1 (§5.2.1): a MOTE round-trips through a deniable session; tamper fails closed.
// ============================================================================================

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

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    (Node::with_identity(ik, seal, net.endpoint(ik_pub.clone())), ik_pub, seal_pub)
}

#[test]
fn deniable_1to1_mote_round_trips_both_directions() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    // Bob publishes a deniable prekey bundle (with a root-IK cert over his deniable identity key);
    // Alice — holding Bob's KT-resolved root IK — opens a deniable session and routes the first
    // MOTE embedded in the X3DH init.
    let bundle = bob.deniable_publish_bundle();
    assert_eq!(bundle.cert.ik, bob_ik, "bundle cert is issued under Bob's root IK");
    assert_eq!(bundle.cert.device_key, bundle.bundle.ik, "cert binds the deniable identity key");
    assert_ne!(bundle.bundle.ik, bob_ik, "deniable IK is a dedicated key, NOT Bob's root IK (§5.2.1)");

    let first = deniable_payload(&alice_ik, "deniable hello", b"you cannot prove I wrote this");
    let init = alice.deniable_open(&bob_ik, &bundle, &first).expect("X3DH initiate");
    assert_eq!(init.cert.ik, alice_ik, "init cert is issued under Alice's root IK");
    assert_eq!(init.cert.device_key, init.init.ik_a, "cert binds Alice's deniable identity key");

    // Bob accepts against Alice's KT-resolved root IK: verifies the cert, establishes the session,
    // and recovers the first MOTE exactly.
    let got = bob.deniable_accept(&alice_ik, &init).expect("X3DH accept");
    assert_eq!(got, first, "the first deniable MOTE round-trips through X3DH");

    // The peers' session keys: Bob keys by Alice's deniable IK (init.ik_a); Alice by Bob's (bundle.ik).
    let alice_deniable_ik = init.init.ik_a.clone();
    let bob_deniable_ik = bundle.bundle.ik.clone();
    assert_eq!(
        alice.deniable_identity_public().as_deref(),
        Some(alice_deniable_ik.as_slice()),
        "Alice provisioned a dedicated deniable identity, distinct from her root IK"
    );
    assert_ne!(alice_deniable_ik, alice_ik, "deniable IK is NOT the node's root IK (§5.2.1)");

    // Bob replies over the ratchet; Alice opens it — the reverse-direction MOTE round-trips.
    let reply = deniable_payload(&bob_deniable_ik, "deniable reply", b"nor can you prove I did");
    let msg = bob.deniable_send(&alice_deniable_ik, &reply).expect("ratchet encrypt");
    let got_reply = alice.deniable_recv(&bob_deniable_ik, &msg).expect("ratchet decrypt");
    assert_eq!(got_reply, reply, "the reply MOTE round-trips back over the ratchet");
}

#[test]
fn deniable_tampered_message_fails_closed() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    let init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();
    bob.deniable_accept(&alice_ik, &init).unwrap();

    // Bob sends; the ciphertext is flipped in transit; Alice's open MUST fail (shared-key MAC).
    let reply = deniable_payload(&bundle.bundle.ik, "re", b"authentic content");
    let mut msg = bob.deniable_send(&init.init.ik_a, &reply).unwrap();
    msg.ct[0] ^= 0xff;
    let err = alice.deniable_recv(&bundle.bundle.ik, &msg);
    assert!(err.is_err(), "a tampered deniable message fails closed (AEAD tag / shared-key MAC)");
}

#[test]
fn deniable_accept_without_bundle_is_rejected() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    // Bob is a responder; Alice is NOT (never published a bundle) — so Alice cannot accept an init.
    let bundle = bob.deniable_publish_bundle();
    let init = alice
        .deniable_open(&bob_ik, &bundle, &deniable_payload(&alice_ik, "x", b"y"))
        .unwrap();
    // Bob (the real responder) accepts fine; a fresh non-responder node cannot.
    assert!(bob.deniable_accept(&alice_ik, &init).is_ok());
    let (mut carol, _c_ik, _) = make_node(&net);
    assert!(matches!(
        carol.deniable_accept(&alice_ik, &init),
        Err(dmtap::DeniableRouteError::NotResponder)
    ));
}

// --- The IK-certification of the deniable identity key (§5.2.1(a), §1.2) ---------------------
//
// The deniable `idk` is bound to the root identity by a `DeviceCert` chain
// (`root IK ▶ deniable Ed25519 IK ▶ idk`). A responder VERIFIES that chain against the peer's
// KT-resolved root IK and fails closed on any break: a wrong/attacker root IK, a cert that
// vouches for a different deniable key, or a tampered cert. Certifying the KEY does not make any
// MESSAGE non-repudiable — repudiation is preserved.

#[test]
fn deniable_accept_rejects_uncertified_identity_wrong_root_ik() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);
    let (_mallory, mallory_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    let init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();

    // Bob accepts the init but checks it against the WRONG root identity (Mallory's, not Alice's).
    // The DeviceCert (`init.cert`) is Alice's, so it does not chain to Mallory's root IK ⇒ reject,
    // and no one-time prekey is consumed.
    assert!(matches!(
        bob.deniable_accept(&mallory_ik, &init),
        Err(dmtap::DeniableRouteError::UncertifiedIdentity)
    ));
    // The genuine KT-resolved root IK still verifies (proving the reject was the binding, not the
    // crypto), and the still-unspent prekey means the session establishes cleanly.
    assert!(bob.deniable_accept(&alice_ik, &init).is_ok());
}

#[test]
fn deniable_accept_rejects_attacker_forged_cert() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    let mut init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();

    // An attacker cannot sign a binding under Alice's real root IK (that is the whole security
    // property), so the best she can do is present a cert she CAN sign — under a root IK she
    // controls. It is internally valid but does not chain to Alice's KT-resolved root IK ⇒ reject.
    let attacker_root = IdentityKey::from_seed(&[0x99; 32]);
    init.cert = DeviceCert::issue(
        &attacker_root,
        init.init.ik_a.clone(),
        "deniable-1to1",
        NOW,
        None,
        vec![],
    );
    assert!(matches!(
        bob.deniable_accept(&alice_ik, &init),
        Err(dmtap::DeniableRouteError::UncertifiedIdentity)
    ));
}

#[test]
fn deniable_accept_rejects_tampered_cert() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    let mut init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();

    // Flip a byte of the cert signature — its own verification fails, so the binding is rejected.
    init.cert.sig[0] ^= 0xff;
    assert!(matches!(
        bob.deniable_accept(&alice_ik, &init),
        Err(dmtap::DeniableRouteError::UncertifiedIdentity)
    ));
}

#[test]
fn deniable_open_rejects_uncertified_responder_bundle() {
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    let mut bundle = bob.deniable_publish_bundle();
    // Tamper Bob's bundle cert: now it no longer chains bundle.ik to Bob's root IK. Alice's open
    // MUST fail closed BEFORE running X3DH (she never talks to an uncertified deniable identity).
    bundle.cert.sig[0] ^= 0xff;
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    assert!(matches!(
        alice.deniable_open(&bob_ik, &bundle, &first),
        Err(dmtap::DeniableRouteError::UncertifiedIdentity)
    ));
}

#[test]
fn deniable_certification_preserves_repudiation() {
    // The IK-cert binds the deniable KEY to the identity; it must NOT turn the message stream into
    // non-repudiable content. We prove repudiation survives: from her own receiving-chain state
    // Alice forges a message that opens as if Bob authored it — no Bob secret, no signature — so a
    // genuine Bob message and Alice's forgery are indistinguishable (§5.2.1(e)).
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, _) = make_node(&net);
    let (mut bob, bob_ik, _) = make_node(&net);

    let bundle = bob.deniable_publish_bundle();
    let first = deniable_payload(&alice_ik, "hi", b"opening message");
    let init = alice.deniable_open(&bob_ik, &bundle, &first).unwrap();
    bob.deniable_accept(&alice_ik, &init).unwrap();

    let bob_deniable_ik = bundle.bundle.ik.clone();

    // Bob sends a genuine reply; Alice opens it (this advances her receiving chain).
    let genuine = deniable_payload(&bob_deniable_ik, "re", b"a thing Bob really said");
    let msg = bob.deniable_send(&init.init.ik_a, &genuine).unwrap();
    let opened = alice.deniable_recv(&bob_deniable_ik, &msg).unwrap();
    assert_eq!(opened, genuine);

    // Alice, using ONLY her own session state, forges a message attributed to Bob — no signing key
    // is involved. That a valid "from-Bob" message can be fabricated by the recipient is exactly
    // what repudiation means; the cert (over the key) did not add non-repudiation to content.
    let forged_content = deniable_payload(&bob_deniable_ik, "re", b"words Bob never actually wrote");
    let alice_session = alice.deniable_session_snapshot(&bob_deniable_ik).expect("live session");
    let forgery = alice_session
        .forge_peer_message(&forged_content)
        .expect("recipient can forge a peer message");
    let forged_open = alice_session.snapshot().decrypt(&forgery).expect("forgery opens as authentic");
    assert_eq!(forged_open, forged_content, "a recipient-forged 'from-Bob' message is indistinguishable");
}

// ============================================================================================
// 3. Auth (§13): the node logs itself in; a key-bound session authorizes a request; a stolen
//    assertion without the session key is useless.
// ============================================================================================

#[test]
fn node_login_establishes_a_key_bound_session_and_authorizes_a_request() {
    let net = InMemoryNetwork::new();
    let (alice, alice_ik, _) = make_node(&net);
    let clock = SystemClock;
    let origin = "https://rp.example";
    let aud = "rp.example";

    // RP issues an origin-bound challenge; the node's trusted client observes the same origin.
    let challenge = Challenge::new(origin, aud, clock.now_ms(), None);
    let client = TrustedClientStub::new(origin);

    // The node runs its OWN login ceremony: its root IK is the login signer (§13.3).
    let login = alice.login(&client, &challenge).expect("node login");
    assert_eq!(login.assertion.from, alice_ik, "the node's root IK is the login signer");

    // RP verifies and binds the session ONLY to cnf (IK-direct is authorized, §1.2).
    let authorizer = DeviceCertAuthorizer::new();
    let mut replay = InMemoryReplayCache::new();
    let session = verify_login(
        &alice_ik,
        origin,
        aud,
        &challenge,
        &login.assertion,
        &authorizer,
        &mut replay,
        &clock,
    )
    .expect("RP verifies the node's login");
    assert_eq!(session.subject_ik, alice_ik, "session subject is the node identity");

    // A DPoP-style request signed by the retained session key is authorized.
    let htu = "https://rp.example/api/mail";
    let htm = "GET";
    let proof = login.session.prove(htu, htm, &clock);
    let mut req_replay = InMemoryReplayCache::new();
    session
        .verify_request(&proof, htu, htm, &mut req_replay, &clock)
        .expect("key-bound request authorized");

    // A stolen assertion (hence cnf) WITHOUT the session key is useless: an attacker-chosen key
    // fails the proof-of-possession binding (§13.4).
    let stolen = SessionKey::generate();
    let forged = stolen.prove(htu, htm, &clock);
    assert!(matches!(
        session.verify_request(&forged, htu, htm, &mut req_replay, &clock),
        Err(AuthError::SessionKeyMismatch)
    ));
}

#[test]
fn node_login_refuses_on_origin_mismatch() {
    let net = InMemoryNetwork::new();
    let (alice, _ik, _) = make_node(&net);
    let clock = SystemClock;
    // The challenge is for the real RP, but the trusted client observes a look-alike origin: the
    // client refuses to sign before any assertion is produced (§13.3.1 phishing defense).
    let challenge = Challenge::new("https://rp.example", "rp.example", clock.now_ms(), None);
    let phishing_client = TrustedClientStub::new("https://rp.example.evil.com");
    assert!(matches!(alice.login(&phishing_client, &challenge), Err(AuthError::OriginMismatch)));
}

// ============================================================================================
// 4. Transport (§4): the mesh transport is selectable — the same engine drives delivery over the
//    SelectableTransport enum and over a Box<dyn Transport> (the seam dmtap-p2p plugs into).
// ============================================================================================

#[test]
fn transport_is_selectable_enum_and_boxed() {
    let net = InMemoryNetwork::new();

    // Alice runs over the SelectableTransport ENUM; Bob runs over a Box<dyn Transport> — exactly the
    // shape the out-of-tree `dmtap_p2p::Libp2pTransport` uses to plug into a `Node`.
    let alice_ik = IdentityKey::generate();
    let bob_ik = IdentityKey::generate();
    let alice_ik_pub = alice_ik.public();
    let bob_ik_pub = bob_ik.public();

    let alice_t = SelectableTransport::InMemory(net.endpoint(alice_ik_pub.clone()));
    let bob_boxed: Box<dyn Transport> = Box::new(net.endpoint(bob_ik_pub.clone()));

    let mut alice = Node::with_identity(alice_ik, SealKeypair::generate(), alice_t);
    let mut bob = Node::with_identity(bob_ik, SealKeypair::generate(), bob_boxed);

    let (alice_seal, bob_seal) = (alice.seal_public(), bob.seal_public());
    alice.add_contact(&bob_ik_pub, bob_seal);
    bob.add_contact(&alice_ik_pub, alice_seal);

    // A real end-to-end MOTE flows over the selected transports and the ack returns.
    let body = b"delivered over a runtime-selected transport";
    let id = alice.send_mail(&bob_ik_pub, "select", body).expect("send over selectable transport");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight));

    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "delivered over the boxed transport");
    assert_eq!(bob.inbox().exists(), 1);

    alice.poll();
    assert_eq!(
        alice.outbound_state(&id),
        Some(OutState::Acked),
        "the enum + boxed transport carry the full seal→validate→ack path"
    );
}

#[test]
fn boxed_transport_reports_local_addr_and_unreachable() {
    let net = InMemoryNetwork::new();
    let boxed: Box<dyn Transport> = Box::new(net.endpoint(b"alice".to_vec()));
    assert_eq!(boxed.local_addr(), b"alice".to_vec(), "boxed transport forwards local_addr");
    // Unknown peer is unreachable — the trait-object forwards send() faithfully.
    assert_eq!(boxed.send(b"ghost", Frame::Ack(vec![1])), Err(TransportError::Unreachable));
}
