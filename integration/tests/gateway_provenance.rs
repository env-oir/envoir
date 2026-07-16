//! Gateway path provable (spec §7.2a, §7.8.1(b), §8.6): a bridged legacy message and a pure-mesh
//! message land in the **same** recipient inbox, and only the bridged one carries a verifiable
//! gateway attestation chain — proving `gateway`-touched vs. `mesh`-only is a provable property of
//! the delivered message, not a guess about how it arrived.
//!
//! `legacy_to_dmtap.rs` already proves one gateway-bridged message verifies end-to-end; what this
//! file adds is the **distinguishing** composition a real client's transport-path UI (§8.6) needs:
//! deliver a gateway-bridged message *and* a real mesh-only message into the same node, and show
//! that exactly the former produces a verifiable [`envoir_gateway::attestation::Attestation`] while
//! the latter produces none at all — plus that the attestation cannot be forged or lifted onto a
//! different message (a tampered signature, or the same attestation re-presented for a different
//! MOTE, both fail closed).
//!
//! `envoir-gateway` also ships a richer, not-yet-wired-into-`InboundGateway` wire form for this same
//! idea — [`envoir_gateway::provenance::GatewayAttestation`] / `ProvenanceRecord` (§18.3.11/§18.8.1),
//! which additionally supports multi-hop chains and per-operation metering. It is real, exported,
//! and unit-tested in its own crate, but nothing (`InboundGateway` included) currently produces one
//! from a live bridge, so composing it into a real delivery here would just be re-wiring product
//! code inside a test. `// TODO(once InboundGateway emits a provenance::GatewayAttestation): extend
//! this file to assert the ProvenanceRecord assembled from a live bridge is GatewayTouched with
//! exactly one hop, mirroring the mesh-only PureMesh case below.`

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_core::mote::Envelope;
use dmtap_mail::jmap::{self, Request};

use envoir_gateway::attestation::{Attestation, AttestationError, AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::inbound::{
    AllowAllAbuse, DeliveryOutcome, InboundGateway, KeyDirectory, MeshDelivery, RecipientKey,
};

use serde_json::json;

const NOW: u64 = 1_752_600_000_000;
const DOMAIN: &str = "example.org";
const SELECTOR: &str = "gw1";
const RCPT: &str = "alice@example.org";

struct OneUser {
    email: String,
    key: RecipientKey,
}
impl KeyDirectory for OneUser {
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
        if rcpt.eq_ignore_ascii_case(&self.email) {
            Some(self.key.clone())
        } else {
            None
        }
    }
}

/// A `MeshDelivery` that injects the sealed MOTE straight into the shared recipient node and
/// captures the (envelope, attestation) pair — the ONLY path that ever populates `captured`, so its
/// length is a direct count of how many delivered messages are gateway-touched.
struct NodeMesh {
    node: Rc<RefCell<Node<InMemoryTransport>>>,
    gw_from: Vec<u8>,
    captured: Mutex<Vec<(Envelope, Attestation)>>,
}

impl MeshDelivery for NodeMesh {
    fn deliver(&self, env: &Envelope, attestation: &Attestation) -> DeliveryOutcome {
        self.captured.lock().unwrap().push((env.clone(), attestation.clone()));
        let outcome = self.node.borrow_mut().receive_mote(&self.gw_from, &env.det_cbor());
        match outcome {
            InboundOutcome::Stored { .. } | InboundOutcome::Duplicate { .. } => DeliveryOutcome::Acked,
            _ => DeliveryOutcome::NoAck,
        }
    }
}

struct MeshRef(Rc<NodeMesh>);
impl MeshDelivery for MeshRef {
    fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
        self.0.deliver(env, att)
    }
}

fn jmap_first_email_with_subject(
    node: &mut Node<InMemoryTransport>,
    subject: &str,
) -> serde_json::Value {
    let req: Request = serde_json::from_value(json!({
        "using": [jmap::CAP_CORE, jmap::CAP_MAIL],
        "methodCalls": [
            ["Email/query", { "accountId": RCPT }, "0"],
            ["Email/get", {
                "accountId": RCPT,
                "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                "properties": ["subject", "from", "bodyValues"]
            }, "1"]
        ]
    }))
    .unwrap();
    let resp = jmap::process(node.store_mut(), RCPT, &req);
    let list = resp.method_responses[1].1["list"].as_array().cloned().unwrap_or_default();
    list.iter()
        .find(|e| e["subject"] == subject)
        .cloned()
        .unwrap_or_else(|| panic!("no email with subject {subject:?} in {list:?}"))
}

fn sample_rfc5322() -> Vec<u8> {
    format!(
        "From: sender@gmail.com\r\nTo: {RCPT}\r\nSubject: bridged from legacy\r\n\r\nCrossed the bridge.\r\n"
    )
    .into_bytes()
}

#[test]
fn gateway_bridged_and_pure_mesh_messages_are_distinguishable_and_tampering_is_rejected() {
    // The recipient node — a real envoir-node, shared between the gateway's delivery seam and the
    // test's direct mesh send.
    let net = InMemoryNetwork::new();
    let recip_ik = IdentityKey::generate();
    let recip_seal = SealKeypair::generate();
    let recip_ik_pub = recip_ik.public();
    let recip_seal_pub = *recip_seal.public();
    let node = Rc::new(RefCell::new(Node::with_identity(
        recip_ik,
        recip_seal,
        net.endpoint(recip_ik_pub.clone()),
    )));

    // The gateway's own identity, pinned so its legacy-origin MOTE is accepted (not cold-deferred).
    let gw_ik = IdentityKey::generate();
    let gw_ik_pub = gw_ik.public();
    node.borrow_mut().add_contact(&gw_ik_pub, [0u8; 32]);

    // A second, ordinary mesh sender — Alice — pinned as a normal contact. Her messages never touch
    // any gateway component at all.
    let mesh_sender_ik = IdentityKey::generate();
    let mesh_sender_seal = SealKeypair::generate();
    let mesh_sender_ik_pub = mesh_sender_ik.public();
    let mesh_sender_seal_pub = *mesh_sender_seal.public();
    node.borrow_mut().add_contact(&mesh_sender_ik_pub, mesh_sender_seal_pub);
    let mut mesh_sender = Node::with_identity(
        mesh_sender_ik,
        mesh_sender_seal,
        net.endpoint(mesh_sender_ik_pub.clone()),
    );
    // Alice must resolve Bob's real sealing key to address him — a stand-in for the naming lookup
    // `full_roundtrip.rs` exercises properly; here the point is the gateway/mesh distinction, not
    // resolution, so the key is simply known.
    mesh_sender.add_contact(&recip_ik_pub, recip_seal_pub);

    // Domain-anchored attestation key, published in the (in-memory) DNS zone.
    let att_key = AttestationKey::generate(DOMAIN, SELECTOR);
    let published = StaticGwKeys::new().publish(DOMAIN, SELECTOR, att_key.public());

    let directory = OneUser {
        email: RCPT.into(),
        key: RecipientKey { ik: recip_ik_pub.clone(), seal_pub: recip_seal_pub.to_vec() },
    };
    let mesh = Rc::new(NodeMesh {
        node: node.clone(),
        gw_from: gw_ik_pub,
        captured: Mutex::new(Vec::new()),
    });
    let gw = InboundGateway::new(
        gw_ik,
        vec![att_key],
        Box::new(directory),
        Box::new(MeshRef(mesh.clone())),
        Box::new(AllowAllAbuse),
    );

    // 1. A real, pure-mesh message: no gateway component is ever invoked for this send.
    let mesh_secret = b"never touched any gateway";
    mesh_sender
        .send_mail(&recip_ik_pub, "pure mesh mail", mesh_secret)
        .expect("mesh send");
    node.borrow_mut().poll();
    assert_eq!(node.borrow().inbox().exists(), 1, "the mesh-only message is stored");
    assert_eq!(mesh.captured.lock().unwrap().len(), 0, "no attestation for a pure-mesh message");

    // 2. A real gateway-bridged legacy message.
    let reply = gw.accept_message("sender@gmail.com", RCPT, &sample_rfc5322(), NOW);
    assert_eq!(reply.code, 250, "node durably acked ⇒ gateway returns 250 (§19.7.1)");
    assert_eq!(node.borrow().inbox().exists(), 2, "both messages now sit in the same inbox");

    // Exactly ONE message ever produced a verifiable attestation — the gateway-bridged one. This is
    // the provable distinguishing property: `captured.len()` counts gateway relays, not deliveries.
    let captured = mesh.captured.lock().unwrap().clone();
    assert_eq!(captured.len(), 1, "only the bridged message carries an attestation");
    let (env, att) = &captured[0];
    let key = published.resolve_gw_key(DOMAIN, &att.selector);
    att.verify(DOMAIN, key.as_deref(), &env.id).expect("the real attestation verifies");
    assert_eq!(att.smtp_mail_from, "sender@gmail.com");

    // 3. Both messages are visible over a real dmtap-mail JMAP view, independently addressable.
    let mut n = node.borrow_mut();
    let bridged = jmap_first_email_with_subject(&mut n, "bridged from legacy");
    let mesh_only = jmap_first_email_with_subject(&mut n, "pure mesh mail");
    assert!(bridged["bodyValues"]["1"]["value"]
        .as_str()
        .unwrap_or("")
        .contains("Crossed the bridge"));
    assert!(mesh_only["bodyValues"]["1"]["value"]
        .as_str()
        .unwrap_or("")
        .contains(std::str::from_utf8(mesh_secret).unwrap()));
    drop(n);

    // 4. Tampering: a bit-flipped signature fails closed.
    let mut bad_sig = att.clone();
    bad_sig.sig[0] ^= 0xff;
    assert!(matches!(
        bad_sig.verify(DOMAIN, key.as_deref(), &env.id),
        Err(AttestationError::BadSignature(_))
    ));

    // 5. Tampering: lifting the exact same (validly-signed) attestation onto a DIFFERENT delivered
    //    MOTE is rejected — an attestation cannot be replayed to vouch for content it never covered.
    let other_reply = gw.accept_message(
        "someone-else@gmail.com",
        RCPT,
        b"From: someone-else@gmail.com\r\nTo: alice@example.org\r\nSubject: another\r\n\r\nx\r\n",
        NOW + 1,
    );
    assert_eq!(other_reply.code, 250);
    let other_env = mesh.captured.lock().unwrap()[1].0.clone();
    assert_ne!(other_env.id, env.id, "a distinct MOTE, distinct content address");
    assert_eq!(
        att.verify(DOMAIN, key.as_deref(), &other_env.id),
        Err(AttestationError::MoteMismatch),
        "an attestation lifted onto a different message's content address must be rejected"
    );
}
