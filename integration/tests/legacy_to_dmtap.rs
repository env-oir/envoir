//! legacy → DMTAP end-to-end (spec §7.2 / §19.7.1 + §2.7 + §8).
//!
//! An RFC 5322 message is fed into the **real** `envoir-gateway` inbound, which seals it into an
//! encrypted MOTE and (via a `MeshDelivery` adapter) delivers it into a **real** `envoir-node`.
//! The node runs the §2.7 validation pipeline, decrypts, and files it to the inbox; a **real**
//! `dmtap-mail` JMAP view then sees the message with its plaintext intact. The gateway attestation
//! (§7.2a) is verified end-to-end against the domain-published key.
//!
//! Nothing between the components is mocked — the gateway's `build_mote`, the node's `validate`, and
//! the mail store's RFC 5322 projection are all the production code paths.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use serde_json::json;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_core::mote::Envelope;
use dmtap_mail::jmap::{self, Request};

use envoir_gateway::attestation::{Attestation, AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::inbound::{
    AllowAllAbuse, DeliveryOutcome, InboundGateway, KeyDirectory, MeshDelivery, MxSession,
    RecipientKey,
};

const NOW: u64 = 1_752_600_000_000;
const DOMAIN: &str = "example.org";
const SELECTOR: &str = "gw1";
const RCPT: &str = "alice@example.org";

/// A one-entry recipient directory (spec §3 resolve).
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

/// A `MeshDelivery` that injects the sealed MOTE straight into a real node and reports a durable ack
/// iff the node actually stored (or deduped) it — exactly the §19.7.1 rule mapping "the recipient
/// durably acked" onto the gateway's 250/451 decision. It also captures the (envelope, attestation)
/// pair so the test can verify the attestation independently.
struct NodeMesh {
    node: Rc<RefCell<Node<InMemoryTransport>>>,
    /// The gateway's identity — the transport return path / pinned-sender the node classifies on.
    gw_from: Vec<u8>,
    captured: Mutex<Vec<(Envelope, Attestation)>>,
}

impl MeshDelivery for NodeMesh {
    fn deliver(&self, env: &Envelope, attestation: &Attestation) -> DeliveryOutcome {
        self.captured.lock().unwrap().push((env.clone(), attestation.clone()));
        let outcome = self.node.borrow_mut().receive_mote(&self.gw_from, &env.det_cbor());
        match outcome {
            InboundOutcome::Stored { .. } | InboundOutcome::Duplicate { .. } => {
                DeliveryOutcome::Acked
            }
            _ => DeliveryOutcome::NoAck,
        }
    }
}

/// A `Box<dyn MeshDelivery>` forwarder so the gateway can own the trait object while the test keeps
/// an `Rc` handle to inspect captures.
struct MeshRef(Rc<NodeMesh>);
impl MeshDelivery for MeshRef {
    fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
        self.0.deliver(env, att)
    }
}

/// Build the recipient node + gateway, wired together. Returns everything the tests inspect.
struct Wired {
    node: Rc<RefCell<Node<InMemoryTransport>>>,
    gw: InboundGateway,
    mesh: Rc<NodeMesh>,
    published: StaticGwKeys,
}

fn wire() -> Wired {
    // The recipient node (a real envoir-node).
    let recip_ik = IdentityKey::generate();
    let recip_seal = SealKeypair::generate();
    let recip_ik_pub = recip_ik.public();
    let recip_seal_pub = recip_seal.public().to_vec();

    let net = InMemoryNetwork::new();
    let node = Rc::new(RefCell::new(Node::with_identity(
        recip_ik,
        recip_seal,
        net.endpoint(recip_ik_pub.clone()),
    )));

    // The gateway identity — the node must pin it so the legacy-origin MOTE is accepted (not
    // deferred as a cold sender), and so the §2.7 step-8 `Payload.from == pin` check passes.
    let gw_ik = IdentityKey::generate();
    let gw_ik_pub = gw_ik.public();
    node.borrow_mut().add_contact(&gw_ik_pub, [0u8; 32]);

    // Domain-anchored attestation key, published in the (in-memory) DNS zone.
    let att_key = AttestationKey::generate(DOMAIN, SELECTOR);
    let published = StaticGwKeys::new().publish(DOMAIN, SELECTOR, att_key.public());

    let directory = OneUser {
        email: RCPT.into(),
        key: RecipientKey { ik: recip_ik_pub, seal_pub: recip_seal_pub },
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

    Wired { node, gw, mesh, published }
}

fn sample_rfc5322() -> Vec<u8> {
    format!(
        "From: sender@gmail.com\r\nTo: {RCPT}\r\nSubject: hello from legacy\r\n\r\nGreetings across the bridge.\r\n"
    )
    .into_bytes()
}

/// Run a JMAP `Email/query` → `Email/get` chain against the node's live store and return the first
/// email object (RFC 8621) — the modern-client view of the delivered MOTE.
fn jmap_first_email(node: &mut Node<InMemoryTransport>) -> serde_json::Value {
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
    // method_responses[1] is the Email/get invocation `(name, args, callId)`.
    let get = &resp.method_responses[1].1;
    get["list"][0].clone()
}

#[test]
fn legacy_message_bridges_into_the_node_and_is_visible_over_jmap() {
    let w = wire();

    // Feed the RFC 5322 message into the gateway; a durable ack from the node yields 250.
    let reply = w.gw.accept_message("sender@gmail.com", RCPT, &sample_rfc5322(), NOW);
    assert_eq!(reply.code, 250, "node durably acked ⇒ gateway returns 250 (§19.7.1)");

    // The MOTE landed in the node's INBOX (real §2.7 accept path).
    assert_eq!(w.node.borrow().inbox().exists(), 1, "MOTE stored in the node's mail store");

    // The gateway attestation verifies end-to-end against the domain-published key (§7.2a).
    let captured = w.mesh.captured.lock().unwrap();
    let (env, att) = captured.first().expect("one delivery captured");
    let key = w.published.resolve_gw_key(DOMAIN, &att.selector);
    att.verify(DOMAIN, key.as_deref(), &env.id).expect("gateway attestation verifies");
    assert_eq!(att.smtp_mail_from, "sender@gmail.com");
    assert_eq!(att.smtp_rcpt_to, RCPT);
    drop(captured);

    // A dmtap-mail JMAP view sees the message with its plaintext intact.
    let mut node = w.node.borrow_mut();
    let email = jmap_first_email(&mut node);
    assert_eq!(email["subject"], "hello from legacy", "subject projected to JMAP");
    let body = email["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    assert!(
        body.contains("Greetings across the bridge"),
        "the legacy plaintext round-tripped through gateway → node → JMAP view; got {body:?}"
    );
}

#[test]
fn line_fed_mx_transaction_delivers_into_the_node() {
    // Drive the gateway's line-fed MX SMTP session (RFC 5321) rather than accept_message directly,
    // exercising the full transaction: EHLO → MAIL → RCPT → DATA → `.`.
    let w = wire();
    let mut s = MxSession::new(&w.gw, "203.0.113.9", NOW);
    assert_eq!(s.greeting().code, 220);
    assert_eq!(s.feed_line("EHLO gmail.com").code, 250);
    assert_eq!(s.feed_line("MAIL FROM:<sender@gmail.com>").code, 250);
    assert_eq!(s.feed_line(&format!("RCPT TO:<{RCPT}>")).code, 250);
    assert_eq!(s.feed_line("DATA").code, 354);
    assert_eq!(s.feed_line("From: sender@gmail.com").code, 0);
    assert_eq!(s.feed_line(&format!("To: {RCPT}")).code, 0);
    assert_eq!(s.feed_line("Subject: via smtp").code, 0);
    assert_eq!(s.feed_line("").code, 0);
    assert_eq!(s.feed_line("Delivered over the legacy bridge.").code, 0);
    let final_reply = s.feed_line(".");
    assert_eq!(final_reply.code, 250, "end of DATA returns 250 after the node durably acked");

    assert_eq!(w.node.borrow().inbox().exists(), 1, "the line-fed message reached the node inbox");
    let mut node = w.node.borrow_mut();
    let email = jmap_first_email(&mut node);
    assert_eq!(email["subject"], "via smtp");
}
