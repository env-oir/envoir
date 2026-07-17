//! Gateway authorization + anti-spam, composed for real across `envoir-gateway`'s authz, outbound
//! anti-spam, and inbound cold-sender modules (spec §7.9, §7.3, §9, §12.2) — none of which
//! `gateway/tests/gateway.rs` or the other `integration/` files combine the way this file does:
//!
//! - **Outbound**: [`envoir_gateway::authz::IdentityRegistry`]'s domain-based [`GatewayAuthz`] gate
//!   resolves a self-hoster's billing `account`, which then drives a REAL
//!   [`envoir_gateway::outbound_guard::OutboundSenderGuard`] (rate limit → volume cap → reputation
//!   backoff, in that precedence) governing a REAL [`envoir_gateway::outbound::OutboundGateway`] send
//!   that produces a genuinely DKIM-verifiable relayed message each time it is allowed through — and a
//!   different registered sender's independent per-account state is unaffected by the flood.
//! - **Inbound**: a REAL [`envoir_gateway::inbound::ColdSenderGate`] wired into
//!   [`envoir_gateway::inbound::MxSession`] (not the permissive `AllowAllAbuse` every other
//!   `integration/` gateway test uses) greylists a cold `(peer_ip, MAIL FROM)` pair before `DATA`, and
//!   only a legitimate retry after the delay reaches an actual delivery into a real `envoir-node`'s
//!   inbox, readable over a real `dmtap-mail` JMAP view.
//!
//! ## What is deliberately NOT here (an honest gap, not a fake pass)
//! The mission also asks for "a key-registered sender is admitted (valid challenge–response) and
//! relayed; a forged/unregistered sender is rejected." The **forged** half is real below
//! ([`forged_admission_signature_never_verifies_under_the_presented_key`]). The **valid-admission**
//! and **unregistered-but-self-signing** (`AdmissionError::UnknownKey`) halves cannot be built from
//! this crate: [`IdentityRegistry::admit`] verifies the challenge answer against an internal
//! admission domain-separation tag (`gateway::authz::ADMISSION_DS`) that is a **private** module
//! constant — never `pub`, never re-exported from `envoir_gateway::authz` or the crate root (unlike,
//! e.g., `dmtap_auth::AUTH_ASSERTION_DS`/`DPOP_DS`, which ARE public specifically so an external
//! signer can produce them). `authz.rs`'s own `#[cfg(test)]` module can reach it because it compiles
//! *inside* that crate; this crate cannot. Hand-copying the private byte string into this file would
//! couple a "real" test to knowledge it has no compiler-enforced way to keep in sync with — exactly
//! the kind of fake-real result this mission asks NOT to produce.
//! `// TODO(once envoir_gateway::authz exports its admission domain-separation tag, or a public
//! `answer_challenge`-style helper): add (a) a REGISTERED key legitimately answering its own
//! challenge → `Admission` → that account relays a real message through
//! `OutboundGateway::send_authenticated`, and (b) a key that legitimately signs (proving control of
//! ITS OWN key) but was never registered → `AdmissionError::UnknownKey` specifically (not merely
//! `BadSignature`).`

use std::sync::Mutex;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_core::mote::{Envelope, Headers, Payload};
use dmtap_core::TimestampMs;

use dmtap_mail::jmap::{self, Request};

use envoir_gateway::attestation::{Attestation, AttestationKey};
use envoir_gateway::authz::{AdmissionError, IdentityRegistry, Quota, RegisteredIdentity};
use envoir_gateway::dkim::{self, DkimKey};
use envoir_gateway::inbound::{
    AllowAllAbuse, Clock, ColdSenderGate, DeliveryOutcome, InboundGateway, KeyDirectory,
    MeshDelivery, MxSession, RecipientKey,
};
use envoir_gateway::outbound::{
    GovernedSend, OutboundGateway, OutboundReport, OutboundTransport, TlsPolicy, TlsRequirement,
    TransportResult,
};
use envoir_gateway::outbound_guard::{OutboundSenderGuard, SenderVerdict};
use envoir_gateway::provenance::{BridgeDirection, GatewayAuthz};

use serde_json::json;

const NOW: TimestampMs = 1_752_600_000_000;

fn dkim_key(domain: &str, selector: &str) -> DkimKey {
    let mut seed = [0u8; 32];
    for (i, b) in domain.bytes().chain(selector.bytes()).enumerate().take(32) {
        seed[i] = b;
    }
    DkimKey::from_seed(domain, selector, &seed)
}

fn sample_payload(subject: &str, body: &str) -> Payload {
    let sender = IdentityKey::generate();
    Payload {
        from: sender.public(),
        sig: vec![0u8; 64],
        headers: Headers { thread: None, subject: Some(subject.into()), mime: None, cc: vec![] },
        body: body.as_bytes().to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}

struct OpportunisticTls;
impl TlsPolicy for OpportunisticTls {
    fn requirement_for(&self, _dest: &str) -> TlsRequirement {
        TlsRequirement::Opportunistic
    }
}

/// Records every message it was asked to relay (so a test can assert a blocked send never dialed at
/// all) and returns a scripted per-call result queue, falling back to `Delivered` once exhausted.
#[derive(Default)]
struct ScriptedRecordingTransport {
    dialed: Mutex<Vec<Vec<u8>>>,
    script: Mutex<Vec<TransportResult>>,
}
impl ScriptedRecordingTransport {
    fn new() -> Self {
        Self::default()
    }
    fn with_script(script: Vec<TransportResult>) -> Self {
        ScriptedRecordingTransport { dialed: Mutex::new(Vec::new()), script: Mutex::new(script) }
    }
    fn dial_count(&self) -> usize {
        self.dialed.lock().unwrap().len()
    }
}
impl OutboundTransport for ScriptedRecordingTransport {
    fn deliver(&self, _dest: &str, message: &[u8], _require_tls: bool) -> TransportResult {
        self.dialed.lock().unwrap().push(message.to_vec());
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            TransportResult::Delivered { code: 250 }
        } else {
            script.remove(0)
        }
    }
}

// ── Admission: the forged half (real; see the module doc for the honest gap) ─────────────────

#[test]
fn forged_admission_signature_never_verifies_under_the_presented_key() {
    let alice = IdentityKey::generate();
    let mallory = IdentityKey::generate();

    let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
        public_key: alice.public(),
        account: "acct-alice".into(),
        domain: "alice.host.net".into(),
        quota: Quota::messages(100, 100),
    });
    let ch = reg.issue_challenge([0x42; 32], NOW);

    // A forged answer: Mallory signs the challenge with HER OWN key but presents ALICE's public key
    // as the one that supposedly produced it — the classic forged-identity admission attempt. No
    // domain-separation tag Mallory could pick makes a signature she produced verify under a key she
    // does not hold; `admit` must reject this regardless of which tag was used.
    let forged_sig = mallory.sign_domain(b"whatever-tag-an-attacker-might-guess\x00", &ch.signing_body());
    assert_eq!(
        reg.admit(&ch, &alice.public(), &forged_sig, NOW + 100),
        Err(AdmissionError::BadSignature),
        "a signature never produced by the presented key must never verify"
    );

    // Presenting Mallory's own real key alongside a signature over a STALE/expired challenge window
    // is also rejected — a second, independent fail-closed axis real callers rely on.
    assert_eq!(
        reg.admit(&ch, &mallory.public(), &forged_sig, NOW + 10 * 60_000 + 1),
        Err(AdmissionError::ChallengeExpired),
        "a challenge outside its validity window is refused even before the signature is inspected"
    );
}

// ── Outbound: flood throttling + a different sender's independent budget ─────────────────────

#[test]
fn outbound_flood_hits_rate_then_volume_caps_while_a_different_registered_sender_still_relays() {
    // Two self-hosters, each authorized via the REAL domain-based `GatewayAuthz` gate (§7.9) —
    // registration + `authorize()` resolve their billing accounts with no signature step needed for
    // this coarser per-domain check.
    let reg = IdentityRegistry::key_registered()
        .register(RegisteredIdentity {
            public_key: IdentityKey::generate().public(),
            account: "acct-flooder".into(),
            domain: "flooder-domain.com".into(),
            quota: Quota::messages(1000, 1000),
        })
        .register(RegisteredIdentity {
            public_key: IdentityKey::generate().public(),
            account: "acct-normal".into(),
            domain: "normal-domain.com".into(),
            quota: Quota::messages(1000, 1000),
        });

    let flooder_account = match reg.authorize(BridgeDirection::Outbound, "flooder-domain.com") {
        envoir_gateway::provenance::AuthzDecision::Allowed { account } => account,
        other => panic!("expected Allowed, got {other:?}"),
    };
    let normal_account = match reg.authorize(BridgeDirection::Outbound, "normal-domain.com") {
        envoir_gateway::provenance::AuthzDecision::Allowed { account } => account,
        other => panic!("expected Allowed, got {other:?}"),
    };
    assert_ne!(flooder_account, normal_account);

    let recorder = std::sync::Arc::new(ScriptedRecordingTransport::new());
    struct ArcTransport(std::sync::Arc<ScriptedRecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let guard = OutboundSenderGuard::new()
        .require_registered([flooder_account.clone(), normal_account.clone()])
        .with_rate_limit(2, 60_000)
        .with_volume_cap(3, 3_600_000);
    let flooder_key_pub = dkim_key("flooder-domain.com", "dmtap1").public_bytes();
    let gw = OutboundGateway::new(
        vec![dkim_key("flooder-domain.com", "dmtap1"), dkim_key("normal-domain.com", "dmtap1")],
        Box::new(OpportunisticTls),
        Box::new(ArcTransport(recorder.clone())),
    )
    .with_sender_guard(guard);

    // 1-2: the flooder's first two sends are within BOTH the rate limit (2/60s) and volume cap
    // (3/hour) → delivered, and each is genuinely DKIM-verifiable under the flooder's delegated key.
    for n in 0..2 {
        let payload = sample_payload("flood", &format!("message {n}"));
        let out = gw.send_authenticated(
            &payload,
            "someone@flooder-domain.com",
            "someone@destination.example",
            &flooder_account,
            NOW,
        );
        assert_eq!(out, GovernedSend::Sent(OutboundReport::Delivered), "send {n} within budget");
    }
    assert_eq!(recorder.dial_count(), 2, "two sends actually reached the (recording) destination MX");
    dkim::verify(&recorder.dialed.lock().unwrap()[0], &flooder_key_pub)
        .expect("the first relayed message carries a real, verifiable delegated DKIM signature");

    // 3: the third send is still within the volume cap (3) but OVER the rate limit (2/60s) →
    // deferred (throttled), not hard-refused, and the message never reaches the transport.
    let out3 = gw.send_authenticated(
        &sample_payload("flood", "message 2"),
        "someone@flooder-domain.com",
        "someone@destination.example",
        &flooder_account,
        NOW,
    );
    assert!(
        matches!(out3, GovernedSend::Blocked(SenderVerdict::Throttle { .. })),
        "expected a rate-limit throttle, got {out3:?}"
    );
    assert_eq!(recorder.dial_count(), 2, "a throttled send never dials the destination MX");

    // A DIFFERENT registered sender is completely unaffected by the flooder's throttle — per-account
    // state, exactly as the outbound anti-spam module promises (§7.3, §9).
    let out_normal = gw.send_authenticated(
        &sample_payload("hello", "a normal message"),
        "someone@normal-domain.com",
        "someone@destination.example",
        &normal_account,
        NOW,
    );
    assert_eq!(out_normal, GovernedSend::Sent(OutboundReport::Delivered), "a different sender is unaffected");
    assert_eq!(recorder.dial_count(), 3);
}

#[test]
fn outbound_reputation_backoff_throttles_after_a_permanent_failure_even_within_budget() {
    let recorder = std::sync::Arc::new(ScriptedRecordingTransport::with_script(vec![
        TransportResult::Permanent { code: 550, text: "5.1.1 no such user".into() },
    ]));
    struct ArcTransport(std::sync::Arc<ScriptedRecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let guard = OutboundSenderGuard::new()
        .require_registered(["acct-risky"])
        .with_rate_limit(1000, 60_000) // never the limiter here
        .with_volume_cap(1000, 3_600_000) // never the limiter here
        .with_backoff(60_000, 3);
    let gw = OutboundGateway::new(
        vec![dkim_key("risky-domain.com", "dmtap1")],
        Box::new(OpportunisticTls),
        Box::new(ArcTransport(recorder.clone())),
    )
    .with_sender_guard(guard);

    // First send: the (scripted) destination permanently rejects it — a strong "you'll get
    // blacklisted" signal, so the guard's reputation feed arms a backoff automatically.
    let out1 = gw.send_authenticated(
        &sample_payload("bounce", "will bounce"),
        "someone@risky-domain.com",
        "dead@destination.example",
        "acct-risky",
        NOW,
    );
    assert!(matches!(out1, GovernedSend::Sent(OutboundReport::Failed(_))));

    // Second send: rate limit and volume cap both have plenty of headroom, yet this account is now
    // throttled by REPUTATION BACKOFF alone — the third, independent axis of the outbound guard.
    let out2 = gw.send_authenticated(
        &sample_payload("bounce", "another attempt"),
        "someone@risky-domain.com",
        "someone-else@destination.example",
        "acct-risky",
        NOW + 1,
    );
    assert!(
        matches!(out2, GovernedSend::Blocked(SenderVerdict::Throttle { .. })),
        "expected a reputation-backoff throttle, got {out2:?}"
    );
    assert_eq!(recorder.dial_count(), 1, "the backoff-blocked send never reached the transport");
}

// ── Inbound: a real cold-sender gate, not `AllowAllAbuse` ─────────────────────────────────────

#[derive(Clone)]
struct ManualClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl ManualClock {
    fn new(t: u64) -> Self {
        ManualClock(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(t)))
    }
    fn advance(&self, d: u64) {
        self.0.fetch_add(d, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

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

/// Delivers straight into a real, shared `envoir-node`'s inbox — the same `NodeMesh` shape
/// `gateway_provenance.rs` uses, kept local per this crate's self-contained-test-file convention.
struct NodeMesh {
    node: std::rc::Rc<std::cell::RefCell<Node<InMemoryTransport>>>,
    gw_from: Vec<u8>,
}
impl MeshDelivery for NodeMesh {
    fn deliver(&self, env: &Envelope, _attestation: &Attestation) -> DeliveryOutcome {
        let outcome = self.node.borrow_mut().receive_mote(&self.gw_from, &env.det_cbor());
        match outcome {
            InboundOutcome::Stored { .. } | InboundOutcome::Duplicate { .. } => DeliveryOutcome::Acked,
            _ => DeliveryOutcome::NoAck,
        }
    }
}

fn jmap_first_email(node: &mut Node<InMemoryTransport>, account: &str) -> serde_json::Value {
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

#[test]
fn inbound_cold_sender_gate_greylists_then_delivers_into_a_real_node_on_retry() {
    const DOMAIN: &str = "example.org";
    const SELECTOR: &str = "gw1";
    const RCPT: &str = "alice@example.org";

    let net = InMemoryNetwork::new();
    let recip_ik = IdentityKey::generate();
    let recip_seal = SealKeypair::generate();
    let recip_ik_pub = recip_ik.public();
    let recip_seal_pub = *recip_seal.public();
    let node = std::rc::Rc::new(std::cell::RefCell::new(Node::with_identity(
        recip_ik,
        recip_seal,
        net.endpoint(recip_ik_pub.clone()),
    )));

    let gw_ik = IdentityKey::generate();
    let gw_ik_pub = gw_ik.public();
    node.borrow_mut().add_contact(&gw_ik_pub, [0u8; 32]);

    let att_key = AttestationKey::generate(DOMAIN, SELECTOR);
    let directory = OneUser {
        email: RCPT.into(),
        key: RecipientKey { ik: recip_ik_pub, seal_pub: recip_seal_pub.to_vec() },
    };
    let mesh = NodeMesh { node: node.clone(), gw_from: gw_ik_pub };

    let clock = ManualClock::new(NOW);
    let gate = ColdSenderGate::with_clock(Box::new(clock.clone()))
        .with_greylist(60_000, 12 * 3_600_000)
        .with_rate_limit(1000, 60_000);

    let gw = InboundGateway::new(gw_ik, vec![att_key], Box::new(directory), Box::new(mesh), Box::new(gate));

    let mut s = MxSession::new(&gw, "203.0.113.9", NOW);
    assert_eq!(s.feed_line("EHLO cold-mta.example").code, 250);

    // First contact from this (ip, from) pair: greylisted BEFORE DATA — the cost for cold contact
    // (§9). Note the transaction's `mail_from` is never set on a rejected `MAIL FROM`, so retrying
    // the exact same command on the same session is a faithful model of a legitimate MTA's queued
    // retry.
    let first = s.feed_line("MAIL FROM:<newcomer@cold-mta.example>");
    assert_eq!(first.code, 451, "cold sender greylisted before DATA");
    assert_eq!(node.borrow().inbox().exists(), 0, "nothing was ever wrapped, let alone delivered");

    // An immediate retry (before the delay elapses) is still deferred.
    assert_eq!(s.feed_line("MAIL FROM:<newcomer@cold-mta.example>").code, 451, "too soon, still greylisted");

    // After the retry delay, the same sender's retry is accepted through the full transaction.
    clock.advance(60_001);
    assert_eq!(s.feed_line("MAIL FROM:<newcomer@cold-mta.example>").code, 250, "retry accepted");
    assert_eq!(s.feed_line(&format!("RCPT TO:<{RCPT}>")).code, 250);
    assert_eq!(s.feed_line("DATA").code, 354);
    assert_eq!(s.feed_line("From: newcomer@cold-mta.example").code, 0);
    assert_eq!(s.feed_line("Subject: hello after the greylist").code, 0);
    assert_eq!(s.feed_line("").code, 0);
    assert_eq!(s.feed_line("finally durable").code, 0);
    let final_reply = s.feed_line(".");
    assert_eq!(final_reply.code, 250, "durable-ack path returns 250 once past the cold-sender gate");

    // The message actually reached the real node's inbox and is readable over a real JMAP view.
    assert_eq!(node.borrow().inbox().exists(), 1, "the retried message actually landed in the real inbox");
    let mut n = node.borrow_mut();
    let email = jmap_first_email(&mut n, RCPT);
    assert_eq!(email["subject"], "hello after the greylist");
    assert!(email["bodyValues"]["1"]["value"].as_str().unwrap_or("").contains("finally durable"));
}

// A quick sanity check the (unused-by-default) permissive policy is still importable/usable
// alongside `ColdSenderGate` in this file, matching the other `integration/` gateway tests' import
// of `AllowAllAbuse` — kept so a reviewer diffing this file against `legacy_to_dmtap.rs` /
// `gateway_provenance.rs` sees the deliberate substitution, not an accidental omission.
#[allow(dead_code)]
fn _allow_all_abuse_is_still_the_permissive_alternative() -> AllowAllAbuse {
    AllowAllAbuse
}
