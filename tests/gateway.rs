//! Integration tests for the DMTAP legacy gateway (spec §7 / §19.7).
//!
//! Everything network-facing is a trait, so the full inbound and outbound flows run in-process.

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{
    validate, Envelope, Headers, Hpke, Kind, Outcome, Payload, RecipientCtx, SealKeypair,
};

use envoir_gateway::attestation::{Attestation, AttestationError, AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::dkim::{self, DkimError, DkimKey};
use envoir_gateway::inbound::{
    AbuseDecision, AntiAbuse, DeliveryOutcome, InboundGateway, KeyDirectory, MeshDelivery,
    MxSession, RecipientKey,
};
use envoir_gateway::outbound::{
    OutboundError, OutboundGateway, OutboundReport, OutboundTransport, TlsPolicy, TlsRequirement,
    TransportResult,
};

const NOW: u64 = 1_752_600_000_000;
const DOMAIN: &str = "example.org";
const GW_SELECTOR: &str = "gw1";

// ---------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------

/// A recipient whose secret we keep so tests can decrypt the delivered MOTE.
struct TestRecipient {
    email: String,
    ik: IdentityKey,
    seal: SealKeypair,
}

impl TestRecipient {
    fn new(email: &str) -> Self {
        TestRecipient { email: email.into(), ik: IdentityKey::generate(), seal: SealKeypair::generate() }
    }
    fn recipient_key(&self) -> RecipientKey {
        RecipientKey { ik: self.ik.public(), seal_pub: self.seal.public().to_vec() }
    }
}

/// A one-entry directory (spec §3 resolve).
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

/// A mesh delivery that captures the delivered MOTE + attestation and returns a fixed outcome.
struct CapturingDelivery {
    outcome: DeliveryOutcome,
    captured: std::sync::Mutex<Option<(Envelope, Attestation)>>,
}
impl CapturingDelivery {
    fn new(outcome: DeliveryOutcome) -> Self {
        CapturingDelivery { outcome, captured: std::sync::Mutex::new(None) }
    }
}
impl MeshDelivery for CapturingDelivery {
    fn deliver(&self, env: &Envelope, attestation: &Attestation) -> DeliveryOutcome {
        *self.captured.lock().unwrap() = Some((env.clone(), attestation.clone()));
        self.outcome
    }
}

/// Anti-abuse that blocks one IP prefix (models an RBL hit / rate limit), else accepts.
struct BlockIp(&'static str);
impl AntiAbuse for BlockIp {
    fn check(&self, peer_ip: &str, _mail_from: &str) -> AbuseDecision {
        if peer_ip.starts_with(self.0) {
            AbuseDecision::Reject { code: 554, reason: "5.7.1 blocked by reputation".into() }
        } else {
            AbuseDecision::Accept
        }
    }
}

fn build_inbound(
    gw_ik: IdentityKey,
    att_key: AttestationKey,
    recip: &TestRecipient,
    outcome: DeliveryOutcome,
    abuse: Box<dyn AntiAbuse>,
) -> (InboundGateway, std::sync::Arc<CapturingDelivery>) {
    // The gateway owns its delivery trait object; we keep an Arc clone to inspect captures. To do
    // that with a Box<dyn>, wrap an Arc-backed forwarder.
    let delivery = std::sync::Arc::new(CapturingDelivery::new(outcome));
    let directory = Box::new(OneUser { email: recip.email.clone(), key: recip.recipient_key() });
    struct ArcDelivery(std::sync::Arc<CapturingDelivery>);
    impl MeshDelivery for ArcDelivery {
        fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
            self.0.deliver(env, att)
        }
    }
    let gw = InboundGateway::new(
        gw_ik,
        vec![att_key],
        directory,
        Box::new(ArcDelivery(delivery.clone())),
        abuse,
    );
    (gw, delivery)
}

fn sample_message(to: &str) -> Vec<u8> {
    format!(
        "From: sender@gmail.com\r\nTo: {to}\r\nSubject: hello from legacy\r\n\r\nGreetings across the bridge.\r\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------------------------
// Inbound (§7.2 / §19.7.1)
// ---------------------------------------------------------------------------------------------

#[test]
fn inbound_wraps_into_attested_encrypted_mote_for_the_right_key() {
    let gw_seed = [7u8; 32];
    let gw_pub = IdentityKey::from_seed(&gw_seed).public();
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let att_pub = att_key.public();
    let recip = TestRecipient::new("alice@example.org");
    let (gw, _d) = build_inbound(
        IdentityKey::from_seed(&gw_seed),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );

    let (env, attestation) = gw
        .wrap_and_attest("sender@gmail.com", &recip.email, &sample_message(&recip.email), NOW)
        .expect("wrap");

    // Addressed to the recipient's identity key.
    assert!(env.to.resolves_to_key(&recip.ik.public()), "MOTE routed to the recipient key");
    assert_eq!(env.kind, Kind::Mail);

    // The recipient can decrypt it; the payload is from the GATEWAY (legacy-origin) and carries the
    // original message text.
    let ctx = RecipientCtx {
        our_ik: &recip.ik.public(),
        seal_secret: recip.seal.secret(),
        sender_is_known: true,
    };
    let payload = match validate(&Hpke, &env, &ctx).expect("validate") {
        Outcome::Accepted(p) => *p,
        Outcome::Deferred => panic!("known-contact MOTE must be accepted"),
    };
    assert_eq!(payload.from, gw_pub, "Payload.from is the gateway identity");
    assert!(
        String::from_utf8_lossy(&payload.body).contains("Greetings across the bridge"),
        "original message body is carried into the MOTE"
    );
    assert_eq!(payload.headers.subject.as_deref(), Some("hello from legacy"));

    // The attestation is bound to THIS MOTE and to the SMTP envelope.
    assert_eq!(attestation.mote_id, env.id);
    assert_eq!(attestation.smtp_mail_from, "sender@gmail.com");
    assert_eq!(attestation.smtp_rcpt_to, recip.email);
    assert_eq!(attestation.gateway_key, att_pub);
}

#[test]
fn inbound_returns_250_only_on_durable_ack() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let reply = gw.accept_message("s@gmail.com", &recip.email, &sample_message(&recip.email), NOW);
    assert_eq!(reply.code, 250, "durable ack → 250");
    assert!(reply.is_ok());
}

#[test]
fn inbound_returns_451_when_no_durable_ack() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::NoAck, // reachable-but-no-durable-ack OR unreachable
        Box::new(AllowAll),
    );
    let reply = gw.accept_message("s@gmail.com", &recip.email, &sample_message(&recip.email), NOW);
    assert_eq!(reply.code, 451, "no durable ack → 451 (never 250 on mere hand-off)");
    assert!(!reply.is_ok());
}

#[test]
fn inbound_unknown_recipient_is_550() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let reply = gw.accept_message("s@gmail.com", "nobody@example.org", &sample_message("nobody@example.org"), NOW);
    assert_eq!(reply.code, 550);
}

#[test]
fn inbound_domain_without_attestation_key_defers_451() {
    // Recipient resolves, but the gateway holds no attestation key for the domain → 451, never a
    // silently-unattested delivery (§19.7.1 failure table).
    let recip = TestRecipient::new("alice@other.example");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR); // only example.org, not other.example
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let reply = gw.accept_message("s@gmail.com", &recip.email, &sample_message(&recip.email), NOW);
    assert_eq!(reply.code, 451);
}

#[test]
fn mx_session_full_transaction_reaches_250() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, delivery) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let mut s = MxSession::new(&gw, "203.0.113.9", NOW);
    assert_eq!(s.greeting().code, 220);
    assert_eq!(s.feed_line("EHLO gmail.com").code, 250);
    assert_eq!(s.feed_line("MAIL FROM:<sender@gmail.com>").code, 250);
    assert_eq!(s.feed_line(&format!("RCPT TO:<{}>", recip.email)).code, 250);
    assert_eq!(s.feed_line("DATA").code, 354);
    assert_eq!(s.feed_line("From: sender@gmail.com").code, 0);
    assert_eq!(s.feed_line("Subject: hi").code, 0);
    assert_eq!(s.feed_line("").code, 0);
    assert_eq!(s.feed_line("body line one").code, 0);
    assert_eq!(s.feed_line("..dotstuffed line").code, 0);
    let final_reply = s.feed_line(".");
    assert_eq!(final_reply.code, 250, "durable-ack path returns 250 at end of DATA");
    assert!(delivery.captured.lock().unwrap().is_some(), "a MOTE was delivered");
}

#[test]
fn mx_session_rejects_spam_before_data() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, delivery) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(BlockIp("198.51.100.")),
    );
    let mut s = MxSession::new(&gw, "198.51.100.66", NOW);
    assert_eq!(s.feed_line("EHLO spammer").code, 250);
    let mail = s.feed_line("MAIL FROM:<spam@bad.example>");
    assert_eq!(mail.code, 554, "blocked before DATA — never accepts the body");
    assert!(delivery.captured.lock().unwrap().is_none(), "no MOTE was ever built for spam");
}

#[test]
fn mx_session_unknown_recipient_rejected_at_rcpt_before_data() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let mut s = MxSession::new(&gw, "203.0.113.9", NOW);
    s.feed_line("EHLO gmail.com");
    s.feed_line("MAIL FROM:<sender@gmail.com>");
    let rcpt = s.feed_line("RCPT TO:<ghost@example.org>");
    assert_eq!(rcpt.code, 550, "unknown recipient refused at RCPT, before DATA");
}

// ---------------------------------------------------------------------------------------------
// Attestation (§7.2a)
// ---------------------------------------------------------------------------------------------

#[test]
fn attestation_verifies_under_the_domain_published_key() {
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let published: StaticGwKeys = StaticGwKeys::new().publish(DOMAIN, GW_SELECTOR, att_key.public());
    let mote_id = dmtap_core::ContentId::of(b"some-mote");
    let att = att_key.attest(&mote_id, "bob@gmail.com", "alice@example.org", NOW);

    // Recipient-side check: look up the key under the recipient's OWN domain + the attestation's
    // selector, then verify.
    let key = published.resolve_gw_key(DOMAIN, &att.selector);
    assert!(att.verify(DOMAIN, key.as_deref(), &mote_id).is_ok(), "genuine attestation verifies");
}

#[test]
fn forged_attestation_is_rejected() {
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let published = StaticGwKeys::new().publish(DOMAIN, GW_SELECTOR, att_key.public());
    let mote_id = dmtap_core::ContentId::of(b"real-mote");
    let good = att_key.attest(&mote_id, "bob@gmail.com", "alice@example.org", NOW);
    let key = published.resolve_gw_key(DOMAIN, GW_SELECTOR);

    // (a) Tampered signature.
    let mut bad_sig = good.clone();
    bad_sig.sig[0] ^= 0xff;
    assert!(matches!(
        bad_sig.verify(DOMAIN, key.as_deref(), &mote_id),
        Err(AttestationError::BadSignature(_))
    ));

    // (b) Tampered signed field (claims a different legacy origin).
    let mut bad_field = good.clone();
    bad_field.smtp_mail_from = "attacker@evil.example".into();
    assert!(bad_field.verify(DOMAIN, key.as_deref(), &mote_id).is_err());

    // (c) Attestation forged by an operator whose key the domain never published.
    let rogue = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let rogue_att = rogue.attest(&mote_id, "bob@gmail.com", "alice@example.org", NOW);
    assert_eq!(
        rogue_att.verify(DOMAIN, key.as_deref(), &mote_id),
        Err(AttestationError::KeyMismatch),
        "a key not published under the domain is rejected"
    );

    // (d) No key published for the domain at all.
    assert_eq!(
        good.verify(DOMAIN, None, &mote_id),
        Err(AttestationError::NoPublishedKey)
    );

    // (e) Attestation for a different domain than the recipient's own.
    assert_eq!(
        good.verify("someone-else.example", key.as_deref(), &mote_id),
        Err(AttestationError::WrongDomain)
    );

    // (f) Attestation lifted onto a different MOTE.
    let other_mote = dmtap_core::ContentId::of(b"different-mote");
    assert_eq!(
        good.verify(DOMAIN, key.as_deref(), &other_mote),
        Err(AttestationError::MoteMismatch)
    );
}

// ---------------------------------------------------------------------------------------------
// Outbound (§7.3 / §19.7.2)
// ---------------------------------------------------------------------------------------------

/// A transport that records what it was asked and returns a scripted result. It genuinely enforces
/// TLS: if `require_tls` and the destination is not in its TLS-capable set, it returns
/// `TlsUnavailable` rather than "delivering" in cleartext.
struct ScriptedTransport {
    tls_capable: bool,
    on_success: TransportResult,
    last: std::sync::Mutex<Option<Vec<u8>>>,
}
impl ScriptedTransport {
    fn new(tls_capable: bool, on_success: TransportResult) -> Self {
        ScriptedTransport { tls_capable, on_success, last: std::sync::Mutex::new(None) }
    }
}
impl OutboundTransport for ScriptedTransport {
    fn deliver(&self, _dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
        if require_tls && !self.tls_capable {
            return TransportResult::TlsUnavailable;
        }
        *self.last.lock().unwrap() = Some(message.to_vec());
        self.on_success.clone()
    }
}

struct FixedTls(TlsRequirement);
impl TlsPolicy for FixedTls {
    fn requirement_for(&self, _dest: &str) -> TlsRequirement {
        self.0
    }
}

fn sample_payload() -> Payload {
    // A minimal, self-consistent mail payload (from a decrypted outbound MOTE).
    let sender = IdentityKey::generate();
    let mut p = Payload {
        from: sender.public(),
        sig: Vec::new(),
        headers: Headers { thread: None, subject: Some("meeting notes".into()), mime: None, cc: vec![] },
        body: b"Here are the notes from today.\r\n".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    };
    // Outbound rendering does not depend on the payload sig, but keep the shape realistic.
    p.sig = vec![0u8; 64];
    p
}

fn dkim_key(domain: &str, selector: &str) -> DkimKey {
    // Deterministic seed for reproducibility.
    let mut seed = [0u8; 32];
    for (i, b) in domain.bytes().chain(selector.bytes()).enumerate().take(32) {
        seed[i] = b;
    }
    DkimKey::from_seed(domain, selector, &seed)
}

#[test]
fn outbound_produces_a_verifiable_delegated_dkim_signature() {
    let key = dkim_key("alice-domain.com", "dmtap1");
    let pubk = key.public_bytes();
    let gw = OutboundGateway::new(
        vec![key],
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    );
    let payload = sample_payload();

    let signed = gw
        .translate_and_sign(&payload, "alice@alice-domain.com", "bob@gmail.com", NOW)
        .expect("delegated signing");

    let text = String::from_utf8_lossy(&signed);
    assert!(text.starts_with("DKIM-Signature:"), "DKIM header is prepended");
    assert!(text.contains("d=alice-domain.com"), "signs as the sender's domain");
    assert!(text.contains("s=dmtap1"), "uses the delegated selector");
    assert!(text.contains("a=ed25519-sha256"));

    // The signature genuinely verifies under the delegated public key (RFC 8463).
    dkim::verify(&signed, &pubk).expect("DKIM signature must verify");

    // Tampering the body breaks the body hash → verification fails.
    let mut tampered = signed.clone();
    if let Some(pos) = tampered.windows(5).position(|w| w == b"notes") {
        tampered[pos] ^= 0x20;
    }
    assert!(dkim::verify(&tampered, &pubk).is_err(), "a modified body fails DKIM");
}

#[test]
fn outbound_refuses_to_sign_undelegated_domain() {
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")], // only alice-domain.com is delegated
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    );
    let payload = sample_payload();
    let err = gw
        .translate_and_sign(&payload, "mallory@not-mine.com", "bob@gmail.com", NOW)
        .unwrap_err();
    assert_eq!(err, OutboundError::NotDelegated("not-mine.com".into()));

    // And the end-to-end send reports it as a permanent failure (not retried blindly).
    let report = gw.send(&payload, "mallory@not-mine.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Failed(OutboundError::NotDelegated("not-mine.com".into())));
}

#[test]
fn outbound_full_send_delivers_over_tls() {
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    );
    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Delivered);
}

#[test]
fn outbound_refuses_cleartext_when_tls_required() {
    // Policy requires TLS but the destination offers none → abort, never cleartext (§7.3 step 4).
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(ScriptedTransport::new(false, TransportResult::Delivered { code: 250 })),
    );
    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(
        report,
        OutboundReport::Failed(OutboundError::TlsEnforcementFailed("gmail.com".into()))
    );
}

#[test]
fn outbound_transient_failure_defers_to_node_retry() {
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Opportunistic)),
        Box::new(ScriptedTransport::new(
            true,
            TransportResult::Transient { code: 451, text: "4.2.1 mailbox busy".into() },
        )),
    );
    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Deferred { code: 451, text: "4.2.1 mailbox busy".into() });
}

#[test]
fn outbound_permanent_failure_is_reported_failed() {
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Opportunistic)),
        Box::new(ScriptedTransport::new(
            true,
            TransportResult::Permanent { code: 550, text: "5.1.1 no such user".into() },
        )),
    );
    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(
        report,
        OutboundReport::Failed(OutboundError::DestinationRejected {
            code: 550,
            text: "5.1.1 no such user".into()
        })
    );
}

#[test]
fn dkim_signature_fails_under_the_wrong_key() {
    let key = dkim_key("alice-domain.com", "dmtap1");
    let correct_pub = key.public_bytes();
    let gw = OutboundGateway::new(
        vec![key],
        Box::new(FixedTls(TlsRequirement::Opportunistic)),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    );
    let signed = gw
        .translate_and_sign(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW)
        .unwrap();
    // A genuinely different key must not verify the signature.
    let other = DkimKey::from_seed("x", "y", &[9u8; 32]);
    assert_eq!(dkim::verify(&signed, &other.public_bytes()), Err(DkimError::SignatureInvalid));
    // Sanity: the correct delegated key still verifies.
    dkim::verify(&signed, &correct_pub).unwrap();
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

struct AllowAll;
impl AntiAbuse for AllowAll {
    fn check(&self, _peer_ip: &str, _mail_from: &str) -> AbuseDecision {
        AbuseDecision::Accept
    }
}
