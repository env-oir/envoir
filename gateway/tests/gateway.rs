//! Integration tests for the DMTAP legacy gateway (spec §7 / §19.7).
//!
//! Everything network-facing is a trait, so the full inbound and outbound flows run in-process.

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{
    validate, Envelope, Headers, Hpke, Kind, Outcome, Payload, RecipientCtx, SealKeypair,
};

use envoir_gateway::attestation::{Attestation, AttestationError, AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::dkim::{self, DkimError, DkimKey, StaticDkimKeys};
use envoir_gateway::inbound::{
    AbuseDecision, AntiAbuse, Clock, ColdSenderGate, DeliveryOutcome, DkimPolicy, InboundGateway,
    KeyDirectory, MeshDelivery, MxSession, RecipientKey,
};
use envoir_gateway::provenance::{Origin, ProvenanceError, ProvenanceRecord};
use envoir_gateway::mta_sts::{InMemoryPolicyFetcher, InMemoryTxtResolver, MtaStsTlsPolicy};
use envoir_gateway::mx::{InMemoryMxResolver, MxHost};
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

/// A transport that records every host it was asked to dial (so a test can assert it was NEVER
/// invoked — e.g. because MX-pattern filtering aborted before any dial was attempted) as well as
/// enforcing TLS the same way `ScriptedTransport` does.
struct RecordingTransport {
    tls_capable: bool,
    on_success: TransportResult,
    dialed: std::sync::Mutex<Vec<String>>,
}
impl RecordingTransport {
    fn new(tls_capable: bool, on_success: TransportResult) -> Self {
        RecordingTransport { tls_capable, on_success, dialed: std::sync::Mutex::new(Vec::new()) }
    }
    fn dialed_hosts(&self) -> Vec<String> {
        self.dialed.lock().unwrap().clone()
    }
}
impl OutboundTransport for RecordingTransport {
    fn deliver(&self, dest: &str, _message: &[u8], require_tls: bool) -> TransportResult {
        self.dialed.lock().unwrap().push(dest.to_string());
        if require_tls && !self.tls_capable {
            return TransportResult::TlsUnavailable;
        }
        self.on_success.clone()
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
// MX resolution + MTA-STS enforcement, end to end through OutboundGateway::send (§7.3 step 4).
// ---------------------------------------------------------------------------------------------

/// A policy that requires TLS for every destination and constrains delivery to a fixed set of MX
/// hostname patterns — models an MTA-STS `enforce` policy without going through the DNS/HTTPS seams.
struct FixedMtaStsEnforce(Vec<String>);
impl TlsPolicy for FixedMtaStsEnforce {
    fn requirement_for(&self, _dest: &str) -> TlsRequirement {
        TlsRequirement::Required
    }
    fn allowed_mx_patterns(&self, _dest: &str) -> Vec<String> {
        self.0.clone()
    }
}

#[test]
fn send_dials_the_lowest_preference_mx_host() {
    let mx = InMemoryMxResolver::new().with_mx(
        "gmail.com",
        &[("mx-backup.gmail.com", 20), ("mx-primary.gmail.com", 5)],
    );
    let transport = std::sync::Arc::new(RecordingTransport::new(true, TransportResult::Delivered { code: 250 }));
    struct ArcTransport(std::sync::Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Opportunistic)),
        Box::new(ArcTransport(transport.clone())),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Delivered);
    assert_eq!(
        transport.dialed_hosts(),
        vec!["mx-primary.gmail.com".to_string()],
        "the lowest-preference (highest-priority) MX host is dialed"
    );
}

#[test]
fn send_falls_back_to_the_domain_when_no_mx_records() {
    let mx = InMemoryMxResolver::new(); // nothing published for any domain
    let transport = std::sync::Arc::new(RecordingTransport::new(true, TransportResult::Delivered { code: 250 }));
    struct ArcTransport(std::sync::Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Opportunistic)),
        Box::new(ArcTransport(transport.clone())),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@no-mx.example", NOW);
    assert_eq!(report, OutboundReport::Delivered);
    assert_eq!(
        transport.dialed_hosts(),
        vec!["no-mx.example".to_string()],
        "no MX records → dial the domain itself (A/AAAA fallback, RFC 5321 §5.1)"
    );
}

#[test]
fn mta_sts_enforce_delivers_over_tls_to_a_pattern_matching_mx() {
    let mx = InMemoryMxResolver::new().with_mx("gmail.com", &[("mx1.gmail.com", 10)]);
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedMtaStsEnforce(vec!["*.gmail.com".to_string()])),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Delivered);
}

#[test]
fn mta_sts_enforce_aborts_when_peer_offers_no_tls_never_downgrades() {
    // The resolved MX host DOES match the enforce policy's `mx:` pattern, but the transport (the
    // "peer") is not TLS-capable. This MUST abort — never silently send in cleartext.
    let mx = InMemoryMxResolver::new().with_mx("gmail.com", &[("mx1.gmail.com", 10)]);
    let transport = std::sync::Arc::new(RecordingTransport::new(false, TransportResult::Delivered { code: 250 }));
    struct ArcTransport(std::sync::Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedMtaStsEnforce(vec!["*.gmail.com".to_string()])),
        Box::new(ArcTransport(transport.clone())),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(
        report,
        OutboundReport::Failed(OutboundError::TlsEnforcementFailed("gmail.com".into())),
        "enforce policy + plaintext-only peer → aborted, not downgraded"
    );
    // The transport WAS dialed (it is the pattern-matching MX host) but never got to "succeed" in
    // cleartext — `deliver` itself refused, and no cleartext send occurred.
    assert_eq!(transport.dialed_hosts(), vec!["mx1.gmail.com".to_string()]);
}

#[test]
fn mta_sts_enforce_aborts_when_no_resolved_mx_matches_any_pattern_never_downgrades() {
    // The domain's actual MX hosts don't match the policy's `mx:` patterns at all (e.g. a stale
    // policy, or an attacker who hijacked MX records to point somewhere the policy never
    // authorized). MUST abort before ever dialing — not fall back to an unconstrained/plaintext
    // host.
    let mx = InMemoryMxResolver::new().with_mx("gmail.com", &[("mx1.attacker-controlled.example", 10)]);
    let transport = std::sync::Arc::new(RecordingTransport::new(true, TransportResult::Delivered { code: 250 }));
    struct ArcTransport(std::sync::Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedMtaStsEnforce(vec!["*.gmail.com".to_string()])),
        Box::new(ArcTransport(transport.clone())),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(
        report,
        OutboundReport::Failed(OutboundError::NoMxMatchesPolicy(
            "gmail.com".into(),
            vec!["*.gmail.com".to_string()],
            vec!["mx1.attacker-controlled.example".to_string()],
        )),
        "no resolved MX host matches the enforce policy's mx: patterns → aborted"
    );
    assert!(
        transport.dialed_hosts().is_empty(),
        "the non-matching host must never even be dialed, let alone sent to in cleartext"
    );
}

#[test]
fn mta_sts_enforce_picks_the_lowest_preference_mx_among_matching_candidates() {
    // Two MX candidates; only the higher-preference-number (lower priority) one matches the
    // enforce policy's pattern. The gateway must still dial the best MATCHING one, not just the
    // globally-lowest-preference one that fails the pattern.
    let mx = InMemoryMxResolver::new().with_mx(
        "gmail.com",
        &[("mx-unlisted.rogue.example", 1), ("mx-listed.gmail.com", 10)],
    );
    let transport = std::sync::Arc::new(RecordingTransport::new(true, TransportResult::Delivered { code: 250 }));
    struct ArcTransport(std::sync::Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, dest: &str, message: &[u8], require_tls: bool) -> TransportResult {
            self.0.deliver(dest, message, require_tls)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedMtaStsEnforce(vec!["*.gmail.com".to_string()])),
        Box::new(ArcTransport(transport.clone())),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Delivered);
    assert_eq!(transport.dialed_hosts(), vec!["mx-listed.gmail.com".to_string()]);
}

#[test]
fn mta_sts_testing_mode_is_opportunistic_and_ignores_mx_patterns() {
    // `testing` mode: TLS is opportunistic and non-matching MX hosts are NOT excluded — violations
    // would be reported out-of-band, not blocked.
    let mx = InMemoryMxResolver::new().with_mx("gmail.com", &[("mx1.gmail.com", 10)]);
    let txt = InMemoryTxtResolver::new().with_txt("_mta-sts.gmail.com", &["v=STSv1; id=1"]);
    let fetcher = InMemoryPolicyFetcher::new()
        .with_policy("gmail.com", "version: STSv1\nmode: testing\nmx: mx.never-matches.example\n");
    let policy = MtaStsTlsPolicy::new(Box::new(txt), Box::new(fetcher));

    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(policy),
        Box::new(ScriptedTransport::new(false, TransportResult::Delivered { code: 250 })), // no TLS offered
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(
        report,
        OutboundReport::Delivered,
        "testing mode does not mandate TLS or filter MX hosts — cleartext delivery proceeds"
    );
}

#[test]
fn mta_sts_end_to_end_through_dns_txt_and_https_policy_seams() {
    // The full composition: TXT signal + fetched policy text parsed into an enforce policy with a
    // real (in-memory) DNS/HTTPS seam, driving OutboundGateway::send end to end.
    let txt = InMemoryTxtResolver::new().with_txt("_mta-sts.gmail.com", &["v=STSv1; id=42"]);
    let fetcher = InMemoryPolicyFetcher::new()
        .with_policy("gmail.com", "version: STSv1\nmode: enforce\nmx: *.gmail.com\nmax_age: 86400\n");
    let policy = MtaStsTlsPolicy::new(Box::new(txt), Box::new(fetcher));
    let mx = InMemoryMxResolver::new().with_mx("gmail.com", &[("mx1.gmail.com", 10)]);

    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(policy),
        Box::new(ScriptedTransport::new(true, TransportResult::Delivered { code: 250 })),
    )
    .with_mx_resolver(Box::new(mx));

    let report = gw.send(&sample_payload(), "alice@alice-domain.com", "bob@gmail.com", NOW);
    assert_eq!(report, OutboundReport::Delivered);
}

#[test]
fn mx_host_struct_is_reachable_from_the_public_api() {
    // Sanity: MxHost is part of the public surface tests (and operators) construct directly.
    let h = MxHost { host: "mx.example.org".into(), preference: 10 };
    assert_eq!(h.preference, 10);
}

// ---------------------------------------------------------------------------------------------
// Inbound legacy→DMTAP: DKIM verification (§7.2 step 2) + provenance stamping (§7.8 / §18.8.1)
// ---------------------------------------------------------------------------------------------

/// DKIM-sign a legacy RFC 5322 message as `domain`/`selector`, returning `(signed_bytes, pubkey)`.
fn dkim_signed_inbound(domain: &str, selector: &str, to: &str) -> (Vec<u8>, [u8; 32]) {
    let mut seed = [0u8; 32];
    for (i, b) in domain.bytes().chain(selector.bytes()).enumerate().take(32) {
        seed[i] = b;
    }
    let key = DkimKey::from_seed(domain, selector, &seed);
    let pubk = key.public_bytes();
    let msg = format!(
        "From: alice@{domain}\r\nTo: {to}\r\nSubject: hi\r\nDate: Tue, 15 Jul 2026 00:00:00 +0000\r\n\r\nsigned legacy body\r\n"
    )
    .into_bytes();
    let header = dkim::sign(&key, &msg, NOW / 1000);
    let mut out = header.into_bytes();
    out.extend_from_slice(&msg);
    (out, pubk)
}

#[test]
fn inbound_dkim_enforce_rejects_a_broken_signature_but_accepts_a_valid_one() {
    let recip = TestRecipient::new("bob@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (base_gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let (signed, pubk) = dkim_signed_inbound("sender.example", "s1", &recip.email);
    let resolver = StaticDkimKeys::new().publish("sender.example", "s1", pubk.to_vec());
    let gw = base_gw.with_dkim(Box::new(resolver), DkimPolicy::Enforce);

    // A valid inbound signature is accepted (durable ack → 250).
    let ok = gw.accept_message("alice@sender.example", &recip.email, &signed, NOW);
    assert_eq!(ok.code, 250, "a genuinely DKIM-signed legacy message is accepted");

    // Tamper the body: the signature no longer verifies → enforce rejects it (5xx), before wrapping.
    let mut tampered = signed.clone();
    let pos = tampered.windows(6).position(|w| w == b"signed").unwrap();
    tampered[pos] ^= 0x20;
    let bad = gw.accept_message("alice@sender.example", &recip.email, &tampered, NOW);
    assert_eq!(bad.code, 550, "a present-but-invalid DKIM signature is refused under enforce");
    assert!(bad.text.to_lowercase().contains("dkim"));
}

#[test]
fn inbound_dkim_annotate_delivers_regardless_of_verdict() {
    let recip = TestRecipient::new("bob@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let (base_gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );
    let (signed, pubk) = dkim_signed_inbound("sender.example", "s1", &recip.email);
    let resolver = StaticDkimKeys::new().publish("sender.example", "s1", pubk.to_vec());
    let gw = base_gw.with_dkim(Box::new(resolver), DkimPolicy::Annotate);

    // Even a broken signature is delivered under annotate (DMARC p= enforcement is a seam), but the
    // verdict is still computable for downstream policy.
    let mut tampered = signed.clone();
    let pos = tampered.windows(6).position(|w| w == b"signed").unwrap();
    tampered[pos] ^= 0x20;
    let reply = gw.accept_message("alice@sender.example", &recip.email, &tampered, NOW);
    assert_eq!(reply.code, 250, "annotate mode delivers regardless of the DKIM verdict");
    assert!(matches!(
        gw.verify_inbound_dkim(&tampered),
        envoir_gateway::dkim::DkimVerdict::Fail(_)
    ));
}

#[test]
fn inbound_stamps_a_verifiable_gateway_provenance_record() {
    let recip = TestRecipient::new("bob@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let att_pub = att_key.public();
    let published = StaticGwKeys::new().publish(DOMAIN, GW_SELECTOR, att_pub.clone());
    let (gw, _d) = build_inbound(
        IdentityKey::generate(),
        att_key,
        &recip,
        DeliveryOutcome::Acked,
        Box::new(AllowAll),
    );

    let data = sample_message(&recip.email);
    let bridged = gw
        .wrap_attest_and_stamp("sender@gmail.com", &recip.email, &data, NOW)
        .expect("bridge + stamp");

    // The normative gateway attestation is signed over the EXACT legacy bytes and verifies under the
    // domain-published _dmtap-gw key.
    let key = published.resolve_gw_key(DOMAIN, GW_SELECTOR);
    bridged
        .gateway_attestation
        .verify(key.as_deref(), &data)
        .expect("gateway attestation verifies over the exact bytes");
    // Lifted onto different bytes → digest no longer binds → rejected.
    assert_eq!(
        bridged.gateway_attestation.verify(key.as_deref(), b"different bytes"),
        Err(ProvenanceError::Invalid)
    );
    assert_eq!(bridged.gateway_attestation.legacy_from.as_deref(), Some("sender@gmail.com"));

    // The client-facing provenance record is gateway-touched with exactly one hop, and round-trips.
    assert_eq!(bridged.provenance.origin, Origin::GatewayTouched);
    assert_eq!(bridged.provenance.gateway_hops(), 1);
    assert!(!bridged.provenance.is_pure_mesh());
    let decoded = ProvenanceRecord::from_det_cbor(&bridged.provenance.det_cbor()).unwrap();
    assert_eq!(decoded, bridged.provenance);
}

// ---------------------------------------------------------------------------------------------
// Cold-sender anti-abuse gate (§9 / §7.2 step 2)
// ---------------------------------------------------------------------------------------------

/// A manual clock whose backing counter is shared via `Arc` between the clone handed to the gate and
/// the handle a test keeps to advance time — so time moves without sleeping.
#[derive(Clone)]
struct ManualClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl ManualClock {
    fn new(t: u64) -> Self {
        ManualClock(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(t)))
    }
}
impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
fn advance(c: &ManualClock, d: u64) {
    c.0.fetch_add(d, std::sync::atomic::Ordering::SeqCst);
}

fn rejected(d: &AbuseDecision) -> u16 {
    match d {
        AbuseDecision::Reject { code, .. } => *code,
        AbuseDecision::Accept => 0,
    }
}

#[test]
fn cold_sender_is_greylisted_then_accepted_on_retry() {
    let clock = ManualClock::new(1_000_000);
    let gate = ColdSenderGate::with_clock(Box::new(clock.clone()))
        .with_greylist(60_000, 12 * 3_600_000)
        .with_rate_limit(1000, 60_000);

    // First contact from a cold (ip, from) pair → deferred 451 (cost for cold contact).
    let first = gate.check("203.0.113.9", "stranger@gmail.com");
    assert_eq!(rejected(&first), 451);
    // An immediate retry (delay not elapsed) is still deferred.
    assert_eq!(rejected(&gate.check("203.0.113.9", "stranger@gmail.com")), 451);
    // After the retry delay a legitimate MTA's re-send is accepted.
    advance(&clock, 60_000);
    assert_eq!(gate.check("203.0.113.9", "stranger@gmail.com"), AbuseDecision::Accept);
}

#[test]
fn cold_sender_gate_lets_known_contacts_and_blocks_the_blocked() {
    let clock = ManualClock::new(1_000_000);
    let gate = ColdSenderGate::with_clock(Box::new(clock.clone()))
        .allow_ip_prefix("198.51.100.")
        .allow_sender("friend@partner.example")
        .block_ip_prefix("192.0.2.")
        .block_sender("spammer@bad.example");

    // Known IP prefix and known sender are free (no greylist delay).
    assert_eq!(gate.check("198.51.100.7", "anyone@wherever.example"), AbuseDecision::Accept);
    assert_eq!(gate.check("203.0.113.1", "friend@partner.example"), AbuseDecision::Accept);
    // Blocked IP and blocked sender are hard-rejected 554.
    assert_eq!(rejected(&gate.check("192.0.2.5", "x@y.example")), 554);
    assert_eq!(rejected(&gate.check("203.0.113.1", "spammer@bad.example")), 554);
}

#[test]
fn cold_sender_gate_enforces_a_per_ip_rate_limit() {
    let clock = ManualClock::new(1_000_000);
    // Zero greylist delay so a retry is accepted immediately; budget of 2 accepts per window.
    let gate = ColdSenderGate::with_clock(Box::new(clock.clone()))
        .with_greylist(0, 12 * 3_600_000)
        .with_rate_limit(2, 60_000);

    // First sight greylists (no accept recorded); the next two pass, then the budget is spent.
    assert_eq!(rejected(&gate.check("203.0.113.50", "s@gmail.com")), 451); // greylist
    assert_eq!(gate.check("203.0.113.50", "s@gmail.com"), AbuseDecision::Accept); // accept 1
    assert_eq!(gate.check("203.0.113.50", "s@gmail.com"), AbuseDecision::Accept); // accept 2
    let over = gate.check("203.0.113.50", "s@gmail.com");
    assert_eq!(rejected(&over), 451, "over budget → deferred");
    if let AbuseDecision::Reject { reason, .. } = over {
        assert!(reason.to_lowercase().contains("rate limit"));
    }
    // The window slides: well past it, the sender is served again.
    advance(&clock, 61_000);
    assert_eq!(gate.check("203.0.113.50", "s@gmail.com"), AbuseDecision::Accept);
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
