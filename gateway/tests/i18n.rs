//! Protocol-i18n integration tests for the gateway (the audit items 1–4): 8-bit legacy DATA must
//! survive the inbound pipeline byte-exact (and DKIM-verify over the ORIGINAL bytes), IDN
//! destinations must cross the DNS/dial/SNI boundary as A-labels (punycode) — with a specific,
//! diagnosable error when no A-label spelling exists — outbound headers must reach the legacy wire
//! RFC 2047-encoded (pure ASCII, DKIM over the final bytes), and the transport must gate
//! SMTPUTF8/8BITMIME needs against what the peer actually advertised (RFC 6531/6152) instead of
//! shipping raw UTF-8 and hoping.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{
    validate, Envelope, Headers, Hpke, Outcome, Payload, RecipientCtx, SealKeypair,
};

use envoir_gateway::attestation::{Attestation, AttestationKey};
use envoir_gateway::dkim::{self, DkimKey, DkimVerdict, StaticDkimKeys};
use envoir_gateway::inbound::{
    AbuseDecision, AntiAbuse, DeliveryOutcome, DkimPolicy, InboundGateway, KeyDirectory,
    MeshDelivery, MxSession, RecipientKey,
};
use envoir_gateway::mx::{DnsMxResolver, MxHost, MxResolver};
use envoir_gateway::outbound::{
    OutboundError, OutboundGateway, OutboundReport, OutboundTransport, TlsPolicy, TlsRequirement,
    TransportResult,
};
use envoir_gateway::SmtpTcpTransport;

const NOW: u64 = 1_752_600_000_000;
const DOMAIN: &str = "example.org";
const GW_SELECTOR: &str = "gw1";

// --- test doubles (each integration test file is its own crate, so redefine) ------------------

struct TestRecipient {
    email: String,
    ik: IdentityKey,
    seal: SealKeypair,
}
impl TestRecipient {
    fn new(email: &str) -> Self {
        TestRecipient {
            email: email.into(),
            ik: IdentityKey::generate(),
            seal: SealKeypair::generate(),
        }
    }
    fn recipient_key(&self) -> RecipientKey {
        RecipientKey { ik: self.ik.public(), seal_pub: self.seal.public().to_vec() }
    }
}

struct OneUser {
    email: String,
    key: RecipientKey,
}
impl KeyDirectory for OneUser {
    fn resolve(&self, rcpt: &str) -> Option<RecipientKey> {
        rcpt.eq_ignore_ascii_case(&self.email).then(|| self.key.clone())
    }
}

struct CapturingDelivery {
    captured: Mutex<Option<(Envelope, Attestation)>>,
}
impl MeshDelivery for CapturingDelivery {
    fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
        *self.captured.lock().unwrap() = Some((env.clone(), att.clone()));
        DeliveryOutcome::Acked
    }
}
struct ArcDelivery(Arc<CapturingDelivery>);
impl MeshDelivery for ArcDelivery {
    fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
        self.0.deliver(env, att)
    }
}

struct AllowAll;
impl AntiAbuse for AllowAll {
    fn check(&self, _peer_ip: &str, _mail_from: &str) -> AbuseDecision {
        AbuseDecision::Accept
    }
}

struct FixedTls(TlsRequirement);
impl TlsPolicy for FixedTls {
    fn requirement_for(&self, _dest: &str) -> TlsRequirement {
        self.0
    }
}

/// A transport that records every host it was asked to dial — used to assert the gateway refused
/// an unspellable domain BEFORE any dial was attempted.
struct RecordingTransport {
    dialed: Mutex<Vec<String>>,
}
impl RecordingTransport {
    fn new() -> Self {
        RecordingTransport { dialed: Mutex::new(Vec::new()) }
    }
}
impl OutboundTransport for RecordingTransport {
    fn deliver(&self, dest: &str, _message: &[u8], _require_tls: bool) -> TransportResult {
        self.dialed.lock().unwrap().push(dest.to_string());
        TransportResult::Delivered { code: 250 }
    }
}

fn dkim_key(domain: &str, selector: &str) -> DkimKey {
    let mut seed = [0u8; 32];
    for (i, b) in domain.bytes().chain(selector.bytes()).enumerate().take(32) {
        seed[i] = b;
    }
    DkimKey::from_seed(domain, selector, &seed)
}

fn sample_payload(subject: &str) -> Payload {
    let sender = IdentityKey::generate();
    Payload {
        from: sender.public(),
        sig: vec![0u8; 64],
        headers: Headers { thread: None, subject: Some(subject.into()), mime: None, cc: vec![] },
        body: b"Here are the notes from today.\r\n".to_vec(),
        refs: vec![],
        attach: vec![],
        expires: None,
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Inbound (audit item 1): an 8-bit ISO-8859-1 DATA payload crosses the whole inbound pipeline
//    (line feed → dot-unstuffing → DKIM verify → MOTE seal) byte-exact. The message is DKIM-signed
//    by the "sender's MTA" over the ORIGINAL Latin-1 bytes and the gateway runs
//    DkimPolicy::Enforce, so the 250 below is only reachable if the gateway's verification hashed
//    exactly those bytes — the pre-fix lossy path turned 0xE9 into U+FFFD before verification,
//    which under Enforce bounced the message (550) and corrupted the stored copy.
// ---------------------------------------------------------------------------------------------

#[test]
fn latin1_data_survives_inbound_byte_exact_and_dkim_verifies_under_enforce() {
    // Raw ISO-8859-1 bytes (NOT valid UTF-8): "café" = 63 61 66 E9, "über" = FC 62 65 72.
    let body: Vec<u8> =
        [&b"Bonjour le caf"[..], &[0xE9], &b" \r\net l'"[..], &[0xFC], &b"ber-gateway.\r\n"[..]]
            .concat();
    let mut msg: Vec<u8> = format!(
        "From: sender@legacy-sender.example\r\nTo: alice@{DOMAIN}\r\n\
         Subject: salut\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n"
    )
    .into_bytes();
    msg.extend_from_slice(&body);

    // The sender's MTA signs the exact 8-bit bytes (RFC 8463 ed25519-sha256, relaxed/relaxed).
    let sender_key = dkim_key("legacy-sender.example", "s1");
    let sender_pub = sender_key.public_bytes();
    let mut signed = dkim::sign(&sender_key, &msg, NOW / 1000).into_bytes();
    signed.extend_from_slice(&msg);

    // Sanity: our own verifier passes over the original bytes...
    let resolver =
        StaticDkimKeys::new().publish("legacy-sender.example", "s1", sender_pub.to_vec());
    let recip = TestRecipient::new(&format!("alice@{DOMAIN}"));
    let delivery = Arc::new(CapturingDelivery { captured: Mutex::new(None) });
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![AttestationKey::generate(DOMAIN, GW_SELECTOR)],
        Box::new(OneUser { email: recip.email.clone(), key: recip.recipient_key() }),
        Box::new(ArcDelivery(delivery.clone())),
        Box::new(AllowAll),
    )
    .with_dkim(Box::new(resolver), DkimPolicy::Enforce);
    assert!(
        matches!(gw.verify_inbound_dkim(&signed), DkimVerdict::Pass { .. }),
        "byte-based canonicalization verifies the 8-bit message"
    );
    // ...and FAILS over the lossy-mangled copy (each 0xE9/0xFC → U+FFFD), which is exactly what
    // the pre-fix line reader fed it: this pins WHY the byte path matters.
    let mangled = String::from_utf8_lossy(&signed).into_owned().into_bytes();
    assert!(
        matches!(gw.verify_inbound_dkim(&mangled), DkimVerdict::Fail(_)),
        "the U+FFFD-corrupted copy must NOT verify — the bytes are not the message"
    );

    // Drive the MX session over the RAW line-byte entry point, dot-stuffed like a real client.
    let mut s = MxSession::new(&gw, "203.0.113.9", NOW);
    assert_eq!(s.feed_line("EHLO legacy-sender.example").code, 250);
    assert_eq!(s.feed_line("MAIL FROM:<sender@legacy-sender.example>").code, 250);
    assert_eq!(s.feed_line(&format!("RCPT TO:<{}>", recip.email)).code, 250);
    assert_eq!(s.feed_line("DATA").code, 354);
    let mut lines: Vec<&[u8]> =
        signed.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).collect();
    // The message ends with CRLF, so the split leaves one empty tail that is not a wire line
    // (interior empty lines — the header/body separator — are kept and fed).
    assert_eq!(lines.pop(), Some(&b""[..]));
    for line in lines {
        let mut stuffed: Vec<u8> = Vec::with_capacity(line.len() + 1);
        if line.first() == Some(&b'.') {
            stuffed.push(b'.');
        }
        stuffed.extend_from_slice(line);
        assert_eq!(s.feed_line_bytes(&stuffed).code, 0, "no reply mid-DATA");
    }
    let final_reply = s.feed_line_bytes(b".");
    assert_eq!(
        final_reply.code, 250,
        "DKIM Enforce + published key: only a byte-exact reassembly (verdict Pass) reaches 250; \
         got {final_reply:?}"
    );

    // The sealed MOTE carries the ORIGINAL Latin-1 body bytes — no U+FFFD (EF BF BD), no
    // UTF-8-re-encoded C3 A9.
    let (env, _att) = delivery.captured.lock().unwrap().clone().expect("delivered");
    let ctx = RecipientCtx {
        our_ik: &recip.ik.public(),
        seal_secret: recip.seal.secret(),
        sender_is_known: true,
    };
    let payload = match validate(&Hpke, &env, &ctx).expect("validate") {
        Outcome::Accepted(p) => *p,
        Outcome::Deferred => panic!("known-contact MOTE must be accepted"),
    };
    assert_eq!(payload.body, body, "body bytes are exactly the sender's ISO-8859-1 bytes");
    assert!(
        !payload.body.windows(3).any(|w| w == [0xEF, 0xBF, 0xBD]),
        "no U+FFFD replacement bytes anywhere in the stored body"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. Outbound DNS (audit item 2): an IDN destination's MX query goes out with the PUNYCODED qname
//    on the wire — asserted on the actual UDP datagram bytes — and never the raw UTF-8 label.
// ---------------------------------------------------------------------------------------------

#[test]
fn idn_mx_query_carries_punycoded_qname_on_the_wire() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind fake DNS");
    let addr = server.local_addr().expect("addr");
    server.set_read_timeout(Some(Duration::from_secs(10))).ok();

    let captured_query: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let captured2 = captured_query.clone();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let (n, peer) = match server.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => return,
        };
        let query = buf[..n].to_vec();
        *captured2.lock().unwrap() = query.clone();
        // Minimal well-formed response: echo id + question, answer "10 mail.example.net" with the
        // owner name compressed back to the question (offset 12).
        let mut resp = Vec::new();
        resp.extend_from_slice(&query[..2]); // id
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RD+RA, NOERROR
        resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        resp.extend_from_slice(&1u16.to_be_bytes()); // ancount
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..n]); // question section verbatim
        resp.extend_from_slice(&[0xC0, 12]); // owner = pointer to qname
        resp.extend_from_slice(&15u16.to_be_bytes()); // TYPE MX
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&10u16.to_be_bytes()); // preference
        for label in ["mail", "example", "net"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        let _ = server.send_to(&resp, peer);
    });

    let hosts =
        DnsMxResolver::new(addr).with_timeout(Duration::from_secs(10)).resolve_mx("bücher.example");
    handle.join().expect("fake DNS thread");

    let query = captured_query.lock().unwrap().clone();
    assert!(!query.is_empty(), "the resolver actually queried the fake DNS server");
    // The qname on the wire is the A-label form: length-13 label "xn--bcher-kva"...
    let mut expected_label = vec![13u8];
    expected_label.extend_from_slice(b"xn--bcher-kva");
    assert!(
        query.windows(expected_label.len()).any(|w| w == expected_label),
        "wire query must carry the punycoded label, got {query:02x?}"
    );
    // ...and never the raw UTF-8 spelling (`ü` = C3 BC).
    assert!(
        !query.windows(2).any(|w| w == [0xC3, 0xBC]),
        "raw UTF-8 label bytes must never reach the DNS wire"
    );
    assert_eq!(
        hosts,
        vec![MxHost { host: "mail.example.net".into(), preference: 10 }],
        "the punycoded query resolves normally"
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Outbound (audit item 2): a destination domain with NO valid A-label spelling is a specific,
//    diagnosable permanent error — at both the gateway and the raw transport — and never the
//    opaque TlsUnavailable it used to drown in. Nothing is ever dialed.
// ---------------------------------------------------------------------------------------------

#[test]
fn unspellable_destination_domain_is_a_specific_error_not_a_tls_abort() {
    // Gateway level: refused before MX resolution / transport, with the offending domain named.
    let transport = Arc::new(RecordingTransport::new());
    struct ArcTransport(Arc<RecordingTransport>);
    impl OutboundTransport for ArcTransport {
        fn deliver(&self, d: &str, m: &[u8], t: bool) -> TransportResult {
            self.0.deliver(d, m, t)
        }
    }
    let gw = OutboundGateway::new(
        vec![dkim_key("alice-domain.com", "dmtap1")],
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(ArcTransport(transport.clone())),
    );
    let report = gw.send(&sample_payload("hi"), "alice@alice-domain.com", "bob@exa mple.bad", NOW);
    match report {
        OutboundReport::Failed(OutboundError::IdnNotConvertible(domain, _reason)) => {
            assert_eq!(domain, "exa mple.bad", "the error names the unspellable domain");
        }
        other => panic!("expected IdnNotConvertible, got {other:?}"),
    }
    assert!(
        transport.dialed.lock().unwrap().is_empty(),
        "an unspellable domain must never reach the transport"
    );

    // Transport level (defense in depth for direct users): specific 553 5.1.2, not TlsUnavailable,
    // and no socket is ever opened (there is no server behind this test).
    let t = SmtpTcpTransport::new("gateway.test")
        .with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
    match t.deliver("exa mple.bad", b"From: a@b.c\r\nTo: d@e.f\r\n\r\nx\r\n", true) {
        TransportResult::Permanent { code, text } => {
            assert_eq!(code, 553);
            assert!(text.contains("5.1.2"), "enhanced status names the address problem: {text}");
            assert!(
                text.contains("IDNA") || text.contains("A-label"),
                "the reason is diagnosable, not generic: {text}"
            );
        }
        other => panic!("expected a specific Permanent error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Outbound render (audit item 3): non-ASCII Subject / display-names / IDN domains reach the
//    legacy wire as pure-ASCII RFC 2047 encoded-words + A-label domains, and DKIM signs the FINAL
//    encoded bytes (verify passes over exactly what would hit the socket).
// ---------------------------------------------------------------------------------------------

#[test]
fn outbound_headers_are_rfc2047_encoded_ascii_and_dkim_signs_the_final_bytes() {
    let key = dkim_key("alice-domain.com", "dmtap1");
    let pubk = key.public_bytes();
    let gw = OutboundGateway::new(
        vec![key],
        Box::new(FixedTls(TlsRequirement::Required)),
        Box::new(RecordingTransport::new()),
    );
    let payload = sample_payload("Réunion — 会議メモ ✓");
    let signed = gw
        .translate_and_sign(
            &payload,
            "Älice Müller <alice@alice-domain.com>",
            "Bøb <bob@bücher.example>",
            NOW,
        )
        .expect("translate + sign");

    // The whole header block is wire-safe ASCII: strict MTAs never see a raw 8-bit header byte.
    let head_end = signed.windows(4).position(|w| w == b"\r\n\r\n").expect("header/body separator");
    let head = &signed[..head_end];
    assert!(
        head.iter().all(|&b| b < 0x80),
        "header block must be pure ASCII, got {:?}",
        String::from_utf8_lossy(head)
    );
    let head_text = std::str::from_utf8(head).expect("ASCII header block");
    assert!(head_text.contains("=?UTF-8?B?"), "non-ASCII values are RFC 2047 encoded-words");
    assert!(
        head_text.contains("bob@xn--bcher-kva.example"),
        "the IDN recipient domain is A-labeled in To:, got:\n{head_text}"
    );
    // Round trip: the encoded Subject decodes back to the author's text.
    let parsed = dmtap_mail::mime::ParsedMessage::parse(&signed);
    let subject = parsed.header("Subject").map(dmtap_mail::mime::decode_encoded_words);
    assert_eq!(subject.as_deref(), Some("Réunion — 会議メモ ✓"));

    // DKIM was computed over the final (encoded) bytes: an independent verify passes verbatim.
    dkim::verify(&signed, &pubk).expect("DKIM must verify over the exact emitted bytes");
}

// ---------------------------------------------------------------------------------------------
// 5. Outbound transport EAI posture (audit item 4): SMTPUTF8/8BITMIME needs are checked against
//    the peer's actual EHLO capabilities — specific, correctly-permanent failures when absent,
//    explicit MAIL parameters when present, and the lossless negotiate-down (no parameter at all)
//    for messages that never needed the extension.
// ---------------------------------------------------------------------------------------------

/// A capability-configurable plaintext mini MX that records the MAIL line it saw (if any).
fn spawn_caps_mx(caps: &'static [&'static str]) -> (SocketAddr, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mail_line: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mail2 = mail_line.clone();
    thread::spawn(move || {
        let (stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(_) => return,
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut w = stream.try_clone().expect("clone");
        let mut r = BufReader::new(stream);
        let send = |w: &mut TcpStream, s: &str| {
            let _ = w.write_all(s.as_bytes());
            let _ = w.flush();
        };
        send(&mut w, "220 caps-mx ready\r\n");
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let verb = line.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => {
                    let mut reply = String::from("250-caps-mx\r\n");
                    for c in caps {
                        reply.push_str(&format!("250-{c}\r\n"));
                    }
                    reply.push_str("250 OK\r\n");
                    send(&mut w, &reply);
                }
                "MAIL" => {
                    *mail2.lock().unwrap() = Some(line.trim_end().to_string());
                    send(&mut w, "250 2.1.0 sender ok\r\n");
                }
                "RCPT" => send(&mut w, "250 2.1.5 recipient ok\r\n"),
                "DATA" => {
                    send(&mut w, "354 go ahead\r\n");
                    loop {
                        let mut dl = String::new();
                        if r.read_line(&mut dl).unwrap_or(0) == 0 {
                            return;
                        }
                        if dl == ".\r\n" || dl == ".\n" {
                            break;
                        }
                    }
                    send(&mut w, "250 2.6.0 done\r\n");
                }
                "QUIT" => {
                    send(&mut w, "221 2.0.0 bye\r\n");
                    break;
                }
                _ => send(&mut w, "250 2.0.0 ok\r\n"),
            }
        }
    });
    (addr, mail_line)
}

fn transport_to(addr: SocketAddr) -> SmtpTcpTransport {
    SmtpTcpTransport::new("gateway.test")
        .with_fixed_addr(addr)
        .with_timeouts(Duration::from_secs(10), Duration::from_secs(10))
}

#[test]
fn smtputf8_needed_but_not_advertised_is_a_specific_permanent_failure() {
    // Non-ASCII LOCAL PART: genuinely needs SMTPUTF8 (a domain would have been A-labeled away).
    // The peer offers 8BITMIME but not SMTPUTF8, so the SMTPUTF8 gate is the decisive one.
    let (addr, mail_line) = spawn_caps_mx(&["8BITMIME"]);
    let msg = "From: alice@alice-domain.com\r\nTo: <bøb@dest.example>\r\nSubject: hi\r\n\r\nx\r\n";
    let result = transport_to(addr).deliver("dest.example", msg.as_bytes(), false);
    match result {
        TransportResult::Permanent { code, text } => {
            assert_eq!(code, 553);
            assert!(text.contains("SMTPUTF8"), "the failure names SMTPUTF8: {text}");
            assert!(text.contains("5.6.7"), "RFC 6531 enhanced status: {text}");
        }
        other => panic!("expected the specific SMTPUTF8 permanent failure, got {other:?}"),
    }
    assert!(
        mail_line.lock().unwrap().is_none(),
        "MAIL must never be attempted with an address the peer cannot carry"
    );
}

#[test]
fn eight_bit_body_but_no_8bitmime_is_a_specific_permanent_failure() {
    let (addr, mail_line) = spawn_caps_mx(&[]);
    // ASCII envelope/headers, 8-bit (UTF-8) body: needs 8BITMIME, not SMTPUTF8.
    let msg =
        "From: alice@alice-domain.com\r\nTo: <bob@dest.example>\r\nSubject: hi\r\n\r\ncafé\r\n";
    let result = transport_to(addr).deliver("dest.example", msg.as_bytes(), false);
    match result {
        TransportResult::Permanent { code, text } => {
            assert_eq!(code, 554);
            assert!(text.contains("8BITMIME"), "the failure names 8BITMIME: {text}");
            assert!(text.contains("5.6.3"), "conversion-not-supported enhanced status: {text}");
        }
        other => panic!("expected the specific 8BITMIME permanent failure, got {other:?}"),
    }
    assert!(mail_line.lock().unwrap().is_none(), "no MAIL for a body the peer refused to carry");
}

#[test]
fn advertised_extensions_are_requested_explicitly_and_ascii_needs_nothing() {
    // Peer advertises both: the transport asks for exactly what the message needs.
    let (addr, mail_line) = spawn_caps_mx(&["8BITMIME", "SMTPUTF8"]);
    let msg =
        "From: alice@alice-domain.com\r\nTo: <bøb@dest.example>\r\nSubject: hi\r\n\r\ncafé\r\n";
    let result = transport_to(addr).deliver("dest.example", msg.as_bytes(), false);
    assert_eq!(result, TransportResult::Delivered { code: 250 });
    let mail = mail_line.lock().unwrap().clone().expect("MAIL was sent");
    assert!(mail.contains(" SMTPUTF8"), "SMTPUTF8 requested: {mail}");
    assert!(mail.contains(" BODY=8BITMIME"), "BODY=8BITMIME requested: {mail}");

    // The lossless negotiate-down: a pure-ASCII message asks for nothing, so a bare-bones peer
    // (no extensions at all) still receives it.
    let (addr, mail_line) = spawn_caps_mx(&[]);
    let msg = "From: alice@alice-domain.com\r\nTo: <bob@dest.example>\r\nSubject: hi\r\n\r\nx\r\n";
    let result = transport_to(addr).deliver("dest.example", msg.as_bytes(), false);
    assert_eq!(result, TransportResult::Delivered { code: 250 });
    let mail = mail_line.lock().unwrap().clone().expect("MAIL was sent");
    assert!(
        !mail.contains("SMTPUTF8") && !mail.contains("BODY="),
        "an ASCII 7-bit message requests no extensions: {mail}"
    );
}
