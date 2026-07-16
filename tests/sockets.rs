//! Real-socket integration tests for the gateway (spec §7): the concrete inbound `TcpListener` MX
//! and the concrete outbound SMTP-over-STARTTLS client, driven against each other (and tiny in-test
//! SMTP servers) over `127.0.0.1`. Proves:
//!   - EHLO → STARTTLS → DATA delivers end-to-end, and the inbound socket path produces the same
//!     attested, recipient-sealed MOTE as the in-process `accept_message` tests;
//!   - a TLS-required peer that offers no STARTTLS is REFUSED, never downgraded to cleartext;
//!   - destination reply codes 250 / 451 / 550 map to Delivered / Transient / Permanent.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::{validate, Envelope, Hpke, Kind, Outcome, RecipientCtx, SealKeypair};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use envoir_gateway::attestation::{Attestation, AttestationKey, GwKeyResolver, StaticGwKeys};
use envoir_gateway::inbound::{
    AbuseDecision, AntiAbuse, DeliveryOutcome, InboundGateway, KeyDirectory, MeshDelivery,
    RecipientKey,
};
use envoir_gateway::outbound::{OutboundTransport, TransportResult};
use envoir_gateway::{MxListener, SmtpTcpTransport};

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
        TestRecipient { email: email.into(), ik: IdentityKey::generate(), seal: SealKeypair::generate() }
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
    outcome: DeliveryOutcome,
    captured: Mutex<Option<(Envelope, Attestation)>>,
}
impl MeshDelivery for CapturingDelivery {
    fn deliver(&self, env: &Envelope, att: &Attestation) -> DeliveryOutcome {
        *self.captured.lock().unwrap() = Some((env.clone(), att.clone()));
        self.outcome
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

/// A self-signed cert for `DOMAIN` plus the matching inbound TLS server config.
fn self_signed() -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![DOMAIN.to_string()]).expect("self-signed cert");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let cfg = envoir_gateway::server_config(vec![cert_der.clone()], key.into())
        .expect("server config");
    (cert_der, cfg)
}

fn sample_message(to: &str) -> Vec<u8> {
    format!(
        "From: sender@gmail.com\r\nTo: {to}\r\nSubject: hello from legacy\r\n\r\nGreetings across the bridge.\r\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------------------------
// 1. Full loopback: EHLO → STARTTLS → DATA delivers, and the socket path yields the same attested,
//    recipient-sealed MOTE the in-process pipeline produces.
// ---------------------------------------------------------------------------------------------

#[test]
fn loopback_starttls_delivers_and_produces_attested_mote() {
    let recip = TestRecipient::new("alice@example.org");
    let att_key = AttestationKey::generate(DOMAIN, GW_SELECTOR);
    let att_pub = att_key.public();
    let delivery = Arc::new(CapturingDelivery {
        outcome: DeliveryOutcome::Acked,
        captured: Mutex::new(None),
    });
    let gw = InboundGateway::new(
        IdentityKey::generate(),
        vec![att_key],
        Box::new(OneUser { email: recip.email.clone(), key: recip.recipient_key() }),
        Box::new(ArcDelivery(delivery.clone())),
        Box::new(AllowAll),
    );

    let (cert_der, server_cfg) = self_signed();
    let listener = MxListener::bind("127.0.0.1:0", Some(server_cfg)).expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Client runs in a thread (gateway stays in the main thread — it is not Send).
    let msg = sample_message(&recip.email);
    let client = thread::spawn(move || {
        let transport = SmtpTcpTransport::with_test_root("gateway.test", cert_der)
            .with_fixed_addr(addr)
            .with_timeouts(Duration::from_secs(10), Duration::from_secs(10));
        // require_tls = true: this send MUST go over the negotiated STARTTLS channel.
        transport.deliver(DOMAIN, &msg, true)
    });

    listener.serve_once(&gw, NOW).expect("serve one connection");
    let result = client.join().expect("client thread");
    assert_eq!(result, TransportResult::Delivered { code: 250 }, "STARTTLS DATA delivered → 250");

    // The inbound socket path built a MOTE and handed it to the mesh.
    let (env, attestation) = delivery.captured.lock().unwrap().clone().expect("a MOTE was delivered");

    // It is addressed to the recipient's identity key and is a mail MOTE.
    assert!(env.to.resolves_to_key(&recip.ik.public()), "sealed to the recipient key");
    assert_eq!(env.kind, Kind::Mail);

    // The recipient can decrypt it and it carries the original legacy body — identical semantics to
    // the in-process `accept_message` tests.
    let ctx = RecipientCtx {
        our_ik: &recip.ik.public(),
        seal_secret: recip.seal.secret(),
        sender_is_known: true,
    };
    let payload = match validate(&Hpke, &env, &ctx).expect("validate") {
        Outcome::Accepted(p) => *p,
        Outcome::Deferred => panic!("known-contact MOTE must be accepted"),
    };
    assert!(
        String::from_utf8_lossy(&payload.body).contains("Greetings across the bridge"),
        "original legacy body carried through the socket path"
    );
    assert_eq!(payload.headers.subject.as_deref(), Some("hello from legacy"));

    // The attestation is domain-anchored, bound to THIS MOTE and the SMTP envelope, and verifies
    // under the domain-published key.
    assert_eq!(attestation.mote_id, env.id);
    // MxSession keeps the SMTP envelope `MAIL FROM` verbatim (angle brackets and all); the socket
    // path preserves it faithfully.
    assert!(
        attestation.smtp_mail_from.contains("sender@gmail.com"),
        "attested SMTP MAIL FROM carries the envelope sender, got {:?}",
        attestation.smtp_mail_from
    );
    assert_eq!(attestation.smtp_rcpt_to, recip.email);
    let published: StaticGwKeys = StaticGwKeys::new().publish(DOMAIN, GW_SELECTOR, att_pub);
    let key = published.resolve_gw_key(DOMAIN, &attestation.selector);
    assert!(
        attestation.verify(DOMAIN, key.as_deref(), &env.id).is_ok(),
        "socket-path attestation verifies under the domain-anchored key"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. TLS required + peer offers no STARTTLS → REFUSED, never downgraded to cleartext.
// ---------------------------------------------------------------------------------------------

#[test]
fn tls_required_but_no_starttls_is_refused_not_downgraded() {
    let saw_mail = Arc::new(AtomicBool::new(false));
    let (addr, _srv) = spawn_mini_mx(MiniMxScript {
        offer_starttls: false,
        final_code: 250,
        saw_mail: saw_mail.clone(),
    });

    let transport = SmtpTcpTransport::new("gateway.test")
        .with_fixed_addr(addr)
        .with_timeouts(Duration::from_secs(10), Duration::from_secs(10));
    // require_tls = true, but the peer never advertises STARTTLS → must abort.
    let result = transport.deliver("plain-mx.test", &sample_message("bob@plain-mx.test"), true);

    assert_eq!(result, TransportResult::TlsUnavailable, "no STARTTLS under required TLS → abort");
    // Crucially, the transport never proceeded to send the message in cleartext.
    assert!(!saw_mail.load(Ordering::SeqCst), "must NOT have sent MAIL/DATA in cleartext");
}

// ---------------------------------------------------------------------------------------------
// 3. Reply-code → TransportResult mapping (250 / 451 / 550).
// ---------------------------------------------------------------------------------------------

#[test]
fn reply_code_mapping_delivered_transient_permanent() {
    for (code, expect) in [
        (250u16, TransportResult::Delivered { code: 250 }),
        (451u16, TransportResult::Transient { code: 451, text: "done".into() }),
        (550u16, TransportResult::Permanent { code: 550, text: "done".into() }),
    ] {
        let saw_mail = Arc::new(AtomicBool::new(false));
        let (addr, _srv) = spawn_mini_mx(MiniMxScript {
            offer_starttls: false,
            final_code: code,
            saw_mail: saw_mail.clone(),
        });
        let transport = SmtpTcpTransport::new("gateway.test")
            .with_fixed_addr(addr)
            .with_timeouts(Duration::from_secs(10), Duration::from_secs(10));
        // Opportunistic (require_tls = false): peer offers no STARTTLS, so cleartext is allowed.
        let result = transport.deliver("code-mx.test", &sample_message("bob@code-mx.test"), false);
        assert_eq!(result, expect, "final reply {code} maps correctly");
        assert!(saw_mail.load(Ordering::SeqCst), "the message reached the DATA stage");
    }
}

// --- a tiny in-test SMTP server -------------------------------------------------------------

struct MiniMxScript {
    offer_starttls: bool,
    final_code: u16,
    saw_mail: Arc<AtomicBool>,
}

/// Spawn a one-shot plaintext SMTP server on `127.0.0.1:0`; returns its address + join handle.
fn spawn_mini_mx(script: MiniMxScript) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mini bind");
    let addr = listener.local_addr().expect("mini addr");
    let handle = thread::spawn(move || {
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
        send(&mut w, "220 mini-mx ready\r\n");
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let verb = line.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => {
                    if script.offer_starttls {
                        send(&mut w, "250-mini-mx\r\n250 STARTTLS\r\n");
                    } else {
                        send(&mut w, "250 mini-mx\r\n");
                    }
                }
                "STARTTLS" => send(&mut w, "502 5.5.1 not really\r\n"),
                "MAIL" => {
                    script.saw_mail.store(true, Ordering::SeqCst);
                    send(&mut w, "250 2.1.0 sender ok\r\n");
                }
                "RCPT" => send(&mut w, "250 2.1.5 recipient ok\r\n"),
                "DATA" => {
                    send(&mut w, "354 go ahead\r\n");
                    // Consume the body until the lone-dot terminator.
                    loop {
                        let mut dl = String::new();
                        if r.read_line(&mut dl).unwrap_or(0) == 0 {
                            return;
                        }
                        if dl == ".\r\n" || dl == ".\n" {
                            break;
                        }
                    }
                    send(&mut w, &format!("{} done\r\n", script.final_code));
                }
                "QUIT" => {
                    send(&mut w, "221 2.0.0 bye\r\n");
                    break;
                }
                _ => send(&mut w, "250 2.0.0 ok\r\n"),
            }
        }
    });
    (addr, handle)
}
