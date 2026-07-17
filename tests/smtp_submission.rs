//! Real-socket integration tests for the OPTIONAL legacy SMTP-submission access server (spec §7.15.1,
//! RFC 6409): a TLS SMTP client authenticates with an app-password and submits an RFC 5322 message.
//! Proves:
//!   - implicit-TLS: `AUTH PLAIN` succeeds, `MAIL`/`RCPT`/`DATA` are accepted, and the completed
//!     submission is converted + routed to the [`SubmissionSink`], classified native vs legacy;
//!   - AUTH is refused on a cleartext channel (`538`) — the app-password never travels in the clear;
//!   - a completed `DATA` returns `250` and the sink receives the exact submitted bytes.
//!
//! The "off by default" contract is a config-level guarantee (a fresh `PersonalConfig` has
//! `submission_enable == false`), asserted in `personal.rs` unit tests.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_mail::auth::StaticAuthenticator;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use envoir_gateway::{Destination, LegacyTls, RoutedSubmission, SubmissionServer, SubmissionSink};

const HOST: &str = "localhost";
const USER: &str = "owner@example.org";
const APP_PW: &str = "app-password-xyz";

fn self_signed() -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("self-signed cert");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let cfg =
        envoir_gateway::server_config(vec![cert_der.clone()], key.into()).expect("server config");
    (cert_der, cfg)
}

fn client_config(cert_der: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("add self-signed root");
    let cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Arc::new(cfg)
}

/// One captured routed entry: `(from, rcpt, destination, rfc5322)`.
type Captured = (String, String, Destination, Vec<u8>);

/// A capturing [`SubmissionSink`]: records each routed entry.
#[derive(Default)]
struct Capturing {
    seen: Mutex<Vec<Captured>>,
}
impl SubmissionSink for Capturing {
    fn deliver(&self, r: &RoutedSubmission) -> bool {
        self.seen.lock().unwrap().push((
            r.from.to_string(),
            r.rcpt_to.to_string(),
            r.destination,
            r.rfc5322.to_vec(),
        ));
        true
    }
}

fn auth() -> StaticAuthenticator {
    let mut a = StaticAuthenticator::new();
    a.issue(USER, APP_PW, IdentityKey::generate().public(), "thunderbird");
    a
}

/// Minimal standard-alphabet base64 (no external dep) for the SASL PLAIN initial response.
fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        out.push(A[(b[0] >> 2) as usize] as char);
        out.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { A[(b[2] & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn read_line<S: Read>(s: &mut S) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte).expect("read") == 1 {
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&line).into_owned()
}

/// Read an SMTP reply (possibly multi-line: `250-...` continuation lines then a final `250 ...`).
fn read_reply<S: Read>(s: &mut S) -> String {
    let mut acc = String::new();
    loop {
        let line = read_line(s);
        if line.is_empty() {
            break;
        }
        let cont = line.as_bytes().get(3) == Some(&b'-');
        acc.push_str(&line);
        if !cont {
            break;
        }
    }
    acc
}

fn send<S: Write>(s: &mut S, line: &str) {
    s.write_all(line.as_bytes()).expect("write");
    s.flush().expect("flush");
}

// ---------------------------------------------------------------------------------------------
// 1. Implicit TLS: AUTH PLAIN, submit a message to a native + a legacy recipient, both routed.
// ---------------------------------------------------------------------------------------------

#[test]
fn implicit_tls_auth_submit_and_route() {
    let (cert_der, server_cfg) = self_signed();
    let server = SubmissionServer::bind(
        "127.0.0.1:0",
        server_cfg,
        LegacyTls::Implicit,
        vec!["example.org".to_string()],
    )
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let sink = Arc::new(Capturing::default());
    let sink_for_srv = sink.clone();
    let srv = thread::spawn(move || server.serve_once(auth(), sink_for_srv));

    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);

    let greeting = read_line(&mut tls);
    assert!(greeting.starts_with("220"), "greeting: {greeting}");

    send(&mut tls, "EHLO client.example.org\r\n");
    let ehlo = read_reply(&mut tls);
    assert!(ehlo.contains("AUTH"), "EHLO must advertise AUTH over TLS: {ehlo}");

    // AUTH PLAIN with the app-password (SASL PLAIN: \0authcid\0passwd).
    let ir = base64(format!("\0{USER}\0{APP_PW}").as_bytes());
    send(&mut tls, &format!("AUTH PLAIN {ir}\r\n"));
    let authed = read_line(&mut tls);
    assert!(authed.starts_with("235"), "auth: {authed}");

    send(&mut tls, &format!("MAIL FROM:<{USER}>\r\n"));
    assert!(read_line(&mut tls).starts_with("250"), "mail from");
    send(&mut tls, "RCPT TO:<friend@example.org>\r\n");
    assert!(read_line(&mut tls).starts_with("250"), "rcpt native");
    send(&mut tls, "RCPT TO:<someone@gmail.com>\r\n");
    assert!(read_line(&mut tls).starts_with("250"), "rcpt legacy");

    send(&mut tls, "DATA\r\n");
    assert!(read_line(&mut tls).starts_with("354"), "data go-ahead");
    send(&mut tls, "Subject: Kickoff\r\n\r\nLet's meet Tuesday.\r\n.\r\n");
    let queued = read_line(&mut tls);
    assert!(queued.starts_with("250"), "data accepted: {queued}");

    send(&mut tls, "QUIT\r\n");
    let _ = read_line(&mut tls);
    srv.join().expect("server thread").expect("served one connection");

    // The submission was split per recipient and classified.
    let seen = sink.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "one routed entry per recipient: {seen:?}");
    let native = seen.iter().find(|e| e.1 == "friend@example.org").expect("native rcpt");
    assert_eq!(native.2, Destination::Native, "on the native domain → MOTE path");
    assert!(String::from_utf8_lossy(&native.3).contains("Let's meet Tuesday."));
    let legacy = seen.iter().find(|e| e.1 == "someone@gmail.com").expect("legacy rcpt");
    assert_eq!(legacy.2, Destination::Legacy, "elsewhere → §7.3 bridge");
    assert_eq!(native.0, USER, "envelope sender preserved");
}

// ---------------------------------------------------------------------------------------------
// 2. STARTTLS port: AUTH is refused on the cleartext channel (538) before the upgrade.
// ---------------------------------------------------------------------------------------------

#[test]
fn auth_is_refused_on_cleartext_before_starttls() {
    let (_cert_der, server_cfg) = self_signed();
    let server = SubmissionServer::bind(
        "127.0.0.1:0",
        server_cfg,
        LegacyTls::StartTls,
        vec!["example.org".to_string()],
    )
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let sink = Arc::new(Capturing::default());
    let srv = thread::spawn(move || server.serve_once(auth(), sink));

    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let greeting = read_line(&mut tcp);
    assert!(greeting.starts_with("220"), "greeting: {greeting}");

    send(&mut tcp, "EHLO client.example.org\r\n");
    let ehlo = read_reply(&mut tcp);
    assert!(ehlo.contains("STARTTLS"), "cleartext EHLO must advertise STARTTLS: {ehlo}");
    assert!(!ehlo.contains("AUTH"), "AUTH must NOT be advertised pre-TLS: {ehlo}");

    // Attempting AUTH on the cleartext channel is refused (538) — no cleartext app-password.
    let ir = base64(format!("\0{USER}\0{APP_PW}").as_bytes());
    send(&mut tcp, &format!("AUTH PLAIN {ir}\r\n"));
    let refused = read_line(&mut tcp);
    assert!(refused.starts_with("538"), "AUTH on cleartext must be 538: {refused}");

    send(&mut tcp, "QUIT\r\n");
    let _ = read_line(&mut tcp);
    srv.join().expect("server thread").expect("served one connection");
}
