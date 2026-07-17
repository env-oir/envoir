//! Real-socket integration tests for the OPTIONAL legacy POP3 access server (spec §7.15.1, RFC 1939):
//! a TLS POP3 client authenticates over TLS to the gateway's [`Pop3AccessServer`] and downloads a
//! seeded maildrop. Proves:
//!   - implicit-TLS: a valid app-password logs in (`USER`/`PASS`) and RETRs a seeded message;
//!   - a wrong app-password is refused fail-closed (`-ERR`);
//!   - STLS: the cleartext port advertises `STLS`, upgrades in place, then serves the session over TLS;
//!   - the server is store-backed by the operator's mailbox snapshot (a seeded `MemoryStore`).
//!
//! The "off by default" contract is a config-level guarantee, asserted in `personal.rs` unit tests
//! (a fresh `PersonalConfig` has `pop3_enable == false`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dmtap_core::identity::IdentityKey;
use dmtap_mail::auth::StaticAuthenticator;
use dmtap_mail::store::MemoryStore;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use envoir_gateway::{LegacyTls, Pop3AccessServer};

const HOST: &str = "localhost";
const USER: &str = "owner@dmtap.local";
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

/// A store seeded with two messages in INBOX (the operator's mailbox snapshot) + owner credentials.
fn seed() -> (MemoryStore, StaticAuthenticator) {
    let mut store = MemoryStore::new();
    store.deliver_raw(
        "INBOX",
        b"Subject: First\r\nFrom: a@example.com\r\n\r\nhello one\r\n".to_vec(),
        vec![],
        1_752_000_000_000,
    );
    store.deliver_raw(
        "INBOX",
        b"Subject: Second\r\nFrom: b@example.com\r\n\r\nhello two\r\n".to_vec(),
        vec![],
        1_752_000_001_000,
    );
    let mut auth = StaticAuthenticator::new();
    auth.issue(USER, APP_PW, IdentityKey::generate().public(), "thunderbird");
    (store, auth)
}

/// Read one CRLF line, byte-at-a-time (so no bytes are consumed past it — important across STLS).
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

/// Send a single-line command and read exactly one response line (for +OK/-ERR single-line replies).
fn cmd_line<S: Read + Write>(s: &mut S, cmd: &str) -> String {
    s.write_all(cmd.as_bytes()).expect("write");
    s.flush().expect("flush");
    read_line(s)
}

/// Send a command whose reply is a multi-line block terminated by a lone `.` line (RETR/LIST); return
/// the whole block.
fn cmd_multiline<S: Read + Write>(s: &mut S, cmd: &str) -> String {
    s.write_all(cmd.as_bytes()).expect("write");
    s.flush().expect("flush");
    let mut acc = String::new();
    loop {
        let line = read_line(s);
        if line.is_empty() {
            break;
        }
        acc.push_str(&line);
        if line == ".\r\n" {
            break;
        }
    }
    acc
}

// ---------------------------------------------------------------------------------------------
// 1. Implicit TLS: a valid app-password logs in and downloads the seeded maildrop (STAT/RETR).
// ---------------------------------------------------------------------------------------------

#[test]
fn implicit_tls_login_stat_retr() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        Pop3AccessServer::bind("127.0.0.1:0", server_cfg, LegacyTls::Implicit).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);

    let greeting = read_line(&mut tls);
    assert!(greeting.starts_with("+OK"), "greeting: {greeting}");

    assert!(cmd_line(&mut tls, &format!("USER {USER}\r\n")).starts_with("+OK"));
    let pass = cmd_line(&mut tls, &format!("PASS {APP_PW}\r\n"));
    assert!(pass.starts_with("+OK"), "pass: {pass}");

    // STAT reports 2 messages; RETR 1 returns the seeded body over TLS.
    let stat = cmd_line(&mut tls, "STAT\r\n");
    assert!(stat.starts_with("+OK 2 "), "stat: {stat}");
    let retr = cmd_multiline(&mut tls, "RETR 1\r\n");
    assert!(retr.contains("hello one"), "retr: {retr}");
    assert!(retr.contains("Subject: First"), "retr headers: {retr}");

    let _ = cmd_line(&mut tls, "QUIT\r\n");
    srv.join().expect("server thread").expect("served one connection");
}

// ---------------------------------------------------------------------------------------------
// 2. A wrong app-password is refused fail-closed (-ERR, never +OK into Transaction state).
// ---------------------------------------------------------------------------------------------

#[test]
fn bad_password_is_rejected_fail_closed() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        Pop3AccessServer::bind("127.0.0.1:0", server_cfg, LegacyTls::Implicit).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);
    let _ = read_line(&mut tls); // greeting

    assert!(cmd_line(&mut tls, &format!("USER {USER}\r\n")).starts_with("+OK"));
    let pass = cmd_line(&mut tls, "PASS not-the-password\r\n");
    assert!(pass.starts_with("-ERR"), "wrong password must be -ERR: {pass}");

    // Still in Authorization state → a transaction command is refused.
    let stat = cmd_line(&mut tls, "STAT\r\n");
    assert!(stat.starts_with("-ERR"), "unauthenticated STAT must be -ERR: {stat}");

    let _ = cmd_line(&mut tls, "QUIT\r\n");
    srv.join().expect("server thread").expect("served one connection");
}

// ---------------------------------------------------------------------------------------------
// 3. STLS: the cleartext port advertises STLS, upgrades in place, then serves over TLS.
// ---------------------------------------------------------------------------------------------

#[test]
fn stls_upgrades_in_place_then_logs_in() {
    let (cert_der, server_cfg) = self_signed();
    let server =
        Pop3AccessServer::bind("127.0.0.1:0", server_cfg, LegacyTls::StartTls).expect("bind");
    let addr = server.local_addr().expect("addr");
    let (store, auth) = seed();
    let srv = thread::spawn(move || server.serve_once(store, auth));

    // Phase 1: cleartext.
    let mut tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let greeting = read_line(&mut tcp);
    assert!(greeting.starts_with("+OK"), "greeting: {greeting}");

    // CAPA advertises STLS pre-TLS.
    let capa = cmd_multiline(&mut tcp, "CAPA\r\n");
    assert!(capa.contains("STLS"), "must advertise STLS pre-TLS: {capa}");

    // Issue STLS; the server acks +OK, then we drive the TLS handshake on the same socket.
    let stls = cmd_line(&mut tcp, "STLS\r\n");
    assert!(stls.starts_with("+OK"), "stls ack: {stls}");

    let conn = ClientConnection::new(client_config(cert_der), ServerName::try_from(HOST).unwrap())
        .expect("client conn");
    let mut tls = StreamOwned::new(conn, tcp);

    // Phase 2 (encrypted): log in and STAT.
    assert!(cmd_line(&mut tls, &format!("USER {USER}\r\n")).starts_with("+OK"));
    assert!(cmd_line(&mut tls, &format!("PASS {APP_PW}\r\n")).starts_with("+OK"));
    let stat = cmd_line(&mut tls, "STAT\r\n");
    assert!(stat.starts_with("+OK 2 "), "stat after stls: {stat}");

    let _ = cmd_line(&mut tls, "QUIT\r\n");
    srv.join().expect("server thread").expect("served one connection");
}
