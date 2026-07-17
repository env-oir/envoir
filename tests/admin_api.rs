//! Real-socket integration test for the multi-tenant admin API (spec §7 "gateway as a business"): a
//! rustls HTTPS client drives the gateway's [`AdminServer`] over TLS and exercises the fail-closed
//! auth + a full add-domain → add-recipient → usage round-trip. Proves:
//!   - the admin token is required (a request with no / wrong `Authorization` is `401`), so the
//!     control surface is fail-closed over a real socket, not just at the handler level;
//!   - a correctly-authenticated `POST /v1/domains` provisions a domain end-to-end and returns its
//!     freshly-generated DKIM public key + seed;
//!   - the whole thing runs over TLS (the admin token never travels in cleartext).
//!
//! The "off by default" contract (an [`AdminAuth::disabled`] gateway refuses everything, and a fresh
//! [`MultiDomainGateway`] serves no domains) is asserted in the `admin.rs` / `multidomain.rs` unit
//! tests; this file proves the live transport.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use envoir_gateway::{AdminApi, AdminAuth, AdminServer, MultiDomainGateway, UsageMeter};

const HOST: &str = "localhost";
const TOKEN: &str = "integration-admin-token-xyz";

/// A self-signed cert for `localhost` plus the matching gateway TLS server config and the DER cert.
fn self_signed() -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("self-signed cert");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let cfg =
        envoir_gateway::server_config(vec![cert_der.clone()], key.into()).expect("server config");
    (cert_der, cfg)
}

/// A client TLS config trusting exactly the test's self-signed cert.
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

/// Open one TLS connection, send a raw HTTP request, and return `(status_code, body)`.
fn request(
    addr: std::net::SocketAddr,
    client: Arc<ClientConfig>,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &str,
) -> (u16, String) {
    let server_name = ServerName::try_from(HOST).unwrap();
    let conn = ClientConnection::new(client, server_name).expect("client conn");
    let sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tls = StreamOwned::new(conn, sock);

    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n");
    if let Some(t) = auth {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    head.push_str(body);
    tls.write_all(head.as_bytes()).expect("write request");
    tls.flush().ok();

    let mut raw = Vec::new();
    // Read to EOF (the server sends `Connection: close`).
    let _ = tls.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[test]
fn admin_api_over_tls_is_fail_closed_and_provisions_a_domain() {
    let (cert_der, server_cfg) = self_signed();
    let client = client_config(cert_der);

    // Build a shared gateway + meter + token-authed API, and bind the admin server on an ephemeral port.
    let gateway = Arc::new(Mutex::new(MultiDomainGateway::new()));
    let meter = UsageMeter::new();
    let api = AdminApi::new(gateway.clone(), meter, AdminAuth::with_token(TOKEN));
    let server = AdminServer::bind("127.0.0.1:0", server_cfg, api).expect("bind admin server");
    let addr = server.local_addr().expect("addr");

    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    let handle = thread::spawn(move || {
        let _ = server.serve_until(&sd);
    });

    // 1. No token → 401 (fail-closed over the real socket).
    let (status, _) = request(addr, client.clone(), "GET", "/v1/domains", None, "");
    assert_eq!(status, 401, "unauthenticated request must be rejected");

    // 2. Wrong token → 401.
    let (status, _) = request(addr, client.clone(), "GET", "/v1/domains", Some("wrong"), "");
    assert_eq!(status, 401);

    // 3. Correct token → provision a domain end-to-end.
    let (status, body) = request(
        addr,
        client.clone(),
        "POST",
        "/v1/domains",
        Some(TOKEN),
        "domain=host.net&selector=gw7",
    );
    assert_eq!(status, 201, "authenticated add-domain: {body}");
    assert!(body.contains("\"dkim_public\""), "returns a publishable DKIM key: {body}");
    assert!(body.contains("host.net"));

    // 4. The domain is now really served (observed through the shared gateway).
    assert!(gateway.lock().unwrap().serves("host.net"));

    // 5. Add a recipient over the API and confirm it routes.
    let ik = dmtap_core::identity::IdentityKey::generate().public();
    let ik_b64 = envoir_gateway::b64::encode(&ik);
    let seal_b64 = envoir_gateway::b64::encode(&[5u8; 32]);
    let (status, body) = request(
        addr,
        client.clone(),
        "POST",
        "/v1/domains/host.net/recipients",
        Some(TOKEN),
        &format!("email=alice@host.net&ik_b64={ik_b64}&seal_b64={seal_b64}"),
    );
    assert_eq!(status, 201, "add recipient: {body}");
    // The gateway now routes alice@host.net to a directory recipient.
    assert!(gateway.lock().unwrap().route("x@gmail.com", "alice@host.net", 0).is_ok());

    // 6. Usage endpoint is reachable and authed.
    let (status, body) = request(addr, client, "GET", "/v1/usage", Some(TOKEN), "");
    assert_eq!(status, 200);
    assert!(body.contains("\"usage\""));

    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = handle.join();
}
