//! A **real** MX listener (spec §7.2): a `TcpListener` SMTP server that runs the
//! `greeting → EHLO → [STARTTLS] → MAIL/RCPT/DATA` dialog and feeds the assembled RFC 5322 into the
//! verified [`MxSession`] pipeline (anti-abuse gate, recipient resolution, seal, attest,
//! ack-before-`250`). The socket layer here adds only framing + STARTTLS; every protocol decision
//! stays in [`crate::inbound`]. STARTTLS is advertised when a server cert is configured; MAIL/RCPT/
//! DATA and the terminating `.` are delegated verbatim to `MxSession` so its behaviour is identical
//! to the in-process `accept_message` tests.

use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use dmtap_core::TimestampMs;

use crate::inbound::{InboundGateway, MxSession, SmtpReply};
use crate::net::{crypto_provider, read_line, write_all};

/// Build a rustls [`ServerConfig`] from a certificate chain + private key (both DER). Used to offer
/// STARTTLS on the inbound listener. In production the operator supplies real cert/key material
/// (load via [`load_certs`] / [`load_private_key`] from PEM files); tests pass a self-signed pair.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

/// Load a PEM certificate chain (operator-supplied TLS cert for the MX).
pub fn load_certs(pem: &mut dyn io::BufRead) -> io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(pem).collect()
}

/// Load the first PEM private key (PKCS#8 / SEC1 / PKCS#1).
pub fn load_private_key(pem: &mut dyn io::BufRead) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(pem)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in PEM"))
}

/// A listening MX socket. Stateless (§7.4): each accepted connection is an independent transaction.
pub struct MxListener {
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
}

impl MxListener {
    /// Bind an MX listener. `tls = Some(cfg)` advertises and terminates STARTTLS; `None` is a
    /// plaintext dev listener (no STARTTLS offered).
    pub fn bind(addr: impl std::net::ToSocketAddrs, tls: Option<Arc<ServerConfig>>) -> io::Result<Self> {
        Ok(MxListener { listener: TcpListener::bind(addr)?, tls })
    }

    /// The address actually bound (useful with an ephemeral `:0` port in tests).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection and drive its SMTP transaction against `gw`, stamping messages
    /// with `now`. Returns after the peer `QUIT`s or disconnects.
    pub fn serve_once(&self, gw: &InboundGateway, now: TimestampMs) -> io::Result<()> {
        let (stream, peer) = self.listener.accept()?;
        let peer_ip = peer.ip().to_string();
        handle_connection(stream, gw, &peer_ip, now, self.tls.clone())
    }

    /// Serve connections forever, one at a time, stamping each with the current wall-clock time. A
    /// per-connection error is logged to stderr and does not stop the listener (statelessness means
    /// a dropped connection loses nothing — the legacy sender retries).
    pub fn serve_forever(&self, gw: &InboundGateway) -> io::Result<()> {
        for stream in self.listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("gateway: accept error: {e}");
                    continue;
                }
            };
            let peer_ip = stream
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            if let Err(e) = handle_connection(stream, gw, &peer_ip, now_ms(), self.tls.clone()) {
                eprintln!("gateway: session with {peer_ip} ended: {e}");
            }
        }
        Ok(())
    }
}

/// Current wall-clock time in ms since the Unix epoch.
fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as TimestampMs).unwrap_or(0)
}

/// Drive one SMTP transaction. EHLO/STARTTLS/QUIT are handled at the socket layer (framing +
/// TLS upgrade); MAIL/RCPT/DATA and all data lines are delegated verbatim to [`MxSession`].
fn handle_connection(
    tcp: TcpStream,
    gw: &InboundGateway,
    peer_ip: &str,
    now: TimestampMs,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let mut conn = ServerStream::Plain(tcp);
    let mut session = MxSession::new(gw, peer_ip, now);
    write_all(&mut conn, &session.greeting().wire())?;

    let mut in_data = false;
    let mut secured = false;

    loop {
        let line = match read_line(&mut conn)? {
            Some(l) => l,
            None => break, // peer disconnected
        };

        if in_data {
            // Everything is message content until the terminating '.'; feed straight through.
            let reply = session.feed_line(&line);
            if reply.code != 0 {
                write_all(&mut conn, &reply.wire())?;
                in_data = false;
            }
            continue;
        }

        let verb = line.split(' ').next().unwrap_or("").to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" => {
                if tls.is_some() && !secured {
                    write_all(&mut conn, "250-envoir-gateway at your service\r\n")?;
                    write_all(&mut conn, "250 STARTTLS\r\n")?;
                } else {
                    write_all(&mut conn, "250 envoir-gateway at your service\r\n")?;
                }
            }
            "STARTTLS" => match (&tls, secured) {
                (Some(cfg), false) => {
                    write_all(&mut conn, &SmtpReply::new(220, "2.0.0 ready to start TLS").wire())?;
                    conn.upgrade(cfg.clone())?;
                    secured = true;
                    // RFC 3207 §4.2: discard SMTP state established before TLS.
                    session = MxSession::new(gw, peer_ip, now);
                }
                (Some(_), true) => {
                    write_all(&mut conn, &SmtpReply::new(503, "5.5.1 already secured").wire())?;
                }
                (None, _) => {
                    write_all(&mut conn, &SmtpReply::new(502, "5.5.1 STARTTLS not available").wire())?;
                }
            },
            "QUIT" => {
                write_all(&mut conn, &session.feed_line("QUIT").wire())?;
                break;
            }
            "DATA" => {
                let reply = session.feed_line("DATA");
                let code = reply.code;
                write_all(&mut conn, &reply.wire())?;
                if code == 354 {
                    in_data = true;
                }
            }
            _ => {
                let reply = session.feed_line(&line);
                write_all(&mut conn, &reply.wire())?;
            }
        }
    }
    Ok(())
}

/// A server stream upgradable from plaintext to rustls TLS in place (STARTTLS termination).
enum ServerStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
    /// Transient state only while swapping Plain → Tls; never observed by I/O.
    Taken,
}

impl ServerStream {
    /// Terminate STARTTLS: take the underlying TCP socket and wrap it in a rustls server session,
    /// completing the handshake eagerly so a failure surfaces here.
    fn upgrade(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        let tcp = match std::mem::replace(self, ServerStream::Taken) {
            ServerStream::Plain(t) => t,
            other => {
                *self = other;
                return Err(io::Error::new(io::ErrorKind::Other, "already TLS"));
            }
        };
        let conn =
            ServerConnection::new(config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.conn.complete_io(&mut tls.sock)?;
        *self = ServerStream::Tls(Box::new(tls));
        Ok(())
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ServerStream::Plain(t) => t.read(buf),
            ServerStream::Tls(s) => s.read(buf),
            ServerStream::Taken => Err(io::Error::new(io::ErrorKind::Other, "stream in transition")),
        }
    }
}
impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ServerStream::Plain(t) => t.write(buf),
            ServerStream::Tls(s) => s.write(buf),
            ServerStream::Taken => Err(io::Error::new(io::ErrorKind::Other, "stream in transition")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ServerStream::Plain(t) => t.flush(),
            ServerStream::Tls(s) => s.flush(),
            ServerStream::Taken => Ok(()),
        }
    }
}

/// Convenience: read PEM cert + key from byte slices (e.g. embedded config) into a [`ServerConfig`].
pub fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(&mut BufReader::new(cert_pem))?;
    let key = load_private_key(&mut BufReader::new(key_pem))?;
    server_config(certs, key).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
