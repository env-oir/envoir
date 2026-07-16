//! A **real** [`OutboundTransport`] over TCP + STARTTLS (spec §7.3 step 4).
//!
//! [`SmtpTcpTransport`] opens an actual SMTP client connection to the destination MX, runs
//! `EHLO → STARTTLS → MAIL/RCPT/DATA`, and maps the destination's reply codes onto
//! [`TransportResult`] (2xx delivered / 4xx transient / 5xx permanent). It enforces the spec's hard
//! rule: if TLS is **required** by policy but the peer offers no `STARTTLS` (or the TLS handshake /
//! certificate validation fails), it **aborts** with [`TransportResult::TlsUnavailable`] and never
//! falls back to cleartext (§7.3). The in-process [`crate::outbound`] trait is unchanged — this is a
//! thin socket impl that slots behind it; unit tests keep using the scripted transport.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::net::{crypto_provider, read_line, read_reply, write_all};
use crate::outbound::{OutboundTransport, TransportResult};

/// A concrete SMTP-client transport to a destination MX. Stateless per send (§7.4): one TCP
/// connection, one message, closed on completion.
pub struct SmtpTcpTransport {
    ehlo_name: String,
    port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
    client_config: Arc<ClientConfig>,
    /// Test/override hook: connect here instead of resolving `dest_domain:port`. The TLS SNI /
    /// certificate name is still taken from `dest_domain`, so cert validation stays honest.
    fixed_addr: Option<SocketAddr>,
}

impl SmtpTcpTransport {
    /// A transport that validates destination certificates against the Mozilla webpki root set —
    /// the production default. `ehlo_name` is the gateway's own hostname announced in `EHLO`.
    pub fn new(ehlo_name: impl Into<String>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(ehlo_name, roots)
    }

    /// A transport that trusts exactly `cert` as a root — used by the in-process loopback tests
    /// that stand up a self-signed MX. Never appropriate in production.
    pub fn with_test_root(ehlo_name: impl Into<String>, cert: CertificateDer<'static>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(cert).expect("valid test root cert");
        Self::with_roots(ehlo_name, roots)
    }

    fn with_roots(ehlo_name: impl Into<String>, roots: RootCertStore) -> Self {
        let client_config = ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        SmtpTcpTransport {
            ehlo_name: ehlo_name.into(),
            port: 25,
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(60),
            client_config: Arc::new(client_config),
            fixed_addr: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_fixed_addr(mut self, addr: SocketAddr) -> Self {
        self.fixed_addr = Some(addr);
        self
    }

    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    /// Resolve the socket to dial for `dest_domain` (test override wins, else `dest_domain:port`).
    fn dial_addr(&self, dest_domain: &str) -> io::Result<SocketAddr> {
        if let Some(a) = self.fixed_addr {
            return Ok(a);
        }
        (dest_domain, self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for destination"))
    }

    /// Run the full SMTP client transaction. A network/protocol error is reported as `Transient`
    /// (the node's queue retries, §19.3.3); an explicit 5xx from the peer is `Permanent`; a TLS
    /// requirement that cannot be met is `TlsUnavailable`.
    fn run(&self, dest_domain: &str, message: &[u8], require_tls: bool) -> TransportResult {
        match self.try_run(dest_domain, message, require_tls) {
            Ok(result) => result,
            Err(TransportAbort::Tls) => TransportResult::TlsUnavailable,
            Err(TransportAbort::Permanent { code, text }) => TransportResult::Permanent { code, text },
            Err(TransportAbort::Io(e)) => {
                TransportResult::Transient { code: 421, text: format!("4.4.0 {e}") }
            }
        }
    }

    fn try_run(
        &self,
        dest_domain: &str,
        message: &[u8],
        require_tls: bool,
    ) -> Result<TransportResult, TransportAbort> {
        let addr = self.dial_addr(dest_domain)?;
        let tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)?;
        tcp.set_read_timeout(Some(self.io_timeout))?;
        tcp.set_write_timeout(Some(self.io_timeout))?;
        let mut stream = ClientStream::Plain(tcp);

        // Greeting.
        expect_2xx(read_reply(&mut stream)?)?;

        // EHLO → capability list.
        let caps = self.ehlo(&mut stream)?;
        let starttls_offered = caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS"));

        if require_tls && !starttls_offered {
            // Policy demands TLS but the peer offers none — abort, never cleartext (§7.3).
            return Err(TransportAbort::Tls);
        }

        // Upgrade whenever TLS is on offer (mandatory if required, opportunistic otherwise). A
        // failed handshake after issuing STARTTLS aborts rather than silently downgrading.
        if starttls_offered {
            write_all(&mut stream, "STARTTLS\r\n")?;
            let (code, _t) = read_reply(&mut stream)?;
            if !(200..300).contains(&code) {
                return Err(TransportAbort::Tls);
            }
            stream = stream
                .upgrade(&self.client_config, dest_domain)
                .map_err(|_| TransportAbort::Tls)?;
            // Re-EHLO over the encrypted channel (RFC 3207 §4.2).
            self.ehlo(&mut stream)?;
        }

        // Envelope is derived from the rendered message headers (the trait carries only the bytes).
        let mail_from = header_addr(message, "from").unwrap_or_else(|| "<>".to_string());
        let rcpt_to = header_addr(message, "to")
            .ok_or_else(|| TransportAbort::Io(io::Error::new(io::ErrorKind::InvalidInput, "no To: header")))?;

        write_all(&mut stream, &format!("MAIL FROM:<{mail_from}>\r\n"))?;
        expect_2xx(read_reply(&mut stream)?)?;
        write_all(&mut stream, &format!("RCPT TO:<{rcpt_to}>\r\n"))?;
        expect_2xx(read_reply(&mut stream)?)?;
        write_all(&mut stream, "DATA\r\n")?;
        let (code, text) = read_reply(&mut stream)?;
        if code != 354 {
            return Ok(classify(code, text));
        }

        // Body, dot-stuffed (RFC 5321 §4.5.2), terminated by <CRLF>.<CRLF> with exactly one CRLF
        // before the terminating dot (avoid injecting a spurious trailing blank line).
        write_dot_stuffed(&mut stream, message)?;
        if !message.ends_with(b"\r\n") {
            write_all(&mut stream, "\r\n")?;
        }
        write_all(&mut stream, ".\r\n")?;
        let (final_code, final_text) = read_reply(&mut stream)?;

        // Best-effort QUIT; ignore its outcome.
        let _ = write_all(&mut stream, "QUIT\r\n");
        Ok(classify(final_code, final_text))
    }

    /// Send `EHLO` and collect the advertised capability tokens (one per continuation line).
    fn ehlo(&self, stream: &mut ClientStream) -> Result<Vec<String>, TransportAbort> {
        write_all(stream, &format!("EHLO {}\r\n", self.ehlo_name))?;
        let mut caps = Vec::new();
        loop {
            let line = read_line(stream)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no EHLO reply"))?;
            if line.len() < 3 {
                return Err(TransportAbort::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short EHLO reply",
                )));
            }
            let code: u16 = line[..3].parse().map_err(|_| {
                TransportAbort::Io(io::Error::new(io::ErrorKind::InvalidData, "bad EHLO code"))
            })?;
            if !(200..300).contains(&code) {
                return Err(TransportAbort::Permanent { code, text: line });
            }
            let more = line.as_bytes().get(3) == Some(&b'-');
            // The first token after the code is the capability keyword (the first line is the
            // greeting/domain, which we simply ignore for capability purposes).
            if let Some(rest) = line.get(4..) {
                if let Some(tok) = rest.split_whitespace().next() {
                    caps.push(tok.to_string());
                }
            }
            if !more {
                break;
            }
        }
        Ok(caps)
    }
}

impl OutboundTransport for SmtpTcpTransport {
    fn deliver(&self, dest_domain: &str, message: &[u8], require_tls: bool) -> TransportResult {
        self.run(dest_domain, message, require_tls)
    }
}

/// Map a destination reply code to a [`TransportResult`] (§19.7.2).
fn classify(code: u16, text: String) -> TransportResult {
    match code {
        200..=299 => TransportResult::Delivered { code },
        400..=499 => TransportResult::Transient { code, text },
        _ => TransportResult::Permanent { code, text },
    }
}

/// Internal abort reasons, mapped to a [`TransportResult`] by [`SmtpTcpTransport::run`].
enum TransportAbort {
    Io(io::Error),
    Tls,
    Permanent { code: u16, text: String },
}
impl From<io::Error> for TransportAbort {
    fn from(e: io::Error) -> Self {
        TransportAbort::Io(e)
    }
}

fn expect_2xx((code, text): (u16, String)) -> Result<(), TransportAbort> {
    if (200..300).contains(&code) {
        Ok(())
    } else if (400..500).contains(&code) {
        // A transient rejection to a control command — surface as a retryable transient.
        Err(TransportAbort::Io(io::Error::new(io::ErrorKind::Other, format!("{code} {text}"))))
    } else {
        Err(TransportAbort::Permanent { code, text })
    }
}

/// Extract a bare address from an RFC 5322 header (`From:`/`To:`): the text inside `<...>` if
/// present, else the first whitespace-delimited token containing `@`.
fn header_addr(message: &[u8], name: &str) -> Option<String> {
    let head_end = message.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(message.len());
    let head = String::from_utf8_lossy(&message[..head_end]);
    for line in head.split("\r\n") {
        if let Some((h, v)) = line.split_once(':') {
            if h.trim().eq_ignore_ascii_case(name) {
                let v = v.trim();
                if let (Some(l), Some(r)) = (v.find('<'), v.rfind('>')) {
                    if l < r {
                        return Some(v[l + 1..r].trim().to_string());
                    }
                }
                if let Some(tok) = v.split_whitespace().find(|t| t.contains('@')) {
                    return Some(tok.trim_matches(|c| c == '<' || c == '>').to_string());
                }
            }
        }
    }
    None
}

/// Write the message body performing SMTP dot-stuffing: any line beginning with `.` gets an extra
/// leading `.` so it is not mistaken for the terminator (RFC 5321 §4.5.2).
fn write_dot_stuffed(w: &mut dyn Write, message: &[u8]) -> io::Result<()> {
    let mut at_line_start = true;
    for &b in message {
        if at_line_start && b == b'.' {
            w.write_all(b".")?;
        }
        w.write_all(&[b])?;
        at_line_start = b == b'\n';
    }
    w.flush()
}

/// A client stream that can be upgraded from plaintext to rustls TLS in place (STARTTLS).
enum ClientStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl ClientStream {
    /// Perform the TLS ClientHello/handshake, validating the peer certificate against the
    /// configured roots for `server_name`. A handshake or certificate error is returned as `Err`.
    fn upgrade(self, config: &Arc<ClientConfig>, server_name: &str) -> io::Result<ClientStream> {
        let tcp = match self {
            ClientStream::Plain(t) => t,
            ClientStream::Tls(_) => {
                return Err(io::Error::new(io::ErrorKind::Other, "already TLS"))
            }
        };
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let conn = ClientConnection::new(config.clone(), name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut tls = StreamOwned::new(conn, tcp);
        // Drive the handshake eagerly so certificate validation failures surface here (not later).
        tls.conn.complete_io(&mut tls.sock)?;
        Ok(ClientStream::Tls(Box::new(tls)))
    }
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientStream::Plain(t) => t.read(buf),
            ClientStream::Tls(s) => s.read(buf),
        }
    }
}
impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ClientStream::Plain(t) => t.write(buf),
            ClientStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ClientStream::Plain(t) => t.flush(),
            ClientStream::Tls(s) => s.flush(),
        }
    }
}
