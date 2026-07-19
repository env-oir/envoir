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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::idn;
use crate::net::{crypto_provider, read_line_str, read_reply, write_all};
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

    /// Resolve the socket to dial for `dest_domain` (test override wins, else `dest_domain:port`),
    /// enforcing the SSRF guard: a domain that resolves **only** to a loopback / private / link-local
    /// / unique-local / unspecified / broadcast address is refused rather than dialed.
    ///
    /// The gateway dials whatever a *destination's* MX name resolves to. Without a guard, a hostile
    /// (or hijacked) MX record — or an attacker-chosen `To:` domain — could point the gateway's
    /// socket at `127.0.0.1`, a private-range service, or the cloud metadata endpoint
    /// `169.254.169.254`, turning the gateway into an SSRF pivot into the operator's own network.
    /// This filters the *resolved IPs* (fail-closed) so only publicly-routable destinations are
    /// reachable. The [`Self::with_fixed_addr`] override is the single, explicit, operator/test hook
    /// that bypasses this (used only by the in-process loopback tests / an operator deliberately
    /// pinning a smarthost) — it is never populated by name resolution.
    fn dial_addr(&self, dest_domain: &str) -> io::Result<SocketAddr> {
        if let Some(a) = self.fixed_addr {
            return Ok(a); // explicit pin — intentionally exempt from the SSRF guard (see docs).
        }
        let mut resolved_any = false;
        for addr in (dest_domain, self.port).to_socket_addrs()? {
            resolved_any = true;
            if !is_forbidden_dest_ip(addr.ip()) {
                return Ok(addr);
            }
        }
        if resolved_any {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to dial {dest_domain}: it resolves only to disallowed \
                     (loopback/private/link-local/unique-local/unspecified/broadcast) addresses"
                ),
            ))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "no address for destination"))
        }
    }

    /// Run the full SMTP client transaction. A network/protocol error is reported as `Transient`
    /// (the node's queue retries, §19.3.3); an explicit 5xx from the peer is `Permanent`; a TLS
    /// requirement that cannot be met is `TlsUnavailable`.
    fn run(&self, dest_domain: &str, message: &[u8], require_tls: bool) -> TransportResult {
        match self.try_run(dest_domain, message, require_tls) {
            Ok(result) => result,
            Err(TransportAbort::Tls) => TransportResult::TlsUnavailable,
            Err(TransportAbort::Permanent { code, text }) => {
                TransportResult::Permanent { code, text }
            }
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
        // A-label (punycode) the destination before it touches the ASCII worlds below: the OS
        // resolver in `dial_addr` and the rustls SNI `ServerName` in `upgrade` (which flatly
        // rejects non-ASCII — previously surfacing as an opaque `TlsUnavailable`). A domain with
        // no DNS spelling is a specific, diagnosable PERMANENT failure: retrying cannot ever make
        // `bücher.<invalid>` spellable (RFC 3463 5.1.2, bad destination system address).
        let dest_domain = idn::domain_to_ascii(dest_domain)
            .map_err(|e| TransportAbort::Permanent { code: 553, text: format!("5.1.2 {e}") })?;
        let dest_domain = dest_domain.as_str();
        let addr = self.dial_addr(dest_domain)?;
        let tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)?;
        tcp.set_read_timeout(Some(self.io_timeout))?;
        tcp.set_write_timeout(Some(self.io_timeout))?;
        let mut stream = ClientStream::Plain(tcp);

        // Greeting.
        expect_2xx(read_reply(&mut stream)?)?;

        // EHLO → capability list.
        let mut caps = self.ehlo(&mut stream)?;
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
            // Re-EHLO over the encrypted channel (RFC 3207 §4.2) — and the capability list MUST be
            // re-read from it: pre-TLS capabilities are unauthenticated and void after the upgrade.
            caps = self.ehlo(&mut stream)?;
        }

        // Envelope is derived from the rendered message headers (the trait carries only the bytes).
        let mail_from = header_addr(message, "from").unwrap_or_else(|| "<>".to_string());
        let rcpt_to = header_addr(message, "to").ok_or_else(|| {
            TransportAbort::Io(io::Error::new(io::ErrorKind::InvalidInput, "no To: header"))
        })?;

        // Honest EAI posture (RFC 6531/6152): check what THIS message actually needs against what
        // the peer actually advertised, instead of shipping raw UTF-8 and hoping.
        //
        // - A non-ASCII ENVELOPE address (in practice a non-ASCII local part — the renderer already
        //   A-labels domains, which is the lossless negotiate-down for IDN-domain recipients)
        //   requires SMTPUTF8. RFC 6531 §3.1: a client MUST NOT use it against a peer that did not
        //   advertise it, so a missing capability is a specific PERMANENT failure (5.6.7, address
        //   requires internationalization) — the peer will not grow the extension on retry.
        // - An 8-bit message body requires 8BITMIME. There is no lossless downgrade for a body we
        //   have already DKIM-signed (re-encoding to QP would break the signed bytes), so a peer
        //   without it is the specific PERMANENT 5.6.3 (conversion required but not supported); a
        //   pure-ASCII body simply never asks for the extension.
        let has_cap = |cap: &str| caps.iter().any(|c| c.eq_ignore_ascii_case(cap));
        let needs_smtputf8 = !mail_from.is_ascii() || !rcpt_to.is_ascii();
        let needs_8bitmime = message.iter().any(|&b| b >= 0x80);
        if needs_smtputf8 && !has_cap("SMTPUTF8") {
            return Err(TransportAbort::Permanent {
                code: 553,
                text: format!(
                    "5.6.7 envelope address requires SMTPUTF8 (RFC 6531) but {dest_domain} does \
                     not advertise it; cannot deliver without corrupting the address"
                ),
            });
        }
        if needs_8bitmime && !has_cap("8BITMIME") {
            return Err(TransportAbort::Permanent {
                code: 554,
                text: format!(
                    "5.6.3 message body is 8-bit but {dest_domain} does not advertise 8BITMIME \
                     (RFC 6152); refusing to send bytes the peer has not agreed to carry"
                ),
            });
        }
        let mut mail_params = String::new();
        if needs_8bitmime {
            mail_params.push_str(" BODY=8BITMIME");
        }
        if needs_smtputf8 {
            mail_params.push_str(" SMTPUTF8");
        }

        write_all(&mut stream, &format!("MAIL FROM:<{mail_from}>{mail_params}\r\n"))?;
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
            let line = read_line_str(stream)?
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

/// The SSRF destination-IP deny-list (fail-closed). Returns `true` for an address the gateway MUST
/// NOT dial when resolving a destination MX name:
///
/// - **loopback** — `127.0.0.0/8`, `::1`;
/// - **RFC 1918 private** — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
/// - **link-local** — `169.254.0.0/16` (which includes the cloud metadata address
///   `169.254.169.254`) and IPv6 `fe80::/10`;
/// - **IPv6 unique-local (ULA)** — `fc00::/7`;
/// - **unspecified / this-network** — `0.0.0.0`, `0.0.0.0/8`, `::`;
/// - **broadcast** — `255.255.255.255`.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped and judged by their embedded IPv4 so
/// a private target cannot be smuggled through the v6 form.
pub(crate) fn is_forbidden_dest_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => is_forbidden_v4(mapped),
            None => is_forbidden_v6(v6),
        },
    }
}

fn is_forbidden_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()        // 127.0.0.0/8
        || v4.is_private()   // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()// 169.254.0.0/16 (incl. 169.254.169.254 metadata)
        || v4.is_unspecified()// 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
        || v4.octets()[0] == 0 // 0.0.0.0/8 "this network" (RFC 1122)
}

fn is_forbidden_v6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback()                     // ::1
        || v6.is_unspecified()           // ::
        || (seg[0] & 0xffc0) == 0xfe80   // fe80::/10 link-local
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local (ULA)
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
        Err(TransportAbort::Io(io::Error::other(format!("{code} {text}"))))
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
            ClientStream::Tls(_) => return Err(io::Error::other("already TLS")),
        };
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let conn = ClientConnection::new(config.clone(), name).map_err(io::Error::other)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn ssrf_guard_forbids_loopback_private_linklocal_and_metadata() {
        // Loopback.
        assert!(is_forbidden_dest_ip(v4("127.0.0.1")));
        assert!(is_forbidden_dest_ip(v4("127.255.255.254")));
        assert!(is_forbidden_dest_ip(v6("::1")));
        // RFC 1918 private.
        assert!(is_forbidden_dest_ip(v4("10.0.0.5")));
        assert!(is_forbidden_dest_ip(v4("172.16.4.4")));
        assert!(is_forbidden_dest_ip(v4("172.31.255.1")));
        assert!(is_forbidden_dest_ip(v4("192.168.1.1")));
        // Link-local, including the cloud metadata endpoint.
        assert!(is_forbidden_dest_ip(v4("169.254.1.1")));
        assert!(is_forbidden_dest_ip(v4("169.254.169.254")), "cloud metadata address is refused");
        assert!(is_forbidden_dest_ip(v6("fe80::1")));
        // IPv6 unique-local (fc00::/7 covers fc.. and fd..).
        assert!(is_forbidden_dest_ip(v6("fc00::1")));
        assert!(is_forbidden_dest_ip(v6("fd12:3456:789a::1")));
        // Unspecified / this-network / broadcast.
        assert!(is_forbidden_dest_ip(v4("0.0.0.0")));
        assert!(is_forbidden_dest_ip(v4("0.1.2.3")));
        assert!(is_forbidden_dest_ip(v4("255.255.255.255")));
        assert!(is_forbidden_dest_ip(v6("::")));
    }

    #[test]
    fn ssrf_guard_unwraps_v4_mapped_v6_and_judges_the_embedded_v4() {
        // A private IPv4 target smuggled through the v4-mapped IPv6 form is still refused.
        assert!(is_forbidden_dest_ip(v6("::ffff:127.0.0.1")));
        assert!(is_forbidden_dest_ip(v6("::ffff:10.0.0.1")));
        assert!(is_forbidden_dest_ip(v6("::ffff:169.254.169.254")));
        // A public IPv4 mapped into v6 is still allowed.
        assert!(!is_forbidden_dest_ip(v6("::ffff:93.184.216.34")));
    }

    #[test]
    fn ssrf_guard_allows_ordinary_public_addresses() {
        assert!(!is_forbidden_dest_ip(v4("93.184.216.34"))); // example.com
        assert!(!is_forbidden_dest_ip(v4("142.250.72.36"))); // a Google MX-range addr
        assert!(!is_forbidden_dest_ip(v4("8.8.8.8")));
        assert!(!is_forbidden_dest_ip(v6("2606:2800:220:1:248:1893:25c8:1946")));
        assert!(!is_forbidden_dest_ip(v6("2001:4860:4860::8888")));
        // Boundary: 172.15.x and 172.32.x are NOT in 172.16/12.
        assert!(!is_forbidden_dest_ip(v4("172.15.0.1")));
        assert!(!is_forbidden_dest_ip(v4("172.32.0.1")));
    }

    #[test]
    fn dial_addr_refuses_a_domain_resolving_only_to_loopback() {
        // `localhost` resolves to loopback only → the guard fails closed with PermissionDenied.
        let t = SmtpTcpTransport::new("gw.example.org");
        match t.dial_addr("localhost") {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            Ok(a) => panic!("expected loopback refusal, dialed {a}"),
        }
    }

    #[test]
    fn fixed_addr_override_bypasses_the_guard() {
        // The explicit operator/test pin is the one sanctioned way to reach a loopback address.
        let loop_addr: SocketAddr = "127.0.0.1:2525".parse().unwrap();
        let t = SmtpTcpTransport::new("gw.example.org").with_fixed_addr(loop_addr);
        assert_eq!(t.dial_addr("anything.example").unwrap(), loop_addr);
    }
}
