//! Shared TLS-terminating transport for the OPTIONAL **line-based** legacy access servers — POP3
//! (spec §7.15.1, RFC 1939) and SMTP-submission (§7.15.1, RFC 6409). It is the line-protocol sibling
//! of [`crate::imap_access`]'s literal-aware IMAP transport: both reuse the gateway's own rustls
//! [`ServerConfig`] and both terminate TLS at the gateway (the legacy-client reachability ingress,
//! §7.15.2 — the legacy protocol is spoken in the clear only *after* TLS is terminated here).
//!
//! ## Transport & the in-band upgrade (fail-closed)
//! There is no cleartext option for auth: every legacy surface carries a reusable app-password, so a
//! confidential channel is mandatory (§7.15.1). Two TLS modes, exactly mirroring the IMAP server:
//! - [`LegacyTls::Implicit`] wraps the socket in TLS before the greeting (ports 995 / 465).
//! - [`LegacyTls::StartTls`] starts in cleartext, advertises the in-band upgrade verb (`STLS` for
//!   POP3, `STARTTLS` for submission), and **upgrades the socket in place** on that command — after
//!   verifying the client did NOT pipeline any bytes behind it (the STARTTLS command-injection guard;
//!   pipelined post-upgrade data drops the connection fail-closed).
//!
//! The concrete protocol state machines live in `dmtap-mail` (`Pop3Session`, `SmtpSession`); this
//! module only drives their line-fed loop and performs the TLS termination they cannot. A protocol
//! plugs in through the [`LineProtocol`] trait.

use std::cell::RefCell;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Hard cap on a single protocol line before it is refused fail-closed (defends against an unbounded
/// line flood driving the server to OOM). Matches the IMAP transport's 64 MiB literal ceiling, which
/// also bounds a submission `DATA` line that is one long base64 blob.
const MAX_LINE: usize = 64 * 1024 * 1024;

/// How a line-based legacy access server presents TLS. There is no cleartext-auth option: the
/// app-password must never travel in the clear (§7.15.1). Both modes reuse the gateway's own cert/key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyTls {
    /// Cleartext port that advertises the in-band upgrade verb and upgrades in place on it (POP3 110
    /// `STLS` / submission 587 `STARTTLS`).
    StartTls,
    /// TLS from the first byte (implicit-TLS ports 995 / 465).
    Implicit,
}

impl LegacyTls {
    /// Parse the config spelling (`starttls` / `implicit`). Case-insensitive.
    pub fn parse(v: &str) -> Option<LegacyTls> {
        match v.trim().to_ascii_lowercase().as_str() {
            "starttls" | "start-tls" | "start_tls" => Some(LegacyTls::StartTls),
            "implicit" | "implicit-tls" | "tls" | "993" | "995" | "465" => {
                Some(LegacyTls::Implicit)
            }
            _ => None,
        }
    }

    /// Whether TLS is terminated before the greeting (implicit) rather than negotiated in-band.
    pub fn is_implicit(&self) -> bool {
        matches!(self, LegacyTls::Implicit)
    }
}

/// A line-based legacy protocol session the shared loop drives (POP3 / SMTP-submission). The concrete
/// impls wrap `dmtap-mail`'s `Pop3Session` / `SmtpSession`; this trait exposes only what the transport
/// needs to (a) frame the dialog and (b) know when to terminate the in-band TLS upgrade.
pub trait LineProtocol {
    /// The session's opening greeting (sent once, before the first client line).
    fn greeting(&mut self) -> String;
    /// Feed one client line (CRLF already stripped); return the reply to write back (empty ⇒ nothing
    /// is written, e.g. a submission `DATA` content line).
    fn feed_line(&mut self, line: &str) -> String;
    /// Whether `line` is the in-band TLS-upgrade command (`STLS` / `STARTTLS`).
    fn is_starttls(&self, line: &str) -> bool;
    /// Whether a reply to the upgrade command indicates the server accepted it (POP3 `+OK`, SMTP `2xx`).
    fn accepts_upgrade(&self, reply: &str) -> bool;
    /// Whether `line` ends the session (`QUIT`).
    fn is_quit(&self, line: &str) -> bool;
}

/// Drive one line-based [`LineProtocol`] session to completion over `stream`, terminating TLS per
/// `mode`. Implicit TLS is negotiated before the greeting; STARTTLS/STLS upgrades the socket in place
/// on the upgrade command (rejecting pipelined post-command bytes — the command-injection guard).
pub fn serve_line_session<P: LineProtocol>(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    mode: LegacyTls,
    mut proto: P,
) -> io::Result<()> {
    // Build the (possibly already-encrypted) transport. Implicit TLS terminates before the greeting.
    let (transport, mut secured) = match mode {
        LegacyTls::Implicit => {
            let conn = ServerConnection::new(tls.clone()).map_err(io::Error::other)?;
            let mut tls_stream = StreamOwned::new(conn, stream);
            tls_stream.conn.complete_io(&mut tls_stream.sock)?;
            (UpgradableStream::Tls(Box::new(tls_stream)), true)
        }
        LegacyTls::StartTls => (UpgradableStream::Plain(stream), false),
    };

    // One shared, upgradable handle behind an `Rc<RefCell<..>>`: reader + writer each hold a clone.
    // Upgrading TLS mutates the cell in place, so the reader/writer keep working across the boundary.
    // Single-threaded per connection — the `Rc` never leaves this thread, the `RefCell` never
    // double-borrows (reads and writes are strictly sequential).
    let cell = Rc::new(RefCell::new(transport));
    let mut reader = BufReader::new(SharedStream(cell.clone()));
    let mut writer = SharedStream(cell.clone());

    writer.write_all(proto.greeting().as_bytes())?;
    writer.flush()?;

    let mut line = String::new();
    loop {
        line.clear();
        if read_line_capped(&mut reader, &mut line)? == 0 {
            break; // clean EOF
        }
        let cmd = line.trim_end_matches(['\r', '\n']);
        let wants_upgrade = !secured && proto.is_starttls(cmd);
        let quit = proto.is_quit(cmd);

        let reply = proto.feed_line(cmd);
        if !reply.is_empty() {
            writer.write_all(reply.as_bytes())?;
            writer.flush()?;
        }

        if wants_upgrade && proto.accepts_upgrade(&reply) {
            // Command-injection guard: the client MUST NOT have pipelined bytes after the upgrade
            // command. If our buffered reader already holds post-command data, drop the connection
            // fail-closed rather than fold it into the TLS session.
            if !reader.buffer().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pipelined data after STARTTLS/STLS — possible command injection",
                ));
            }
            cell.borrow_mut().upgrade(tls.clone())?;
            secured = true;
        }

        if quit {
            break;
        }
    }
    Ok(())
}

/// Read up to (and including) the next `\n` into `out`, but refuse a line longer than [`MAX_LINE`]
/// (fail-closed, bounded memory). Returns bytes read (`0` at clean EOF).
fn read_line_capped<R: BufRead>(reader: &mut R, out: &mut String) -> io::Result<usize> {
    let mut buf = Vec::new();
    let mut total = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            total += pos + 1;
            break;
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
        total += n;
        if buf.len() > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "protocol line too long"));
        }
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(total)
}

/// A cheaply-cloneable handle to the per-connection stream. Both the buffered reader and the writer
/// hold one; reads and writes are strictly sequential within a single thread.
struct SharedStream(Rc<RefCell<UpgradableStream>>);

impl Read for SharedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}
impl Write for SharedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// A server stream upgradable from plaintext to rustls TLS in place (STARTTLS/STLS termination), the
/// same shape the inbound MX and the IMAP access server use.
enum UpgradableStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
    /// Transient state only while swapping Plain → Tls; never observed by I/O.
    Taken,
}

impl UpgradableStream {
    /// Terminate the in-band upgrade: take the underlying TCP socket and wrap it in a rustls server
    /// session, completing the handshake eagerly so a failure surfaces here (fail-closed).
    fn upgrade(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        let tcp = match std::mem::replace(self, UpgradableStream::Taken) {
            UpgradableStream::Plain(t) => t,
            other => {
                *self = other;
                return Err(io::Error::other("STARTTLS/STLS on an already-secured stream"));
            }
        };
        let conn = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.conn.complete_io(&mut tls.sock)?;
        *self = UpgradableStream::Tls(Box::new(tls));
        Ok(())
    }
}

impl Read for UpgradableStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            UpgradableStream::Plain(t) => t.read(buf),
            UpgradableStream::Tls(s) => s.read(buf),
            UpgradableStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
}
impl Write for UpgradableStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            UpgradableStream::Plain(t) => t.write(buf),
            UpgradableStream::Tls(s) => s.write(buf),
            UpgradableStream::Taken => Err(io::Error::other("stream in transition")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            UpgradableStream::Plain(t) => t.flush(),
            UpgradableStream::Tls(s) => s.flush(),
            UpgradableStream::Taken => Ok(()),
        }
    }
}

/// The first whitespace-delimited token of a client line, uppercased — the protocol verb. Used by the
/// [`LineProtocol`] impls to recognize `STLS` / `STARTTLS` / `QUIT` case-insensitively.
pub(crate) fn verb_of(line: &str) -> String {
    line.split_whitespace().next().unwrap_or("").to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls_mode_spellings() {
        assert_eq!(LegacyTls::parse("starttls"), Some(LegacyTls::StartTls));
        assert_eq!(LegacyTls::parse("STARTTLS"), Some(LegacyTls::StartTls));
        assert_eq!(LegacyTls::parse("implicit"), Some(LegacyTls::Implicit));
        assert_eq!(LegacyTls::parse("995"), Some(LegacyTls::Implicit));
        assert_eq!(LegacyTls::parse("plaintext"), None);
        assert!(LegacyTls::Implicit.is_implicit());
        assert!(!LegacyTls::StartTls.is_implicit());
    }

    #[test]
    fn verb_is_the_uppercased_first_token() {
        assert_eq!(verb_of("stls\r\n"), "STLS");
        assert_eq!(verb_of("  QuIt  "), "QUIT");
        assert_eq!(verb_of("MAIL FROM:<a@b>"), "MAIL");
        assert_eq!(verb_of(""), "");
    }
}
