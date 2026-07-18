//! Optional blocking TCP servers (feature `net`) — thread-per-connection, **std only** (no async
//! runtime), driving the synchronous session state machines. A real node terminates TLS first
//! (spec §8.2) and hands the plaintext stream here; these helpers speak the cleartext protocol.
//!
//! The IMAP [`read_imap_command`] reader implements the synchronizing-literal handshake (RFC 9051
//! §4.3): on a `{n}` literal it emits a `+` continuation and reads exactly `n` bytes; a `{n+}`
//! (LITERAL+) literal is read without prompting. This is what makes APPEND and large arguments
//! work over a real socket.

use std::io::{self, BufRead, Write};
use std::net::TcpListener;

use crate::auth::Authenticator;
use crate::imap::Session;
use crate::pop3::Pop3Session;
use crate::smtp::SmtpSession;
use crate::store::MailStore;

/// Hard cap on a single IMAP literal (matches the SMTP/JMAP 50 MiB message ceiling, rounded up).
/// A hostile `{9999999999}` literal must never be pre-allocated — we reject the command instead of
/// letting the client drive the server to OOM.
pub const MAX_LITERAL: usize = 64 * 1024 * 1024;

/// Hard cap on a single command line before a literal (defends against an unbounded line flood).
const MAX_LINE: usize = 1024 * 1024;

/// Read one complete IMAP command (assembling synchronizing/non-sync literals) from `reader`,
/// prompting on `writer`. Returns `Ok(None)` at clean EOF. Oversized literals/lines are refused
/// with a `BAD` and surfaced as an error so the caller drops the connection (fail closed).
pub fn read_imap_command<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = read_until_lf(reader, &mut line)?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if line.len() > MAX_LINE {
            let _ = writer.write_all(b"* BAD command line too long\r\n");
            let _ = writer.flush();
            return Err(io::Error::new(io::ErrorKind::InvalidData, "command line too long"));
        }
        buf.extend_from_slice(&line);
        match trailing_literal(&line) {
            Some((size, _sync)) if size > MAX_LITERAL => {
                let _ = writer.write_all(b"* BAD literal too large\r\n");
                let _ = writer.flush();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "literal exceeds MAX_LITERAL"));
            }
            Some((size, sync)) => {
                if sync {
                    writer.write_all(b"+ Ready for literal data\r\n")?;
                    writer.flush()?;
                }
                let mut lit = vec![0u8; size];
                reader.read_exact(&mut lit)?;
                buf.extend_from_slice(&lit);
                // Loop to read the remainder of the command after the literal.
            }
            None => return Ok(Some(buf)),
        }
    }
}

/// Read up to (and including) the next `\n`, but **stop once `MAX_LINE` bytes have accrued** even
/// if no newline has arrived — so a client that streams forever without a line terminator cannot
/// drive the server to OOM (the caller then rejects the over-long line). Returns bytes read.
fn read_until_lf<R: BufRead>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
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
            out.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            total += pos + 1;
            break;
        }
        let n = available.len();
        out.extend_from_slice(available);
        reader.consume(n);
        total += n;
        if out.len() > MAX_LINE {
            break; // bounded — the caller sees an over-long line and refuses the command
        }
    }
    Ok(total)
}

/// If the (CRLF-terminated) line ends with a literal introducer `{n}` or `{n+}`, return
/// `(n, is_synchronizing)`.
fn trailing_literal(line: &[u8]) -> Option<(usize, bool)> {
    let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    if trimmed.last() != Some(&b'}') {
        return None;
    }
    let open = trimmed.iter().rposition(|&b| b == b'{')?;
    let inner = &trimmed[open + 1..trimmed.len() - 1];
    let (digits, sync) = if inner.last() == Some(&b'+') {
        (&inner[..inner.len() - 1], false)
    } else {
        (inner, true)
    };
    let n: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((n, sync))
}

/// Serve IMAP on `listener`, building a fresh session per connection via `make_session`.
pub fn serve_imap<S, A, F>(listener: TcpListener, make_session: F) -> io::Result<()>
where
    S: MailStore + Send + 'static,
    A: Authenticator + Send + 'static,
    F: Fn() -> Session<S, A> + Send + Sync + 'static,
{
    let make = std::sync::Arc::new(make_session);
    for stream in listener.incoming() {
        let stream = stream?;
        let make = make.clone();
        std::thread::spawn(move || {
            let mut session = make();
            let mut reader = io::BufReader::new(stream.try_clone().expect("clone stream"));
            let mut writer = stream;
            let _ = writer.write_all(&session.greeting());
            let _ = writer.flush();
            while let Ok(Some(cmd)) = read_imap_command(&mut reader, &mut writer) {
                let resp = session.process(&cmd);
                if writer.write_all(&resp).is_err() {
                    break;
                }
                let _ = writer.flush();
                if session.state() == crate::imap::State::Logout {
                    break;
                }
            }
        });
    }
    Ok(())
}

/// Serve POP3 on `listener` (line-based), building a session per connection.
pub fn serve_pop3<S, A, F>(listener: TcpListener, make_session: F) -> io::Result<()>
where
    S: MailStore + Send + 'static,
    A: Authenticator + Send + 'static,
    F: Fn() -> Pop3Session<S, A> + Send + Sync + 'static,
{
    let make = std::sync::Arc::new(make_session);
    for stream in listener.incoming() {
        let stream = stream?;
        let make = make.clone();
        std::thread::spawn(move || {
            let mut session = make();
            let mut reader = io::BufReader::new(stream.try_clone().expect("clone"));
            let mut writer = stream;
            let _ = writer.write_all(session.greeting().as_bytes());
            let _ = writer.flush();
            // Byte-based line loop: `read_line` would *error out* the whole connection on any
            // non-UTF-8 byte. Commands are ASCII, so the lossy decode below never alters a valid
            // command, and RETR/TOP replies go out via `feed_line_raw` byte-exact.
            let mut line: Vec<u8> = Vec::new();
            loop {
                line.clear();
                if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                strip_crlf(&mut line);
                let cmd = String::from_utf8_lossy(&line).into_owned();
                let quit = cmd.eq_ignore_ascii_case("QUIT");
                let resp = session.feed_line_raw(&cmd);
                if writer.write_all(&resp).is_err() {
                    break;
                }
                let _ = writer.flush();
                if quit {
                    break;
                }
            }
        });
    }
    Ok(())
}

/// Serve SMTP submission on `listener` (line-based), building a session per connection.
pub fn serve_smtp<A, F>(listener: TcpListener, make_session: F) -> io::Result<()>
where
    A: Authenticator + Send + 'static,
    F: Fn() -> SmtpSession<A> + Send + Sync + 'static,
{
    let make = std::sync::Arc::new(make_session);
    for stream in listener.incoming() {
        let stream = stream?;
        let make = make.clone();
        std::thread::spawn(move || {
            let mut session = make();
            let mut reader = io::BufReader::new(stream.try_clone().expect("clone"));
            let mut writer = stream;
            let _ = writer.write_all(session.greeting().as_bytes());
            let _ = writer.flush();
            // DATA must be carried as raw bytes end-to-end: we advertise 8BITMIME, and the old
            // `read_line` path *refused the connection* at the first non-UTF-8 byte (and any
            // lossy variant corrupts ISO-8859-x/GB18030/Shift_JIS bodies to U+FFFD before the
            // parser ever sees them). `read_until` + `feed_line_bytes` is lossless.
            let mut line: Vec<u8> = Vec::new();
            loop {
                line.clear();
                if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                strip_crlf(&mut line);
                let quit = line.eq_ignore_ascii_case(b"QUIT");
                let resp = session.feed_line_bytes(&line);
                if !resp.is_empty() && writer.write_all(resp.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
                if quit {
                    break;
                }
            }
        });
    }
    Ok(())
}

/// Remove one trailing CRLF (or bare LF) in place — the byte-level equivalent of the old
/// `trim_end_matches(['\r','\n'])`, restricted to a single terminator so a line legitimately
/// ending in `\r` bytes deeper in DATA content is not over-trimmed.
fn strip_crlf(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_simple_command() {
        let mut r = Cursor::new(b"a LOGIN alice secret\r\n".to_vec());
        let mut w = Vec::new();
        let cmd = read_imap_command(&mut r, &mut w).unwrap().unwrap();
        assert_eq!(cmd, b"a LOGIN alice secret\r\n");
        assert!(w.is_empty(), "no continuation for a literal-free command");
    }

    #[test]
    fn reads_synchronizing_literal() {
        let mut r = Cursor::new(b"a APPEND INBOX {5}\r\nHELLO\r\n".to_vec());
        let mut w = Vec::new();
        let cmd = read_imap_command(&mut r, &mut w).unwrap().unwrap();
        assert!(cmd.windows(5).any(|c| c == b"HELLO"));
        assert_eq!(w, b"+ Ready for literal data\r\n", "must prompt for a sync literal");
    }

    #[test]
    fn reads_nonsync_literal_without_prompt() {
        let mut r = Cursor::new(b"a APPEND INBOX {5+}\r\nHELLO\r\n".to_vec());
        let mut w = Vec::new();
        let cmd = read_imap_command(&mut r, &mut w).unwrap().unwrap();
        assert!(cmd.windows(5).any(|c| c == b"HELLO"));
        assert!(w.is_empty(), "LITERAL+ must not prompt");
    }

    #[test]
    fn detects_trailing_literal() {
        assert_eq!(trailing_literal(b"a APPEND INBOX {11}\r\n"), Some((11, true)));
        assert_eq!(trailing_literal(b"a APPEND INBOX {11+}\r\n"), Some((11, false)));
        assert_eq!(trailing_literal(b"a NOOP\r\n"), None);
    }

    #[test]
    fn oversized_literal_is_refused_not_allocated() {
        // A hostile `{huge}` literal must be rejected (fail closed), never pre-allocated → no OOM.
        let cmd = format!("a APPEND INBOX {{{}}}\r\n", MAX_LITERAL + 1);
        let mut r = Cursor::new(cmd.into_bytes());
        let mut w = Vec::new();
        let err = read_imap_command(&mut r, &mut w).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(w.windows(4).any(|c| c == b"BAD "), "must warn BAD: {:?}", String::from_utf8_lossy(&w));
    }
}
