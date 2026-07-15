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

/// Read one complete IMAP command (assembling synchronizing/non-sync literals) from `reader`,
/// prompting on `writer`. Returns `Ok(None)` at clean EOF.
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
        buf.extend_from_slice(&line);
        match trailing_literal(&line) {
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

fn read_until_lf<R: BufRead>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
    let n = reader.read_until(b'\n', out)?;
    Ok(n)
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
            loop {
                match read_imap_command(&mut reader, &mut writer) {
                    Ok(Some(cmd)) => {
                        let resp = session.process(&cmd);
                        if writer.write_all(&resp).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                        if session.state() == crate::imap::State::Logout {
                            break;
                        }
                    }
                    _ => break,
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
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let cmd = line.trim_end_matches(['\r', '\n']);
                let quit = cmd.eq_ignore_ascii_case("QUIT");
                let resp = session.feed_line(cmd);
                if writer.write_all(resp.as_bytes()).is_err() {
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
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let cmd = line.trim_end_matches(['\r', '\n']);
                let quit = cmd.eq_ignore_ascii_case("QUIT");
                let resp = session.feed_line(cmd);
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
}
