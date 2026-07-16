//! Shared SMTP-over-socket plumbing for the real inbound/outbound network legs (spec §7).
//!
//! The verified bridge logic lives in [`crate::inbound`] / [`crate::outbound`] behind traits; this
//! module is *only* the thin socket layer those traits abstracted away: line framing, SMTP reply
//! parsing, and the shared rustls crypto provider. It holds no protocol policy of its own.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;

/// The process-wide rustls crypto provider (ring). Built explicitly per-config via
/// `*_with_provider` so we never depend on a global `install_default` having run — important in a
/// test binary where several configs are constructed concurrently.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Read one CRLF-terminated line from `r`, returning it **without** the trailing CR/LF. `Ok(None)`
/// signals a clean EOF at a line boundary (peer hung up). Reads a byte at a time so we never buffer
/// past the line — critical for STARTTLS, where the very next byte after our `220` is TLS
/// ClientHello and must not be swallowed by a read-ahead buffer.
pub(crate) fn read_line(r: &mut dyn Read) -> io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => {
                // EOF. A clean line boundary → None; a partial line → surface as unexpected EOF.
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed mid-line"));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                    return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
                }
                buf.push(byte[0]);
                // A defensive cap so a hostile peer can't force unbounded growth on one line.
                if buf.len() > 64 * 1024 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "SMTP line too long"));
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Read a (possibly multi-line) SMTP reply and return `(code, joined_text)`. Continuation lines use
/// `NNN-text`; the final line uses `NNN text` (RFC 5321 §4.2.1).
pub(crate) fn read_reply(r: &mut dyn Read) -> io::Result<(u16, String)> {
    let mut text = String::new();
    loop {
        let line = read_line(r)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no SMTP reply"))?;
        if line.len() < 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short SMTP reply line"));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-numeric SMTP code"))?;
        let more = line.as_bytes().get(3) == Some(&b'-');
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(line.get(4..).unwrap_or("").trim());
        if !more {
            return Ok((code, text));
        }
    }
}

/// Write a full string to `w` and flush.
pub(crate) fn write_all(w: &mut dyn Write, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}
