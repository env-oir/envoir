//! RFC 5322 / MIME (RFC 2045–2049) rendering and parsing.
//!
//! Two directions:
//! - **render** — a decrypted MOTE [`Payload`] → an RFC 5322 message (spec §8.2: the node
//!   "presents normal RFC 5322/MIME to the authenticated client").
//! - **parse** — a stored RFC 5322 message → headers + a MIME [`BodyPart`] tree, which the IMAP
//!   layer projects as ENVELOPE (RFC 9051 §7.5.2) and BODYSTRUCTURE (§7.5.3), and SEARCH reads.
//!
//! The parser is deliberately bounded but faithful: it unfolds headers, splits `multipart/*` on
//! its boundary and recurses, and classifies leaf parts with type/subtype/params/encoding/size.

use dmtap_core::keyname;
use dmtap_core::mote::Payload;
use dmtap_core::TimestampMs;

/// A parsed message: ordered headers, the raw body, and the MIME structure tree.
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub structure: BodyPart,
}

/// A MIME body part (RFC 2045). Leaf `Single` or container `Multipart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyPart {
    Single {
        mime_type: String,
        subtype: String,
        params: Vec<(String, String)>,
        id: Option<String>,
        description: Option<String>,
        encoding: String,
        octets: usize,
        /// Line count for `text/*` (RFC 9051 body-type-text `body-fld-lines`).
        lines: usize,
    },
    Multipart {
        subtype: String,
        parts: Vec<BodyPart>,
        params: Vec<(String, String)>,
    },
}

/// An RFC 5322 address parsed into the IMAP ENVELOPE 4-tuple (name, adl, mailbox, host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub name: Option<String>,
    pub adl: Option<String>,
    pub mailbox: Option<String>,
    pub host: Option<String>,
}

impl ParsedMessage {
    /// Parse raw RFC 5322 bytes into headers + body + MIME structure.
    pub fn parse(raw: &[u8]) -> ParsedMessage {
        let (headers, body) = split_headers(raw);
        let structure = parse_structure(&headers, body);
        ParsedMessage { headers, body: body.to_vec(), structure }
    }

    /// First header value (case-insensitive), header-unfolded.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parse an address-bearing header (From/To/Cc/…) into ENVELOPE addresses.
    pub fn addresses(&self, name: &str) -> Vec<Address> {
        self.header(name).map(parse_address_list).unwrap_or_default()
    }
}

/// Split a message at the first blank line into (headers, body). Handles CRLF and bare LF, and
/// unfolds continuation lines (leading WSP) per RFC 5322 §2.2.3.
fn split_headers(raw: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let text = raw;
    // Find the header/body separator: CRLFCRLF or LFLF.
    let mut sep = None;
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\n' {
            // blank line?
            if i + 1 < text.len() && text[i + 1] == b'\n' {
                sep = Some((i + 1, i + 2));
                break;
            }
            if i + 2 < text.len() && text[i + 1] == b'\r' && text[i + 2] == b'\n' {
                sep = Some((i + 1, i + 3));
                break;
            }
        }
        i += 1;
    }
    let (hdr_end, body_start) = sep.unwrap_or((text.len(), text.len()));
    let hdr_bytes = &text[..hdr_end];
    let body = &text[body_start.min(text.len())..];
    (parse_header_block(hdr_bytes), body)
}

fn parse_header_block(bytes: &[u8]) -> Vec<(String, String)> {
    let s = String::from_utf8_lossy(bytes);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in s.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !out.is_empty() {
            // Folded continuation — append to the previous value.
            let last = out.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line.trim());
        } else if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let val = line[colon + 1..].trim().to_string();
            out.push((name, val));
        }
    }
    out
}

/// Content-Type header → (type, subtype, params).
fn content_type(headers: &[(String, String)]) -> (String, String, Vec<(String, String)>) {
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("text/plain");
    parse_content_type(ct)
}

/// Parse a Content-Type value like `multipart/mixed; boundary="x"; charset=utf-8`.
pub fn parse_content_type(v: &str) -> (String, String, Vec<(String, String)>) {
    let mut parts = v.split(';');
    let full = parts.next().unwrap_or("text/plain").trim();
    let (mt, st) = full.split_once('/').unwrap_or(("text", "plain"));
    let mut params = Vec::new();
    for p in parts {
        if let Some((k, val)) = p.split_once('=') {
            let val = val.trim().trim_matches('"').to_string();
            params.push((k.trim().to_ascii_lowercase(), val));
        }
    }
    (mt.trim().to_ascii_lowercase(), st.trim().to_ascii_lowercase(), params)
}

fn header_val<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn parse_structure(headers: &[(String, String)], body: &[u8]) -> BodyPart {
    let (mt, st, params) = content_type(headers);
    let encoding = header_val(headers, "Content-Transfer-Encoding")
        .unwrap_or("7BIT")
        .trim()
        .to_ascii_uppercase();
    let id = header_val(headers, "Content-ID").map(str::to_string);
    let description = header_val(headers, "Content-Description").map(str::to_string);

    if mt == "multipart" {
        let boundary = params.iter().find(|(k, _)| k == "boundary").map(|(_, v)| v.clone());
        let parts = match boundary {
            Some(b) => split_multipart(body, &b)
                .into_iter()
                .map(|seg| {
                    let (h, bd) = split_headers(seg);
                    parse_structure(&h, bd)
                })
                .collect(),
            None => Vec::new(),
        };
        BodyPart::Multipart { subtype: st, parts, params }
    } else {
        let octets = body.len();
        let lines = if mt == "text" { count_lines(body) } else { 0 };
        BodyPart::Single {
            mime_type: mt,
            subtype: st,
            params,
            id,
            description,
            encoding,
            octets,
            lines,
        }
    }
}

/// Split a multipart body into its part segments on `--boundary` delimiters (RFC 2046 §5.1).
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let text = body;
    let bytes = delim.as_bytes();
    let mut segments = Vec::new();
    let mut positions = Vec::new();
    let mut i = 0;
    while i + bytes.len() <= text.len() {
        if &text[i..i + bytes.len()] == bytes {
            positions.push(i);
            i += bytes.len();
        } else {
            i += 1;
        }
    }
    // Segments live between consecutive delimiters; skip the preamble (before first) and the
    // closing `--boundary--`.
    for w in positions.windows(2) {
        let start = w[0] + bytes.len();
        let end = w[1];
        // Trim the CRLF that follows the opening delimiter and precedes the next.
        let seg = &text[start..end];
        let seg = seg.strip_prefix(b"\r\n").or_else(|| seg.strip_prefix(b"\n")).unwrap_or(seg);
        segments.push(seg);
    }
    segments
}

/// Top-level MIME part segments (each includes that part's own headers + body). Empty for a
/// non-multipart message. Used by IMAP `BODY[n]` / `BODY[n.MIME]` section fetches.
pub fn part_segments(raw: &[u8]) -> Vec<Vec<u8>> {
    let (headers, body) = split_headers(raw);
    let (mt, _st, params) = content_type(&headers);
    if mt != "multipart" {
        return Vec::new();
    }
    match params.iter().find(|(k, _)| k == "boundary").map(|(_, v)| v.clone()) {
        Some(b) => split_multipart(body, &b).into_iter().map(|s| s.to_vec()).collect(),
        None => Vec::new(),
    }
}

/// The byte offset where the body begins: `raw[..body_offset]` is the header block (through the
/// blank-line terminator) and `raw[body_offset..]` is the body. Returns `raw.len()` if there is no
/// blank line. This is the borrow-friendly core of [`header_and_body`] — the IMAP `BODY[]`/
/// `BODY[HEADER]`/`BODY[TEXT]` fetches slice on it without copying the whole message.
pub fn body_offset(raw: &[u8]) -> usize {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\n' {
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                return i + 2;
            }
            if i + 2 < raw.len() && raw[i + 1] == b'\r' && raw[i + 2] == b'\n' {
                return i + 3;
            }
        }
        i += 1;
    }
    raw.len()
}

/// Split a raw message into (header-block-bytes, body-bytes). Public for section fetches.
pub fn header_and_body(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let s = body_offset(raw);
    (raw[..s].to_vec(), raw[s..].to_vec())
}

/// Parse just the header block (no MIME-structure walk) — cheap for `BODY[HEADER.FIELDS (...)]`,
/// which needs header lines but not the multipart tree.
pub fn headers_only(raw: &[u8]) -> Vec<(String, String)> {
    let s = body_offset(raw);
    parse_header_block(&raw[..s])
}

fn count_lines(body: &[u8]) -> usize {
    if body.is_empty() {
        return 0;
    }
    body.iter().filter(|&&b| b == b'\n').count().max(1)
}

/// Parse an RFC 5322 address list into ENVELOPE addresses. Handles `Name <mbox@host>`,
/// bare `mbox@host`, quoted display names, and comma separation. Group syntax is flattened.
pub fn parse_address_list(v: &str) -> Vec<Address> {
    let mut out = Vec::new();
    for raw in split_addresses(v) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        out.push(parse_one_address(raw));
    }
    out
}

/// Split on commas that are not inside quotes or angle brackets.
fn split_addresses(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut in_angle = false;
    for c in v.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                cur.push(c);
            }
            '<' if !in_quote => {
                in_angle = true;
                cur.push(c);
            }
            '>' if !in_quote => {
                in_angle = false;
                cur.push(c);
            }
            ',' if !in_quote && !in_angle => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn parse_one_address(raw: &str) -> Address {
    let (name, addr) = if let (Some(lt), Some(gt)) = (raw.find('<'), raw.rfind('>')) {
        let name = raw[..lt].trim().trim_matches('"').trim();
        let addr = raw[lt + 1..gt].trim();
        (if name.is_empty() { None } else { Some(name.to_string()) }, addr.to_string())
    } else {
        (None, raw.trim().to_string())
    };
    let (mailbox, host) = match addr.split_once('@') {
        Some((m, h)) => (Some(m.to_string()), Some(h.to_string())),
        None if addr.is_empty() => (None, None),
        None => (Some(addr), None),
    };
    Address { name, adl: None, mailbox, host }
}

// --- Rendering a MOTE payload into RFC 5322 ------------------------------------------------

/// Strip CR/LF from a value about to be embedded verbatim in an RFC 5322 header line. `subject`
/// and `mime` on an inbound MOTE [`Payload`] are attacker-controlled (the *sender* sets them, spec
/// §2.4) — without this, a hostile peer could smuggle a bare CR/LF to inject extra headers (e.g. a
/// forged `Bcc:`) or a blank line to terminate the header block early and splice attacker-chosen
/// bytes into what the client renders as the body (RFC 5322 §2.2 forbids raw CR/LF in a value).
fn sanitize_header_value(v: &str) -> String {
    v.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Render a decrypted MOTE [`Payload`] (spec §2.4) into an RFC 5322 message (spec §8.2).
///
/// The sender identity key is projected to a stable, human-checkable local-part via the 8-word
/// **key-name** (spec §3.9.1); this is the address a legacy client sees for a DMTAP peer.
pub fn render_rfc5322(payload: &Payload, ts: TimestampMs) -> Vec<u8> {
    let from = address_for_key(&payload.from);
    let subject = sanitize_header_value(payload.headers.subject.as_deref().unwrap_or(""));
    let mime = sanitize_header_value(
        payload.headers.mime.as_deref().unwrap_or("text/plain; charset=utf-8"),
    );
    let date = format_rfc5322_date(ts);
    // A deterministic Message-ID from the content, so threading is stable across a re-render.
    let mid = format!("<{}@dmtap.local>", hex(&blake3_16(&payload.body)));

    let mut msg = String::new();
    msg.push_str(&format!("From: {from}\r\n"));
    if let Some(thread) = &payload.headers.thread {
        msg.push_str(&format!("References: <{}@dmtap.local>\r\n", hex(thread)));
    }
    msg.push_str(&format!("Date: {date}\r\n"));
    msg.push_str(&format!("Subject: {subject}\r\n"));
    msg.push_str(&format!("Message-ID: {mid}\r\n"));
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str(&format!("Content-Type: {mime}\r\n"));
    msg.push_str("Content-Transfer-Encoding: 8bit\r\n");
    msg.push_str("\r\n");
    let mut bytes = msg.into_bytes();
    bytes.extend_from_slice(&payload.body);
    if !payload.body.ends_with(b"\n") {
        bytes.extend_from_slice(b"\r\n");
    }
    bytes
}

/// The RFC 5322 address a legacy client sees for a DMTAP identity key: `<keyname>@dmtap.local`.
pub fn address_for_key(ik: &[u8]) -> String {
    if ik.is_empty() {
        return "unknown@dmtap.local".into();
    }
    format!("{}@dmtap.local", keyname::encode(ik))
}

fn blake3_16(b: &[u8]) -> [u8; 16] {
    // Reuse the core's content-address digest (BLAKE3-256) and take the first 16 bytes.
    let cid = dmtap_core::ContentId::of(b);
    let digest = cid.digest();
    let mut out = [0u8; 16];
    let n = digest.len().min(16);
    out[..n].copy_from_slice(&digest[..n]);
    out
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Format a Unix-ms timestamp as an RFC 5322 date-time in UTC, e.g.
/// `Wed, 15 Jul 2026 12:34:56 +0000`.
pub fn format_rfc5322_date(ms: TimestampMs) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mon, d) = civil_from_days(days);
    let wd = weekday_from_days(days);
    const WK: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MO: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        WK[wd],
        d,
        MO[(mon - 1) as usize],
        y,
        h,
        mi,
        s
    )
}

/// Format a Unix-ms timestamp as an IMAP INTERNALDATE, e.g. `15-Jul-2026 12:34:56 +0000`
/// (RFC 9051 `date-time`).
pub fn format_internal_date(ms: TimestampMs) -> String {
    let secs = (ms / 1000) as i64;
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mon, d) = ymd_from_ms(ms);
    const MO: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{:02}-{}-{:04} {:02}:{:02}:{:02} +0000", d, MO[(mon - 1) as usize], y, h, mi, s)
}

/// (year, month, day) in UTC for a Unix-ms timestamp — used by IMAP SEARCH date keys.
pub fn ymd_from_ms(ms: TimestampMs) -> (i64, i64, i64) {
    let days = ((ms / 1000) as i64).div_euclid(86400);
    civil_from_days(days)
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Weekday for a days-since-epoch count. 1970-01-01 was a Thursday (index 3).
fn weekday_from_days(z: i64) -> usize {
    (((z % 7) + 3 + 7) % 7) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_headers_and_body() {
        let raw = b"From: a@b.com\r\nSubject: Hi\r\n\r\nbody line\r\n";
        let p = ParsedMessage::parse(raw);
        assert_eq!(p.header("subject"), Some("Hi"));
        assert_eq!(p.header("FROM"), Some("a@b.com"));
        assert_eq!(p.body, b"body line\r\n");
    }

    #[test]
    fn unfolds_headers() {
        let raw = b"Subject: a very\r\n long subject\r\n\r\nx";
        let p = ParsedMessage::parse(raw);
        assert_eq!(p.header("subject"), Some("a very long subject"));
    }

    #[test]
    fn parses_address_list() {
        let addrs = parse_address_list("Foo Bar <foo@bar.com>, baz@qux.com");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].name.as_deref(), Some("Foo Bar"));
        assert_eq!(addrs[0].mailbox.as_deref(), Some("foo"));
        assert_eq!(addrs[0].host.as_deref(), Some("bar.com"));
        assert_eq!(addrs[1].mailbox.as_deref(), Some("baz"));
    }

    #[test]
    fn single_part_structure() {
        let raw = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello\nworld\n";
        let p = ParsedMessage::parse(raw);
        match p.structure {
            BodyPart::Single { mime_type, subtype, lines, .. } => {
                assert_eq!((mime_type.as_str(), subtype.as_str()), ("text", "plain"));
                assert_eq!(lines, 2);
            }
            _ => panic!("expected single part"),
        }
    }

    #[test]
    fn multipart_structure() {
        let raw = b"Content-Type: multipart/alternative; boundary=\"BND\"\r\n\r\n\
                    --BND\r\nContent-Type: text/plain\r\n\r\nplain\r\n\
                    --BND\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n\
                    --BND--\r\n";
        let p = ParsedMessage::parse(raw);
        match p.structure {
            BodyPart::Multipart { subtype, parts, .. } => {
                assert_eq!(subtype, "alternative");
                assert_eq!(parts.len(), 2);
                match &parts[1] {
                    BodyPart::Single { subtype, .. } => assert_eq!(subtype, "html"),
                    _ => panic!(),
                }
            }
            _ => panic!("expected multipart"),
        }
    }

    #[test]
    fn renders_mote_payload() {
        use dmtap_core::identity::IdentityKey;
        use dmtap_core::mote::{Headers, Payload};
        let ik = IdentityKey::generate();
        let payload = Payload {
            from: ik.public(),
            sig: vec![],
            headers: Headers { subject: Some("Hello".into()), ..Default::default() },
            body: b"Hi there".to_vec(),
            refs: vec![],
            attach: vec![],
            expires: None,
        };
        let raw = render_rfc5322(&payload, 1_752_000_000_000);
        let parsed = ParsedMessage::parse(&raw);
        assert_eq!(parsed.header("subject"), Some("Hello"));
        assert!(parsed.header("from").unwrap().ends_with("@dmtap.local"));
        assert!(parsed.header("date").is_some());
    }

    #[test]
    fn renders_mote_payload_rejects_header_injection() {
        use dmtap_core::identity::IdentityKey;
        use dmtap_core::mote::{Headers, Payload};
        let ik = IdentityKey::generate();
        // A hostile sender's subject/mime carry embedded CR/LF, trying to (a) inject a forged
        // header and (b) splice a fake blank line that would end the header block early.
        let payload = Payload {
            from: ik.public(),
            sig: vec![],
            headers: Headers {
                subject: Some("Hi\r\nBcc: attacker@evil.example\r\n\r\nInjected body".into()),
                mime: Some("text/plain\r\nX-Injected: yes".into()),
                ..Default::default()
            },
            body: b"legit body".to_vec(),
            refs: vec![],
            attach: vec![],
            expires: None,
        };
        let raw = render_rfc5322(&payload, 1_752_000_000_000);
        // The header block must never contain a raw CR/LF that didn't come from the renderer's own
        // fixed line terminators — i.e. no "\r\nBcc:" / "\r\n\r\n" smuggled in via a header value.
        let (hdr_bytes, body) = header_and_body(&raw);
        let hdr = String::from_utf8_lossy(&hdr_bytes);
        assert!(!hdr.contains("\r\nBcc:"), "Subject must not inject a sibling header: {hdr:?}");
        assert!(
            !hdr.contains("\r\nX-Injected"),
            "Content-Type must not inject a sibling header: {hdr:?}"
        );
        let parsed = ParsedMessage::parse(&raw);
        // The smuggled header names must not parse out as real, distinct headers.
        assert_eq!(parsed.header("bcc"), None);
        assert_eq!(parsed.header("x-injected"), None);
        // The legitimate body must still be exactly the payload body, not the smuggled text — the
        // attacker's embedded blank line must not have spliced "Injected body" in as real content.
        assert_eq!(body, b"legit body\r\n");
        assert_eq!(parsed.body, b"legit body\r\n");
        // The value survives (a client sees *something* for Subject) but with CR/LF stripped, so it
        // can never be mistaken for a header/body boundary or a second header line.
        assert!(!parsed.header("subject").unwrap().contains('\r'));
        assert!(!parsed.header("subject").unwrap().contains('\n'));
    }

    #[test]
    fn rfc5322_date_format() {
        // 1752537600000 ms == Tue, 15 Jul 2025 00:00:00 UTC.
        let s = format_rfc5322_date(1_752_537_600_000);
        assert_eq!(s, "Tue, 15 Jul 2025 00:00:00 +0000", "got {s}");
    }

    #[test]
    fn civil_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(weekday_from_days(0), 3); // Thursday
    }
}
