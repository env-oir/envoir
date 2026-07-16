//! IMAP response encoding (RFC 9051 §7): status responses, the ENVELOPE and BODYSTRUCTURE
//! projections, FETCH body-section extraction, and the `astring`/`nstring`/literal quoting rules.
//!
//! Everything here is pure string/byte production so it round-trips in unit tests.

use std::borrow::Cow;

use crate::mime::{self, BodyPart, ParsedMessage};

use super::parser::Section;

/// Quote a string as an IMAP `string`: a quoted-string when it is "safe", otherwise a literal.
pub fn imap_string(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    let needs_literal = s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0 || b >= 0x80);
    if needs_literal {
        format!("{{{}}}\r\n{}", s.len(), s)
    } else {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }
}

/// An IMAP `nstring`: `NIL` when absent, else a quoted/literal string.
pub fn nstring(s: Option<&str>) -> String {
    match s {
        None => "NIL".to_string(),
        Some(v) => imap_string(v),
    }
}

/// Encode the ENVELOPE structure (RFC 9051 §7.5.2) from parsed headers.
pub fn envelope(p: &ParsedMessage) -> String {
    let date = nstring(p.header("Date"));
    let subject = nstring(p.header("Subject"));
    let from = addr_list(&p.addresses("From"));
    // Sender / Reply-To default to From when their headers are absent (RFC 9051 §7.5.2).
    let sender = if p.header("Sender").is_some() { addr_list(&p.addresses("Sender")) } else { from.clone() };
    let reply_to =
        if p.header("Reply-To").is_some() { addr_list(&p.addresses("Reply-To")) } else { from.clone() };
    let to = addr_list(&p.addresses("To"));
    let cc = addr_list(&p.addresses("Cc"));
    let bcc = addr_list(&p.addresses("Bcc"));
    let in_reply_to = nstring(p.header("In-Reply-To"));
    let message_id = nstring(p.header("Message-ID").or_else(|| p.header("Message-Id")));
    format!(
        "({date} {subject} {from} {sender} {reply_to} {to} {cc} {bcc} {in_reply_to} {message_id})"
    )
}

fn addr_list(addrs: &[mime::Address]) -> String {
    if addrs.is_empty() {
        return "NIL".to_string();
    }
    let mut out = String::from("(");
    for a in addrs {
        out.push_str(&format!(
            "({} {} {} {})",
            nstring(a.name.as_deref()),
            nstring(a.adl.as_deref()),
            nstring(a.mailbox.as_deref()),
            nstring(a.host.as_deref()),
        ));
    }
    out.push(')');
    out
}

/// Encode BODYSTRUCTURE (RFC 9051 §7.5.3). `extensible` controls whether the extension data
/// (md5/disposition/language/location) is appended — BODYSTRUCTURE includes it, bare BODY omits it.
pub fn body_structure(part: &BodyPart, extensible: bool) -> String {
    match part {
        BodyPart::Multipart { subtype, parts, params } => {
            let mut out = String::from("(");
            for p in parts {
                out.push_str(&body_structure(p, extensible));
            }
            out.push(' ');
            out.push_str(&imap_string(&subtype.to_uppercase()));
            if extensible {
                out.push(' ');
                out.push_str(&param_list(params));
                out.push_str(" NIL NIL NIL"); // disposition language location
            }
            out.push(')');
            out
        }
        BodyPart::Single { mime_type, subtype, params, id, description, encoding, octets, lines } => {
            let mut out = format!(
                "({} {} {} {} {} {} {}",
                imap_string(&mime_type.to_uppercase()),
                imap_string(&subtype.to_uppercase()),
                param_list(params),
                nstring(id.as_deref()),
                nstring(description.as_deref()),
                imap_string(encoding),
                octets,
            );
            if mime_type == "text" {
                out.push_str(&format!(" {lines}"));
            }
            if extensible {
                out.push_str(" NIL NIL NIL NIL"); // md5 disposition language location
            }
            out.push(')');
            out
        }
    }
}

fn param_list(params: &[(String, String)]) -> String {
    if params.is_empty() {
        return "NIL".to_string();
    }
    let mut out = String::from("(");
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{} {}", imap_string(&k.to_uppercase()), imap_string(v)));
    }
    out.push(')');
    out
}

/// Extract the bytes for a FETCH `BODY[section]` request from the raw message. `[]`, `[HEADER]`
/// and `[TEXT]` **borrow** the raw bytes (no copy — the partial-fetch path then slices only the
/// requested window); field-filtered and part sections must build new bytes.
pub fn extract_section<'a>(raw: &'a [u8], section: &Section) -> Cow<'a, [u8]> {
    match section {
        Section::Full => Cow::Borrowed(raw),
        Section::Header => Cow::Borrowed(&raw[..mime::body_offset(raw)]),
        Section::Text => Cow::Borrowed(&raw[mime::body_offset(raw)..]),
        Section::HeaderFields(fields) => Cow::Owned(selected_headers(raw, fields, true)),
        Section::HeaderFieldsNot(fields) => Cow::Owned(selected_headers(raw, fields, false)),
        Section::Part(path) => Cow::Owned(
            extract_part(raw, path)
                .map(|seg| seg[mime::body_offset(&seg)..].to_vec())
                .unwrap_or_default(),
        ),
        Section::PartMime(path) => Cow::Owned(
            extract_part(raw, path)
                .map(|seg| seg[..mime::body_offset(&seg)].to_vec())
                .unwrap_or_default(),
        ),
    }
}

/// Header lines matching (or not matching) `fields`, followed by the terminating CRLF. Parses only
/// the header block (not the MIME tree) — the common Apple/Thunderbird "headers preview" fetch.
fn selected_headers(raw: &[u8], fields: &[String], include: bool) -> Vec<u8> {
    let headers = mime::headers_only(raw);
    let wanted: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut out = String::new();
    for (name, value) in &headers {
        let is_wanted = wanted.contains(&name.to_ascii_lowercase());
        if is_wanted == include {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Walk a numeric MIME part path (1-based) into the raw message, returning that part's segment.
fn extract_part(raw: &[u8], path: &[u32]) -> Option<Vec<u8>> {
    let mut current = raw.to_vec();
    for &idx in path {
        let segs = mime::part_segments(&current);
        let seg = segs.get(idx.checked_sub(1)? as usize)?.clone();
        current = seg;
    }
    Some(current)
}

/// Extract and **CTE-decode** a body part for a FETCH `BINARY[section]` request (RFC 3516). An
/// empty path is the whole message body; a numeric path is that MIME part. The part's
/// `Content-Transfer-Encoding` (base64 / quoted-printable) is decoded so the client receives the
/// raw binary content; `7bit`/`8bit`/`binary` pass through unchanged.
pub fn extract_binary(raw: &[u8], path: &[u32]) -> Vec<u8> {
    let segment = if path.is_empty() {
        raw.to_vec()
    } else {
        match extract_part(raw, path) {
            Some(seg) => seg,
            None => return Vec::new(),
        }
    };
    let headers = mime::headers_only(&segment);
    let cte = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Transfer-Encoding"))
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let body = &segment[mime::body_offset(&segment)..];
    match cte.as_str() {
        "base64" => crate::util::base64_decode(&String::from_utf8_lossy(body)).unwrap_or_default(),
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(),
    }
}

/// Decode a quoted-printable body (RFC 2045 §6.7): `=XX` hex escapes and `=`-soft line breaks.
fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'=' {
            // Soft line break: `=` at end of line.
            if body.get(i + 1) == Some(&b'\r') && body.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if body.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            let hi = body.get(i + 1).and_then(|c| (*c as char).to_digit(16));
            let lo = body.get(i + 2).and_then(|c| (*c as char).to_digit(16));
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(body[i]);
        i += 1;
    }
    out
}

/// Render a [`Section`] back to its IMAP wire label (for the FETCH `BODY[label]` response).
pub fn section_label(section: &Section) -> String {
    match section {
        Section::Full => String::new(),
        Section::Header => "HEADER".into(),
        Section::Text => "TEXT".into(),
        Section::HeaderFields(f) => format!("HEADER.FIELDS ({})", f.join(" ")),
        Section::HeaderFieldsNot(f) => format!("HEADER.FIELDS.NOT ({})", f.join(" ")),
        Section::Part(p) => join_path(p),
        Section::PartMime(p) => format!("{}.MIME", join_path(p)),
    }
}

fn join_path(p: &[u32]) -> String {
    p.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
}

/// Apply a `<start.count>` partial to a byte slice (RFC 9051 §6.4.5).
pub fn apply_partial(bytes: &[u8], partial: Option<(u32, u32)>) -> (Vec<u8>, Option<u32>) {
    match partial {
        None => (bytes.to_vec(), None),
        Some((start, count)) => {
            let start = start as usize;
            let end = (start + count as usize).min(bytes.len());
            let slice = if start >= bytes.len() { &[][..] } else { &bytes[start..end] };
            (slice.to_vec(), Some(start as u32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_nstrings() {
        assert_eq!(imap_string("hi"), "\"hi\"");
        assert_eq!(imap_string(""), "\"\"");
        assert_eq!(nstring(None), "NIL");
        assert!(imap_string("a\r\nb").starts_with("{4}\r\n"));
    }

    #[test]
    fn envelope_projection() {
        let raw = b"Date: Wed, 15 Jul 2026 12:00:00 +0000\r\n\
                    From: Alice <alice@example.com>\r\n\
                    To: bob@example.net\r\n\
                    Subject: Hi\r\nMessage-ID: <abc@x>\r\n\r\nbody";
        let p = ParsedMessage::parse(raw);
        let env = envelope(&p);
        assert!(env.contains("\"Hi\""));
        assert!(env.contains("\"alice\""));
        assert!(env.contains("\"example.com\""));
        assert!(env.contains("<abc@x>"));
    }

    #[test]
    fn bodystructure_text() {
        let raw = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello\nworld\n";
        let p = ParsedMessage::parse(raw);
        let bs = body_structure(&p.structure, true);
        assert!(bs.starts_with("(\"TEXT\" \"PLAIN\""));
        assert!(bs.contains("\"CHARSET\" \"utf-8\""));
    }

    #[test]
    fn section_extraction() {
        let raw = b"From: a@b\r\nSubject: S\r\n\r\nthe body\r\n";
        assert_eq!(extract_section(raw, &Section::Text).as_ref(), b"the body\r\n");
        // [] and [HEADER]/[TEXT] must borrow the raw bytes (no allocation) so partial fetches slice.
        assert!(matches!(extract_section(raw, &Section::Full), Cow::Borrowed(_)));
        assert!(matches!(extract_section(raw, &Section::Text), Cow::Borrowed(_)));
        let hf = extract_section(raw, &Section::HeaderFields(vec!["Subject".into()])).into_owned();
        let s = String::from_utf8(hf).unwrap();
        assert!(s.contains("Subject: S"));
        assert!(!s.contains("From:"));
    }

    #[test]
    fn multipart_part_extraction() {
        let raw = b"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                    --B\r\nContent-Type: text/plain\r\n\r\nfirst part\r\n\
                    --B\r\nContent-Type: text/html\r\n\r\n<p>second</p>\r\n--B--\r\n";
        let part1 = extract_section(raw, &Section::Part(vec![1]));
        assert_eq!(String::from_utf8_lossy(part1.as_ref()).trim(), "first part");
    }
}
