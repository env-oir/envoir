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
//!
//! i18n surface (all total, fuzz-friendly, std-only):
//! - [`decode_encoded_words`] / [`encode_header_value`] / [`encode_display_name`] — RFC 2047, so
//!   non-English legacy headers display correctly and non-ASCII MOTE headers render wire-safely.
//! - [`decode_transfer_encoding`] + [`decode_charset`] → [`decoded_body_text`] — CTE + charset
//!   decode for display, with the honest `isEncodingProblem` flag for charsets we don't implement.

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
    // Headers are an ASCII superset, so the *split* below is byte-safe either way — but the values
    // must not be UTF-8-lossy'd first: legacy senders still emit raw 8-bit ISO-8859-1 headers, and
    // a U+FFFD here destroys the byte identity forever. Valid UTF-8 passes through unchanged;
    // anything else falls back to Latin-1, whose byte→char map is total and lossless (every byte
    // 0x00–0xFF maps to the same-numbered scalar), so no header byte is ever discarded.
    let s: std::borrow::Cow<'_, str> = match std::str::from_utf8(bytes) {
        Ok(v) => std::borrow::Cow::Borrowed(v),
        Err(_) => std::borrow::Cow::Owned(bytes.iter().map(|&b| b as char).collect()),
    };
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

// --- RFC 2047 encoded-words + charsets + transfer encodings --------------------------------
//
// Charset strategy (deliberate, std-only): we implement UTF-8, US-ASCII and ISO-8859-1 ourselves —
// together they cover the overwhelming majority of legacy mail, and Latin-1 is a trivial, total
// byte→char map. Everything else (GB18030, Shift_JIS, KOI8-R, …) would require a real conversion
// table crate (encoding_rs, ~heavy) that this crate's std-only philosophy refuses by default; for
// those we lossy-decode and report it honestly (`isEncodingProblem: true` in JMAP) instead of
// asserting a clean decode we did not perform. If full charset coverage ever becomes worth a dep,
// this one function is the seam.

/// Decode `bytes` labeled with a MIME `charset` into text. Returns `(text, encoding_problem)`:
/// `encoding_problem` is `true` whenever the result is *not* a faithful decode (invalid UTF-8 was
/// replaced, or the charset is one we do not implement and the bytes were non-ASCII). Never fails.
pub fn decode_charset(bytes: &[u8], charset: &str) -> (String, bool) {
    let cs = charset.trim().trim_matches('"').to_ascii_lowercase();
    match cs.as_str() {
        // An absent charset defaults through the UTF-8 arm: pure ASCII (the RFC default) is valid
        // UTF-8, and mislabeled-but-valid UTF-8 (very common) decodes correctly too.
        "utf-8" | "utf8" | "" => match std::str::from_utf8(bytes) {
            Ok(s) => (s.to_string(), false),
            Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
        },
        "us-ascii" | "ascii" | "ansi_x3.4-1968" => {
            if bytes.is_ascii() {
                // Safe: just checked — every byte is ASCII, hence valid UTF-8.
                (String::from_utf8_lossy(bytes).into_owned(), false)
            } else {
                // 8-bit bytes under a us-ascii label are a lie; decode as Latin-1 (lossless, and
                // the most common reality behind that lie) but flag it.
                (bytes.iter().map(|&b| b as char).collect(), true)
            }
        }
        "iso-8859-1" | "iso8859-1" | "iso_8859-1" | "latin1" | "latin-1" | "l1" | "cp819" => {
            // ISO-8859-1: byte 0xNN is scalar U+00NN — total, lossless, infallible.
            (bytes.iter().map(|&b| b as char).collect(), false)
        }
        _ => {
            // Unimplemented charset. Nearly every charset in the wild is an ASCII superset, so
            // all-ASCII content under any label is a faithful decode; otherwise be honest.
            if bytes.is_ascii() {
                (String::from_utf8_lossy(bytes).into_owned(), false)
            } else {
                (String::from_utf8_lossy(bytes).into_owned(), true)
            }
        }
    }
}

/// Decode a Content-Transfer-Encoding (RFC 2045 §6): `base64` and `quoted-printable` are decoded,
/// the identity encodings (`7bit`/`8bit`/`binary`) pass through. A malformed base64 body is
/// returned as-is (fail open to the raw bytes — never panic, never lose data); QP tolerates
/// malformed escapes by passing them through verbatim.
pub fn decode_transfer_encoding(body: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        // base64 payloads are ASCII by construction, so a lossy view cannot corrupt valid input;
        // stray non-alphabet bytes make the decode fail → fall back to the raw body.
        "base64" => crate::util::base64_decode(&String::from_utf8_lossy(body))
            .unwrap_or_else(|| body.to_vec()),
        "quoted-printable" => qp_decode(body),
        _ => body.to_vec(),
    }
}

/// Quoted-printable decode (RFC 2045 §6.7): `=XX` hex escapes and soft line breaks (`=` before
/// CRLF/LF). Malformed escapes are emitted verbatim so hostile input can only ever look odd.
fn qp_decode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        if b != b'=' {
            out.push(b);
            i += 1;
            continue;
        }
        // Soft line break: `=` immediately before the line terminator joins the lines.
        if body[i + 1..].starts_with(b"\r\n") {
            i += 3;
        } else if body[i + 1..].starts_with(b"\n") {
            i += 2;
        } else if let (Some(h), Some(l)) =
            (body.get(i + 1).and_then(hex_val), body.get(i + 2).and_then(hex_val))
        {
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

fn hex_val(b: &u8) -> Option<u8> {
    (*b as char).to_digit(16).map(|d| d as u8)
}

/// Decode RFC 2047 encoded-words (`=?charset?B|Q?text?=`) in an (unfolded) header value.
///
/// - B (base64) and Q (RFC 2047 §4.2: `_`→SP, `=XX`) encodings; charsets per [`decode_charset`].
/// - Linear whitespace between two *adjacent* encoded-words is elided (§6.2) — multi-word CJK
///   subjects fold into encoded-word-per-line and must reassemble seamlessly.
/// - Anything malformed (bad hex, stray base64 bytes, truncated introducer, unknown encoding
///   letter) is passed through verbatim: this runs on attacker-controlled header text and must be
///   total — worst case the user sees the raw encoded form, exactly today's behavior.
pub fn decode_encoded_words(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let mut last_was_encoded = false;
    while !rest.is_empty() {
        // Peel leading linear whitespace, then the next SP/TAB-delimited token.
        let ws_end = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let (ws, after) = rest.split_at(ws_end);
        let tok_end = after.find([' ', '\t']).unwrap_or(after.len());
        let (tok, next) = after.split_at(tok_end);
        if tok.is_empty() {
            out.push_str(ws);
            break;
        }
        match decode_encoded_word_run(tok) {
            Some(decoded) => {
                // §6.2: the whitespace separating two encoded-words is not displayed.
                if !last_was_encoded {
                    out.push_str(ws);
                }
                out.push_str(&decoded);
                last_was_encoded = true;
            }
            None => {
                out.push_str(ws);
                out.push_str(tok);
                last_was_encoded = false;
            }
        }
        rest = next;
    }
    out
}

/// Decode a whitespace-free token that must consist entirely of one or more encoded-words
/// (some senders butt them together with no separator). `None` → not/malformed encoded-words.
fn decode_encoded_word_run(tok: &str) -> Option<String> {
    if !tok.starts_with("=?") {
        return None;
    }
    let mut out = String::new();
    let mut rest = tok;
    while !rest.is_empty() {
        let (piece, used) = decode_one_encoded_word(rest)?;
        out.push_str(&piece);
        rest = &rest[used..];
    }
    Some(out)
}

/// Parse one `=?charset?enc?text?=` at the start of `s` → (decoded text, bytes consumed).
fn decode_one_encoded_word(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    let charset = &body[..q1];
    // RFC 2047 §2 caps the whole word at 75 chars; a huge "charset" is garbage, refuse early.
    if charset.is_empty() || charset.len() > 60 {
        return None;
    }
    let after = &body[q1 + 1..];
    let enc = after.chars().next()?;
    let after_enc = after[enc.len_utf8()..].strip_prefix('?')?;
    let text_end = after_enc.find("?=")?;
    let text = &after_enc[..text_end];
    // encoded-text may not contain SP or `?` (§2) — a stray `?` before our `?=` means malformed.
    if text.contains('?') || text.contains(' ') {
        return None;
    }
    let bytes = match enc {
        'B' | 'b' => crate::util::base64_decode(text)?,
        'Q' | 'q' => q_word_decode(text)?,
        _ => return None,
    };
    // RFC 2231 §5 allows a `*lang` suffix on the charset (`=?UTF-8*en?...`); drop the language.
    let charset = charset.split('*').next().unwrap_or(charset);
    let (decoded, _problem) = decode_charset(&bytes, charset);
    let used = 2 + q1 + 1 + enc.len_utf8() + 1 + text_end + 2;
    Some((decoded, used))
}

/// Q-encoding decode (RFC 2047 §4.2): `_` is SPACE, `=XX` is a hex byte. Bad hex → malformed.
fn q_word_decode(text: &str) -> Option<Vec<u8>> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {
                let h = b.get(i + 1).and_then(hex_val)?;
                let l = b.get(i + 2).and_then(hex_val)?;
                out.push((h << 4) | l);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// The user-visible text of a parsed message body: Content-Transfer-Encoding decoded (base64/QP),
/// then charset-decoded per the Content-Type `charset` parameter. Returns `(text, problem)` where
/// `problem` is the honest JMAP `isEncodingProblem` flag from [`decode_charset`]. This is the ONE
/// body-display path — JMAP bodyValues, previews/snippets and body search all go through it, so
/// search always matches exactly what a user sees.
pub fn decoded_body_text(p: &ParsedMessage) -> (String, bool) {
    let encoding = p.header("Content-Transfer-Encoding").unwrap_or("7bit");
    let raw = decode_transfer_encoding(&p.body, encoding);
    let (_, _, params) = content_type(&p.headers);
    let charset =
        params.iter().find(|(k, _)| k == "charset").map(|(_, v)| v.as_str()).unwrap_or("");
    decode_charset(&raw, charset)
}

// --- RFC 2047 encoding (header render toward the legacy wire) -------------------------------

/// Bytes-per-encoded-word ceiling. `=?UTF-8?B?` + base64(30 B → 40 chars) + `?=` = 52 chars, so
/// even after a `Subject: ` prefix (or a fold's leading SP) every line stays well under the RFC
/// 5322 §2.1.1 78-char SHOULD and the RFC 2047 §2 75-char encoded-word cap.
const ENCODED_WORD_MAX_BYTES: usize = 30;

/// Encode a header value for the RFC 5322 wire: printable-ASCII values pass through verbatim;
/// anything else becomes UTF-8 B-encoded-words (RFC 2047), chunked on char boundaries and joined
/// with folding whitespace (`CRLF SP`) so long non-ASCII subjects fold RFC-compliantly. Strict
/// MTAs mangle or reject raw 8-bit header bytes — this is the only correct legacy spelling.
/// (The gateway's outbound render adopts this same function; keep it total and allocation-cheap.)
pub fn encode_header_value(v: &str) -> String {
    if is_wire_safe_ascii(v) {
        return v.to_string();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in v.chars() {
        if chunk.len() + c.len_utf8() > ENCODED_WORD_MAX_BYTES && !chunk.is_empty() {
            words.push(encode_one_word(&chunk));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(encode_one_word(&chunk));
    }
    // Adjacent encoded-words rejoin with their separating whitespace elided on decode (§6.2), so
    // folding here is display-lossless.
    words.join("\r\n ")
}

/// Encode an address display-name for the wire (RFC 5322 `display-name` phrase context):
/// non-ASCII → encoded-word(s); ASCII with phrase-unsafe specials → quoted-string; else verbatim.
pub fn encode_display_name(name: &str) -> String {
    if !is_wire_safe_ascii(name) {
        return encode_header_value(name);
    }
    let atom_safe = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || "!#$%&'*+-/=?^_`{|}~.".contains(c));
    if atom_safe {
        name.to_string()
    } else {
        let escaped: String =
            name.chars().flat_map(|c| match c {
                '"' | '\\' => vec!['\\', c],
                _ => vec![c],
            }).collect();
        format!("\"{escaped}\"")
    }
}

/// Printable ASCII (plus TAB) — the bytes that may appear verbatim in a header value on the wire.
fn is_wire_safe_ascii(v: &str) -> bool {
    v.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

fn encode_one_word(chunk: &str) -> String {
    format!("=?UTF-8?B?{}?=", crate::util::base64_encode(chunk.as_bytes()))
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
    // MOTE subjects are native UTF-8; the legacy wire wants RFC 2047 (raw 8-bit header bytes get
    // mangled or bounced by strict MTAs). ASCII subjects pass through untouched.
    msg.push_str(&format!("Subject: {}\r\n", encode_header_value(&subject)));
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

    // --- RFC 2047 / charset / CTE ------------------------------------------------------------

    #[test]
    fn decodes_b_encoded_words() {
        // UTF-8 B: Japanese.
        assert_eq!(
            decode_encoded_words("=?UTF-8?B?44GT44KT44Gr44Gh44Gv?="),
            "こんにちは"
        );
        // Cyrillic.
        assert_eq!(
            decode_encoded_words("=?UTF-8?B?0J/RgNC40LLQtdGC?="),
            "Привет"
        );
        // Mixed plain + encoded keeps the separating whitespace against plain text.
        assert_eq!(
            decode_encoded_words("Re: =?UTF-8?B?0J/RgNC40LLQtdGC?= (fwd)"),
            "Re: Привет (fwd)"
        );
    }

    #[test]
    fn decodes_q_encoded_words() {
        assert_eq!(decode_encoded_words("=?UTF-8?Q?Hello_World?="), "Hello World");
        assert_eq!(
            decode_encoded_words("=?ISO-8859-1?Q?Gr=FC=DFe_aus_M=FCnchen?="),
            "Grüße aus München"
        );
        // Lowercase encoding letter and charset are accepted.
        assert_eq!(decode_encoded_words("=?iso-8859-1?q?caf=E9?="), "café");
    }

    #[test]
    fn adjacent_encoded_words_elide_whitespace() {
        // §6.2: whitespace between two encoded-words is not displayed — a folded CJK subject
        // must reassemble seamlessly (including TAB folds and butted-together words).
        assert_eq!(
            decode_encoded_words("=?UTF-8?B?44GT44KT?= =?UTF-8?B?44Gr44Gh44Gv?="),
            "こんにちは"
        );
        assert_eq!(
            decode_encoded_words("=?UTF-8?Q?a?= \t =?UTF-8?Q?b?="),
            "ab"
        );
        assert_eq!(decode_encoded_words("=?UTF-8?Q?a?==?UTF-8?Q?b?="), "ab");
    }

    #[test]
    fn malformed_encoded_words_pass_through_verbatim() {
        for bad in [
            "=?UTF-8?X?abc?=",        // unknown encoding letter
            "=?UTF-8?Q?=ZZ?=",        // bad hex
            "=?UTF-8?B?!!notb64!!?=", // stray base64 bytes
            "=?UTF-8?B?abc",          // truncated (no ?= terminator)
            "=??B?abc?=",             // empty charset
            "=?UTF-8?Q?a?b?=",        // stray ? inside encoded-text
            "plain text only",
            "=?",
        ] {
            assert_eq!(decode_encoded_words(bad), bad, "must pass through: {bad}");
        }
        // A valid word followed by butted-on garbage: the whole token is malformed → verbatim.
        let tok = "=?UTF-8?Q?ok?=garbage";
        assert_eq!(decode_encoded_words(tok), tok);
    }

    #[test]
    fn unknown_charset_encoded_word_never_panics() {
        // GB2312-labeled bytes we can't decode: lossy text comes out, nothing panics.
        let s = decode_encoded_words("=?GB2312?B?xOO6ww==?=");
        assert!(!s.is_empty());
    }

    #[test]
    fn encode_header_round_trips_through_parse() {
        for subject in [
            "こんにちは、世界 — 長いテストの件名です。すべての文字が往復すること。",
            "Привет, Алиса! Это очень длинная тема письма для проверки свёртки строк.",
            "café ≤ 76 chars",
        ] {
            let encoded = encode_header_value(subject);
            // Every physical line obeys the RFC 5322 78-char SHOULD (incl. the header name).
            for line in format!("Subject: {encoded}").split("\r\n") {
                assert!(line.len() <= 78, "overlong fold line ({}): {line}", line.len());
            }
            // Full stack: render as a header, parse (unfold), decode → identical text.
            let raw = format!("Subject: {encoded}\r\n\r\nx");
            let p = ParsedMessage::parse(raw.as_bytes());
            assert_eq!(decode_encoded_words(p.header("Subject").unwrap()), subject);
        }
    }

    #[test]
    fn encode_header_leaves_ascii_untouched() {
        assert_eq!(encode_header_value("Weekly report [v2] (final)"), "Weekly report [v2] (final)");
    }

    #[test]
    fn encode_display_name_forms() {
        assert_eq!(encode_display_name("Alice Example"), "Alice Example");
        // Phrase specials require quoting; embedded quotes/backslashes are escaped.
        assert_eq!(encode_display_name("Smith, John"), "\"Smith, John\"");
        assert_eq!(encode_display_name("a \"b\" c"), "\"a \\\"b\\\" c\"");
        // Non-ASCII becomes an encoded word that decodes back.
        let enc = encode_display_name("Алиса");
        assert!(enc.starts_with("=?UTF-8?B?"), "{enc}");
        assert_eq!(decode_encoded_words(&enc), "Алиса");
    }

    #[test]
    fn renders_non_ascii_subject_as_encoded_words() {
        use dmtap_core::identity::IdentityKey;
        use dmtap_core::mote::{Headers, Payload};
        let ik = IdentityKey::generate();
        let payload = Payload {
            from: ik.public(),
            sig: vec![],
            headers: Headers { subject: Some("Привет, мир".into()), ..Default::default() },
            body: b"hi".to_vec(),
            refs: vec![],
            attach: vec![],
            expires: None,
        };
        let raw = render_rfc5322(&payload, 1_752_000_000_000);
        let (hdr, _) = header_and_body(&raw);
        // The wire header block must be pure ASCII — strict MTAs mangle/reject raw 8-bit headers.
        assert!(hdr.is_ascii(), "raw 8-bit bytes leaked into headers: {:?}", String::from_utf8_lossy(&hdr));
        let p = ParsedMessage::parse(&raw);
        assert_eq!(decode_encoded_words(p.header("Subject").unwrap()), "Привет, мир");
    }

    #[test]
    fn decode_charset_matrix() {
        // Latin-1 is decoded exactly, never flagged.
        assert_eq!(decode_charset(b"caf\xe9", "ISO-8859-1"), ("café".to_string(), false));
        assert_eq!(decode_charset(b"caf\xe9", "latin1"), ("café".to_string(), false));
        // Valid UTF-8 (also when the charset param is absent).
        assert_eq!(decode_charset("día".as_bytes(), "utf-8"), ("día".to_string(), false));
        assert_eq!(decode_charset("día".as_bytes(), ""), ("día".to_string(), false));
        // Invalid UTF-8 under a utf-8 label: lossy + flagged.
        let (s, problem) = decode_charset(b"a\xff b", "utf-8");
        assert!(problem && s.contains('\u{FFFD}'));
        // 8-bit under a us-ascii label is a lie: Latin-1 fallback + flagged.
        assert_eq!(decode_charset(b"caf\xe9", "us-ascii"), ("café".to_string(), true));
        // Unimplemented charset, ASCII content: faithful, unflagged (every charset is an ASCII
        // superset in practice).
        assert_eq!(decode_charset(b"hello", "gb18030"), ("hello".to_string(), false));
        // Unimplemented charset, 8-bit content: honestly flagged.
        let (_, problem) = decode_charset(b"\xc4\xe3\xba\xc3", "gb18030");
        assert!(problem, "GB18030 8-bit content must be flagged as an encoding problem");
    }

    #[test]
    fn decodes_transfer_encodings() {
        assert_eq!(decode_transfer_encoding(b"aGVsbG8gd29ybGQ=", "base64"), b"hello world");
        // base64 with folded lines (whitespace) still decodes.
        assert_eq!(decode_transfer_encoding(b"aGVs\r\nbG8=", "BASE64"), b"hello");
        // Malformed base64 falls back to the raw bytes — never lost, never a panic.
        assert_eq!(decode_transfer_encoding(b"!!not-base64!!", "base64"), b"!!not-base64!!");
        // Quoted-printable: hex escapes + soft line breaks; malformed escapes verbatim.
        assert_eq!(decode_transfer_encoding(b"Gr=C3=BC=C3=9Fe", "quoted-printable"), "Grüße".as_bytes());
        assert_eq!(decode_transfer_encoding(b"foo=\r\nbar", "quoted-printable"), b"foobar");
        assert_eq!(decode_transfer_encoding(b"foo=\nbar", "quoted-printable"), b"foobar");
        assert_eq!(decode_transfer_encoding(b"a=Zb", "quoted-printable"), b"a=Zb");
        // Identity encodings pass through byte-exact.
        assert_eq!(decode_transfer_encoding(b"caf\xe9", "8bit"), b"caf\xe9");
    }

    #[test]
    fn decoded_body_text_full_stack() {
        // base64 + explicit UTF-8 charset.
        let raw = b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n0J/RgNC40LLQtdGCLCDQvNC40YAh\r\n";
        let p = ParsedMessage::parse(raw);
        let (text, problem) = decoded_body_text(&p);
        assert_eq!(text.trim_end(), "Привет, мир!");
        assert!(!problem);

        // 8-bit Latin-1 declared as such: decoded faithfully, unflagged.
        let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGr\xfc\xdfe\r\n";
        let p = ParsedMessage::parse(raw);
        let (text, problem) = decoded_body_text(&p);
        assert_eq!(text.trim_end(), "Grüße");
        assert!(!problem);

        // GB18030 8-bit: lossy, honestly flagged.
        let raw = b"Content-Type: text/plain; charset=gb18030\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\xc4\xe3\xba\xc3\r\n";
        let p = ParsedMessage::parse(raw);
        let (_, problem) = decoded_body_text(&p);
        assert!(problem, "an undecoded GB18030 body must be flagged");
    }

    #[test]
    fn raw_latin1_headers_survive_parse() {
        // A legacy sender emitting raw 8-bit ISO-8859-1 headers (no 2047 at all): the Latin-1
        // fallback keeps the text instead of U+FFFD.
        let raw = b"Subject: Gr\xfc\xdfe\r\nFrom: a@b.com\r\n\r\nx";
        let p = ParsedMessage::parse(raw);
        assert_eq!(p.header("Subject"), Some("Grüße"));
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
