//! DKIM delegated-selector signing — spec §7.3.
//!
//! Outbound legacy mail is DKIM-signed **as the sender's domain**, using a selector the domain
//! owner delegated to the gateway (`<selector>._domainkey.<domain>` publishes the gateway's DKIM
//! public key). This cleanly separates *deliverability reputation* (the gateway's key) from
//! *identity* (the user's DMTAP key, which the gateway never holds). The gateway MUST refuse to
//! sign for a domain it was not delegated for (§7.3 / §19.7.2 failure table).
//!
//! Algorithm: **ed25519-sha256** (RFC 8463) with **relaxed/relaxed** canonicalization (RFC 6376
//! §3.4.2/§3.4.5). Ed25519 is used rather than RSA because the DMTAP suite already ships an
//! Ed25519 stack (no new primitive) and RFC 8463 is a first-class DKIM algorithm. The signer and
//! an independent [`verify`] are both implemented so tests confirm a real, checkable signature.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::b64;
use crate::dns::{self, UdpDnsClient, TYPE_TXT};

/// A per-domain delegated DKIM signing key (the private half of what the domain published at
/// `<selector>._domainkey.<domain>`).
pub struct DkimKey {
    domain: String,
    selector: String,
    signing: SigningKey,
}

impl DkimKey {
    /// Build from a 32-byte Ed25519 seed.
    pub fn from_seed(
        domain: impl Into<String>,
        selector: impl Into<String>,
        seed: &[u8; 32],
    ) -> Self {
        DkimKey {
            domain: domain.into(),
            selector: selector.into(),
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The DKIM public key to publish (base64, as it appears in the `p=` tag of the DNS record).
    pub fn public_p_tag(&self) -> String {
        b64::encode(self.signing.verifying_key().as_bytes())
    }

    /// Raw 32-byte public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn selector(&self) -> &str {
        &self.selector
    }
}

/// The set of headers signed, in order. `From` is mandatory (RFC 6376 §5.4); the rest are signed
/// when present.
const SIGNED_HEADERS: &[&str] = &["from", "to", "subject", "date", "message-id"];

/// Sign `message` (a full RFC 5322 byte string, CRLF line endings) as domain `key.domain` using
/// the delegated selector, at time `t` (seconds since epoch). Returns the complete
/// `DKIM-Signature:` header line (folded onto one logical line, CRLF-terminated) to prepend to the
/// message. Relaxed/relaxed, ed25519-sha256 (RFC 8463 / RFC 6376).
pub fn sign(key: &DkimKey, message: &[u8], t: u64) -> String {
    let (headers, body) = split_headers_body(message);

    // 1. Body hash over the relaxed-canonicalized body (RFC 6376 §3.4.4).
    let bh = b64::encode(&Sha256::digest(canonicalize_body(body)));

    // 2. Choose which of the signed-header set are actually present, preserving SIGNED_HEADERS order,
    //    then **oversign `from`** (RFC 6376 §5.4.2 / §8.15, M3AAWG best practice): list it once more
    //    than it appears. A verifier consuming instances bottom-up (see `assemble_signed_headers`)
    //    thereby binds not just the present From but the ABSENCE of any second From — an attacker who
    //    appends another From then fails verification, since the extra h= entry now resolves to their
    //    added header instead of the null string it was signed over.
    let mut h_names: Vec<&str> =
        SIGNED_HEADERS.iter().copied().filter(|h| find_header(&headers, h).is_some()).collect();
    h_names.push("from");
    let h_tag = h_names.join(":");

    // 3. Build the DKIM-Signature header value with an empty b= (the value signed over itself).
    let dkim_header_base = format!(
        "v=1; a=ed25519-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        key.domain, key.selector, t, h_tag, bh
    );

    // 4. Assemble the signing input: each signed header (relaxed, bottom-up per-name), then the
    //    DKIM-Signature header itself (relaxed, empty b=) with NO trailing CRLF (RFC 6376 §3.7).
    let mut signing_input = assemble_signed_headers(&headers, &h_names);
    signing_input.extend_from_slice(strip_final_crlf(&canonicalize_header(
        "DKIM-Signature",
        dkim_header_base.as_bytes(),
    )));

    // 5. Sign SHA-256(signing_input) with Ed25519 (RFC 8463 §3).
    let digest = Sha256::digest(&signing_input);
    let sig: Signature = key.signing.sign(&digest);
    let b = b64::encode(&sig.to_bytes());

    format!("DKIM-Signature: {dkim_header_base}{b}\r\n")
}

/// Verify a DKIM-signed message against the given raw Ed25519 public key (32 bytes). Returns the
/// error reason on any failure. This is an independent checker (not just "did we sign it"): it
/// re-canonicalizes and re-hashes exactly as a receiving MTA would.
pub fn verify(message: &[u8], public_key: &[u8]) -> Result<(), DkimError> {
    let (headers, body) = split_headers_body(message);
    let (_dkim_name, dkim_value) =
        find_header(&headers, "dkim-signature").ok_or(DkimError::NoSignature)?;
    // The DKIM-Signature tag list is ASCII by construction (base64/tokens), so this decode is
    // lossless for any signature that could verify; the signing-input reconstruction below still
    // uses the raw value bytes (`empty_b_value`), never this text view.
    let tags = parse_tags(&String::from_utf8_lossy(dkim_value));

    let get = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    if get("a").as_deref() != Some("ed25519-sha256") {
        return Err(DkimError::UnsupportedAlgorithm);
    }
    // Enforce relaxed/relaxed — we do not implement simple canonicalization.
    match get("c").as_deref() {
        Some("relaxed/relaxed") | None => {}
        Some(_) => return Err(DkimError::UnsupportedCanonicalization),
    }

    // Body hash check.
    let bh_expected = get("bh").ok_or(DkimError::MalformedSignature)?;
    let bh_actual = b64::encode(&Sha256::digest(canonicalize_body(body)));
    if bh_expected != bh_actual {
        return Err(DkimError::BodyHashMismatch);
    }

    let h_tag = get("h").ok_or(DkimError::MalformedSignature)?;
    let b_tag = get("b").ok_or(DkimError::MalformedSignature)?;

    let h_names: Vec<&str> = h_tag.split(':').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    // RFC 6376 §5.4: `from` MUST be signed. Reject a signature whose h= omits it outright — a
    // signature over only `subject` (etc.) would otherwise "verify" while leaving the
    // identity-bearing From entirely unbound, which DMARC alignment would then wrongly trust.
    if !h_names.iter().any(|n| n.eq_ignore_ascii_case("from")) {
        return Err(DkimError::FromFieldNotSigned);
    }

    // Rebuild the signing input: signed headers (bottom-up per-name instance, RFC 6376 §5.4.2 — see
    // `assemble_signed_headers` for the oversigning-correct semantics), then the DKIM-Signature
    // header with b= emptied.
    let mut signing_input = assemble_signed_headers(&headers, &h_names);
    let dkim_emptied = empty_b_value(dkim_value);
    signing_input
        .extend_from_slice(strip_final_crlf(&canonicalize_header("DKIM-Signature", &dkim_emptied)));

    // Verify Ed25519 over SHA-256(signing_input).
    let vk_bytes: [u8; 32] = public_key.try_into().map_err(|_| DkimError::BadPublicKey)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| DkimError::BadPublicKey)?;
    let sig_bytes = b64::decode(&b_tag).map_err(|_| DkimError::MalformedSignature)?;
    let sig_arr: [u8; 64] =
        sig_bytes.as_slice().try_into().map_err(|_| DkimError::MalformedSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    let digest = Sha256::digest(&signing_input);
    vk.verify(&digest, &sig).map_err(|_| DkimError::SignatureInvalid)
}

// --- Inbound DKIM verification (spec §7.2 step 2 / §9): resolver-driven ----------------------

/// Resolves the DKIM public key published at `<selector>._domainkey.<domain>` (RFC 6376 §3.6.1) —
/// the DNS TXT lookup, abstracted so inbound verification is testable in-process. **The live DNS
/// fetch is a documented seam**: a production impl queries `<selector>._domainkey.<domain>` for a
/// `TYPE_TXT` record (via [`crate::dns`]) and feeds the record's value through
/// [`parse_public_key_txt`] to get the raw key bytes; [`StaticDkimKeys`] is the in-process double.
pub trait DkimKeyResolver {
    /// Return the raw Ed25519 public key (32 bytes) published for `domain`/`selector`, or `None`
    /// when the domain publishes no key under that selector (verification then cannot proceed).
    fn resolve_dkim_key(&self, domain: &str, selector: &str) -> Option<Vec<u8>>;
}

/// An in-memory `DkimKeyResolver` for tests and single-domain deployments: a static map of
/// `(domain, selector) → public key`, modelling the sender domain's `_domainkey` TXT records.
#[derive(Debug, Default, Clone)]
pub struct StaticDkimKeys {
    entries: Vec<(String, String, Vec<u8>)>,
}

impl StaticDkimKeys {
    pub fn new() -> Self {
        Self::default()
    }
    /// Publish `key` at `<selector>._domainkey.<domain>`.
    pub fn publish(
        mut self,
        domain: impl Into<String>,
        selector: impl Into<String>,
        key: Vec<u8>,
    ) -> Self {
        self.entries.push((domain.into(), selector.into(), key));
        self
    }
}

impl DkimKeyResolver for StaticDkimKeys {
    fn resolve_dkim_key(&self, domain: &str, selector: &str) -> Option<Vec<u8>> {
        self.entries
            .iter()
            .find(|(d, s, _)| d.eq_ignore_ascii_case(domain) && s == selector)
            .map(|(_, _, k)| k.clone())
    }
}

/// The real, DNS-backed [`DkimKeyResolver`]: queries `<selector>._domainkey.<domain>` for a `TXT`
/// record (RFC 6376 §3.6.1) and extracts the `p=` key via [`parse_public_key_txt`]. See
/// [`crate::dns`] module docs for the underlying wire-format caveats (UDP-only, no TC/EDNS0/
/// retries/caching/DNSSEC) — a lookup failure or a record with no usable `p=` both surface as
/// [`DkimVerdict::KeyUnavailable`] (this trait, like [`crate::mta_sts::TxtResolver`], does not
/// distinguish NODATA from a resolver error).
pub struct DnsDkimKeyResolver {
    client: UdpDnsClient,
}

impl DnsDkimKeyResolver {
    pub fn new(dns_server: SocketAddr) -> Self {
        DnsDkimKeyResolver { client: UdpDnsClient::new(dns_server) }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }
}

impl DkimKeyResolver for DnsDkimKeyResolver {
    fn resolve_dkim_key(&self, domain: &str, selector: &str) -> Option<Vec<u8>> {
        let name = format!("{selector}._domainkey.{domain}");
        let msg = self.client.query(&name, TYPE_TXT).ok()?;
        msg.answers
            .iter()
            .filter(|rr| rr.rtype == TYPE_TXT)
            .map(dns::parse_txt_rdata)
            .find_map(|txt| parse_public_key_txt(&txt))
    }
}

/// The outcome of verifying an inbound message's DKIM signature against the resolved public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimVerdict {
    /// The signature is present and cryptographically verifies as `domain`/`selector`.
    Pass { domain: String, selector: String },
    /// A signature is present but does not verify (bad body hash, bad signature, wrong algorithm).
    Fail(DkimError),
    /// The message carries no DKIM-Signature header at all (unsigned legacy mail).
    NoSignature,
    /// A signature names `domain`/`selector` but no key is published there — cannot verify (the
    /// `_domainkey` TXT lookup returned nothing). Treated as "unverified", never as pass.
    KeyUnavailable { domain: String, selector: String },
}

/// Extract the signing domain (`d=`) and selector (`s=`) from a message's DKIM-Signature header,
/// so a verifier knows which `<selector>._domainkey.<domain>` key to resolve. `None` if the message
/// has no DKIM-Signature or the header lacks either tag.
pub fn signing_domain_selector(message: &[u8]) -> Option<(String, String)> {
    let (headers, _body) = split_headers_body(message);
    let (_name, value) = find_header(&headers, "dkim-signature")?;
    let tags = parse_tags(&String::from_utf8_lossy(value));
    let get = |k: &str| tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    Some((get("d")?, get("s")?))
}

/// Verify an inbound message's DKIM signature (RFC 6376), resolving the public key via `resolver`.
/// This composes [`signing_domain_selector`] (which key to fetch) with the independent [`verify`]
/// (the actual cryptographic check) — a real, checkable verification, not a stub. The only external
/// dependency (the `_domainkey` DNS TXT fetch) is behind the [`DkimKeyResolver`] seam.
pub fn verify_with_resolver(message: &[u8], resolver: &dyn DkimKeyResolver) -> DkimVerdict {
    let (domain, selector) = match signing_domain_selector(message) {
        Some(ds) => ds,
        None => return DkimVerdict::NoSignature,
    };
    match resolver.resolve_dkim_key(&domain, &selector) {
        Some(key) => match verify(message, &key) {
            Ok(()) => DkimVerdict::Pass { domain, selector },
            Err(e) => DkimVerdict::Fail(e),
        },
        None => DkimVerdict::KeyUnavailable { domain, selector },
    }
}

/// Parse the `p=` base64 public key out of a DKIM `_domainkey` DNS TXT record value
/// (`v=DKIM1; k=ed25519; p=<base64>`, RFC 6376 §3.6.1 / RFC 8463). Returns the raw key bytes, or
/// `None` if there is no `p=` tag or it does not decode. This is the pure half of the DNS seam: a
/// real [`DkimKeyResolver`] queries the TXT record via [`crate::dns`] and pipes the value here.
pub fn parse_public_key_txt(txt: &str) -> Option<Vec<u8>> {
    for part in txt.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("p=") {
            let v: String = v.chars().filter(|c| !c.is_whitespace()).collect();
            // An empty p= (RFC 6376: a revoked key) is treated as "no usable key".
            if v.is_empty() {
                return None;
            }
            return b64::decode(&v).ok();
        }
    }
    None
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum DkimError {
    #[error("message carries no DKIM-Signature header")]
    NoSignature,
    #[error("unsupported DKIM algorithm (expected ed25519-sha256)")]
    UnsupportedAlgorithm,
    #[error("unsupported canonicalization (expected relaxed/relaxed)")]
    UnsupportedCanonicalization,
    #[error("DKIM h= tag does not cover the mandatory From header (RFC 6376 §5.4)")]
    FromFieldNotSigned,
    #[error("malformed DKIM-Signature header")]
    MalformedSignature,
    #[error("body hash (bh=) does not match")]
    BodyHashMismatch,
    #[error("DKIM public key is malformed")]
    BadPublicKey,
    #[error("DKIM signature does not verify")]
    SignatureInvalid,
}

// --- RFC 6376 canonicalization + header helpers --------------------------------------------
//
// Everything below is **byte-based** on purpose (the protocol-i18n audit's item 1): RFC 6376
// canonicalization is defined over octets, and legacy mail legitimately carries raw 8-bit bytes
// (ISO-8859-x subjects, GB18030 bodies) in both headers and body. The previous `from_utf8_lossy`
// round-trips replaced those bytes with U+FFFD (or re-encoded Latin-1 as two-byte UTF-8) before
// hashing, so a perfectly valid external signature over an 8-bit message could never verify —
// which under `DkimPolicy::Reject` bounced legitimate international mail. Only the ASCII-by-spec
// DKIM tag list gets a text view.

/// Split a message into (header lines, body). Headers are returned as `(name, value-bytes)` pairs
/// with folding preserved in `value` (canonicalization handles unfolding). Names are decoded as
/// text (header field names are ASCII per RFC 5322 §2.2; a non-ASCII name can never match a signed
/// name and so only ever describes an unsigned header).
fn split_headers_body(message: &[u8]) -> (Vec<(String, Vec<u8>)>, &[u8]) {
    let (head, body) = match find_blank_line(message) {
        Some(idx) => (&message[..idx], &message[idx + 4..]),
        None => (message, &b""[..]),
    };
    (parse_headers(head), body)
}

/// Find the index of the CRLFCRLF that ends the header block.
fn find_blank_line(message: &[u8]) -> Option<usize> {
    message.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Split on CRLF pairs (never lone CR or LF — RFC 5322 line breaks are CRLF on the SMTP wire).
fn split_crlf(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
            out.push(&bytes[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    out.push(&bytes[start..]);
    out
}

/// `bytes` with one trailing CRLF removed (RFC 6376 §3.7: the final DKIM-Signature line in the
/// signing input carries no terminator).
fn strip_final_crlf(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r\n").unwrap_or(bytes)
}

/// Parse header lines into `(name, value-bytes)`, joining continuation (folded) lines into the
/// value verbatim (fold CRLF+WSP included — unfolding is canonicalization's job).
fn parse_headers(head: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for raw in split_crlf(head) {
        if raw.is_empty() {
            continue;
        }
        if raw[0] == b' ' || raw[0] == b'\t' {
            // Continuation of the previous header value (folded line).
            if let Some(last) = out.last_mut() {
                last.1.extend_from_slice(b"\r\n");
                last.1.extend_from_slice(raw);
            }
            continue;
        }
        if let Some(colon) = raw.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&raw[..colon]).into_owned();
            out.push((name, raw[colon + 1..].to_vec()));
        }
    }
    out
}

/// Find a header by case-insensitive name; returns the ORIGINAL `(name, value)` (last occurrence,
/// matching how a single-instance signed header is treated). Used for both signing and verifying.
fn find_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<(&'a str, &'a [u8])> {
    headers
        .iter()
        .rev()
        .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(n, v)| (n.as_str(), v.as_slice()))
}

/// Assemble the canonicalized signing bytes for an ordered `h=` name list, honoring RFC 6376
/// §5.4.2's multiple-instance rule: repeated instances of the same field name are consumed from the
/// **bottom of the message upward**, one physical instance per repetition. An `h=` entry with no
/// remaining instance contributes the **null string** (nothing) — which is precisely what lets
/// oversigning (listing a name once more than it appears) detect a later-added instance: the extra
/// entry, signed over the null string, instead binds the attacker's added header at verify time and
/// the signature fails. This replaces the previous `find_header`-per-entry loop, which always
/// resolved every repeat of a name to the single bottom-most instance (so a repeated `from` bound
/// nothing new and oversigning was inert).
fn assemble_signed_headers(headers: &[(String, Vec<u8>)], h_names: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, name) in h_names.iter().enumerate() {
        let key = name.trim();
        // How many earlier h= entries already claimed this name ⇒ which repetition this is (0-based).
        let occurrence = h_names[..k].iter().filter(|m| m.trim().eq_ignore_ascii_case(key)).count();
        // The `occurrence`-th instance of `key` counting from the BOTTOM of the message (§5.4.2);
        // `None` (fewer instances than h= entries) ⇒ the null string, contributing nothing.
        let instance = headers
            .iter()
            .rev()
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case(key))
            .nth(occurrence);
        if let Some((n, v)) = instance {
            out.extend_from_slice(&canonicalize_header(n, v));
        }
    }
    out
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2): lowercase name, unfold, compress internal
/// WSP runs to a single SP in the value, strip leading/trailing value WSP, single CRLF terminator.
/// Operates on octets: WSP/CRLF are ASCII, so 8-bit value bytes pass through untouched — exactly
/// what an octet-faithful verifier on the other side hashes.
fn canonicalize_header(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(name.len() + value.len() + 3);
    out.extend(name.trim().bytes().map(|b| b.to_ascii_lowercase()));
    out.push(b':');
    // Unfold (drop CRLF pairs), then collapse WSP runs to one SP, suppressing leading WSP.
    let mut val: Vec<u8> = Vec::with_capacity(value.len());
    let mut in_wsp = false;
    let mut i = 0;
    while i < value.len() {
        let b = value[i];
        if b == b'\r' && value.get(i + 1) == Some(&b'\n') {
            i += 2;
            continue;
        }
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp && !val.is_empty() {
                val.push(b' ');
            }
            in_wsp = false;
            val.push(b);
        }
        i += 1;
    }
    // Trailing WSP is dropped because a space is only emitted before the next non-WSP byte.
    out.extend_from_slice(&val);
    out.extend_from_slice(b"\r\n");
    out
}

/// Relaxed body canonicalization (RFC 6376 §3.4.4): strip trailing WSP per line, collapse internal
/// WSP runs to one SP, remove trailing empty lines, terminate with a single CRLF (empty body → "").
/// Octet-based: an ISO-8859-x / GB18030 body hashes over its original bytes (see module note).
fn canonicalize_body(body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for line in split_crlf(body) {
        // Collapse internal WSP runs, strip trailing WSP (§3.4.4 keeps a leading run as one SP).
        let mut collapsed: Vec<u8> = Vec::with_capacity(line.len());
        let mut in_wsp = false;
        for &b in line {
            if b == b' ' || b == b'\t' {
                in_wsp = true;
            } else {
                if in_wsp {
                    collapsed.push(b' ');
                }
                in_wsp = false;
                collapsed.push(b);
            }
        }
        // Trailing WSP is dropped because we only emit a space before the next non-WSP byte.
        lines.push(collapsed);
    }
    // Remove trailing empty lines.
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(l);
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Parse `k=v; k2=v2` DKIM tag lists (RFC 6376 §3.2). WSP around tokens is stripped; base64 values
/// keep their folding removed.
fn parse_tags(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let (k, v) = part.split_once('=')?;
            // For b=/bh=, folding whitespace inside the value must be ignored.
            let v: String = v.chars().filter(|c| !c.is_whitespace()).collect();
            Some((k.trim().to_string(), v))
        })
        .collect()
}

/// Return the DKIM-Signature value with the `b=` tag's content removed (kept as `b=`), preserving
/// everything else **byte**-verbatim (RFC 6376 §3.7: the b= value is emptied but the tag stays —
/// and any non-ASCII byte a sloppy signer put elsewhere in the value must survive untouched, since
/// this reconstruction feeds the signing input).
fn empty_b_value(value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut i = 0;
    let bytes = value;
    while i < bytes.len() {
        // Match a `b` tag at a token boundary: start-of-string or right after ';' (+ optional WSP).
        let at_boundary = i == 0 || {
            let mut j = i;
            while j > 0 && (bytes[j - 1] == b' ' || bytes[j - 1] == b'\t') {
                j -= 1;
            }
            j > 0 && bytes[j - 1] == b';'
        };
        if at_boundary && bytes[i] == b'b' {
            // Ensure it is exactly tag `b`, not `bh`: next non-WSP char must be '='.
            let mut k = i + 1;
            while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'=' {
                out.extend_from_slice(b"b=");
                // Skip the old value up to the next ';' or end.
                let mut m = k + 1;
                while m < bytes.len() && bytes[m] != b';' {
                    m += 1;
                }
                i = m;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] =
        b"From: alice@sender.example\r\nTo: bob@host.net\r\nSubject: hi\r\nDate: Tue, 15 Jul 2026 00:00:00 +0000\r\n\r\nhello over the bridge\r\n";

    fn signed_msg(domain: &str, selector: &str, seed: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let key = DkimKey::from_seed(domain, selector, seed);
        let pubk = key.public_bytes();
        let header = sign(&key, MSG, 1_752_600_000);
        let mut out = header.into_bytes();
        out.extend_from_slice(MSG);
        (out, pubk)
    }

    #[test]
    fn inbound_verify_passes_for_a_genuinely_signed_message() {
        let (msg, pubk) = signed_msg("sender.example", "s1", &[3u8; 32]);
        let resolver = StaticDkimKeys::new().publish("sender.example", "s1", pubk.to_vec());
        assert_eq!(
            verify_with_resolver(&msg, &resolver),
            DkimVerdict::Pass { domain: "sender.example".into(), selector: "s1".into() }
        );
    }

    #[test]
    fn inbound_verify_fails_on_a_tampered_body() {
        let (msg, pubk) = signed_msg("sender.example", "s1", &[4u8; 32]);
        let mut tampered = msg.clone();
        let pos = tampered.windows(5).position(|w| w == b"hello").unwrap();
        tampered[pos] ^= 0x20;
        let resolver = StaticDkimKeys::new().publish("sender.example", "s1", pubk.to_vec());
        assert!(matches!(verify_with_resolver(&tampered, &resolver), DkimVerdict::Fail(_)));
    }

    #[test]
    fn inbound_verify_reports_no_signature_and_key_unavailable() {
        // Unsigned message → NoSignature.
        assert_eq!(verify_with_resolver(MSG, &StaticDkimKeys::new()), DkimVerdict::NoSignature);
        // Signed, but the domain publishes no key under that selector → KeyUnavailable, not Pass.
        let (msg, _pubk) = signed_msg("sender.example", "s1", &[5u8; 32]);
        assert_eq!(
            verify_with_resolver(&msg, &StaticDkimKeys::new()),
            DkimVerdict::KeyUnavailable { domain: "sender.example".into(), selector: "s1".into() }
        );
    }

    #[test]
    fn verify_rejects_a_signature_whose_h_omits_from() {
        // RFC 6376 §5.4: `from` MUST be covered. Rewrite a genuine signature's h= to drop `from`
        // (body/bh untouched, so the bh check still passes and we reach the from-coverage check).
        let key = DkimKey::from_seed("sender.example", "s1", &[7u8; 32]);
        let header = sign(&key, MSG, 1_752_600_000);
        let start = header.find("h=").expect("h= tag present");
        let end = start + header[start..].find(';').expect("h= is terminated by ';'");
        let rewritten = format!("{}h=subject{}", &header[..start], &header[end..]);
        let mut msg = rewritten.into_bytes();
        msg.extend_from_slice(MSG);
        assert_eq!(verify(&msg, &key.public_bytes()), Err(DkimError::FromFieldNotSigned));
    }

    #[test]
    fn oversigned_from_detects_an_appended_from_header() {
        // The signer oversigns `from` (h= lists it once more than it appears). A genuine message
        // verifies; an attacker who appends a second From — not covered without oversigning — then
        // fails verification, because the extra h= entry now binds their added header (RFC 6376
        // §5.4.2). This FAILS against the pre-fix behavior (no oversign + last-instance-per-name),
        // where the added From slipped through unbound.
        let key = DkimKey::from_seed("sender.example", "s1", &[8u8; 32]);
        let pubk = key.public_bytes();
        let header = sign(&key, MSG, 1_752_600_000);

        let mut signed = header.clone().into_bytes();
        signed.extend_from_slice(MSG);
        assert_eq!(verify(&signed, &pubk), Ok(()), "the genuine oversigned message verifies");

        let mut tampered = b"From: eve@evil.example\r\n".to_vec();
        tampered.extend_from_slice(header.as_bytes());
        tampered.extend_from_slice(MSG);
        assert_eq!(
            verify(&tampered, &pubk),
            Err(DkimError::SignatureInvalid),
            "an appended From is caught by oversigning"
        );
    }

    #[test]
    fn eight_bit_bodies_and_headers_hash_over_their_original_bytes() {
        // Raw ISO-8859-1 bytes (invalid UTF-8) in BOTH a signed header and the body. The previous
        // lossy-String canonicalization replaced each with U+FFFD before hashing, so a genuine
        // external signature over such a message could never verify (BodyHashMismatch) — this test
        // FAILS against that behavior.
        let msg: Vec<u8> = [
            &b"From: alice@sender.example\r\nSubject: caf"[..],
            &[0xE9],
            &b"\r\n\r\nl'"[..],
            &[0xFC],
            &b"ber-body\r\n"[..],
        ]
        .concat();
        let key = DkimKey::from_seed("sender.example", "s1", &[11u8; 32]);
        let header = sign(&key, &msg, 1_752_600_000);
        let mut signed = header.into_bytes();
        signed.extend_from_slice(&msg);
        assert_eq!(verify(&signed, &key.public_bytes()), Ok(()), "octet-faithful round trip");

        // And the lossy-mangled copy (what a UTF-8-decoding pipeline would have carried) does NOT
        // verify: the replacement characters are simply not the signed bytes.
        let mangled = String::from_utf8_lossy(&signed).into_owned().into_bytes();
        assert!(verify(&mangled, &key.public_bytes()).is_err());
    }

    #[test]
    fn signing_domain_selector_extracts_d_and_s() {
        let (msg, _pubk) = signed_msg("sender.example", "sel7", &[6u8; 32]);
        assert_eq!(
            signing_domain_selector(&msg),
            Some(("sender.example".to_string(), "sel7".to_string()))
        );
        assert_eq!(signing_domain_selector(MSG), None);
    }

    #[test]
    fn parse_public_key_txt_extracts_the_p_tag() {
        let key = DkimKey::from_seed("d", "s", &[9u8; 32]);
        let p = key.public_p_tag();
        let txt = format!("v=DKIM1; k=ed25519; p={p}");
        assert_eq!(parse_public_key_txt(&txt), Some(key.public_bytes().to_vec()));
        // A revoked (empty p=) record yields no key.
        assert_eq!(parse_public_key_txt("v=DKIM1; k=ed25519; p="), None);
        // A round trip: the parsed key verifies a message the private half signed.
        let (msg, _) = signed_msg("d", "s", &[9u8; 32]);
        let parsed = parse_public_key_txt(&txt).unwrap();
        assert!(verify(&msg, &parsed).is_ok());
    }
}
