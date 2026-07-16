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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::b64;

/// A per-domain delegated DKIM signing key (the private half of what the domain published at
/// `<selector>._domainkey.<domain>`).
pub struct DkimKey {
    domain: String,
    selector: String,
    signing: SigningKey,
}

impl DkimKey {
    /// Build from a 32-byte Ed25519 seed.
    pub fn from_seed(domain: impl Into<String>, selector: impl Into<String>, seed: &[u8; 32]) -> Self {
        DkimKey { domain: domain.into(), selector: selector.into(), signing: SigningKey::from_bytes(seed) }
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

    // 2. Choose which of the signed-header set are actually present, preserving SIGNED_HEADERS order.
    let present: Vec<&str> = SIGNED_HEADERS
        .iter()
        .copied()
        .filter(|h| find_header(&headers, h).is_some())
        .collect();
    let h_tag = present.join(":");

    // 3. Build the DKIM-Signature header value with an empty b= (the value signed over itself).
    let dkim_header_base = format!(
        "v=1; a=ed25519-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        key.domain, key.selector, t, h_tag, bh
    );

    // 4. Assemble the signing input: each signed header (relaxed), then the DKIM-Signature header
    //    itself (relaxed, empty b=) with NO trailing CRLF (RFC 6376 §3.7).
    let mut signing_input = Vec::new();
    for h in &present {
        let (name, value) = find_header(&headers, h).expect("filtered to present headers");
        signing_input.extend_from_slice(canonicalize_header(name, value).as_bytes());
    }
    signing_input.extend_from_slice(
        canonicalize_header("DKIM-Signature", &dkim_header_base)
            .trim_end_matches("\r\n")
            .as_bytes(),
    );

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
    let tags = parse_tags(&dkim_value);

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

    // Rebuild the signing input: signed headers, then the DKIM-Signature header with b= emptied.
    let mut signing_input = Vec::new();
    for h in h_tag.split(':') {
        let h = h.trim();
        if let Some((name, value)) = find_header(&headers, h) {
            signing_input.extend_from_slice(canonicalize_header(name, value).as_bytes());
        }
    }
    let dkim_emptied = empty_b_value(&dkim_value);
    signing_input.extend_from_slice(
        canonicalize_header("DKIM-Signature", &dkim_emptied)
            .trim_end_matches("\r\n")
            .as_bytes(),
    );

    // Verify Ed25519 over SHA-256(signing_input).
    let vk_bytes: [u8; 32] = public_key.try_into().map_err(|_| DkimError::BadPublicKey)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| DkimError::BadPublicKey)?;
    let sig_bytes = b64::decode(&b_tag).map_err(|_| DkimError::MalformedSignature)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| DkimError::MalformedSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    let digest = Sha256::digest(&signing_input);
    vk.verify(&digest, &sig).map_err(|_| DkimError::SignatureInvalid)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DkimError {
    #[error("message carries no DKIM-Signature header")]
    NoSignature,
    #[error("unsupported DKIM algorithm (expected ed25519-sha256)")]
    UnsupportedAlgorithm,
    #[error("unsupported canonicalization (expected relaxed/relaxed)")]
    UnsupportedCanonicalization,
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

/// Split a message into (header lines, body). Headers are returned as `(name, value)` pairs with
/// folding preserved in `value` (canonicalization handles unfolding).
fn split_headers_body(message: &[u8]) -> (Vec<(String, String)>, &[u8]) {
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

/// Parse header lines into `(name, value)`, joining continuation (folded) lines into the value.
fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in text.split("\r\n") {
        if raw.is_empty() {
            continue;
        }
        if raw.starts_with(' ') || raw.starts_with('\t') {
            // Continuation of the previous header value (folded line).
            if let Some(last) = out.last_mut() {
                last.1.push_str("\r\n");
                last.1.push_str(raw);
            }
            continue;
        }
        if let Some((name, value)) = raw.split_once(':') {
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// Find a header by case-insensitive name; returns the ORIGINAL `(name, value)` (last occurrence,
/// matching how a single-instance signed header is treated). Used for both signing and verifying.
fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<(&'a str, &'a str)> {
    headers
        .iter()
        .rev()
        .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(n, v)| (n.as_str(), v.as_str()))
}

/// Relaxed header canonicalization (RFC 6376 §3.4.2): lowercase name, unfold, compress internal
/// WSP runs to a single SP in the value, strip leading/trailing value WSP, single CRLF terminator.
fn canonicalize_header(name: &str, value: &str) -> String {
    let name = name.trim().to_ascii_lowercase();
    // Unfold: remove CRLF, then collapse runs of WSP to one space.
    let unfolded = value.replace("\r\n", "");
    let mut collapsed = String::with_capacity(unfolded.len());
    let mut in_wsp = false;
    for ch in unfolded.chars() {
        if ch == ' ' || ch == '\t' {
            in_wsp = true;
        } else {
            if in_wsp && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            in_wsp = false;
            collapsed.push(ch);
        }
    }
    let value = collapsed.trim_end();
    format!("{name}:{value}\r\n")
}

/// Relaxed body canonicalization (RFC 6376 §3.4.4): strip trailing WSP per line, collapse internal
/// WSP runs to one SP, remove trailing empty lines, terminate with a single CRLF (empty body → "").
fn canonicalize_body(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut lines: Vec<String> = Vec::new();
    for line in text.split("\r\n") {
        // Collapse internal WSP runs, strip trailing WSP.
        let mut collapsed = String::with_capacity(line.len());
        let mut in_wsp = false;
        for ch in line.chars() {
            if ch == ' ' || ch == '\t' {
                in_wsp = true;
            } else {
                if in_wsp {
                    collapsed.push(' ');
                }
                in_wsp = false;
                collapsed.push(ch);
            }
        }
        // Trailing WSP is dropped because we only emit a space before the next non-WSP char.
        lines.push(collapsed);
    }
    // Remove trailing empty lines.
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = lines.join("\r\n").into_bytes();
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
/// everything else verbatim (RFC 6376 §3.7: the b= value is emptied but the tag stays).
fn empty_b_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    let bytes = value.as_bytes();
    while i < bytes.len() {
        // Match a `b` tag at a token boundary: start-of-string or right after ';' (+ optional WSP).
        let at_boundary = i == 0
            || {
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
                out.push_str("b=");
                // Skip the old value up to the next ';' or end.
                let mut m = k + 1;
                while m < bytes.len() && bytes[m] != b';' {
                    m += 1;
                }
                i = m;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
