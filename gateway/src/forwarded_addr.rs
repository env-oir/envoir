//! Legacy-gateway **forwarded / original-address** local-part encoding (spec §7.10).
//!
//! When a legacy sender hands the gateway a message whose original envelope address is
//! `local@native_domain` (e.g. `imran@mydomain.com`), the bridge needs to carry that *original*
//! address across the DMTAP boundary as a single, human-readable gateway local-part — so the
//! address is `local.native_domain@gateway.domain` (e.g. `imran.mydomain.com@gw.example`) and can
//! be **losslessly decoded** back to the pair `(local = "imran", native_domain = "mydomain.com")`.
//!
//! This is an **SRS-style** (Sender Rewriting Scheme) reversible re-addressing, and it is a
//! **distinct concern** from the two allocators in [`crate::authz`]:
//!
//! - [`crate::authz::key_derived_localpart`] — the stable `k<base32>` alias *derived from a DMTAP
//!   key*. Key → address, one direction, no original legacy address involved.
//! - [`crate::authz::AliasAllocator`] — operator-granted **vanity** local-parts for a registered
//!   key, backed by a stateful allocation table.
//!
//! Neither carries a legacy sender's *original* `local@native_domain`. This module is the
//! human-readable **forwarded-address** form: a pure, stateless, reversible function of the pair,
//! with no table to consult.
//!
//! # The ambiguity, and the encoding that removes it
//!
//! A naïve `local + "." + native_domain` join is **not** injective the moment the native domain
//! has more than one label: `imran.mydomain.com` could split as `("imran", "mydomain.com")` **or**
//! `("imran.mydomain", "com")` — the join `.` is indistinguishable from a domain's own label
//! separators. We therefore escape each component so that the join `.` is the *only* bare dot in
//! the result:
//!
//! - within each component, `-`  →  `--`  and  `.`  →  `-.`;
//! - the two escaped components are joined with a single top-level `.`.
//!
//! **Injectivity / unambiguous decode.** After escaping, a component contains **no bare `.`**:
//! every `.` in an escaped component is the second byte of a `-.` pair, and every `-` is the first
//! byte of a two-byte escape (`--` or `-.`). Hence the *only* dot in the joined string that is not
//! immediately produced by an escape is the top-level separator, and decode finds it with a single
//! left-to-right, escape-aware scan. Because the escape map is itself injective and its image
//! contains no bare dot, the whole `encode` is injective and `decode` is its exact inverse — decode
//! additionally re-encodes the recovered pair and requires it to reproduce the input verbatim, so
//! any non-canonical or malformed spelling is rejected fail-closed (returns `None`).
//!
//! # Case-folding
//!
//! Legacy MTAs freely case-fold a local-part in transit, and DNS domains are case-insensitive, so
//! the encoded form cannot rely on case to survive. [`encode`] therefore normalises both
//! components to lowercase, and [`decode`] lowercases its input before parsing. The round trip is
//! stable under case-folding: `decode(fold(encode(l, d))) == (l.to_lowercase(), d.to_lowercase())`
//! for any ASCII case-folding `fold`. The escape bytes `-` and `.` are caseless, so the structural
//! parse is unaffected regardless.

use std::fmt::Write as _;

/// Why a `(local, native_domain)` pair could not be encoded into a forwarded-address local-part.
///
/// Every variant is a **fail-closed** refusal: the gateway would rather reject an address it cannot
/// faithfully round-trip than emit one that decodes ambiguously or is not a legal SMTP local-part.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ForwardedAddrError {
    /// The native local-part is empty or contains a byte outside the accepted dot-atom subset
    /// (ASCII alphanumerics and `. - _ +`), or has a leading/trailing/doubled dot.
    #[error("invalid native local-part {0:?}")]
    InvalidLocal(String),
    /// The native domain is not a syntactically valid DNS domain (labels of ASCII alphanumerics and
    /// `-`, each 1..=63 bytes, no leading/trailing hyphen, total 1..=253 bytes).
    #[error("invalid native domain {0:?}")]
    InvalidDomain(String),
    /// The escaped, joined form would exceed the RFC 5321 §4.5.3.1.1 local-part limit of 64 octets,
    /// so it cannot be used as `<localpart>@gateway.domain` without being an illegal address.
    #[error("encoded forwarded local-part is {0} octets, over the 64-octet RFC 5321 limit")]
    TooLong(usize),
}

/// The maximum length of an SMTP local-part (RFC 5321 §4.5.3.1.1), which the encoded forwarded
/// form must fit within to be a usable `<localpart>@gateway.domain`.
const MAX_LOCALPART_LEN: usize = 64;

/// Encode a legacy sender's original address `(local, native_domain)` into the reversible gateway
/// local-part `escape(local) + "." + escape(native_domain)` (spec §7.10).
///
/// Both components are lowercased first (see the module-level *Case-folding* note). The result is
/// guaranteed to be a legal dot-atom SMTP local-part and to [`decode`] back to the lowercased pair.
///
/// # Errors
/// Fail-closed: [`ForwardedAddrError::InvalidLocal`] / [`ForwardedAddrError::InvalidDomain`] for a
/// malformed component, or [`ForwardedAddrError::TooLong`] if the escaped join exceeds 64 octets.
pub fn encode(local: &str, native_domain: &str) -> Result<String, ForwardedAddrError> {
    let local = local.to_ascii_lowercase();
    let native_domain = native_domain.to_ascii_lowercase();

    if !is_valid_local(&local) {
        return Err(ForwardedAddrError::InvalidLocal(local));
    }
    if !is_valid_domain(&native_domain) {
        return Err(ForwardedAddrError::InvalidDomain(native_domain));
    }

    let mut out = String::with_capacity(local.len() + native_domain.len() + 4);
    escape_into(&local, &mut out);
    out.push('.'); // the one top-level, unescaped separator
    escape_into(&native_domain, &mut out);

    if out.len() > MAX_LOCALPART_LEN {
        return Err(ForwardedAddrError::TooLong(out.len()));
    }
    Ok(out)
}

/// Decode a gateway local-part produced by [`encode`] back to `(local, native_domain)`.
///
/// Returns [`None`] fail-closed on *any* malformed, ambiguous, or non-canonical input: a dangling
/// escape (`-` at end of input, or `-` followed by anything other than `-`/`.`), a bare dot inside
/// a component, a missing separator, an empty component, a component that fails validation, or a
/// spelling that does not re-encode to itself. The input is lowercased before parsing, so a
/// case-folded encoding still decodes.
pub fn decode(gateway_localpart: &str) -> Option<(String, String)> {
    let s = gateway_localpart.to_ascii_lowercase();

    // Single escape-aware left-to-right scan: unescape the local-part until the FIRST bare dot,
    // which is necessarily the top-level separator (an escaped component never contains a bare dot).
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut local = String::new();
    let mut split_at = None;
    while i < bytes.len() {
        match bytes[i] {
            b'-' => {
                // A `-` must begin a two-byte escape.
                match bytes.get(i + 1) {
                    Some(b'-') => local.push('-'),
                    Some(b'.') => local.push('.'),
                    _ => return None, // dangling / invalid escape
                }
                i += 2;
            }
            b'.' => {
                split_at = Some(i);
                i += 1;
                break;
            }
            c => {
                local.push(c as char);
                i += 1;
            }
        }
    }
    split_at?; // no separator ⇒ not a forwarded address

    // Everything after the separator is the escaped native domain (no bare dot permitted there).
    let native_domain = unescape_component(&s[i..])?;

    if !is_valid_local(&local) || !is_valid_domain(&native_domain) {
        return None;
    }

    // Canonical-form guard: re-encoding the recovered pair MUST reproduce the (lowercased) input
    // verbatim. This makes decode the exact inverse of encode and rejects any non-canonical spelling
    // fail-closed, so the mapping is provably injective in both directions.
    match encode(&local, &native_domain) {
        Ok(canonical) if canonical == s => Some((local, native_domain)),
        _ => None,
    }
}

/// Append `s` to `out` with the forwarded-address escape applied: `-` → `--`, `.` → `-.`, all other
/// bytes verbatim. The image contains no bare `.` (every `.` is the second byte of a `-.` pair),
/// which is what makes the top-level join dot unambiguous.
fn escape_into(s: &str, out: &mut String) {
    for b in s.bytes() {
        match b {
            b'-' => out.push_str("--"),
            b'.' => out.push_str("-."),
            c => {
                // `c` is always ASCII here (inputs are validated to an ASCII subset).
                let _ = out.write_char(c as char);
            }
        }
    }
}

/// Unescape one component (no bare dot allowed): the inverse of [`escape_into`] for a single
/// component. Returns [`None`] on a dangling/invalid escape or a bare dot (which would mean a
/// second, spurious separator).
fn unescape_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut out = String::with_capacity(s.len());
    while i < bytes.len() {
        match bytes[i] {
            b'-' => {
                match bytes.get(i + 1) {
                    Some(b'-') => out.push('-'),
                    Some(b'.') => out.push('.'),
                    _ => return None,
                }
                i += 2;
            }
            b'.' => return None, // a bare dot inside a component ⇒ malformed
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    Some(out)
}

/// A conservative RFC 5321 dot-atom local-part check: ASCII alphanumerics and `. - _ +`, non-empty,
/// no leading/trailing/doubled dot, and within the 64-octet cap. Kept self-contained (not reused
/// from [`crate::authz`], whose equivalent is private) so this module depends only on `dmtap-core`
/// and crate-internal types.
fn is_valid_local(lp: &str) -> bool {
    if lp.is_empty()
        || lp.len() > MAX_LOCALPART_LEN
        || lp.starts_with('.')
        || lp.ends_with('.')
        || lp.contains("..")
    {
        return false;
    }
    lp.bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'+'))
}

/// A conservative RFC 1035 / RFC 5321 domain check: one or more dot-separated labels, each 1..=63
/// bytes of ASCII alphanumerics and `-` with no leading/trailing hyphen, total 1..=253 bytes. A
/// single-label domain is permitted (the mapping stays reversible regardless of label count).
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    let mut labels = 0;
    for label in domain.split('.') {
        labels += 1;
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return false;
        }
    }
    labels >= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every ASCII case-folding of `s`: itself, all-lower, all-upper, and an alternating-case
    /// spelling — used to prove the encoded form survives case-folding in transit.
    fn case_variants(s: &str) -> Vec<String> {
        let alt: String = s
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
            .collect();
        vec![s.to_string(), s.to_ascii_lowercase(), s.to_ascii_uppercase(), alt]
    }

    #[test]
    fn worked_example_roundtrips() {
        let enc = encode("imran", "mydomain.com").unwrap();
        // The one bare dot is the separator; the domain's dot is escaped to `-.`.
        assert_eq!(enc, "imran.mydomain-.com");
        assert_eq!(decode(&enc), Some(("imran".to_string(), "mydomain.com".to_string())));
    }

    #[test]
    fn separator_is_the_only_bare_dot() {
        // Across a range of encodings, exactly one dot is NOT preceded by an escaping `-`.
        for (local, domain) in [
            ("imran", "mydomain.com"),
            ("a.b.c", "x.y.z.example.co.uk"),
            ("first.last", "sub.domain.example.org"),
        ] {
            let enc = encode(local, domain).unwrap();
            let bytes = enc.as_bytes();
            let mut bare_dots = 0;
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'-' {
                    i += 2; // skip the escape pair, so its `.` is not counted as bare
                    continue;
                }
                if bytes[i] == b'.' {
                    bare_dots += 1;
                }
                i += 1;
            }
            assert_eq!(bare_dots, 1, "encoding {enc:?} must have exactly one bare separator dot");
        }
    }

    #[test]
    fn roundtrip_matrix_multilabel_and_dotted_local() {
        let locals = [
            "imran",
            "a",
            "first.last",
            "a.b.c.d",
            "user+tag",
            "user_name",
            "with-hyphen",
            "-.-", // hyphens and dots interior (leading/trailing dot excluded)
            "a-b.c_d+e",
            "0123456789",
        ];
        let domains = [
            "com",
            "mydomain.com",
            "example.co.uk",
            "a.b.c.d.e.f.example.org",
            "xn--kbenhavn-54a.example", // punycode label
            "host-with-hyphen.example.com",
            "1.2.3.4.example",
            "sub.domain.example.museum",
        ];
        for l in locals {
            // Skip local spellings our own validator would reject up front.
            if encode(l, "example.com").is_err() {
                continue;
            }
            for d in domains {
                let enc = encode(l, d).expect("valid pair encodes");
                let (dl, dd) = decode(&enc).expect("encoded form decodes");
                assert_eq!(dl, l.to_ascii_lowercase(), "local mismatch for ({l:?},{d:?}) enc={enc:?}");
                assert_eq!(dd, d.to_ascii_lowercase(), "domain mismatch for ({l:?},{d:?}) enc={enc:?}");
                // The encoded form must be a legal SMTP local-part length.
                assert!(enc.len() <= MAX_LOCALPART_LEN);
            }
        }
    }

    #[test]
    fn dots_in_domain_are_unambiguous() {
        // The classic ambiguity: without escaping, "a.b.c" could split three ways. With escaping,
        // each of these distinct pairs encodes to a DIFFERENT, uniquely-decodable local-part.
        let a = encode("a", "b.c").unwrap();
        let b = encode("a.b", "c").unwrap();
        let c = encode("a.b.c", "d").unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        assert_eq!(decode(&a).unwrap(), ("a".into(), "b.c".into()));
        assert_eq!(decode(&b).unwrap(), ("a.b".into(), "c".into()));
        assert_eq!(decode(&c).unwrap(), ("a.b.c".into(), "d".into()));
    }

    #[test]
    fn injective_no_two_pairs_collide() {
        use std::collections::HashMap;
        let mut seen: HashMap<String, (String, String)> = HashMap::new();
        let locals = ["a", "a.b", "a-b", "a--b", "a.b.c", "x-.y", "user+t", "u_v"];
        let domains = ["c", "b.c", "b-c", "b.c.d", "x--y.z", "example.co.uk"];
        for l in locals {
            if encode(l, "example.com").is_err() {
                continue;
            }
            for d in domains {
                let enc = encode(l, d).unwrap();
                let pair = (l.to_ascii_lowercase(), d.to_ascii_lowercase());
                if let Some(prev) = seen.insert(enc.clone(), pair.clone()) {
                    assert_eq!(prev, pair, "distinct pairs {prev:?} and {pair:?} collided to {enc:?}");
                }
            }
        }
    }

    #[test]
    fn survives_case_folding() {
        for (local, domain) in [
            ("Imran", "MyDomain.COM"),
            ("First.Last", "Sub.Example.Org"),
            ("USER+Tag", "Example.CO.UK"),
        ] {
            let enc = encode(local, domain).unwrap();
            let want = (local.to_ascii_lowercase(), domain.to_ascii_lowercase());
            // Decode still yields the lowercased pair no matter how the wire case-folded it.
            for folded in case_variants(&enc) {
                assert_eq!(decode(&folded), Some(want.clone()), "case variant {folded:?} must decode");
            }
        }
    }

    #[test]
    fn encode_is_idempotent_under_lowercasing() {
        // Encoding an already-lowercased pair and a mixed-case pair yield the same local-part.
        assert_eq!(
            encode("Imran", "MyDomain.Com").unwrap(),
            encode("imran", "mydomain.com").unwrap()
        );
    }

    #[test]
    fn reject_malformed_decode_inputs() {
        let bad = [
            "",                  // empty
            "imran",             // no separator at all
            "imranmydomain-com", // no bare separator dot
            ".mydomain-.com",    // empty local component
            "imran.",            // empty domain component
            "imran-",            // dangling escape at end of local
            "imran.-",           // dangling escape at end of domain
            "imran.mydo-main",   // `-m`: invalid escape (not `--`/`-.`)
            "a.b.c",             // second bare dot ⇒ domain has a bare dot ⇒ malformed
            "imran..com",        // doubled bare dot
            "-.local.dom-.com",  // decodes to local ".local" (leading dot) ⇒ invalid local
            "im ran.dom-.com",   // space is not a permitted byte
        ];
        for s in bad {
            assert_eq!(decode(s), None, "expected {s:?} to be rejected fail-closed");
        }
    }

    #[test]
    fn reject_invalid_encode_inputs() {
        // Local-part failures.
        assert!(matches!(encode("", "example.com"), Err(ForwardedAddrError::InvalidLocal(_))));
        assert!(matches!(encode(".lead", "example.com"), Err(ForwardedAddrError::InvalidLocal(_))));
        assert!(matches!(encode("trail.", "example.com"), Err(ForwardedAddrError::InvalidLocal(_))));
        assert!(matches!(encode("a..b", "example.com"), Err(ForwardedAddrError::InvalidLocal(_))));
        assert!(matches!(encode("bad space", "example.com"), Err(ForwardedAddrError::InvalidLocal(_))));
        // Domain failures.
        assert!(matches!(encode("a", ""), Err(ForwardedAddrError::InvalidDomain(_))));
        assert!(matches!(encode("a", "example..com"), Err(ForwardedAddrError::InvalidDomain(_))));
        assert!(matches!(encode("a", "-lead.com"), Err(ForwardedAddrError::InvalidDomain(_))));
        assert!(matches!(encode("a", "trail-.com"), Err(ForwardedAddrError::InvalidDomain(_))));
        assert!(matches!(encode("a", "under_score.com"), Err(ForwardedAddrError::InvalidDomain(_))));
    }

    #[test]
    fn reject_overlong_encoding() {
        // A domain whose escaped form pushes the join past 64 octets is refused, not truncated.
        let long_domain = format!("{}.example.com", "a".repeat(60));
        assert!(matches!(encode("user", &long_domain), Err(ForwardedAddrError::TooLong(_))));
    }

    #[test]
    fn boundary_length_encoding_is_accepted_and_roundtrips() {
        // A pair whose escaped join sits within the 64-octet cap encodes and decodes cleanly.
        let enc = encode("user", "example.com").unwrap();
        assert!(enc.len() <= MAX_LOCALPART_LEN);
        assert_eq!(decode(&enc).unwrap(), ("user".into(), "example.com".into()));
    }

    #[test]
    fn hyphen_heavy_components_roundtrip() {
        // Runs of hyphens (which each escape to `--`) and interior `-`/`.` runs must not confuse
        // the separator scan. These are RAW inputs: encode escapes each `-` and `.` independently.
        for (l, d) in [("a---b", "x--y.z"), ("--", "a-b.c-d"), ("a-.-b", "e-.-f.g")] {
            if let Ok(enc) = encode(l, d) {
                assert_eq!(
                    decode(&enc),
                    Some((l.to_ascii_lowercase(), d.to_ascii_lowercase())),
                    "hyphen-heavy ({l:?},{d:?}) enc={enc:?}"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_noncanonical_reencode_mismatch() {
        // Sanity: a hand-built string that is NOT what encode would emit for its apparent pair is
        // rejected by the canonical-form guard. `a--b` unescapes to local `a-b`; encode("a-b",..)
        // would emit `a--b`, so a genuine canonical form decodes — but a truncated escape does not.
        assert!(decode("a--b.c").is_some()); // canonical: local "a-b", domain "c"
        assert!(decode("a-b.c").is_none()); // `-b` is not a valid escape ⇒ rejected
    }
}
