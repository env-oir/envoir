//! IDN → **A-label** (punycode) conversion at the gateway's DNS / dial / SNI boundary.
//!
//! DNS, TCP dialing, and TLS SNI are ASCII worlds: a Unicode (U-label) domain like
//! `bücher.example` must cross into its RFC 5890 A-label form `xn--bcher-kva.example` at exactly
//! the point where a name leaves the gateway's data model and hits the wire. Without this, three
//! independent failures stack up for any IDN destination (the protocol-i18n audit's item 2):
//! raw UTF-8 label bytes go into DNS qnames (never resolving, and a >63-byte label used to be
//! truncated mid-codepoint), the MX A/AAAA fallback dials the bare Unicode name, and rustls'
//! `ServerName` rejects non-ASCII — surfacing as an opaque `TlsUnavailable` instead of the real
//! diagnosis ("this domain has no DNS spelling").
//!
//! One function, called from the three boundaries ([`crate::dns::UdpDnsClient`] for every qname,
//! [`crate::mx::DnsMxResolver`] for the A/AAAA fallback host, and [`crate::outbound`] /
//! [`crate::outbound_tcp`] before resolve/dial/SNI). UTS-46 processing is `idna` — the url/servo
//! processor already pinned in this workspace (see Cargo.toml) — with the **URL deny list**, not
//! STD3: STD3 would reject `_`, and the gateway legitimately queries service-prefixed owner names
//! (`_mta-sts.<domain>`, `<sel>._domainkey.<domain>`). Non-strict UTS-46 skips DNS length checks,
//! so the RFC 1035 limits (63 octets/label, 253 octets/name) are enforced here explicitly —
//! **fail-closed**: a name that cannot be spelled on the DNS wire is a specific, diagnosable error,
//! never a silently-truncated query.

use idna::AsciiDenyList;

/// Why a domain has no valid DNS A-label spelling. Each variant names the offending input so the
/// error is diagnosable at the SMTP/report surface (vs. the opaque TLS abort this replaces).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdnError {
    /// UTS-46 processing itself refused the name (disallowed code points, invalid punycode, …).
    #[error("domain {0:?} is not IDNA-convertible to a DNS A-label form ({1})")]
    NotConvertible(String, String),
    /// A label exceeds the RFC 1035 63-octet limit even in A-label form. Refused rather than
    /// truncated: a truncated qname would just resolve the wrong (or no) name.
    #[error("domain {0:?}: label {1:?} exceeds the 63-octet DNS label limit in A-label form")]
    LabelTooLong(String, String),
    /// The whole name exceeds the RFC 1035 253-octet presentation limit in A-label form.
    #[error("domain {0:?} exceeds the 253-octet DNS name limit in A-label form")]
    NameTooLong(String),
}

/// Convert `domain` to its lowercase A-label (punycode) form, fail-closed on anything that has no
/// valid DNS spelling. Pure-ASCII input passes through (lowercased) — callers may apply this
/// unconditionally at the wire boundary. A single trailing root dot is preserved semantically by
/// the DNS encoder ([`crate::dns`] trims it), so it is stripped here before the length checks.
pub fn domain_to_ascii(domain: &str) -> Result<String, IdnError> {
    let ascii = idna::domain_to_ascii_cow(domain.as_bytes(), AsciiDenyList::URL)
        .map_err(|e| IdnError::NotConvertible(domain.to_string(), e.to_string()))?
        .into_owned();
    // Non-strict UTS-46 (deliberate, see module docs) skips VerifyDnsLength; enforce RFC 1035
    // limits ourselves so an oversized name errors here instead of being truncated at encoding.
    let bare = ascii.strip_suffix('.').unwrap_or(&ascii);
    if bare.len() > 253 {
        return Err(IdnError::NameTooLong(domain.to_string()));
    }
    for label in bare.split('.') {
        if label.len() > 63 {
            return Err(IdnError::LabelTooLong(domain.to_string(), label.to_string()));
        }
    }
    Ok(ascii)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_domain_converts_to_a_labels() {
        assert_eq!(domain_to_ascii("bücher.example").unwrap(), "xn--bcher-kva.example");
        // Case + NFD spelling fold to the same canonical A-label form (UTS-46 mapping).
        assert_eq!(domain_to_ascii("BÜCHER.example").unwrap(), "xn--bcher-kva.example");
        assert_eq!(domain_to_ascii("bu\u{0308}cher.example").unwrap(), "xn--bcher-kva.example");
    }

    #[test]
    fn ascii_passes_through_lowercased_including_service_labels() {
        assert_eq!(domain_to_ascii("Example.ORG").unwrap(), "example.org");
        // The URL deny list (not STD3) is deliberate: `_mta-sts` / `_domainkey` owner names must
        // survive the boundary conversion.
        assert_eq!(
            domain_to_ascii("_mta-sts.xn--bcher-kva.example").unwrap(),
            "_mta-sts.xn--bcher-kva.example"
        );
        assert_eq!(
            domain_to_ascii("gw1._domainkey.example.org").unwrap(),
            "gw1._domainkey.example.org"
        );
    }

    #[test]
    fn genuinely_unspellable_domains_are_specific_errors_not_truncations() {
        // A space is a forbidden domain code point (URL deny list) — no DNS spelling exists.
        assert!(matches!(
            domain_to_ascii("exa mple.bad"),
            Err(IdnError::NotConvertible(d, _)) if d == "exa mple.bad"
        ));
        // Invalid punycode in an xn-- label is refused by UTS-46 processing.
        assert!(matches!(
            domain_to_ascii("xn--999999999.example"),
            Err(IdnError::NotConvertible(..))
        ));
        // A >63-octet label errs instead of being truncated into a wrong qname.
        let long = format!("{}.example", "a".repeat(64));
        assert!(matches!(domain_to_ascii(&long), Err(IdnError::LabelTooLong(..))));
        // A >253-octet total name errs too.
        let huge = vec!["a".repeat(60); 5].join(".");
        assert!(matches!(domain_to_ascii(&huge), Err(IdnError::NameTooLong(..))));
    }
}
