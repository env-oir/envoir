//! DMARC — Domain-based Message Authentication, Reporting & Conformance (RFC 7489) — spec item 2:
//! combine the existing DKIM verdict ([`crate::dkim::DkimVerdict`]) with the new SPF verdict
//! ([`crate::spf::SpfResult`]) and domain alignment into a pass/fail decision against the sender
//! (`RFC5322.From`) domain's published `_dmarc` policy (`none`/`quarantine`/`reject`), applied on
//! inbound (spec §7.2 step 2).
//!
//! **Honest narrowings (documented, not silent):**
//! - **Organizational domain via a real Public Suffix List.** RFC 7489 §3.2's "Organizational
//!   Domain" (the registrable "public-suffix + 1 label") is computed against Mozilla's Public
//!   Suffix List, embedded via the [`psl`] crate (a self-contained, compiled snapshot of the list —
//!   no build-time fetch, no runtime data file, pinned in `Cargo.lock`). So `mail.example.com` →
//!   `example.com`, but `attacker.co.uk` and `victim.co.uk` are recognized as **distinct**
//!   registrants (their organizational domains are themselves, not the shared `co.uk` suffix), and
//!   likewise for private-section multi-label suffixes (`github.io`, `s3.amazonaws.com`). This
//!   closes the former "last two labels" hole where any two domains sharing a 2-label public suffix
//!   were mis-treated as aligned under relaxed mode. Residual narrowing: the embedded list is a
//!   fixed snapshot (the version pinned in `Cargo.lock`), not refreshed at runtime; a public suffix
//!   added upstream after that snapshot is unknown until the dependency is bumped — but see the
//!   fail-closed guard below, which requires **strict** alignment whenever a name has no registrable
//!   domain (i.e. is itself a public suffix / unlistable), so an unknown or bare suffix can never be
//!   folded together under relaxed alignment.
//! - **`pct=` is parsed but not applied as probabilistic sampling.** RFC 7489 §6.3's `pct` tag lets
//!   a domain roll out enforcement to only a percentage of failing messages. This gateway always
//!   applies the full effective policy to every failing message (as if `pct=100`) — a conservative
//!   simplification (never laxer than the published policy, only ever stricter) rather than
//!   probabilistic under-enforcement.
//! - **`quarantine` is annotated, not enacted at the SMTP level.** A stateless legacy bridge with no
//!   mailbox has nowhere to "quarantine" a message into; only `p=reject` (or `sp=reject` for a
//!   subdomain-inherited policy) is translated into an SMTP-level refusal under
//!   [`crate::inbound::DmarcHandling::Enforce`]. `quarantine` is still a distinct, inspectable
//!   [`DmarcDisposition`] for a caller with somewhere to route it (e.g. a downstream spam folder).
//! - **Single-signature DKIM identifier.** Alignment checks the one DKIM signature
//!   [`crate::dkim::verify_with_resolver`] evaluates (pre-existing crate behavior, RFC 6376 §3.4
//!   multi-signature messages are not walked here).
//! - **Two-level discovery**, matching RFC 7489 §6.6.3 precisely (not a full per-label tree walk):
//!   the exact `_dmarc.<header-from-domain>` record is checked, and — only if that domain is not
//!   itself the organizational domain and no record was found there — `_dmarc.<organizational
//!   domain>` is checked as a fallback, with `sp=` (defaulting to `p=`) then governing the
//!   subdomain.
//! - **A DNS lookup failure degrades to "no policy"**, matching this crate's other single-`Vec`
//!   TXT-lookup traits ([`crate::mta_sts::TxtResolver`]) rather than [`crate::spf::SpfResolver`]'s
//!   distinguished failure: RFC 7489 defines no `TempError`-equivalent action for the policy-record
//!   fetch, and DMARC's own enforcement lever (reject) is already the stronger one — SPF's *own*
//!   enforcement gate (spec item 1) independently still applies regardless of whether DMARC's
//!   record fetch happened to fail.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::dkim::DkimVerdict;
use crate::dns::{self, UdpDnsClient, TYPE_TXT};
use crate::spf::SpfResult;

/// The DMARC-published policy action (RFC 7489 §6.3 `p=`/`sp=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

/// The disposition an evaluated-and-failing message should receive (mirrors [`DmarcPolicy`]; kept
/// as a separate type so a future richer verdict — e.g. carrying the sampled/actual `pct` decision
/// — doesn't have to reuse the wire-parsed policy type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcDisposition {
    None,
    Quarantine,
    Reject,
}

fn to_disposition(p: DmarcPolicy) -> DmarcDisposition {
    match p {
        DmarcPolicy::None => DmarcDisposition::None,
        DmarcPolicy::Quarantine => DmarcDisposition::Quarantine,
        DmarcPolicy::Reject => DmarcDisposition::Reject,
    }
}

/// A parsed `_dmarc` TXT record (RFC 7489 §6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub policy: DmarcPolicy,
    /// `sp=` — the policy for subdomains of the organizational domain; `None` means "inherit `p=`"
    /// (RFC 7489 §6.3's stated default).
    pub subdomain_policy: Option<DmarcPolicy>,
    /// `adkim=s` (strict, exact-domain match) vs the default `adkim=r` (relaxed, organizational).
    pub dkim_strict: bool,
    /// `aspf=s` vs the default `aspf=r`.
    pub spf_strict: bool,
    /// `pct=` (0-100, default 100). Parsed for validity; see module docs on why it is not applied
    /// as probabilistic sampling.
    pub pct: u8,
}

/// The overall DMARC verdict (spec item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcVerdict {
    /// SPF-aligned-pass or DKIM-aligned-pass (RFC 7489 §3.1).
    Pass,
    /// Neither authentication mechanism produced an aligned pass; `disposition` is the effective
    /// policy (subdomain `sp=` applied when the record was discovered at the organizational
    /// domain, per module docs).
    Fail { disposition: DmarcDisposition },
    /// No `_dmarc` record was discovered at the header-from domain or its organizational domain
    /// (or no [`DmarcTxtResolver`] is configured) — DMARC makes no assertion.
    NoPolicy,
    /// A discovered record (or a duplicate-record set) could not be parsed/validated (RFC 7489
    /// §6.6.3: an invalid record is treated as if none were published, except this crate surfaces
    /// it distinctly so a caller can tell "no policy" from "a broken one" for diagnostics).
    PermError,
}

/// Resolves `_dmarc` TXT records. Abstract so DMARC evaluation is testable in-process;
/// [`DnsDmarcResolver`] is the real DNS-backed implementation.
pub trait DmarcTxtResolver {
    fn lookup_txt(&self, name: &str) -> Vec<String>;
}

/// An in-memory [`DmarcTxtResolver`] for tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryDmarcResolver {
    records: HashMap<String, Vec<String>>,
}

impl InMemoryDmarcResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_txt(mut self, name: &str, values: &[&str]) -> Self {
        self.records.insert(name.to_ascii_lowercase(), values.iter().map(|v| v.to_string()).collect());
        self
    }
}

impl DmarcTxtResolver for InMemoryDmarcResolver {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        self.records.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
    }
}

/// The real, DNS-backed [`DmarcTxtResolver`] (see [`crate::dns`] module docs for the underlying
/// wire-format caveats).
pub struct DnsDmarcResolver {
    client: UdpDnsClient,
}

impl DnsDmarcResolver {
    pub fn new(dns_server: SocketAddr) -> Self {
        DnsDmarcResolver { client: UdpDnsClient::new(dns_server) }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }
}

impl DmarcTxtResolver for DnsDmarcResolver {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        match self.client.query(name, TYPE_TXT) {
            Ok(msg) => msg.answers.iter().filter(|rr| rr.rtype == TYPE_TXT).map(dns::parse_txt_rdata).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// RFC 7489 §3.2's Organizational Domain: the registrable "public-suffix + 1 label" determined
/// against the Public Suffix List (via the embedded [`psl`] snapshot — see module docs). Returns
/// the input (normalized) unchanged when it has **no** registrable domain — i.e. it is itself a
/// public suffix (`co.uk`, `github.io`) or a single unlistable label (`localhost`) — so callers
/// still get a stable value, and [`domains_aligned`] treats that case fail-closed (strict-only).
pub fn organizational_domain(domain: &str) -> String {
    let d = normalize(domain);
    match psl::domain_str(&d) {
        Some(registrable) => registrable.to_string(),
        None => d,
    }
}

fn domains_aligned(auth_domain: &str, header_domain: &str, strict: bool) -> bool {
    if strict {
        return auth_domain.eq_ignore_ascii_case(header_domain);
    }
    // Relaxed alignment compares organizational (registrable) domains. Fail-closed guard: if
    // *either* name has no registrable domain — it is itself a public suffix (`co.uk`, `github.io`,
    // `s3.amazonaws.com`) or otherwise unlistable — then "public-suffix + 1 label" is undefined and
    // folding the two together would let any two co-tenants of that suffix spoof each other. In that
    // case require STRICT (exact) alignment instead of a relaxed organizational match.
    match (psl::domain_str(&normalize(auth_domain)), psl::domain_str(&normalize(header_domain))) {
        (Some(org_auth), Some(org_header)) => org_auth.eq_ignore_ascii_case(org_header),
        _ => auth_domain.eq_ignore_ascii_case(header_domain),
    }
}

fn is_dmarc1_record(t: &str) -> bool {
    let t = t.trim();
    t == "v=DMARC1" || t.starts_with("v=DMARC1;") || t.starts_with("v=DMARC1 ")
}

fn parse_policy_value(v: &str) -> Result<DmarcPolicy, ()> {
    match v {
        "none" => Ok(DmarcPolicy::None),
        "quarantine" => Ok(DmarcPolicy::Quarantine),
        "reject" => Ok(DmarcPolicy::Reject),
        _ => Err(()),
    }
}

/// Parse a `_dmarc` TXT record body (RFC 7489 §6.3). Unknown tags (`rua=`, `ruf=`, `ri=`, `fo=`,
/// ...) are parsed-and-ignored — this gateway has no reporting seam. Fails closed on a missing
/// mandatory `v=`/`p=`, an unrecognized policy value, or a malformed `pct=`.
fn parse_record(txt: &str) -> Result<DmarcRecord, ()> {
    let mut policy: Option<DmarcPolicy> = None;
    let mut sp: Option<DmarcPolicy> = None;
    let mut adkim_strict = false;
    let mut aspf_strict = false;
    let mut pct: u8 = 100;
    let mut saw_version = false;
    for tag in txt.split(';') {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        let (k, v) = tag.split_once('=').ok_or(())?;
        let k = k.trim();
        let v = v.trim();
        match k {
            "v" => {
                if v != "DMARC1" {
                    return Err(());
                }
                saw_version = true;
            }
            "p" => policy = Some(parse_policy_value(v)?),
            "sp" => sp = Some(parse_policy_value(v)?),
            "adkim" => {
                adkim_strict = match v {
                    "s" => true,
                    "r" => false,
                    _ => return Err(()),
                }
            }
            "aspf" => {
                aspf_strict = match v {
                    "s" => true,
                    "r" => false,
                    _ => return Err(()),
                }
            }
            "pct" => {
                let n: u8 = v.parse().map_err(|_| ())?;
                if n > 100 {
                    return Err(());
                }
                pct = n;
            }
            _ => {} // rua/ruf/ri/fo/future tags: parsed-and-ignored, RFC 7489 §6.3.
        }
    }
    if !saw_version {
        return Err(());
    }
    let policy = policy.ok_or(())?;
    Ok(DmarcRecord { policy, subdomain_policy: sp, dkim_strict: adkim_strict, spf_strict: aspf_strict, pct })
}

enum Discovery {
    Found { record: DmarcRecord, is_subdomain: bool },
    None,
    PermError,
}

enum LookupAt {
    Found(DmarcRecord),
    NotFound,
    PermError,
}

fn lookup_at(resolver: &dyn DmarcTxtResolver, domain: &str) -> LookupAt {
    let name = format!("_dmarc.{}", domain.trim().trim_end_matches('.').to_ascii_lowercase());
    let txts = resolver.lookup_txt(&name);
    let candidates: Vec<&String> = txts.iter().filter(|t| is_dmarc1_record(t)).collect();
    match candidates.len() {
        0 => LookupAt::NotFound,
        1 => match parse_record(candidates[0]) {
            Ok(r) => LookupAt::Found(r),
            Err(()) => LookupAt::PermError,
        },
        // RFC 7489 §6.6.3: more than one record at this exact name is invalid, and processing MUST
        // stop (not fall back further) rather than pick one arbitrarily.
        _ => LookupAt::PermError,
    }
}

/// RFC 7489 §6.6.3 two-level discovery: the exact header-from domain, then (only if distinct and
/// nothing was found) the organizational domain.
fn discover(resolver: &dyn DmarcTxtResolver, header_domain: &str) -> Discovery {
    match lookup_at(resolver, header_domain) {
        LookupAt::Found(record) => return Discovery::Found { record, is_subdomain: false },
        LookupAt::PermError => return Discovery::PermError,
        LookupAt::NotFound => {}
    }
    let org = organizational_domain(header_domain);
    if !header_domain.eq_ignore_ascii_case(&org) {
        match lookup_at(resolver, &org) {
            LookupAt::Found(record) => return Discovery::Found { record, is_subdomain: true },
            LookupAt::PermError => return Discovery::PermError,
            LookupAt::NotFound => {}
        }
    }
    Discovery::None
}

/// The `RFC5322.From` selection for DMARC (RFC 7489 §6.6.1). DMARC is only evaluated normally for a
/// message carrying **exactly one** `From:` header bearing **exactly one** address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderFrom {
    /// Exactly one `From:` header with exactly one address carrying an `@domain` — the domain to
    /// align against.
    Single(String),
    /// No `From:` header at all, or the sole single-address `From:` carries no usable `@domain`.
    /// Nothing to align — DMARC reports [`DmarcVerdict::PermError`] rather than guessing.
    Unusable,
    /// More than one `From:` header, **or** a single `From:` bearing more than one address
    /// (RFC 7489 §6.6.1): such a message MUST NOT be evaluated as if it had one origin. A
    /// fail-closed reject signal — the caller maps it to a rejectable verdict (never a silent pass).
    Ambiguous,
}

/// Select the `RFC5322.From` domain for DMARC per RFC 7489 §6.6.1 (spec item 2). Reuses
/// `dmtap-mail`'s existing header/address parsing (already a gateway dependency for SMTP→MOTE
/// translation) rather than duplicating an RFC 5322 header parser. Enforces §6.6.1's cardinality
/// rules: more than one `From:` header, or more than one address in the `From:`, yields
/// [`HeaderFrom::Ambiguous`] instead of arbitrarily picking one (the previous behavior — last
/// header, first address — which a spoofer could exploit by appending a second `From:` the DKIM
/// oversigning or a downstream client renders differently).
pub fn header_from(data: &[u8]) -> HeaderFrom {
    let headers = dmtap_mail::mime::headers_only(data);
    let froms: Vec<&String> =
        headers.iter().filter(|(n, _)| n.trim().eq_ignore_ascii_case("from")).map(|(_, v)| v).collect();
    let value = match froms.as_slice() {
        [] => return HeaderFrom::Unusable,
        [only] => *only,
        // RFC 7489 §6.6.1: more than one From header ⇒ do not evaluate as single-origin.
        _ => return HeaderFrom::Ambiguous,
    };
    let addrs = dmtap_mail::mime::parse_address_list(value);
    match addrs.as_slice() {
        [] => HeaderFrom::Unusable,
        // The one-and-only address; consistent with the delivered-message parser
        // (`dmtap_mail::mime::ParsedMessage::header`, which takes the FIRST — here also the only —
        // occurrence), never the previous last-header/first-address mix.
        [addr] => match addr.host.clone().filter(|h| !h.is_empty()) {
            Some(h) => HeaderFrom::Single(h),
            None => HeaderFrom::Unusable,
        },
        // RFC 7489 §6.6.1: a From with more than one address ⇒ do not evaluate as single-origin.
        _ => HeaderFrom::Ambiguous,
    }
}

/// The single `RFC5322.From` domain, or `None` when there is not exactly one usable single-address
/// `From:` header. A thin convenience wrapper over [`header_from`]: an ambiguous multi-From /
/// multi-address message collapses to `None` here (its distinct fail-closed reject is available via
/// [`header_from`] directly, which the inbound DMARC path uses).
pub fn header_from_domain(data: &[u8]) -> Option<String> {
    match header_from(data) {
        HeaderFrom::Single(d) => Some(d),
        HeaderFrom::Unusable | HeaderFrom::Ambiguous => None,
    }
}

/// Evaluate DMARC (RFC 7489 §3, spec item 2): discover the `header_from_domain`'s policy (falling
/// back to its organizational domain per RFC 7489 §6.6.3), then combine `spf_result` (evaluated
/// against `envelope_domain`, i.e. the `RFC5321.MailFrom` domain — see [`crate::spf`]) and
/// `dkim_verdict` (from [`crate::dkim::verify_with_resolver`]) with alignment against
/// `header_from_domain` to decide pass/fail.
pub fn evaluate(
    resolver: &dyn DmarcTxtResolver,
    header_from_domain: &str,
    envelope_domain: &str,
    spf_result: Option<SpfResult>,
    dkim_verdict: &DkimVerdict,
) -> DmarcVerdict {
    let (record, is_subdomain) = match discover(resolver, header_from_domain) {
        Discovery::None => return DmarcVerdict::NoPolicy,
        Discovery::PermError => return DmarcVerdict::PermError,
        Discovery::Found { record, is_subdomain } => (record, is_subdomain),
    };

    let spf_aligned = spf_result == Some(SpfResult::Pass)
        && !envelope_domain.is_empty()
        && domains_aligned(envelope_domain, header_from_domain, record.spf_strict);

    let dkim_aligned = if let DkimVerdict::Pass { domain, .. } = dkim_verdict {
        domains_aligned(domain, header_from_domain, record.dkim_strict)
    } else {
        false
    };

    if spf_aligned || dkim_aligned {
        return DmarcVerdict::Pass;
    }

    let effective_policy =
        if is_subdomain { record.subdomain_policy.unwrap_or(record.policy) } else { record.policy };
    DmarcVerdict::Fail { disposition: to_disposition(effective_policy) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkim::DkimError;

    #[test]
    fn organizational_domain_uses_the_public_suffix_list() {
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.c.example.com"), "example.com");
        assert_eq!(organizational_domain("example.com"), "example.com");
        // Single unlistable label / bare public suffix ⇒ returned unchanged.
        assert_eq!(organizational_domain("localhost"), "localhost");
        // PSL-correct: a multi-label public suffix is respected — `foo.co.uk`'s registrable domain
        // is itself (NOT `co.uk`), and a bare public suffix has no registrable domain (kept as-is).
        assert_eq!(organizational_domain("foo.co.uk"), "foo.co.uk");
        assert_eq!(organizational_domain("a.b.foo.co.uk"), "foo.co.uk");
        assert_eq!(organizational_domain("co.uk"), "co.uk");
        // Private-section multi-label suffixes are honored too (co-tenant isolation).
        assert_eq!(organizational_domain("myuser.github.io"), "myuser.github.io");
        assert_eq!(organizational_domain("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
    }

    #[test]
    fn relaxed_alignment_is_psl_correct_across_public_suffixes() {
        // The closed hole: two registrants sharing a 2-label public suffix are NOT aligned under
        // relaxed mode (previously `organizational_domain` = "last two labels" wrongly aligned them).
        assert!(!domains_aligned("attacker.co.uk", "victim.co.uk", false));
        assert!(!domains_aligned("attacker.com.au", "victim.com.au", false));
        assert!(!domains_aligned("evil.github.io", "good.github.io", false));
        assert!(!domains_aligned("evil.s3.amazonaws.com", "good.s3.amazonaws.com", false));
        // Legitimate relaxed alignment still holds (subdomain ↔ its registrable domain).
        assert!(domains_aligned("mail.example.com", "example.com", false));
        assert!(domains_aligned("bounce.example.co.uk", "www.example.co.uk", false));
        // Same registrant under the multi-label suffix aligns; different ones do not.
        assert!(domains_aligned("a.example.co.uk", "b.example.co.uk", false));
        // Fail-closed guard: a name that is ITSELF a public suffix (no registrable domain) demands
        // strict/exact alignment — it can never be folded together with a sibling under relaxed mode.
        assert!(!domains_aligned("co.uk", "example.co.uk", false));
        assert!(domains_aligned("co.uk", "co.uk", false)); // exact still matches
        assert!(!domains_aligned("github.io", "victim.github.io", false));
    }

    #[test]
    fn dmarc_pass_requires_psl_correct_alignment_not_a_shared_suffix() {
        // End-to-end: `victim.co.uk` publishes p=reject; a DKIM pass for `attacker.co.uk` shares the
        // `co.uk` public suffix but is a DIFFERENT registrant, so it must NOT align → reject.
        let r = dmarc_txt("victim.co.uk", "v=DMARC1; p=reject");
        let dkim = DkimVerdict::Pass { domain: "attacker.co.uk".into(), selector: "s1".into() };
        let v = evaluate(&r, "victim.co.uk", "attacker.co.uk", Some(SpfResult::Fail), &dkim);
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Reject });
        // The same registrant (a subdomain) DOES align.
        let dkim_ok = DkimVerdict::Pass { domain: "mail.victim.co.uk".into(), selector: "s1".into() };
        let v_ok = evaluate(&r, "victim.co.uk", "x", Some(SpfResult::Fail), &dkim_ok);
        assert_eq!(v_ok, DmarcVerdict::Pass);
    }

    #[test]
    fn header_from_domain_extracts_from_header() {
        let msg = b"From: Alice <alice@example.org>\r\nTo: bob@host.net\r\nSubject: hi\r\n\r\nbody\r\n";
        assert_eq!(header_from_domain(msg), Some("example.org".to_string()));
        let bare = b"From: alice@bare.example\r\n\r\nbody\r\n";
        assert_eq!(header_from_domain(bare), Some("bare.example".to_string()));
        let none = b"Subject: no from header\r\n\r\nbody\r\n";
        assert_eq!(header_from_domain(none), None);
        // Garbage bytes never panic, just yield None.
        let garbage: &[u8] = &[0xff, 0x00, 0xfe, 0x10, 0x00, 0x00];
        assert_eq!(header_from_domain(garbage), None);
    }

    #[test]
    fn header_from_rejects_multiple_from_headers_and_addresses() {
        // Exactly one single-address From ⇒ Single.
        let ok = b"From: alice@example.org\r\nTo: bob@host.net\r\n\r\nbody\r\n";
        assert_eq!(header_from(ok), HeaderFrom::Single("example.org".to_string()));

        // Two From headers (RFC 7489 §6.6.1) ⇒ Ambiguous, never an arbitrary pick.
        let two_headers =
            b"From: alice@example.org\r\nFrom: eve@attacker.example\r\nTo: bob@host.net\r\n\r\nbody\r\n";
        assert_eq!(header_from(two_headers), HeaderFrom::Ambiguous);
        assert_eq!(header_from_domain(two_headers), None);

        // A single From bearing two addresses ⇒ Ambiguous.
        let two_addrs = b"From: alice@example.org, eve@attacker.example\r\nTo: bob@host.net\r\n\r\nbody\r\n";
        assert_eq!(header_from(two_addrs), HeaderFrom::Ambiguous);
        assert_eq!(header_from_domain(two_addrs), None);

        // No From at all / no domain ⇒ Unusable.
        assert_eq!(header_from(b"Subject: x\r\n\r\nbody\r\n"), HeaderFrom::Unusable);
        assert_eq!(header_from(b"From: not-an-address\r\n\r\nbody\r\n"), HeaderFrom::Unusable);
    }

    fn dmarc_txt(name: &str, body: &str) -> InMemoryDmarcResolver {
        InMemoryDmarcResolver::new().with_txt(&format!("_dmarc.{name}"), &[body])
    }

    #[test]
    fn spf_aligned_pass() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject");
        let dkim = DkimVerdict::NoSignature;
        let v = evaluate(&r, "example.org", "example.org", Some(SpfResult::Pass), &dkim);
        assert_eq!(v, DmarcVerdict::Pass);
    }

    #[test]
    fn dkim_aligned_pass() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject");
        let dkim = DkimVerdict::Pass { domain: "example.org".into(), selector: "s1".into() };
        let v = evaluate(&r, "example.org", "other.example", Some(SpfResult::Fail), &dkim);
        assert_eq!(v, DmarcVerdict::Pass);
    }

    #[test]
    fn relaxed_alignment_matches_organizational_domain() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject; aspf=r");
        // Envelope domain is a subdomain of the header-from's organizational domain — relaxed
        // alignment (the default) still passes.
        let v = evaluate(&r, "example.org", "bounce.example.org", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
        assert_eq!(v, DmarcVerdict::Pass);
    }

    #[test]
    fn strict_alignment_rejects_a_mere_organizational_match() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject; aspf=s");
        let v = evaluate(&r, "example.org", "bounce.example.org", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Reject });
    }

    #[test]
    fn neither_aligned_fails_with_the_published_policy() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=quarantine");
        let dkim = DkimVerdict::Fail(DkimError::SignatureInvalid);
        let v = evaluate(&r, "example.org", "attacker.example", Some(SpfResult::Fail), &dkim);
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Quarantine });
    }

    #[test]
    fn no_record_at_all_is_nopolicy() {
        let r = InMemoryDmarcResolver::new();
        let v = evaluate(&r, "nowhere.example", "nowhere.example", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
        assert_eq!(v, DmarcVerdict::NoPolicy);
    }

    #[test]
    fn falls_back_to_organizational_domain_record_and_applies_sp() {
        // No record at the exact subdomain, but one at the organizational domain with a stricter
        // `sp=` — the subdomain policy governs since the record was found one level up.
        let r = dmarc_txt("example.org", "v=DMARC1; p=none; sp=reject");
        let v = evaluate(
            &r,
            "sub.example.org",
            "attacker.example",
            Some(SpfResult::Fail),
            &DkimVerdict::NoSignature,
        );
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Reject });
    }

    #[test]
    fn subdomain_without_sp_inherits_p() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject"); // no sp= at all
        let v = evaluate(
            &r,
            "sub.example.org",
            "attacker.example",
            Some(SpfResult::Fail),
            &DkimVerdict::NoSignature,
        );
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Reject });
    }

    #[test]
    fn malformed_record_is_permerror_not_a_panic() {
        // Each of these carries a valid "v=DMARC1" prefix (so it IS recognized as a candidate DMARC
        // record — see `is_dmarc1_record`) but is otherwise malformed, so it fails parsing.
        for body in [
            "v=DMARC1", // missing mandatory p=
            "v=DMARC1; p=bogus-policy",
            "v=DMARC1; pct=200",         // out of range
            "v=DMARC1; p=reject; adkim=x", // bad alignment mode value
            "v=DMARC1; garbage-no-equals",
        ] {
            let r = dmarc_txt("bad.example", body);
            let v = evaluate(&r, "bad.example", "bad.example", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
            assert_eq!(v, DmarcVerdict::PermError, "case {body:?}");
        }
    }

    #[test]
    fn a_txt_record_with_no_v_dmarc1_prefix_at_all_is_not_a_candidate_record() {
        // A record lacking the "v=DMARC1" prefix entirely is not recognized as a DMARC record at
        // all (indistinguishable from no record being published) — NoPolicy, not PermError.
        let r = dmarc_txt("bad.example", "p=reject");
        let v = evaluate(&r, "bad.example", "bad.example", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
        assert_eq!(v, DmarcVerdict::NoPolicy);
    }

    #[test]
    fn multiple_records_at_the_same_name_is_permerror() {
        let r = InMemoryDmarcResolver::new()
            .with_txt("_dmarc.dup.example", &["v=DMARC1; p=reject", "v=DMARC1; p=none"]);
        let v = evaluate(&r, "dup.example", "dup.example", Some(SpfResult::Pass), &DkimVerdict::NoSignature);
        assert_eq!(v, DmarcVerdict::PermError);
    }

    #[test]
    fn dkim_alignment_ignores_a_non_passing_dkim_verdict() {
        let r = dmarc_txt("example.org", "v=DMARC1; p=reject");
        // A DKIM signature that names the right domain but does not verify must NOT be treated as
        // aligned — only DkimVerdict::Pass counts.
        let dkim = DkimVerdict::Fail(DkimError::SignatureInvalid);
        let v = evaluate(&r, "example.org", "example.org", Some(SpfResult::SoftFail), &dkim);
        assert_eq!(v, DmarcVerdict::Fail { disposition: DmarcDisposition::Reject });
    }
}
