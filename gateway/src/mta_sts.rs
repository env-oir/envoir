//! MTA-STS policy fetch + enforcement (RFC 8461; spec §7.3 step 4: "enforcing TLS via MTA-STS/DANE").
//!
//! An MTA-STS policy is discovered in two steps (RFC 8461 §3):
//!   1. a `_mta-sts.<domain>` **TXT** record signals that the domain participates and carries the
//!      policy id (used for change detection when a policy is cached — this gateway is stateless
//!      per spec §7.4 and holds no cache, so the id is only used to confirm `v=STSv1` is present);
//!   2. the actual policy body is fetched over **HTTPS** at
//!      `https://mta-sts.<domain>/.well-known/mta-sts.txt` and parsed (§3.2) into a `mode` —
//!      `enforce` | `testing` | `none` — and one or more `mx:` hostname patterns.
//!
//! [`StsPolicy`]/[`parse_policy`] are pure (unit-tested directly against policy text, no network).
//! The two network legs are each their own trait — [`TxtResolver`] and [`PolicyFetcher`] — with a
//! real DNS/HTTPS implementation and an in-memory test double, matching the rest of this crate's
//! "abstract every network effect behind a trait" discipline. [`MtaStsTlsPolicy`] composes the two
//! into the [`crate::outbound::TlsPolicy`] the outbound gateway consults.
//!
//! **Enforcement, and the no-downgrade rule:** in `enforce` mode, [`MtaStsTlsPolicy::requirement_for`]
//! returns [`TlsRequirement::Required`] (STARTTLS mandatory — the transport already refuses to send
//! in cleartext when that is set, §7.3) *and* [`MtaStsTlsPolicy::allowed_mx_patterns`] returns the
//! policy's `mx:` patterns, which [`crate::outbound::OutboundGateway::send`] uses to filter the
//! MX-resolved candidate hosts *before* dialing: a host that matches no pattern is never attempted,
//! and if none of the resolved MX hosts match, the send aborts (`TlsEnforcementFailed`) rather than
//! falling back to an unconstrained/cleartext host. `testing` and `none` modes (and any policy
//! fetch/parse failure — see the note on caching below) are opportunistic: TLS is used if offered,
//! never mandated, and no MX host is excluded.
//!
//! **Known limitation / seam:** RFC 8461 §5 leans on a *cache* of the last-known-good policy: if a
//! fetch fails, an implementation with a cache keeps enforcing the cached policy (fail closed); one
//! without a cache (this gateway — stateless by design, §7.4) has nothing to fall back to and must
//! treat an unreachable/malformed policy as "no policy" (opportunistic) rather than inventing an
//! enforce decision it cannot substantiate. A deployment wanting fail-closed-on-fetch-failure needs
//! to add a persistent policy cache in front of `PolicyFetcher`/`TxtResolver` — a seam, not
//! implemented here. DANE (TLSA records) is a separate, unimplemented seam entirely (see
//! `crate::outbound` docs) — this module only covers MTA-STS.

use crate::dns::{self, UdpDnsClient, TYPE_TXT};
use crate::net::crypto_provider;
use crate::outbound::{TlsPolicy, TlsRequirement};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// A parsed MTA-STS policy mode (RFC 8461 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// TLS + an `mx:`-matching host is mandatory; violations MUST abort delivery, never downgrade.
    Enforce,
    /// Violations SHOULD be reported but delivery proceeds opportunistically.
    Testing,
    /// The domain has explicitly opted out of MTA-STS.
    None,
}

/// A parsed MTA-STS policy document (RFC 8461 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsPolicy {
    pub mode: PolicyMode,
    /// `mx:` patterns (exact hostname, or `*.suffix` wildcard covering exactly one label).
    pub mx_patterns: Vec<String>,
    pub max_age: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StsParseError {
    #[error("policy line is not `key: value`")]
    MalformedLine,
    #[error("missing mandatory `version` field")]
    MissingVersion,
    #[error("unsupported policy version {0:?} (only STSv1)")]
    UnsupportedVersion(String),
    #[error("missing mandatory `mode` field")]
    MissingMode,
    #[error("unrecognized mode {0:?}")]
    UnknownMode(String),
    #[error("mode requires at least one `mx:` pattern")]
    NoMxPatterns,
}

/// Parse an MTA-STS policy body (the `.well-known/mta-sts.txt` content, RFC 8461 §3.2). Unknown keys
/// are ignored per spec; a missing/bad `version` or `mode`, or an enforcing/testing mode with no
/// `mx:` patterns at all, is rejected as malformed.
pub fn parse_policy(text: &str) -> Result<StsPolicy, StsParseError> {
    let mut version: Option<String> = None;
    let mut mode: Option<PolicyMode> = None;
    let mut mx_patterns = Vec::new();
    let mut max_age: Option<u64> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':').ok_or(StsParseError::MalformedLine)?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "version" => version = Some(value.to_string()),
            "mode" => {
                mode = Some(match value {
                    "enforce" => PolicyMode::Enforce,
                    "testing" => PolicyMode::Testing,
                    "none" => PolicyMode::None,
                    other => return Err(StsParseError::UnknownMode(other.to_string())),
                })
            }
            "mx" => mx_patterns.push(value.to_string()),
            "max_age" => max_age = value.parse().ok(),
            _ => {} // unknown keys are ignored, RFC 8461 §3.2
        }
    }

    let version = version.ok_or(StsParseError::MissingVersion)?;
    if version != "STSv1" {
        return Err(StsParseError::UnsupportedVersion(version));
    }
    let mode = mode.ok_or(StsParseError::MissingMode)?;
    if mode != PolicyMode::None && mx_patterns.is_empty() {
        return Err(StsParseError::NoMxPatterns);
    }
    Ok(StsPolicy { mode, mx_patterns, max_age: max_age.unwrap_or(86_400) })
}

/// Does an MX hostname match an MTA-STS `mx:` pattern (RFC 8461 §4.1)? A pattern with no `*.` prefix
/// must match exactly (case-insensitively); a `*.suffix` pattern matches exactly one label prepended
/// to `suffix` (so `*.example.com` matches `mail.example.com` but neither `example.com` itself nor
/// `a.mail.example.com`).
pub fn mx_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.');
    let host = host.trim().trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let host_lower = host.to_ascii_lowercase();
        let suffix_lower = suffix.to_ascii_lowercase();
        let dotted_suffix = format!(".{suffix_lower}");
        match host_lower.strip_suffix(&dotted_suffix) {
            Some(prefix) => !prefix.is_empty() && !prefix.contains('.'),
            None => false,
        }
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Any of `patterns` matches `host`.
pub fn any_pattern_matches(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| mx_pattern_matches(p, host))
}

// -------------------------------------------------------------------------------------------
// The two network seams: TXT lookup + HTTPS policy fetch.
// -------------------------------------------------------------------------------------------

/// Looks up TXT records for a DNS name (used for `_mta-sts.<domain>`). Abstract for testing.
pub trait TxtResolver {
    /// Raw TXT record values for `name` (each entry is one RR's concatenated character-strings).
    /// Empty if the name has no TXT records (or the lookup failed) — this trait does not
    /// distinguish NODATA from a resolver error, matching [`crate::mx::MxResolver`]'s stance.
    fn lookup_txt(&self, name: &str) -> Vec<String>;
}

/// Fetches the raw MTA-STS policy body over HTTPS. Abstract for testing.
pub trait PolicyFetcher {
    /// The raw body of `https://mta-sts.<domain>/.well-known/mta-sts.txt`, or `None` if it could not
    /// be fetched (connection failure, non-2xx, TLS failure, ...).
    fn fetch_policy(&self, domain: &str) -> Option<String>;
}

/// An in-memory [`TxtResolver`] for tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryTxtResolver {
    records: HashMap<String, Vec<String>>,
}
impl InMemoryTxtResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_txt(mut self, name: &str, values: &[&str]) -> Self {
        self.records
            .insert(name.to_ascii_lowercase(), values.iter().map(|v| v.to_string()).collect());
        self
    }
}
impl TxtResolver for InMemoryTxtResolver {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        self.records.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
    }
}

/// An in-memory [`PolicyFetcher`] for tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryPolicyFetcher {
    bodies: HashMap<String, String>,
}
impl InMemoryPolicyFetcher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_policy(mut self, domain: &str, body: &str) -> Self {
        self.bodies.insert(domain.to_ascii_lowercase(), body.to_string());
        self
    }
}
impl PolicyFetcher for InMemoryPolicyFetcher {
    fn fetch_policy(&self, domain: &str) -> Option<String> {
        self.bodies.get(&domain.to_ascii_lowercase()).cloned()
    }
}

/// The real, DNS-backed [`TxtResolver`] (see [`crate::dns`] for the wire-format caveats).
pub struct DnsTxtResolver {
    client: UdpDnsClient,
}
impl DnsTxtResolver {
    pub fn new(dns_server: SocketAddr) -> Self {
        DnsTxtResolver { client: UdpDnsClient::new(dns_server) }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }
}
impl TxtResolver for DnsTxtResolver {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        match self.client.query(name, TYPE_TXT) {
            Ok(msg) => msg
                .answers
                .iter()
                .filter(|rr| rr.rtype == TYPE_TXT)
                .map(dns::parse_txt_rdata)
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// The real, HTTPS-backed [`PolicyFetcher`]: a minimal HTTP/1.1 GET over rustls to
/// `mta-sts.<domain>` (port 443), validating the certificate against the Mozilla root set (the same
/// trust anchors [`crate::outbound_tcp::SmtpTcpTransport::new`] uses).
///
/// **Seam / known limitation:** reads the response body until the peer closes the connection or a
/// generous size cap is hit; it does not implement chunked transfer-encoding. RFC 8461 policy files
/// are tiny plaintext, and real-world servers overwhelmingly send `Content-Length` or close-delimit
/// a response this small, so this is a pragmatic simplification, not a general HTTP client.
pub struct HttpsPolicyFetcher {
    client_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl HttpsPolicyFetcher {
    pub fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let client_config = ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        HttpsPolicyFetcher {
            client_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    fn fetch(&self, domain: &str) -> std::io::Result<String> {
        let host = format!("mta-sts.{domain}");
        let addr: SocketAddr = (host.as_str(), 443u16)
            .to_socket_addrs_first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for mta-sts host"))?;
        let tcp = TcpStream::connect_timeout(&addr, self.connect_timeout)?;
        tcp.set_read_timeout(Some(self.io_timeout))?;
        tcp.set_write_timeout(Some(self.io_timeout))?;
        let name = ServerName::try_from(host.clone())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name"))?;
        let conn = ClientConnection::new(self.client_config.clone(), name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.conn.complete_io(&mut tls.sock)?;

        let request = format!(
            "GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: envoir-gateway\r\n\r\n"
        );
        tls.write_all(request.as_bytes())?;
        tls.flush()?;

        let mut response = Vec::new();
        tls.read_to_end(&mut response)?;
        let text = String::from_utf8_lossy(&response);
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP header/body split"))?;
        let status_line = head.lines().next().unwrap_or("");
        let status_ok = status_line.split_whitespace().nth(1).map(|c| c.starts_with('2')).unwrap_or(false);
        if !status_ok {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("non-2xx MTA-STS policy fetch: {status_line}"),
            ));
        }
        Ok(body.to_string())
    }
}

impl Default for HttpsPolicyFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyFetcher for HttpsPolicyFetcher {
    fn fetch_policy(&self, domain: &str) -> Option<String> {
        self.fetch(domain).ok()
    }
}

/// A tiny local helper trait so `fetch` above can use the same `ToSocketAddrs` resolution the
/// outbound transport uses, without pulling `ToSocketAddrs::to_socket_addrs` iterator boilerplate
/// inline.
trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr>;
}
impl<T: std::net::ToSocketAddrs> ToSocketAddrsFirst for T {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr> {
        self.to_socket_addrs().ok()?.next()
    }
}

// -------------------------------------------------------------------------------------------
// Composing the two seams into the outbound gateway's `TlsPolicy`.
// -------------------------------------------------------------------------------------------

/// The real [`TlsPolicy`]: MTA-STS discovery (TXT signal + HTTPS policy fetch) composed from the two
/// seams above. Stateless — no policy cache (see module docs on why a fetch failure is opportunistic
/// rather than fail-closed here).
pub struct MtaStsTlsPolicy {
    txt: Box<dyn TxtResolver>,
    fetcher: Box<dyn PolicyFetcher>,
}

impl MtaStsTlsPolicy {
    pub fn new(txt: Box<dyn TxtResolver>, fetcher: Box<dyn PolicyFetcher>) -> Self {
        MtaStsTlsPolicy { txt, fetcher }
    }

    /// Resolve the effective policy for `domain`, or `None` if MTA-STS is not signaled / not
    /// retrievable / malformed (all of which this stateless gateway treats as "no policy").
    fn resolve(&self, domain: &str) -> Option<StsPolicy> {
        let txt_name = format!("_mta-sts.{domain}");
        let signaled = self.txt.lookup_txt(&txt_name).iter().any(|v| v.trim_start().starts_with("v=STSv1"));
        if !signaled {
            return None;
        }
        let body = self.fetcher.fetch_policy(domain)?;
        parse_policy(&body).ok()
    }
}

impl TlsPolicy for MtaStsTlsPolicy {
    fn requirement_for(&self, dest_domain: &str) -> TlsRequirement {
        match self.resolve(dest_domain) {
            Some(StsPolicy { mode: PolicyMode::Enforce, .. }) => TlsRequirement::Required,
            _ => TlsRequirement::Opportunistic,
        }
    }

    fn allowed_mx_patterns(&self, dest_domain: &str) -> Vec<String> {
        match self.resolve(dest_domain) {
            Some(StsPolicy { mode: PolicyMode::Enforce, mx_patterns, .. }) => mx_patterns,
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_enforce_policy() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 604800\n";
        let policy = parse_policy(text).expect("valid policy");
        assert_eq!(policy.mode, PolicyMode::Enforce);
        assert_eq!(policy.mx_patterns, vec!["mail.example.com", "*.backup.example.com"]);
        assert_eq!(policy.max_age, 604_800);
    }

    #[test]
    fn parses_a_testing_policy_with_default_max_age() {
        let text = "version: STSv1\nmode: testing\nmx: mail.example.com\n";
        let policy = parse_policy(text).expect("valid policy");
        assert_eq!(policy.mode, PolicyMode::Testing);
        assert_eq!(policy.max_age, 86_400);
    }

    #[test]
    fn none_mode_does_not_require_mx_patterns() {
        let text = "version: STSv1\nmode: none\n";
        let policy = parse_policy(text).expect("valid policy");
        assert_eq!(policy.mode, PolicyMode::None);
        assert!(policy.mx_patterns.is_empty());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nsome_future_key: whatever\n";
        assert!(parse_policy(text).is_ok());
    }

    #[test]
    fn missing_version_is_malformed() {
        let text = "mode: enforce\nmx: mail.example.com\n";
        assert_eq!(parse_policy(text), Err(StsParseError::MissingVersion));
    }

    #[test]
    fn wrong_version_is_malformed() {
        let text = "version: STSv2\nmode: enforce\nmx: mail.example.com\n";
        assert_eq!(parse_policy(text), Err(StsParseError::UnsupportedVersion("STSv2".into())));
    }

    #[test]
    fn missing_mode_is_malformed() {
        let text = "version: STSv1\nmx: mail.example.com\n";
        assert_eq!(parse_policy(text), Err(StsParseError::MissingMode));
    }

    #[test]
    fn unknown_mode_is_malformed() {
        let text = "version: STSv1\nmode: rigorous\nmx: mail.example.com\n";
        assert_eq!(parse_policy(text), Err(StsParseError::UnknownMode("rigorous".into())));
    }

    #[test]
    fn enforce_with_no_mx_patterns_is_malformed() {
        let text = "version: STSv1\nmode: enforce\n";
        assert_eq!(parse_policy(text), Err(StsParseError::NoMxPatterns));
    }

    #[test]
    fn a_line_with_no_colon_is_malformed() {
        let text = "version: STSv1\ngarbage line with no colon\n";
        assert_eq!(parse_policy(text), Err(StsParseError::MalformedLine));
    }

    #[test]
    fn exact_pattern_matches_only_exactly() {
        assert!(mx_pattern_matches("mail.example.com", "mail.example.com"));
        assert!(mx_pattern_matches("MAIL.example.com", "mail.EXAMPLE.com"), "case-insensitive");
        assert!(!mx_pattern_matches("mail.example.com", "other.example.com"));
        assert!(!mx_pattern_matches("mail.example.com", "sub.mail.example.com"));
    }

    #[test]
    fn wildcard_pattern_matches_exactly_one_label() {
        assert!(mx_pattern_matches("*.example.com", "mail.example.com"));
        assert!(mx_pattern_matches("*.example.com", "backup.example.com"));
        assert!(!mx_pattern_matches("*.example.com", "example.com"), "wildcard requires a label, not zero");
        assert!(!mx_pattern_matches("*.example.com", "a.b.example.com"), "wildcard is exactly one label");
        assert!(!mx_pattern_matches("*.example.com", "evilexample.com"), "must be a label boundary, not a suffix");
    }

    #[test]
    fn requirement_is_required_only_in_enforce_mode() {
        let txt = InMemoryTxtResolver::new()
            .with_txt("_mta-sts.enforced.example", &["v=STSv1; id=1"])
            .with_txt("_mta-sts.testing.example", &["v=STSv1; id=1"])
            .with_txt("_mta-sts.opted-out.example", &["v=STSv1; id=1"]);
        let fetcher = InMemoryPolicyFetcher::new()
            .with_policy("enforced.example", "version: STSv1\nmode: enforce\nmx: mx.enforced.example\n")
            .with_policy("testing.example", "version: STSv1\nmode: testing\nmx: mx.testing.example\n")
            .with_policy("opted-out.example", "version: STSv1\nmode: none\n");
        let policy = MtaStsTlsPolicy::new(Box::new(txt), Box::new(fetcher));

        assert_eq!(policy.requirement_for("enforced.example"), TlsRequirement::Required);
        assert_eq!(
            policy.allowed_mx_patterns("enforced.example"),
            vec!["mx.enforced.example".to_string()]
        );

        assert_eq!(policy.requirement_for("testing.example"), TlsRequirement::Opportunistic);
        assert!(policy.allowed_mx_patterns("testing.example").is_empty());

        assert_eq!(policy.requirement_for("opted-out.example"), TlsRequirement::Opportunistic);
    }

    #[test]
    fn no_txt_signal_at_all_is_opportunistic() {
        let policy = MtaStsTlsPolicy::new(
            Box::new(InMemoryTxtResolver::new()),
            Box::new(InMemoryPolicyFetcher::new()),
        );
        assert_eq!(policy.requirement_for("never-heard-of-sts.example"), TlsRequirement::Opportunistic);
        assert!(policy.allowed_mx_patterns("never-heard-of-sts.example").is_empty());
    }

    #[test]
    fn txt_signaled_but_policy_fetch_fails_is_opportunistic_not_enforce() {
        // The domain signals STS via TXT but the HTTPS fetch never succeeds (no entry in the
        // fetcher) — stateless gateway, no cache to fall back on, so this is opportunistic (see
        // module docs), NOT a fail-closed enforce.
        let txt = InMemoryTxtResolver::new().with_txt("_mta-sts.flaky.example", &["v=STSv1; id=1"]);
        let policy = MtaStsTlsPolicy::new(Box::new(txt), Box::new(InMemoryPolicyFetcher::new()));
        assert_eq!(policy.requirement_for("flaky.example"), TlsRequirement::Opportunistic);
    }

    #[test]
    fn txt_signaled_but_policy_body_malformed_is_opportunistic() {
        let txt = InMemoryTxtResolver::new().with_txt("_mta-sts.bad-policy.example", &["v=STSv1; id=1"]);
        let fetcher =
            InMemoryPolicyFetcher::new().with_policy("bad-policy.example", "mode: enforce\nmx: mx.example\n"); // no version
        let policy = MtaStsTlsPolicy::new(Box::new(txt), Box::new(fetcher));
        assert_eq!(policy.requirement_for("bad-policy.example"), TlsRequirement::Opportunistic);
    }
}
