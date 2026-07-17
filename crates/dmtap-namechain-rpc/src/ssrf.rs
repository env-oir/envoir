//! SSRF guard for attacker-controlled CCIP-Read (EIP-3668) gateway URLs.
//!
//! A CCIP `OffchainLookup` revert names the gateway URL to fetch, and **anyone** can register an ENS
//! name pointing at a resolver contract they deployed — so that URL is fully attacker-controlled. If
//! the resolving node dialed it blindly it would be a Server-Side Request Forgery primitive: reaching
//! `http://169.254.169.254/…` (cloud metadata), loopback admin ports, or RFC1918 hosts from inside the
//! node's trust boundary. This module refuses such URLs **before any socket is opened**.
//!
//! Policy: HTTPS scheme only; reject `localhost`; reject any literal IP — or any hostname that
//! resolves — into a loopback / private / link-local / unique-local / CGNAT / metadata range; and,
//! **when the operator configures a [`GatewayAllowlist`]**, additionally require the gateway host to
//! be on it (defense-in-depth over the SSRF range checks — see below).
//!
//! ## Operator allowlist (defense-in-depth)
//! The range checks above stop *internal* SSRF, but any **public** HTTPS host is still dialable, which
//! is a broad attack surface (data-exfil to an attacker gateway, DNS-rebinding, request smuggling
//! against third-party services). An operator that knows the finite set of CCIP gateways it trusts can
//! set a [`GatewayAllowlist`]; a gateway whose host is not on it is then refused **on top of** the
//! range checks. When no allowlist is configured the prior behavior is preserved exactly (any public,
//! SSRF-guarded host is allowed), so nothing breaks for callers that don't opt in.
//!
//! ## DNS-rebinding residual (precise, partially mitigated)
//! For a *hostname* gateway the guard resolves the host and rejects it if any answer is internal, and
//! it now resolves **twice**, rejecting on an internal answer in *either* pass — this defeats a
//! resolver that round-robins or immediately re-answers with an internal address (a cheap rebinding
//! variant). It does **not** close a flip that happens only at the transport's *connect*: the guard
//! and the transport each call `getaddrinfo` independently, so an attacker controlling DNS with a
//! zero TTL can still hand the guard a public IP and the transport an internal one. Fully closing that
//! requires the transport to connect to the exact IP this guard pinned; the [`HttpTransport`] seam
//! accepts only a URL and cannot carry a pinned IP, so that is a deliberate, documented residual — a
//! transport-signature change tracked separately. The allowlist narrows this window further by
//! constraining which hostnames are eligible at all.
//!
//! [`HttpTransport`]: crate::transport::HttpTransport

use crate::NamechainError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// An operator-configured allowlist of CCIP-Read gateway hosts. Each entry is a host or a parent
/// domain; a gateway host matches when it **equals** an entry or is a **subdomain** of one
/// (`gw.example.com` matches the entry `example.com`). Matching is ASCII-case-insensitive and a
/// leading dot on an entry (`.example.com`) is ignored. An empty allowlist matches nothing — but the
/// guard treats "no allowlist configured" (`None`) as "allow any public SSRF-guarded host", so an
/// empty set is never silently constructed by the client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayAllowlist {
    /// Lowercased entries, each with any leading dot stripped; empty entries are dropped.
    domains: Vec<String>,
}

impl GatewayAllowlist {
    /// Build an allowlist from an iterator of host/domain strings. Entries are trimmed, lowercased,
    /// have a leading `.` removed, and blanks are discarded.
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        GatewayAllowlist {
            domains: domains
                .into_iter()
                .map(|s| {
                    s.as_ref()
                        .trim()
                        .trim_start_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// Does this allowlist have no usable entries? (All inputs were blank.)
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Is `host` permitted — equal to an entry, or a subdomain of one?
    fn permits(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.domains.iter().any(|d| host_matches_domain(&host, d))
    }
}

/// `host` matches `domain` when it is exactly `domain` or ends with `.domain` (a real subdomain,
/// checked on a label boundary so `evilexample.com` does NOT match `example.com`).
fn host_matches_domain(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Refuse a CCIP gateway URL that is non-HTTPS, points at an internal address, or — when `allowlist`
/// is `Some` — whose host is not on the operator allowlist. Fail closed.
pub(crate) fn guard_gateway_url(
    url: &str,
    allowlist: Option<&GatewayAllowlist>,
) -> Result<(), NamechainError> {
    // 1. HTTPS only — a plaintext `http://169.254.169.254/…` is the canonical metadata-SSRF payload.
    let after = match url.get(..8) {
        Some(p) if p.eq_ignore_ascii_case("https://") => &url[8..],
        _ => return Err(NamechainError::BlockedGatewayUrl("scheme must be https")),
    };

    // 2. Isolate the host: authority is everything up to the first path/query/fragment delimiter;
    //    drop any `user:pass@` prefix and the `:port` suffix; unwrap an `[ipv6]` literal.
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split(']').next() {
            Some(h) if !h.is_empty() => h,
            _ => return Err(NamechainError::BlockedGatewayUrl("malformed ipv6 host")),
        }
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    if host.is_empty() {
        return Err(NamechainError::BlockedGatewayUrl("empty host"));
    }

    // 3. Never dial the loopback alias by name (it bypasses the literal-IP check below).
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err(NamechainError::BlockedGatewayUrl("localhost host"));
    }

    // 3b. Operator allowlist (defense-in-depth): if configured, the host must be on it. This runs in
    //     addition to — never instead of — the range checks below. Fail fast with a clear reason.
    if let Some(allow) = allowlist {
        if !allow.permits(host) {
            return Err(NamechainError::BlockedGatewayUrl(
                "gateway host not on operator allowlist",
            ));
        }
    }

    // 4a. A literal IP is decided directly — no DNS needed.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_blocked_ip(&ip) {
            Err(NamechainError::BlockedGatewayUrl("host is an internal ip literal"))
        } else {
            Ok(())
        };
    }

    // 4b. A hostname is resolved best-effort and rejected if ANY answer is internal. We resolve TWICE
    //     and reject on an internal answer in EITHER pass, which defeats a resolver that round-robins
    //     or immediately re-answers with an internal address (a cheap DNS-rebinding variant) — see the
    //     module residual note for the connect-time flip this does NOT close. A resolution failure is
    //     left to the transport (its connect will fail closed); we don't fail-open into an internal
    //     address, we just don't have one to block here.
    for _ in 0..2 {
        match (host, 443u16).to_socket_addrs() {
            Ok(addrs) => {
                for a in addrs {
                    if is_blocked_ip(&a.ip()) {
                        return Err(NamechainError::BlockedGatewayUrl(
                            "host resolves to an internal ip",
                        ));
                    }
                }
            }
            // Unresolvable now → nothing to block here; the transport's connect fails closed.
            Err(_) => break,
        }
    }
    Ok(())
}

/// Is `ip` in a range a public gateway must never live in (loopback/private/link-local/metadata/…)?
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped v6 address (`::ffff:a.b.c.d`) is really its embedded v4 — judge it as v4.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(&mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()          // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()      // 127/8
        || ip.is_link_local()    // 169.254/16 — includes the 169.254.169.254 metadata endpoint
        || ip.is_broadcast()     // 255.255.255.255
        || ip.is_unspecified()   // 0.0.0.0
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0             // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)      // 192.0.0/24 IETF protocol assignments
}

fn is_blocked_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let seg = ip.segments();
    (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_https_scheme_is_refused() {
        assert!(guard_gateway_url("http://169.254.169.254/latest/meta-data/", None).is_err());
        assert!(guard_gateway_url("ftp://example.com/x", None).is_err());
        assert!(guard_gateway_url("file:///etc/passwd", None).is_err());
    }

    #[test]
    fn metadata_and_loopback_and_private_ip_literals_are_refused() {
        for u in [
            "https://169.254.169.254/latest/meta-data/iam/",
            "https://127.0.0.1/admin",
            "https://[::1]/x",
            "https://10.0.0.5/x",
            "https://192.168.1.1/x",
            "https://172.16.9.9/x",
            "https://100.100.0.1/x", // CGNAT
            "https://0.0.0.0/x",
            "https://[fe80::1]/x",
            "https://[fc00::1]/x",
            "https://[::ffff:127.0.0.1]/x", // ipv4-mapped loopback
        ] {
            assert!(guard_gateway_url(u, None).is_err(), "should block {u}");
        }
    }

    #[test]
    fn localhost_by_name_is_refused() {
        assert!(guard_gateway_url("https://localhost/x", None).is_err());
        assert!(guard_gateway_url("https://LOCALHOST:8080/x", None).is_err());
        assert!(guard_gateway_url("https://svc.localhost/x", None).is_err());
    }

    #[test]
    fn public_ip_literal_is_allowed() {
        // A public literal (one of the example.com anycast addrs) passes without any DNS.
        assert!(
            guard_gateway_url("https://93.184.216.34/gateway/{sender}/{data}.json", None).is_ok()
        );
    }

    #[test]
    fn userinfo_cannot_smuggle_an_internal_host_past_the_check() {
        // The real host is after the last '@' — the userinfo must not be mistaken for it.
        assert!(guard_gateway_url("https://public.example.com@127.0.0.1/x", None).is_err());
    }

    #[test]
    fn empty_and_malformed_hosts_are_refused() {
        assert!(guard_gateway_url("https:///path-only", None).is_err());
        assert!(guard_gateway_url("https://[::1/x", None).is_err());
    }

    // ---- operator allowlist (defense-in-depth) ----

    #[test]
    fn allowlisted_host_and_subdomain_pass() {
        let allow = GatewayAllowlist::new(["gw.example.com", "ens.gateway.io"]);
        // Exact host match.
        assert!(guard_gateway_url("https://gw.example.com/{sender}/{data}", Some(&allow)).is_ok());
        // Subdomain of an allowlisted parent.
        let allow_parent = GatewayAllowlist::new(["example.com"]);
        assert!(
            guard_gateway_url("https://gw.example.com/x", Some(&allow_parent)).is_ok(),
            "subdomain of an allowlisted parent must pass"
        );
        // Case-insensitive on both sides.
        let allow_ci = GatewayAllowlist::new([".EXAMPLE.com"]);
        assert!(guard_gateway_url("https://GW.Example.Com/x", Some(&allow_ci)).is_ok());
    }

    #[test]
    fn non_allowlisted_public_host_is_refused_when_allowlist_set() {
        let allow = GatewayAllowlist::new(["gw.example.com"]);
        // A perfectly public host that would pass the SSRF checks is still refused off-allowlist.
        let err = guard_gateway_url("https://evil.attacker.example/x", Some(&allow)).unwrap_err();
        assert!(matches!(err, NamechainError::BlockedGatewayUrl(_)));
        // Label-boundary safety: a suffix collision must NOT be treated as a subdomain.
        assert!(guard_gateway_url("https://notexample.com/x", Some(&allow)).is_err());
        assert!(
            guard_gateway_url("https://gw.example.com.evil.tld/x", Some(&allow)).is_err(),
            "an allowlisted label appearing mid-host must not match"
        );
    }

    #[test]
    fn empty_allowlist_matches_nothing() {
        let empty = GatewayAllowlist::new::<[&str; 0], &str>([]);
        assert!(empty.is_empty());
        assert!(guard_gateway_url("https://gw.example.com/x", Some(&empty)).is_err());
    }

    #[test]
    fn unset_allowlist_preserves_prior_behavior() {
        // Passing None keeps the exact pre-allowlist behavior: public host allowed, internal blocked.
        assert!(guard_gateway_url("https://93.184.216.34/gateway/{data}", None).is_ok());
        assert!(guard_gateway_url("https://127.0.0.1/x", None).is_err());
    }

    #[test]
    fn allowlist_never_overrides_the_ssrf_range_checks() {
        // Even if the operator allowlists a name, an internal IP literal under it is still refused:
        // the allowlist is additive, never a bypass. Here the "host" is an internal literal that the
        // operator foolishly allowlisted — the range check must still win.
        let allow = GatewayAllowlist::new(["127.0.0.1"]);
        assert!(guard_gateway_url("https://127.0.0.1/x", Some(&allow)).is_err());
    }
}
