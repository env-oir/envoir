//! MX resolution for outbound delivery (spec §7.3 step 4; RFC 5321 §5.1).
//!
//! RFC 5321 §5.1: the destination for a domain is its MX records, tried in ascending preference
//! order (lowest number first); if the domain has **no** MX records at all, mail is delivered
//! directly to the domain's own A/AAAA address (the domain acts as its own single implicit MX).
//! [`MxResolver`] returns that ordered candidate list; it does not do the final A/AAAA→IP hop —
//! [`crate::outbound_tcp::SmtpTcpTransport`] already resolves whatever hostname it is given via the
//! OS resolver (`ToSocketAddrs`), so the A/AAAA fallback falls out naturally from returning the bare
//! domain as the sole candidate.

use crate::dns::{self, UdpDnsClient, TYPE_MX};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// One candidate destination host for a domain, with its RFC 5321 preference (lower = tried first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxHost {
    pub host: String,
    pub preference: u16,
}

/// Resolves a domain to its ordered MX candidate list (spec §7.3 step 4). Abstract so outbound
/// delivery is testable in-process; [`DnsMxResolver`] is the real DNS-backed implementation.
pub trait MxResolver {
    /// Candidate hosts for `domain`, sorted ascending by preference (RFC 5321 §5.1). MUST return at
    /// least one entry — when there are no MX records, the fallback entry is `domain` itself at
    /// preference 0 (the A/AAAA fallback).
    fn resolve_mx(&self, domain: &str) -> Vec<MxHost>;
}

/// An in-memory MX table for tests: no network, fully deterministic.
#[derive(Debug, Default, Clone)]
pub struct InMemoryMxResolver {
    records: HashMap<String, Vec<MxHost>>,
}

impl InMemoryMxResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish MX records for `domain` (order given does not matter; `resolve_mx` sorts).
    pub fn with_mx(mut self, domain: &str, hosts: &[(&str, u16)]) -> Self {
        let entries =
            hosts.iter().map(|(h, p)| MxHost { host: (*h).to_string(), preference: *p }).collect();
        self.records.insert(domain.to_ascii_lowercase(), entries);
        self
    }
}

impl MxResolver for InMemoryMxResolver {
    fn resolve_mx(&self, domain: &str) -> Vec<MxHost> {
        match self.records.get(&domain.to_ascii_lowercase()) {
            Some(hosts) if !hosts.is_empty() => {
                let mut hosts = hosts.clone();
                hosts.sort_by_key(|h| h.preference);
                hosts
            }
            // No MX published for this domain in the table → RFC 5321 §5.1 A/AAAA fallback: the
            // domain itself is the implicit single MX.
            _ => vec![MxHost { host: domain.to_string(), preference: 0 }],
        }
    }
}

/// The real, DNS-backed [`MxResolver`]: queries `server` for `domain`'s MX records over UDP.
///
/// **Seam / known limitation:** UDP-only (no TCP fallback on a truncated response), no retries, and
/// any query failure (timeout, `SERVFAIL`, malformed reply, ...) is treated the same as "no MX
/// records" — it falls back to the bare domain rather than distinguishing NXDOMAIN from a transient
/// resolver error. A production deployment wanting that distinction (to e.g. defer instead of
/// attempting a doomed connect) can implement `MxResolver` itself using a fuller resolver.
pub struct DnsMxResolver {
    client: UdpDnsClient,
}

impl DnsMxResolver {
    pub fn new(dns_server: SocketAddr) -> Self {
        DnsMxResolver { client: UdpDnsClient::new(dns_server) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }
}

impl MxResolver for DnsMxResolver {
    fn resolve_mx(&self, domain: &str) -> Vec<MxHost> {
        // A-label the domain up front (idempotent for ASCII): the MX query itself is converted
        // again inside `query_raw`, but the RFC 5321 §5.1 A/AAAA **fallback host** below must also
        // be the punycoded form — returning the bare Unicode domain would hand the transport a name
        // it can neither dial nor put in SNI. An unconvertible domain keeps its original spelling
        // here (the doomed query then fails and the fallback is returned verbatim): this trait has
        // no error channel, and [`crate::outbound`] already refuses such destinations with the
        // specific [`crate::outbound::OutboundError::IdnNotConvertible`] before resolving.
        let domain = crate::idn::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_string());
        let fallback = || vec![MxHost { host: domain.to_string(), preference: 0 }];
        let (packet, msg) = match self.client.query_raw(&domain, TYPE_MX) {
            Ok(r) => r,
            Err(_) => return fallback(),
        };
        let mut hosts: Vec<MxHost> = msg
            .answers
            .iter()
            .filter(|rr| rr.rtype == TYPE_MX)
            .filter_map(|rr| {
                dns::parse_mx_rdata(&packet, rr)
                    .ok()
                    .map(|(pref, host)| MxHost { host, preference: pref })
            })
            .collect();
        if hosts.is_empty() {
            // No MX records (or an unparsable / server-failure response) → RFC 5321 §5.1 A/AAAA
            // fallback.
            hosts = fallback();
        }
        hosts.sort_by_key(|h| h.preference);
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_mx_preference_order_lowest_first() {
        let resolver = InMemoryMxResolver::new().with_mx(
            "example.org",
            &[
                ("mx-backup.example.org", 20),
                ("mx-primary.example.org", 10),
                ("mx-tertiary.example.org", 30),
            ],
        );
        let hosts = resolver.resolve_mx("example.org");
        assert_eq!(
            hosts,
            vec![
                MxHost { host: "mx-primary.example.org".into(), preference: 10 },
                MxHost { host: "mx-backup.example.org".into(), preference: 20 },
                MxHost { host: "mx-tertiary.example.org".into(), preference: 30 },
            ],
            "candidates come back sorted ascending by preference (RFC 5321 §5.1)"
        );
    }

    #[test]
    fn no_mx_falls_back_to_the_domain_itself() {
        let resolver = InMemoryMxResolver::new(); // nothing published for any domain
        let hosts = resolver.resolve_mx("no-mx.example.net");
        assert_eq!(
            hosts,
            vec![MxHost { host: "no-mx.example.net".into(), preference: 0 }],
            "no MX records → the domain acts as its own single implicit MX (A/AAAA fallback)"
        );
    }

    #[test]
    fn domain_lookup_is_case_insensitive() {
        let resolver = InMemoryMxResolver::new().with_mx("Example.ORG", &[("mx.example.org", 10)]);
        assert_eq!(
            resolver.resolve_mx("example.org"),
            vec![MxHost { host: "mx.example.org".into(), preference: 10 }]
        );
    }

    #[test]
    fn a_lone_mx_record_still_resolves() {
        let resolver =
            InMemoryMxResolver::new().with_mx("single.example", &[("mx1.single.example", 5)]);
        assert_eq!(
            resolver.resolve_mx("single.example"),
            vec![MxHost { host: "mx1.single.example".into(), preference: 5 }]
        );
    }
}
