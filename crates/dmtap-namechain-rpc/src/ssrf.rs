//! SSRF guard for attacker-controlled CCIP-Read (EIP-3668) gateway URLs.
//!
//! A CCIP `OffchainLookup` revert names the gateway URL to fetch, and **anyone** can register an ENS
//! name pointing at a resolver contract they deployed — so that URL is fully attacker-controlled. If
//! the resolving node dialed it blindly it would be a Server-Side Request Forgery primitive: reaching
//! `http://169.254.169.254/…` (cloud metadata), loopback admin ports, or RFC1918 hosts from inside the
//! node's trust boundary. This module refuses such URLs **before any socket is opened**.
//!
//! Policy: HTTPS scheme only; reject `localhost`; reject any literal IP — or any hostname that
//! resolves — into a loopback / private / link-local / unique-local / CGNAT / metadata range.
//!
//! Residual (documented, not fixed here): DNS **rebinding** — a hostname that passes this check but
//! re-resolves to an internal address at the transport's connect time. Fully closing it needs the
//! transport to pin the IP this guard resolved; that is a transport-layer change tracked separately.

use crate::NamechainError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// Refuse a CCIP gateway URL that is non-HTTPS or points at an internal address. Fail closed.
pub(crate) fn guard_gateway_url(url: &str) -> Result<(), NamechainError> {
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

    // 4a. A literal IP is decided directly — no DNS needed.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_blocked_ip(&ip) {
            Err(NamechainError::BlockedGatewayUrl("host is an internal ip literal"))
        } else {
            Ok(())
        };
    }

    // 4b. A hostname is resolved best-effort and rejected if ANY answer is internal. A resolution
    //     failure is left to the transport (its connect will fail closed); we don't fail-open into an
    //     internal address, we just don't have one to block here.
    if let Ok(addrs) = (host, 443u16).to_socket_addrs() {
        for a in addrs {
            if is_blocked_ip(&a.ip()) {
                return Err(NamechainError::BlockedGatewayUrl("host resolves to an internal ip"));
            }
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
        assert!(guard_gateway_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(guard_gateway_url("ftp://example.com/x").is_err());
        assert!(guard_gateway_url("file:///etc/passwd").is_err());
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
            assert!(guard_gateway_url(u).is_err(), "should block {u}");
        }
    }

    #[test]
    fn localhost_by_name_is_refused() {
        assert!(guard_gateway_url("https://localhost/x").is_err());
        assert!(guard_gateway_url("https://LOCALHOST:8080/x").is_err());
        assert!(guard_gateway_url("https://svc.localhost/x").is_err());
    }

    #[test]
    fn public_ip_literal_is_allowed() {
        // A public literal (one of the example.com anycast addrs) passes without any DNS.
        assert!(guard_gateway_url("https://93.184.216.34/gateway/{sender}/{data}.json").is_ok());
    }

    #[test]
    fn userinfo_cannot_smuggle_an_internal_host_past_the_check() {
        // The real host is after the last '@' — the userinfo must not be mistaken for it.
        assert!(guard_gateway_url("https://public.example.com@127.0.0.1/x").is_err());
    }

    #[test]
    fn empty_and_malformed_hosts_are_refused() {
        assert!(guard_gateway_url("https:///path-only").is_err());
        assert!(guard_gateway_url("https://[::1/x").is_err());
    }
}
