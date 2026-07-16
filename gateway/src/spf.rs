//! SPF — Sender Policy Framework (RFC 7208) — inbound legacy anti-spoofing check (spec §7.2 step 2,
//! §9 "SPF/DMARC" pre-`DATA` checks).
//!
//! `check_host()` (RFC 7208 §4) resolves the sender domain's `v=spf1` TXT record and evaluates its
//! mechanisms against the connecting peer IP, exactly as a legacy MTA would, so the verdict can feed
//! [`crate::inbound::InboundGateway`]'s SPF policy (annotate/enforce) and — combined with the DKIM
//! verdict — [`crate::dmarc`]'s alignment check.
//!
//! **Honest narrowings from full RFC 7208 (documented, not silent):**
//! - **No macro expansion.** `%{...}` macros in `exists`/`include`/`a`/`mx`/`ptr` domain-specs and in
//!   `exp=` are not implemented (RFC 7208 §7-8). A domain-spec containing `%` is treated as a
//!   [`SpfResult::PermError`] for the mechanism using it, rather than silently mis-evaluating a
//!   macro as a literal domain name.
//! - **`ptr` is parsed but never matches.** RFC 7208 §5.5 itself discourages `ptr` (unreliable,
//!   expensive, privacy-costly forward-confirmed-reverse-DNS). This implementation charges its DNS
//!   lookup budget (so a record cannot use `ptr` to dodge the lookup limit) but never claims a
//!   match — a safe, conservative simplification (it can only under-match, never falsely pass).
//! - **`a`/`mx` are IPv4-only.** [`crate::dns`] has no AAAA decoder (see its module docs), so `a`
//!   and `mx` mechanisms only ever match an IPv4 connecting sender; a literal `ip6:` mechanism still
//!   works (it needs no DNS lookup). An IPv6 sender can only match via `ip6`, `include`, or `all`.
//! - **A single aggregate 10-lookup ceiling**, not RFC 7208 §4.6.4's per-clause carve-outs (e.g. the
//!   separate "at most 10 MX names further resolved" rule). Every DNS query this evaluator issues —
//!   the record fetch for a recursed `include`/`redirect` target, each `a`/`mx`/`exists`/`ptr`
//!   mechanism, and each per-MX-host `A` lookup inside `mx` — is charged against one shared counter,
//!   and exceeding it is `PermError`. This is a safe simplification: it still caps total DNS
//!   amplification at the same ceiling the RFC intends, just uniformly rather than clause-by-clause.
//!   Per RFC 7208 §4.6.4, the **initial** record fetch for the top-level checked domain is free (the
//!   charge happens at the `include`/`redirect` call site before recursing, not inside `check_host`
//!   itself).
//! - **Resolver failure is distinguishable from NODATA**, unlike this crate's other single-`Vec`
//!   resolver traits ([`crate::mx::MxResolver`], [`crate::mta_sts::TxtResolver`]): SPF's `TempError`
//!   directly changes SMTP disposition (spec item 1: "fail-closed on hard-fail when enforcing" needs
//!   a genuine defer-and-retry state distinct from "no policy published"), so [`SpfResolver`]
//!   surfaces a lookup failure as `Err(())` rather than folding it into an empty `Ok(vec![])`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::dns::{self, UdpDnsClient, TYPE_A, TYPE_MX, TYPE_TXT};

/// RFC 7208 §2.6 result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// The client is authorized to inject mail with the given identity.
    Pass,
    /// An explicit statement that the client is not authorized (`-` qualifier, or default `all`
    /// with no qualifier is `+`... `Fail` specifically means a `-` mechanism matched).
    Fail,
    /// A weak statement that the host is probably not authorized (`~` qualifier).
    SoftFail,
    /// The domain owner makes no assertion either way (`?` qualifier, or the implicit default when
    /// nothing matches and there is no `redirect`).
    Neutral,
    /// The domain does not publish an SPF policy at all (no `v=spf1` TXT record).
    None,
    /// A transient error — e.g. a DNS lookup for the record or a mechanism's target genuinely
    /// failed (not NODATA). The check should be retried later; RFC 7208 recommends a `4xx` defer.
    TempError,
    /// The published record (or a record it references via `include`/`redirect`) is malformed, or
    /// evaluating it would exceed the DNS-lookup budget (§4.6.4), or it uses an unsupported macro
    /// (this implementation's documented narrowing).
    PermError,
}

/// The SPF verdict for one inbound SMTP transaction (spec item 1), plus the domain it was
/// ultimately evaluated against (the `MAIL FROM` domain, or the `HELO`/`EHLO` domain when
/// `MAIL FROM` is the null reverse-path `<>` or has no domain part, per RFC 7208 §2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfOutcome {
    pub result: SpfResult,
    /// The domain the SPF record was fetched for (empty if [`Self::result`] is `None` because SPF
    /// was never evaluated at all — see [`SpfOutcome::unevaluated`]).
    pub domain: String,
}

impl SpfOutcome {
    /// The honest "SPF was never checked" state — used when no [`SpfResolver`] is configured, or the
    /// connecting peer IP could not even be parsed. Never fabricates a verdict.
    pub fn unevaluated() -> Self {
        SpfOutcome { result: SpfResult::None, domain: String::new() }
    }
}

/// Resolves the DNS records SPF evaluation needs. Abstract so evaluation is testable in-process;
/// [`DnsSpfResolver`] is the real DNS-backed implementation. See the module docs for why lookup
/// failure (`Err`) is distinguished from NODATA (`Ok(vec![])`) here, unlike this crate's other
/// resolver traits.
pub trait SpfResolver {
    /// TXT records for `name` (RFC 7208 §3: candidates are filtered to `v=spf1` records by the
    /// caller). `Err` is a genuine resolution failure (timeout, SERVFAIL, malformed reply).
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, ()>;
    /// A (IPv4-only, see module docs) records for `name`, used by the `a`/`mx`/`exists` mechanisms.
    fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ()>;
    /// MX exchange hostnames for `name` (preference order does not matter for SPF), used by `mx`.
    fn lookup_mx(&self, name: &str) -> Result<Vec<String>, ()>;
}

/// An in-memory [`SpfResolver`] for tests: static TXT/A/MX tables, plus an explicit "this name always
/// fails resolution" set for exercising [`SpfResult::TempError`].
#[derive(Debug, Default, Clone)]
pub struct InMemorySpfResolver {
    txt: HashMap<String, Vec<String>>,
    a: HashMap<String, Vec<Ipv4Addr>>,
    mx: HashMap<String, Vec<String>>,
    failing: HashSet<String>,
}

impl InMemorySpfResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_txt(mut self, name: &str, values: &[&str]) -> Self {
        self.txt.insert(name.to_ascii_lowercase(), values.iter().map(|v| v.to_string()).collect());
        self
    }
    pub fn with_a(mut self, name: &str, ips: &[Ipv4Addr]) -> Self {
        self.a.insert(name.to_ascii_lowercase(), ips.to_vec());
        self
    }
    pub fn with_mx(mut self, name: &str, hosts: &[&str]) -> Self {
        self.mx.insert(name.to_ascii_lowercase(), hosts.iter().map(|h| h.to_string()).collect());
        self
    }
    /// Every lookup (TXT/A/MX) against `name` fails with `Err(())` — models a genuinely broken
    /// resolver/nameserver for `name`, distinct from `name` simply having no records.
    pub fn with_failure(mut self, name: &str) -> Self {
        self.failing.insert(name.to_ascii_lowercase());
        self
    }
}

impl SpfResolver for InMemorySpfResolver {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, ()> {
        let key = name.to_ascii_lowercase();
        if self.failing.contains(&key) {
            return Err(());
        }
        Ok(self.txt.get(&key).cloned().unwrap_or_default())
    }
    fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ()> {
        let key = name.to_ascii_lowercase();
        if self.failing.contains(&key) {
            return Err(());
        }
        Ok(self.a.get(&key).cloned().unwrap_or_default())
    }
    fn lookup_mx(&self, name: &str) -> Result<Vec<String>, ()> {
        let key = name.to_ascii_lowercase();
        if self.failing.contains(&key) {
            return Err(());
        }
        Ok(self.mx.get(&key).cloned().unwrap_or_default())
    }
}

/// The real, DNS-backed [`SpfResolver`] (see [`crate::dns`] module docs for the underlying wire-format
/// caveats: UDP-only, no TC/EDNS0/retries/caching/DNSSEC).
pub struct DnsSpfResolver {
    client: UdpDnsClient,
}

impl DnsSpfResolver {
    pub fn new(dns_server: SocketAddr) -> Self {
        DnsSpfResolver { client: UdpDnsClient::new(dns_server) }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.with_timeout(timeout);
        self
    }
}

impl SpfResolver for DnsSpfResolver {
    fn lookup_txt(&self, name: &str) -> Result<Vec<String>, ()> {
        let msg = self.client.query(name, TYPE_TXT).map_err(|_| ())?;
        Ok(msg.answers.iter().filter(|rr| rr.rtype == TYPE_TXT).map(dns::parse_txt_rdata).collect())
    }
    fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ()> {
        let msg = self.client.query(name, TYPE_A).map_err(|_| ())?;
        Ok(msg.answers.iter().filter(|rr| rr.rtype == TYPE_A).filter_map(dns::parse_a_rdata).collect())
    }
    fn lookup_mx(&self, name: &str) -> Result<Vec<String>, ()> {
        let (packet, msg) = self.client.query_raw(name, TYPE_MX).map_err(|_| ())?;
        Ok(msg
            .answers
            .iter()
            .filter(|rr| rr.rtype == TYPE_MX)
            .filter_map(|rr| dns::parse_mx_rdata(&packet, rr).ok())
            .map(|(_, host)| host)
            .collect())
    }
}

// --- Evaluation (RFC 7208 §4) -----------------------------------------------------------------

/// The aggregate DNS-lookup budget (RFC 7208 §4.6.4 intent; see module docs on the simplification).
const DEFAULT_MAX_LOOKUPS: u32 = 10;
/// A recursion-depth guard for `include`/`redirect` chains, independent of the lookup budget (which
/// already bounds it in practice, but this catches a pathological zero-cost cycle defensively).
const MAX_CHAIN_DEPTH: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

fn qualifier_to_result(q: Qualifier) -> SpfResult {
    match q {
        Qualifier::Pass => SpfResult::Pass,
        Qualifier::Fail => SpfResult::Fail,
        Qualifier::SoftFail => SpfResult::SoftFail,
        Qualifier::Neutral => SpfResult::Neutral,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mechanism {
    All,
    Include(String),
    A { domain: Option<String>, cidr4: u8 },
    Mx { domain: Option<String>, cidr4: u8 },
    Ip4 { net: Ipv4Addr, cidr: u8 },
    Ip6 { net: Ipv6Addr, cidr: u8 },
    Ptr,
    Exists(String),
}

struct ParsedRecord {
    mechanisms: Vec<(Qualifier, Mechanism)>,
    redirect: Option<String>,
}

/// Parse a `v=spf1 ...` record body (the whole TXT value) into its ordered mechanism list plus an
/// optional `redirect=` modifier target. Fails closed (`Err(())`, mapped to [`SpfResult::PermError`])
/// on any unrecognized mechanism, malformed CIDR/IP literal, or a duplicated `redirect=` modifier.
fn parse_record(record: &str) -> Result<ParsedRecord, ()> {
    let mut terms = record.split_whitespace();
    let version = terms.next().ok_or(())?;
    if version != "v=spf1" {
        return Err(());
    }
    let mut mechanisms = Vec::new();
    let mut redirect: Option<String> = None;
    for term in terms {
        if term.is_empty() {
            continue;
        }
        if let Some(eq) = term.find('=') {
            let name = &term[..eq];
            let value = &term[eq + 1..];
            if name.eq_ignore_ascii_case("redirect") {
                if redirect.is_some() || value.is_empty() {
                    return Err(());
                }
                redirect = Some(value.to_string());
            }
            // "exp=" and any unknown modifier are parsed-and-discarded per RFC 7208 §6 (unknown
            // modifiers MUST be ignored); "exp" specifically is never used since this implementation
            // does not generate human-readable explanation strings (no macro-expansion seam, see
            // module docs).
            continue;
        }
        let bytes = term.as_bytes();
        let (qualifier, rest): (Qualifier, &str) = match bytes[0] {
            b'+' => (Qualifier::Pass, &term[1..]),
            b'-' => (Qualifier::Fail, &term[1..]),
            b'~' => (Qualifier::SoftFail, &term[1..]),
            b'?' => (Qualifier::Neutral, &term[1..]),
            _ => (Qualifier::Pass, term),
        };
        let mech = parse_mechanism(rest)?;
        mechanisms.push((qualifier, mech));
    }
    Ok(ParsedRecord { mechanisms, redirect })
}

fn parse_mechanism(s: &str) -> Result<Mechanism, ()> {
    if s.is_empty() {
        return Err(());
    }
    let split_at = s.find(|c| c == ':' || c == '/').unwrap_or(s.len());
    let keyword = &s[..split_at];
    let rest = &s[split_at..];
    match keyword.to_ascii_lowercase().as_str() {
        "all" => {
            if !rest.is_empty() {
                return Err(());
            }
            Ok(Mechanism::All)
        }
        "include" => {
            let v = rest.strip_prefix(':').ok_or(())?;
            if v.is_empty() {
                return Err(());
            }
            Ok(Mechanism::Include(v.to_string()))
        }
        "exists" => {
            let v = rest.strip_prefix(':').ok_or(())?;
            if v.is_empty() {
                return Err(());
            }
            Ok(Mechanism::Exists(v.to_string()))
        }
        "a" => {
            let (domain, cidr4) = parse_domain_spec(rest)?;
            Ok(Mechanism::A { domain, cidr4 })
        }
        "mx" => {
            let (domain, cidr4) = parse_domain_spec(rest)?;
            Ok(Mechanism::Mx { domain, cidr4 })
        }
        "ptr" => {
            // A domain-spec is legal syntax here (`ptr:some.domain`) but this implementation never
            // resolves it (see module docs) — accept-and-ignore rather than reject valid records.
            if !rest.is_empty() && rest.strip_prefix(':').map(|d| d.is_empty()).unwrap_or(true) {
                return Err(());
            }
            Ok(Mechanism::Ptr)
        }
        "ip4" => {
            let v = rest.strip_prefix(':').ok_or(())?;
            let (net, cidr) = parse_ip4_cidr(v)?;
            Ok(Mechanism::Ip4 { net, cidr })
        }
        "ip6" => {
            let v = rest.strip_prefix(':').ok_or(())?;
            let (net, cidr) = parse_ip6_cidr(v)?;
            Ok(Mechanism::Ip6 { net, cidr })
        }
        _ => Err(()),
    }
}

/// Parse the optional `[":" domain-spec] [dual-cidr-length]` suffix shared by `a`/`mx` (RFC 7208
/// §5.3/§5.4). Only `cidr4` is returned/used for matching (see module docs: `a`/`mx` are IPv4-only
/// here); a syntactically-present `ip6-cidr-length` is validated for shape but otherwise unused.
fn parse_domain_spec(rest: &str) -> Result<(Option<String>, u8), ()> {
    let (domain_part, cidr_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let domain = if let Some(d) = domain_part.strip_prefix(':') {
        if d.is_empty() {
            return Err(());
        }
        Some(d.to_string())
    } else if domain_part.is_empty() {
        None
    } else {
        return Err(());
    };
    let cidr4 = parse_dual_cidr(cidr_part)?;
    Ok((domain, cidr4))
}

fn parse_dual_cidr(cidr_part: &str) -> Result<u8, ()> {
    if cidr_part.is_empty() {
        return Ok(32);
    }
    if let Some(v6only) = cidr_part.strip_prefix("//") {
        // ip6-only shorthand ("//64"): ip4 defaults to /32; the ip6 value is validated but unused.
        let v: u8 = v6only.parse().map_err(|_| ())?;
        if v > 128 {
            return Err(());
        }
        return Ok(32);
    }
    let rest = cidr_part.strip_prefix('/').ok_or(())?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.len() {
        1 => {
            let c4: u8 = parts[0].parse().map_err(|_| ())?;
            if c4 > 32 {
                return Err(());
            }
            Ok(c4)
        }
        2 => {
            let c4: u8 = parts[0].parse().map_err(|_| ())?;
            let c6: u8 = parts[1].parse().map_err(|_| ())?;
            if c4 > 32 || c6 > 128 {
                return Err(());
            }
            Ok(c4)
        }
        _ => Err(()),
    }
}

fn parse_ip4_cidr(v: &str) -> Result<(Ipv4Addr, u8), ()> {
    let (addr, cidr) = match v.split_once('/') {
        Some((a, c)) => (a, c.parse::<u8>().map_err(|_| ())?),
        None => (v, 32),
    };
    if cidr > 32 {
        return Err(());
    }
    let ip: Ipv4Addr = addr.parse().map_err(|_| ())?;
    Ok((ip, cidr))
}

fn parse_ip6_cidr(v: &str) -> Result<(Ipv6Addr, u8), ()> {
    let (addr, cidr) = match v.split_once('/') {
        Some((a, c)) => (a, c.parse::<u8>().map_err(|_| ())?),
        None => (v, 128),
    };
    if cidr > 128 {
        return Err(());
    }
    let ip: Ipv6Addr = addr.parse().map_err(|_| ())?;
    Ok((ip, cidr))
}

fn ipv4_in_cidr(ip: Ipv4Addr, net: Ipv4Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let cidr = cidr.min(32);
    let mask: u32 = if cidr == 32 { u32::MAX } else { !(u32::MAX >> cidr) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_cidr(ip: Ipv6Addr, net: Ipv6Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let cidr = cidr.min(128);
    let mask: u128 = if cidr == 128 { u128::MAX } else { !(u128::MAX >> cidr) };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn normalize(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_spf1_record(t: &str) -> bool {
    let t = t.trim();
    t == "v=spf1" || t.starts_with("v=spf1 ")
}

/// Does a mechanism's domain-spec use an unsupported macro (`%`)? Checked before evaluating the
/// mechanism so a macro-using record fails closed as `PermError` rather than being (mis)treated as
/// a literal, almost-certainly-wrong domain name.
fn mechanism_has_macro(m: &Mechanism) -> bool {
    match m {
        Mechanism::Include(d) | Mechanism::Exists(d) => d.contains('%'),
        Mechanism::A { domain: Some(d), .. } | Mechanism::Mx { domain: Some(d), .. } => d.contains('%'),
        _ => false,
    }
}

enum MechOutcome {
    Match,
    NoMatch,
    Abort(SpfResult),
}

struct Evaluator<'r> {
    resolver: &'r dyn SpfResolver,
    lookups: u32,
    max_lookups: u32,
}

impl<'r> Evaluator<'r> {
    fn charge_lookup(&mut self) -> Result<(), SpfResult> {
        self.lookups += 1;
        if self.lookups > self.max_lookups {
            Err(SpfResult::PermError)
        } else {
            Ok(())
        }
    }

    /// RFC 7208 §4: fetch + evaluate `domain`'s SPF record. `depth` bounds `include`/`redirect`
    /// recursion. The **initial** TXT fetch here is never itself charged against the lookup budget
    /// (§4.6.4) — the charge happens at the `include`/`redirect` call site before recursing.
    fn check_host(&mut self, domain: &str, ip: IpAddr, sender: &str, depth: u32) -> SpfResult {
        if depth > MAX_CHAIN_DEPTH {
            return SpfResult::PermError;
        }
        let domain_n = normalize(domain);
        if domain_n.is_empty() {
            return SpfResult::None;
        }
        let txts = match self.resolver.lookup_txt(&domain_n) {
            Ok(v) => v,
            Err(()) => return SpfResult::TempError,
        };
        let candidates: Vec<&String> = txts.iter().filter(|t| is_spf1_record(t)).collect();
        let record = match candidates.len() {
            0 => return SpfResult::None,
            1 => candidates[0],
            _ => return SpfResult::PermError, // multiple SPF records, RFC 7208 §4.5.
        };
        let parsed = match parse_record(record) {
            Ok(p) => p,
            Err(()) => return SpfResult::PermError,
        };

        for (q, m) in &parsed.mechanisms {
            if mechanism_has_macro(m) {
                return SpfResult::PermError;
            }
            match self.eval_mechanism(m, &domain_n, ip, sender, depth) {
                MechOutcome::Match => return qualifier_to_result(*q),
                MechOutcome::NoMatch => continue,
                MechOutcome::Abort(r) => return r,
            }
        }
        if let Some(target) = &parsed.redirect {
            if target.contains('%') {
                return SpfResult::PermError;
            }
            if let Err(e) = self.charge_lookup() {
                return e;
            }
            return self.check_host(target, ip, sender, depth + 1);
        }
        // No mechanism matched and no redirect — RFC 7208 §4.7's implicit default.
        SpfResult::Neutral
    }

    fn eval_mechanism(
        &mut self,
        m: &Mechanism,
        current_domain: &str,
        ip: IpAddr,
        sender: &str,
        depth: u32,
    ) -> MechOutcome {
        match m {
            Mechanism::All => MechOutcome::Match,
            Mechanism::Include(target) => {
                if let Err(e) = self.charge_lookup() {
                    return MechOutcome::Abort(e);
                }
                match self.check_host(target, ip, sender, depth + 1) {
                    SpfResult::Pass => MechOutcome::Match,
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => MechOutcome::NoMatch,
                    SpfResult::TempError => MechOutcome::Abort(SpfResult::TempError),
                    // RFC 7208 §5.2: an included domain with no record ("None") is itself a syntax
                    // problem for the including record — treated as PermError, never silently skipped.
                    SpfResult::None | SpfResult::PermError => MechOutcome::Abort(SpfResult::PermError),
                }
            }
            Mechanism::Ip4 { net, cidr } => match ip {
                IpAddr::V4(v4) => {
                    if ipv4_in_cidr(v4, *net, *cidr) {
                        MechOutcome::Match
                    } else {
                        MechOutcome::NoMatch
                    }
                }
                IpAddr::V6(_) => MechOutcome::NoMatch,
            },
            Mechanism::Ip6 { net, cidr } => match ip {
                IpAddr::V6(v6) => {
                    if ipv6_in_cidr(v6, *net, *cidr) {
                        MechOutcome::Match
                    } else {
                        MechOutcome::NoMatch
                    }
                }
                IpAddr::V4(_) => MechOutcome::NoMatch,
            },
            Mechanism::A { domain, cidr4 } => {
                let v4 = match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => return MechOutcome::NoMatch, // narrowing: no AAAA, see module docs
                };
                let target = domain.clone().unwrap_or_else(|| current_domain.to_string());
                if let Err(e) = self.charge_lookup() {
                    return MechOutcome::Abort(e);
                }
                match self.resolver.lookup_a(&normalize(&target)) {
                    Err(()) => MechOutcome::Abort(SpfResult::TempError),
                    Ok(ips) => {
                        if ips.iter().any(|a| ipv4_in_cidr(v4, *a, *cidr4)) {
                            MechOutcome::Match
                        } else {
                            MechOutcome::NoMatch
                        }
                    }
                }
            }
            Mechanism::Mx { domain, cidr4 } => {
                let v4 = match ip {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => return MechOutcome::NoMatch,
                };
                let target = domain.clone().unwrap_or_else(|| current_domain.to_string());
                if let Err(e) = self.charge_lookup() {
                    return MechOutcome::Abort(e);
                }
                let hosts = match self.resolver.lookup_mx(&normalize(&target)) {
                    Err(()) => return MechOutcome::Abort(SpfResult::TempError),
                    Ok(h) => h,
                };
                for host in hosts {
                    if let Err(e) = self.charge_lookup() {
                        return MechOutcome::Abort(e);
                    }
                    match self.resolver.lookup_a(&normalize(&host)) {
                        Err(()) => return MechOutcome::Abort(SpfResult::TempError),
                        Ok(ips) => {
                            if ips.iter().any(|a| ipv4_in_cidr(v4, *a, *cidr4)) {
                                return MechOutcome::Match;
                            }
                        }
                    }
                }
                MechOutcome::NoMatch
            }
            Mechanism::Ptr => {
                // Charge the budget a real ptr evaluation would have spent (so a record cannot use
                // repeated `ptr` terms to dodge the lookup ceiling) but never claim a match — see
                // module docs.
                if let Err(e) = self.charge_lookup() {
                    return MechOutcome::Abort(e);
                }
                MechOutcome::NoMatch
            }
            Mechanism::Exists(target) => {
                if let Err(e) = self.charge_lookup() {
                    return MechOutcome::Abort(e);
                }
                match self.resolver.lookup_a(&normalize(target)) {
                    Err(()) => MechOutcome::Abort(SpfResult::TempError),
                    Ok(ips) => {
                        if !ips.is_empty() {
                            MechOutcome::Match
                        } else {
                            MechOutcome::NoMatch
                        }
                    }
                }
            }
        }
    }
}

/// Evaluate SPF for `domain` (RFC 7208 §4 `check_host()`), given the connecting `ip` and the
/// `sender` identity (`MAIL FROM`, used only for `%{s}`-style macros — which this implementation
/// does not expand, see module docs — so `sender` is otherwise inert here but kept in the API for
/// fidelity/future use).
pub fn check_host(resolver: &dyn SpfResolver, ip: IpAddr, domain: &str, sender: &str) -> SpfResult {
    let mut ev = Evaluator { resolver, lookups: 0, max_lookups: DEFAULT_MAX_LOOKUPS };
    ev.check_host(domain, ip, sender, 0)
}

fn domain_of(addr: &str) -> Option<&str> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>');
    a.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty())
}

/// The spec-item-1 entry point: evaluate SPF for one inbound SMTP transaction. Implements RFC 7208
/// §2.4's identity selection: when `mail_from` is the null reverse-path (`<>`, used by bounces) or
/// has no `@domain` at all, the check runs against `postmaster@<helo_domain>` instead, using the
/// `HELO`/`EHLO` domain — never silently skipped.
pub fn evaluate(
    resolver: &dyn SpfResolver,
    ip: IpAddr,
    mail_from: &str,
    helo_domain: Option<&str>,
) -> SpfOutcome {
    let trimmed = mail_from.trim();
    let is_null = trimmed.is_empty() || trimmed == "<>";
    let (sender, domain) = if is_null {
        let helo = helo_domain.unwrap_or("").to_string();
        (format!("postmaster@{helo}"), helo)
    } else {
        match domain_of(trimmed) {
            Some(d) => (trimmed.to_string(), d.to_string()),
            None => {
                let helo = helo_domain.unwrap_or("").to_string();
                (format!("postmaster@{helo}"), helo)
            }
        }
    };
    if domain.is_empty() {
        return SpfOutcome { result: SpfResult::None, domain };
    }
    let result = check_host(resolver, ip, &domain, &sender);
    SpfOutcome { result, domain }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn ip4_mechanism_pass_and_implicit_neutral() {
        let r = InMemorySpfResolver::new().with_txt("example.org", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        assert_eq!(check_host(&r, v4("203.0.113.9"), "example.org", "a@example.org"), SpfResult::Pass);
        assert_eq!(check_host(&r, v4("198.51.100.9"), "example.org", "a@example.org"), SpfResult::Fail);
    }

    #[test]
    fn qualifiers_softfail_and_neutral() {
        let r = InMemorySpfResolver::new()
            .with_txt("soft.example", &["v=spf1 ip4:203.0.113.0/24 ~all"])
            .with_txt("neutral.example", &["v=spf1 ip4:203.0.113.0/24 ?all"])
            .with_txt("noall.example", &["v=spf1 ip4:203.0.113.0/24"]);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "soft.example", "a@x"), SpfResult::SoftFail);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "neutral.example", "a@x"), SpfResult::Neutral);
        // No "all" at all and nothing else matched → implicit Neutral (§4.7).
        assert_eq!(check_host(&r, v4("9.9.9.9"), "noall.example", "a@x"), SpfResult::Neutral);
    }

    #[test]
    fn no_record_is_none() {
        let r = InMemorySpfResolver::new();
        assert_eq!(check_host(&r, v4("1.2.3.4"), "nowhere.example", "a@x"), SpfResult::None);
    }

    #[test]
    fn multiple_spf_records_is_permerror() {
        let r = InMemorySpfResolver::new()
            .with_txt("dup.example", &["v=spf1 -all", "v=spf1 +all"]);
        assert_eq!(check_host(&r, v4("1.2.3.4"), "dup.example", "a@x"), SpfResult::PermError);
    }

    #[test]
    fn malformed_record_is_permerror_not_a_panic() {
        let cases = [
            "v=spf1 bogus-mechanism -all",
            "v=spf1 ip4:not-an-ip -all",
            "v=spf1 ip4:1.2.3.4/99 -all", // cidr out of range
            "v=spf1 include: -all",       // empty include target
            "not-even-spf1",
        ];
        for body in cases {
            let r = InMemorySpfResolver::new().with_txt("bad.example", &[body]);
            assert_eq!(
                check_host(&r, v4("1.2.3.4"), "bad.example", "a@x"),
                if body == "not-even-spf1" { SpfResult::None } else { SpfResult::PermError },
                "case {body:?}"
            );
        }
    }

    #[test]
    fn include_propagates_pass_and_treats_none_as_permerror() {
        let r = InMemorySpfResolver::new()
            .with_txt("top.example", &["v=spf1 include:helper.example -all"])
            .with_txt("helper.example", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        assert_eq!(check_host(&r, v4("203.0.113.5"), "top.example", "a@x"), SpfResult::Pass);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "top.example", "a@x"), SpfResult::Fail);

        // Included domain publishes no record at all → PermError (RFC 7208 §5.2), not silently NoMatch.
        let r2 = InMemorySpfResolver::new().with_txt("top2.example", &["v=spf1 include:ghost.example -all"]);
        assert_eq!(check_host(&r2, v4("1.1.1.1"), "top2.example", "a@x"), SpfResult::PermError);
    }

    #[test]
    fn redirect_chains_to_another_record() {
        let r = InMemorySpfResolver::new()
            .with_txt("alias.example", &["v=spf1 redirect=canonical.example"])
            .with_txt("canonical.example", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        assert_eq!(check_host(&r, v4("203.0.113.1"), "alias.example", "a@x"), SpfResult::Pass);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "alias.example", "a@x"), SpfResult::Fail);
    }

    #[test]
    fn a_and_mx_mechanisms_match_ipv4_only() {
        let r = InMemorySpfResolver::new()
            .with_txt("a-mech.example", &["v=spf1 a -all"])
            .with_a("a-mech.example", &[Ipv4Addr::new(203, 0, 113, 9)])
            .with_txt("mx-mech.example", &["v=spf1 mx -all"])
            .with_mx("mx-mech.example", &["mail1.mx-mech.example"])
            .with_a("mail1.mx-mech.example", &[Ipv4Addr::new(198, 51, 100, 9)]);

        assert_eq!(check_host(&r, v4("203.0.113.9"), "a-mech.example", "a@x"), SpfResult::Pass);
        assert_eq!(check_host(&r, v4("203.0.113.10"), "a-mech.example", "a@x"), SpfResult::Fail);
        assert_eq!(check_host(&r, v4("198.51.100.9"), "mx-mech.example", "a@x"), SpfResult::Pass);
        // IPv6 sender can never match `a`/`mx` here — a documented narrowing (no AAAA support).
        assert_eq!(
            check_host(&r, v6("2001:db8::1"), "a-mech.example", "a@x"),
            SpfResult::Fail,
            "ipv6 sender falls through to -all since a/mx cannot match it"
        );
    }

    #[test]
    fn ip6_mechanism_matches_ipv6_senders_directly_no_dns() {
        let r = InMemorySpfResolver::new().with_txt("v6.example", &["v=spf1 ip6:2001:db8::/32 -all"]);
        assert_eq!(check_host(&r, v6("2001:db8::9"), "v6.example", "a@x"), SpfResult::Pass);
        assert_eq!(check_host(&r, v6("2001:dead::9"), "v6.example", "a@x"), SpfResult::Fail);
    }

    #[test]
    fn exists_mechanism_matches_on_any_a_record_presence() {
        let r = InMemorySpfResolver::new()
            .with_txt("ex.example", &["v=spf1 exists:gate.ex.example -all"])
            .with_a("gate.ex.example", &[Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "ex.example", "a@x"), SpfResult::Pass);
        let r2 = InMemorySpfResolver::new().with_txt("ex2.example", &["v=spf1 exists:missing.example -all"]);
        assert_eq!(check_host(&r2, v4("9.9.9.9"), "ex2.example", "a@x"), SpfResult::Fail);
    }

    #[test]
    fn ptr_mechanism_never_matches_but_still_charges_a_lookup() {
        // A record relying solely on `ptr` to pass never passes here (documented narrowing) — it
        // falls through to the default Neutral, not a false Pass.
        let r = InMemorySpfResolver::new().with_txt("ptr.example", &["v=spf1 ptr"]);
        assert_eq!(check_host(&r, v4("9.9.9.9"), "ptr.example", "a@x"), SpfResult::Neutral);
    }

    #[test]
    fn macro_use_is_permerror_not_a_silent_literal_match() {
        let r = InMemorySpfResolver::new()
            .with_txt("macro.example", &["v=spf1 exists:%{i}.spf.macro.example -all"]);
        assert_eq!(check_host(&r, v4("1.2.3.4"), "macro.example", "a@x"), SpfResult::PermError);
    }

    #[test]
    fn dns_failure_is_temperror_distinct_from_no_record() {
        let r = InMemorySpfResolver::new().with_failure("broken.example");
        assert_eq!(check_host(&r, v4("1.2.3.4"), "broken.example", "a@x"), SpfResult::TempError);
    }

    #[test]
    fn nested_dns_failure_inside_include_is_temperror() {
        let r = InMemorySpfResolver::new()
            .with_txt("top.example", &["v=spf1 include:flaky.example -all"])
            .with_failure("flaky.example");
        assert_eq!(check_host(&r, v4("1.2.3.4"), "top.example", "a@x"), SpfResult::TempError);
    }

    #[test]
    fn exceeding_the_lookup_budget_is_permerror_not_infinite_recursion() {
        // A record that includes itself would recurse forever without a guard; the shared lookup
        // budget (and the depth guard) must terminate it as PermError, never hang or panic.
        let r = InMemorySpfResolver::new().with_txt("cyclic.example", &["v=spf1 include:cyclic.example -all"]);
        assert_eq!(check_host(&r, v4("1.2.3.4"), "cyclic.example", "a@x"), SpfResult::PermError);
    }

    #[test]
    fn twelve_includes_in_a_chain_exceeds_the_ten_lookup_ceiling() {
        let mut r = InMemorySpfResolver::new();
        for i in 0..12 {
            let txt = format!("v=spf1 include:next{}.example -all", i + 1);
            r = r.with_txt(&format!("next{i}.example"), &[Box::leak(txt.into_boxed_str())]);
        }
        r = r.with_txt("next12.example", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        assert_eq!(check_host(&r, v4("203.0.113.1"), "next0.example", "a@x"), SpfResult::PermError);
    }

    #[test]
    fn evaluate_falls_back_to_helo_domain_for_null_reverse_path() {
        let r = InMemorySpfResolver::new().with_txt("bounce-mx.example", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        let outcome = evaluate(&r, v4("203.0.113.7"), "<>", Some("bounce-mx.example"));
        assert_eq!(outcome.result, SpfResult::Pass);
        assert_eq!(outcome.domain, "bounce-mx.example");
    }

    #[test]
    fn evaluate_uses_mail_from_domain_when_present() {
        let r = InMemorySpfResolver::new().with_txt("sender.example", &["v=spf1 ip4:203.0.113.0/24 -all"]);
        let outcome = evaluate(&r, v4("203.0.113.7"), "alice@sender.example", Some("irrelevant.example"));
        assert_eq!(outcome.result, SpfResult::Pass);
        assert_eq!(outcome.domain, "sender.example");
    }

    #[test]
    fn unevaluated_outcome_is_the_none_state() {
        let o = SpfOutcome::unevaluated();
        assert_eq!(o.result, SpfResult::None);
        assert!(o.domain.is_empty());
    }

    #[test]
    fn cidr_boundaries() {
        assert!(ipv4_in_cidr(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 0), 24));
        assert!(!ipv4_in_cidr(Ipv4Addr::new(10, 0, 1, 5), Ipv4Addr::new(10, 0, 0, 0), 24));
        assert!(ipv4_in_cidr(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(9, 9, 9, 9), 0), "/0 matches anything");
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(ipv6_in_cidr(a, net, 32));
        let other: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(!ipv6_in_cidr(other, net, 32));
    }
}
