//! Multi-tenant public-gateway mode — the "gateway as a business" surface (spec §7, §7.15.4 `public`).
//!
//! The personal run-mode ([`crate::personal`]) composes the gateway for **one** operator serving
//! **their own** domain. This module lifts that to a real **multi-tenant** gateway that serves
//! **many** domains at once, each an isolated tenant with its own:
//!
//! - **DKIM key + selector** ([`crate::dkim::DkimKey`]) — outbound legacy mail for `d` is signed as
//!   `d` with `d`'s delegated selector; a domain the gateway does not serve is **refused** (§7.3,
//!   fail-closed — never sign for an un-delegated domain).
//! - **Recipient directory** ([`InMemoryDirectory`]) — the inbound `user@d` → DMTAP key mapping.
//! - **Alias registries** — the *same* three address forms the personal gateway has, now keyed per
//!   domain: vanity + key-derived ([`AliasAllocator`], §7.10), random "hide-my-email"
//!   ([`GatewayAliasMap`], §7.10.2), and the stateless forwarded encoding ([`crate::forwarded_addr`],
//!   reused verbatim by callers).
//! - **Per-domain quota + a fail-closed blocklist / user-suspension list**, plus a shared usage
//!   [`GatewayMeter`] ([`UsageMeter`]) the private billing layer (envoir-cloud) reads.
//!
//! Everything is **off by default and fail-closed** (§18.9.11): a fresh [`MultiDomainGateway`] serves
//! **no** domains — every route is [`RouteError::NoSuchDomain`], every DKIM request is refused — until
//! a domain is explicitly added (through the authenticated admin API, [`crate::admin`]). The gateway
//! itself never prices or bills; it only exposes the meter (the OSS/closed split of the two repos).
//!
//! This module is the **model + routing**; [`crate::admin`] is the authenticated control surface that
//! mutates it. The gateway stays stateless in the §7.4 sense (no mail queue); the small amount of
//! state here (which domains, keys, aliases, blocks) is control-plane configuration, re-driven by
//! envoir-cloud on restart, not message durability.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use dmtap_core::TimestampMs;

use crate::alias_map::{AliasTarget, GatewayAliasError, GatewayAliasMap};
use crate::authz::{AliasAllocator, AliasError, Quota, QuotaError, QuotaLedger, Usage};
use crate::directory::InMemoryDirectory;
use crate::dkim::DkimKey;
use crate::inbound::{KeyDirectory, RecipientKey};
use crate::provenance::{BridgeDirection, GatewayMeter, MeterEvent};

/// A fresh CSPRNG 32-byte Ed25519 seed for a newly-provisioned per-domain DKIM key.
fn random_dkim_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS CSPRNG unavailable");
    seed
}

/// Why a multi-domain control operation was refused — every one a hard, fail-closed reject.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MultiDomainError {
    /// The domain is not a syntactically valid DNS domain, so no tenant could be anchored to it.
    #[error("{0:?} is not a valid DNS domain")]
    InvalidDomain(String),
    /// The domain is already served — adding it again would silently clobber its keys/aliases.
    #[error("domain {0:?} is already served by this gateway")]
    DomainExists(String),
    /// No tenant is served for this domain (an operation targeted an unknown domain).
    #[error("domain {0:?} is not served by this gateway")]
    NoSuchDomain(String),
    /// A vanity-alias naming rule was violated (§7.10) — carries the specific [`AliasError`].
    #[error(transparent)]
    Alias(#[from] AliasError),
    /// A supplied DMTAP public key / DKIM seed was not the expected length or encoding.
    #[error("invalid key material: {0}")]
    BadKey(String),
}

/// The resolved destination an inbound `RCPT TO` routed to on a served domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// A directory recipient: the MOTE is sealed to this [`RecipientKey`].
    Directory(RecipientKey),
    /// An alias target (a random "hide-my-email" token or a vanity/key-derived local-part): the
    /// bridge re-routes to this native anchor / identity (§7.10.4).
    Alias(AliasTarget),
}

/// Why an inbound recipient did not route to a deliverable target — each maps to a fail-closed SMTP
/// refusal so a public gateway never becomes an open relay or silently drops mail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteError {
    /// The recipient's domain is not served by this gateway (`550 5.7.1` relaying denied). This is
    /// the default for **every** recipient until a domain is explicitly added.
    #[error("recipient domain not served by this gateway")]
    NoSuchDomain,
    /// The legacy sender is on this domain's (or the global) blocklist (`554 5.7.1`).
    #[error("sender is blocked")]
    SenderBlocked,
    /// The target local user exists but is suspended (`550 5.2.1` mailbox disabled).
    #[error("local user is suspended")]
    UserSuspended,
    /// No directory recipient, live alias, or key-derived address matches (`550 5.1.1` no such user).
    #[error("no such user / unmapped alias")]
    Unmapped,
}

impl RouteError {
    /// The SMTP reply code an MX returns for this refusal (§7.10.3, §21.9).
    pub fn smtp_code(&self) -> u16 {
        match self {
            RouteError::NoSuchDomain => 550,
            RouteError::SenderBlocked => 554,
            RouteError::UserSuspended => 550,
            RouteError::Unmapped => 550,
        }
    }
}

/// One served domain's isolated state (spec §7.15.4 `public`). Not `Clone`/`Debug`-derivable because
/// it owns a [`DkimKey`] (a private signing key); the admin surface only ever mutates it behind the
/// gateway's lock.
pub struct DomainTenant {
    /// The tenant's own domain (lowercased) — the DKIM `d=`, the attestation/alias anchor.
    domain: String,
    /// The delegated DKIM signing key + selector for outbound legacy mail as this domain (§7.3).
    dkim: DkimKey,
    /// The inbound `user@domain` → DMTAP key directory.
    directory: InMemoryDirectory,
    /// Vanity + key-derived local-parts on this domain (§7.10).
    aliases: AliasAllocator,
    /// Random-mode "hide-my-email" alias store (§7.10.2).
    random: GatewayAliasMap,
    /// Legacy senders blocked from reaching this domain (lowercased addresses).
    blocked_senders: HashSet<String>,
    /// Suspended local users (lowercased local-parts): a recipient whose local user is suspended
    /// routes to [`RouteError::UserSuspended`].
    suspended_users: HashSet<String>,
    /// The per-domain relay quota (a ceiling the gateway enforces fail-closed, §12.2). Metering keys
    /// on the domain itself, so this is a per-domain cap and per-domain usage line.
    quota: Quota,
    /// The running quota ledger for this domain (account == the domain).
    ledger: QuotaLedger,
}

impl DomainTenant {
    /// The DKIM public key to publish at `<selector>._domainkey.<domain>` (the `p=` tag) so a
    /// receiving MTA can verify this tenant's outbound signatures. The operator publishes this in DNS.
    pub fn dkim_public_p_tag(&self) -> String {
        self.dkim.public_p_tag()
    }

    /// The DKIM selector this tenant signs with.
    pub fn dkim_selector(&self) -> &str {
        self.dkim.selector()
    }

    /// The tenant's domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Number of directory recipients configured for this domain.
    pub fn recipient_count(&self) -> usize {
        self.directory.len()
    }

    /// The per-domain quota currently in force.
    pub fn quota(&self) -> Quota {
        self.quota
    }

    /// Snapshot of this domain's relay usage so far.
    pub fn usage(&self) -> Usage {
        self.ledger.usage(&self.domain)
    }
}

/// The multi-tenant public gateway: `domain → `[`DomainTenant`], plus a global sender blocklist and a
/// shared usage meter. Fail-closed by construction — an empty gateway serves nobody.
pub struct MultiDomainGateway {
    tenants: HashMap<String, DomainTenant>,
    /// A blocklist applied across **every** domain (a spammer blocked once, blocked everywhere).
    global_blocked: HashSet<String>,
    /// The default per-domain quota a newly-added domain inherits (`Quota::messages(0,0)` ⇒
    /// unlimited) unless the admin overrides it.
    default_quota: Quota,
}

impl Default for MultiDomainGateway {
    fn default() -> Self {
        MultiDomainGateway {
            tenants: HashMap::new(),
            global_blocked: HashSet::new(),
            default_quota: Quota::messages(0, 0),
        }
    }
}

impl MultiDomainGateway {
    /// A fresh gateway that serves **no** domains (the fail-closed default).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default quota applied to domains added afterwards (does not retroactively change
    /// already-served domains; use [`Self::set_domain_quota`] for those).
    pub fn with_default_quota(mut self, quota: Quota) -> Self {
        self.default_quota = quota;
        self
    }

    // ── Domain lifecycle ─────────────────────────────────────────────────────────────────────

    /// Add a served domain with a DKIM key (a freshly generated seed if `dkim_seed` is `None`) under
    /// `selector`. Fail-closed: an invalid domain or one already served is refused. Returns the
    /// 32-byte DKIM seed actually used, so the caller (envoir-cloud) can persist it and re-supply it
    /// on restart (the gateway holds no durable state of its own).
    pub fn add_domain(
        &mut self,
        domain: &str,
        dkim_seed: Option<[u8; 32]>,
        selector: &str,
    ) -> Result<[u8; 32], MultiDomainError> {
        let d = domain.trim().to_ascii_lowercase();
        // Anchoring the alias allocator both validates the domain syntax and gives us the per-domain
        // vanity/key-derived namespace — one construction, one validity check (rule 2, §7.10).
        let aliases = AliasAllocator::for_domain(&d)
            .map_err(|_| MultiDomainError::InvalidDomain(domain.to_string()))?;
        if self.tenants.contains_key(&d) {
            return Err(MultiDomainError::DomainExists(d));
        }
        let selector = {
            let s = selector.trim();
            if s.is_empty() {
                "gw1".to_string()
            } else {
                s.to_string()
            }
        };
        let seed = dkim_seed.unwrap_or_else(random_dkim_seed);
        let dkim = DkimKey::from_seed(d.clone(), selector, &seed);
        let quota = self.default_quota;
        let mut ledger = QuotaLedger::new();
        ledger.upsert_quota(d.clone(), quota);
        let tenant = DomainTenant {
            domain: d.clone(),
            dkim,
            directory: InMemoryDirectory::new(),
            aliases,
            random: GatewayAliasMap::new(),
            blocked_senders: HashSet::new(),
            suspended_users: HashSet::new(),
            quota,
            ledger,
        };
        self.tenants.insert(d, tenant);
        Ok(seed)
    }

    /// Stop serving `domain`, dropping its keys and aliases. Returns whether a tenant existed.
    pub fn remove_domain(&mut self, domain: &str) -> bool {
        self.tenants.remove(&domain.trim().to_ascii_lowercase()).is_some()
    }

    /// Whether `domain` is currently served.
    pub fn serves(&self, domain: &str) -> bool {
        self.tenants.contains_key(&domain.trim().to_ascii_lowercase())
    }

    /// The served domains (lowercased), sorted for a stable admin listing.
    pub fn domains(&self) -> Vec<String> {
        let mut v: Vec<String> = self.tenants.keys().cloned().collect();
        v.sort();
        v
    }

    /// Immutable access to a served tenant.
    pub fn tenant(&self, domain: &str) -> Option<&DomainTenant> {
        self.tenants.get(&domain.trim().to_ascii_lowercase())
    }

    fn tenant_mut(&mut self, domain: &str) -> Result<&mut DomainTenant, MultiDomainError> {
        let d = domain.trim().to_ascii_lowercase();
        self.tenants.get_mut(&d).ok_or(MultiDomainError::NoSuchDomain(d))
    }

    // ── Recipients (per-domain directory) ────────────────────────────────────────────────────

    /// Add (or replace) a directory recipient `email` → `key` on its domain. The local-part is also
    /// reserved in the domain's alias allocator so a vanity can never shadow a real recipient (§7.10
    /// rule 5). Fail-closed: the email MUST be on a served domain.
    pub fn add_recipient(
        &mut self,
        email: &str,
        key: RecipientKey,
    ) -> Result<(), MultiDomainError> {
        let (_, domain) = split_address(email)
            .ok_or_else(|| MultiDomainError::InvalidDomain(email.to_string()))?;
        let tenant = self.tenant_mut(&domain)?;
        tenant.directory.insert(email, key);
        tenant.aliases.reserve_directory_address(email);
        Ok(())
    }

    /// Remove a directory recipient by full address. Returns whether one existed. (The alias
    /// reservation is left in place — a freed local-part is not auto-released to a vanity grab.)
    pub fn remove_recipient(&mut self, email: &str) -> Result<bool, MultiDomainError> {
        let (_, domain) = split_address(email)
            .ok_or_else(|| MultiDomainError::InvalidDomain(email.to_string()))?;
        let tenant = self.tenant_mut(&domain)?;
        Ok(tenant.directory.remove(email))
    }

    // ── Aliases (vanity + random) ────────────────────────────────────────────────────────────

    /// Allocate a vanity local-part for `public_key` on `domain`, returning the bound
    /// fully-qualified `vanity@domain` (§7.10). Every naming rule is enforced fail-closed.
    pub fn allocate_vanity(
        &mut self,
        domain: &str,
        public_key: &[u8],
        local_part: &str,
    ) -> Result<String, MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        Ok(tenant.aliases.allocate_vanity(public_key, local_part)?)
    }

    /// Revoke the vanity currently held by `public_key` on `domain` (§7.10 rule 4, revocable).
    /// Returns the freed fully-qualified address, or `None` if the key held no vanity.
    pub fn revoke_vanity(
        &mut self,
        domain: &str,
        public_key: &[u8],
    ) -> Result<Option<String>, MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        Ok(tenant.aliases.release_vanity(public_key))
    }

    /// Mint a random "hide-my-email" alias on `domain` bound to `target`, returning the opaque
    /// `token@domain`. Optional single-correspondent scope, TTL, and one-time burn (§7.10.2).
    #[allow(clippy::too_many_arguments)]
    pub fn mint_random_alias(
        &mut self,
        domain: &str,
        target: AliasTarget,
        correspondent: Option<String>,
        ttl_ms: Option<u64>,
        one_time: bool,
        now_ms: u64,
    ) -> Result<String, MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        let token = tenant.random.mint_with(target, correspondent, ttl_ms, one_time, now_ms);
        Ok(format!("{token}@{}", tenant.domain))
    }

    /// Burn (revoke) a random alias `token` on `domain` (§7.10.4). Returns whether a row existed.
    pub fn burn_random_alias(
        &mut self,
        domain: &str,
        token: &str,
    ) -> Result<bool, MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        // Accept either the bare token or the fully-qualified `token@domain`.
        let local = token.rsplit_once('@').map(|(l, _)| l).unwrap_or(token);
        Ok(tenant.random.burn(local))
    }

    // ── Blocklist + user suspension ──────────────────────────────────────────────────────────

    /// Block a legacy `sender` on `domain` (per-domain). Idempotent.
    pub fn block_sender(&mut self, domain: &str, sender: &str) -> Result<(), MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        tenant.blocked_senders.insert(sender.trim().to_ascii_lowercase());
        Ok(())
    }

    /// Unblock a legacy `sender` on `domain`. Returns whether it was blocked.
    pub fn unblock_sender(&mut self, domain: &str, sender: &str) -> Result<bool, MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        Ok(tenant.blocked_senders.remove(&sender.trim().to_ascii_lowercase()))
    }

    /// Block a legacy `sender` across **every** served domain (global blocklist). Idempotent.
    pub fn block_sender_global(&mut self, sender: &str) {
        self.global_blocked.insert(sender.trim().to_ascii_lowercase());
    }

    /// Remove a sender from the global blocklist. Returns whether it was present.
    pub fn unblock_sender_global(&mut self, sender: &str) -> bool {
        self.global_blocked.remove(&sender.trim().to_ascii_lowercase())
    }

    /// Suspend a local `user` on `domain` (a local-part or full address; only the local-part is
    /// keyed). A suspended user's inbound mail routes to [`RouteError::UserSuspended`]. Idempotent.
    pub fn suspend_user(&mut self, domain: &str, user: &str) -> Result<(), MultiDomainError> {
        let local = local_part_of(user).to_ascii_lowercase();
        let tenant = self.tenant_mut(domain)?;
        tenant.suspended_users.insert(local);
        Ok(())
    }

    /// Reinstate a suspended local `user` on `domain`. Returns whether it was suspended.
    pub fn unsuspend_user(&mut self, domain: &str, user: &str) -> Result<bool, MultiDomainError> {
        let local = local_part_of(user).to_ascii_lowercase();
        let tenant = self.tenant_mut(domain)?;
        Ok(tenant.suspended_users.remove(&local))
    }

    // ── Quota ────────────────────────────────────────────────────────────────────────────────

    /// Set the per-domain relay quota for `domain` (applied to its ledger immediately).
    pub fn set_domain_quota(&mut self, domain: &str, quota: Quota) -> Result<(), MultiDomainError> {
        let tenant = self.tenant_mut(domain)?;
        tenant.quota = quota;
        tenant.ledger.upsert_quota(tenant.domain.clone(), quota);
        Ok(())
    }

    // ── Routing (inbound) ────────────────────────────────────────────────────────────────────

    /// Route an inbound legacy `RCPT TO` (`rcpt`) from legacy `sender` at `now_ms`, applying the full
    /// fail-closed policy in order: unknown domain → blocklist (global then per-domain) → user
    /// suspension → directory → random alias → vanity/key-derived alias → unmapped. A public gateway
    /// that has added no domain routes **every** recipient to [`RouteError::NoSuchDomain`].
    pub fn route(
        &mut self,
        sender: &str,
        rcpt: &str,
        now_ms: u64,
    ) -> Result<Recipient, RouteError> {
        let (local, domain) = split_address(rcpt).ok_or(RouteError::NoSuchDomain)?;
        // Global blocklist is checked before we borrow the tenant mutably (no borrow conflict).
        if self.global_blocked.contains(&sender.trim().to_ascii_lowercase()) {
            return Err(RouteError::SenderBlocked);
        }
        let tenant = self.tenants.get_mut(&domain).ok_or(RouteError::NoSuchDomain)?;
        if tenant.blocked_senders.contains(&sender.trim().to_ascii_lowercase()) {
            return Err(RouteError::SenderBlocked);
        }
        if tenant.suspended_users.contains(&local) {
            return Err(RouteError::UserSuspended);
        }
        // Resolve against the NORMALIZED `local@domain` (angle brackets stripped, lowercased) so a
        // raw `<Alice@Host.Net>` from `RCPT TO` matches the same way everywhere.
        let clean = format!("{local}@{domain}");
        // 1. A directory recipient (the common case).
        if let Some(key) = tenant.directory.resolve(&clean) {
            return Ok(Recipient::Directory(key));
        }
        // 2. A random "hide-my-email" token (the local-part IS the opaque token).
        match tenant.random.resolve(&local, now_ms) {
            Ok(target) => return Ok(Recipient::Alias(target)),
            Err(GatewayAliasError::Unmapped) => { /* fall through to vanity/key-derived */ }
        }
        // 3. A vanity or key-derived alias on this domain, resolved against the directory's keys.
        let registered: Vec<Vec<u8>> = tenant.directory.iter().map(|(_, k)| k.ik.clone()).collect();
        if let Some(pk) = tenant.aliases.resolve(&clean, &registered) {
            return Ok(Recipient::Alias(AliasTarget::Identity(pk)));
        }
        Err(RouteError::Unmapped)
    }

    // ── DKIM (outbound) ──────────────────────────────────────────────────────────────────────

    /// Sign `message` as DKIM for `domain` at time `t` (seconds since epoch), returning the
    /// `DKIM-Signature:` header, or `None` (fail-closed refusal) if `domain` is not served — the
    /// gateway never signs for a domain it is not delegated for (§7.3).
    pub fn dkim_sign(&self, domain: &str, message: &[u8], t: u64) -> Option<String> {
        let tenant = self.tenant(domain)?;
        Some(crate::dkim::sign(&tenant.dkim, message, t))
    }

    // ── Metering / quota charge ──────────────────────────────────────────────────────────────

    /// Charge one relayed message of `rfc5322_bytes` against `domain`'s quota and, on success, emit
    /// the billable [`MeterEvent`] through `meter` (§12.6). Fail-closed: an unserved domain or a
    /// quota-exceeding relay is refused and **nothing** is metered. The metering account is the
    /// domain itself (a per-domain usage line the private billing layer reads).
    pub fn charge_relay(
        &self,
        domain: &str,
        direction: BridgeDirection,
        rfc5322_bytes: &[u8],
        at: TimestampMs,
        meter: &dyn GatewayMeter,
    ) -> Result<Usage, ChargeError> {
        let tenant =
            self.tenant(domain).ok_or_else(|| ChargeError::NoSuchDomain(domain.to_string()))?;
        tenant
            .ledger
            .charge_and_meter(&tenant.domain, &tenant.domain, direction, rfc5322_bytes, at, meter)
            .map_err(ChargeError::Quota)
    }
}

/// Why a relay charge was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChargeError {
    /// The domain is not served — an unserved domain can never relay (fail-closed).
    #[error("domain {0:?} is not served by this gateway")]
    NoSuchDomain(String),
    /// The per-domain quota would be exceeded.
    #[error(transparent)]
    Quota(QuotaError),
}

// ── Usage meter (the GatewayMeter the private billing layer reads) ───────────────────────────

/// Per-domain aggregated relay usage, the read model the admin `usage` endpoint returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainUsage {
    /// Inbound (legacy → mesh) relays metered for this domain.
    pub inbound: u64,
    /// Outbound (mesh → legacy) relays metered for this domain.
    pub outbound: u64,
    /// Total relayed messages (inbound + outbound).
    pub messages: u64,
}

/// A thread-safe, cloneable [`GatewayMeter`] that aggregates relay events per domain and exposes a
/// read snapshot — the concrete meter a running multi-tenant gateway hands its bridge, and the one
/// the admin `usage` endpoint reads. Unlike [`crate::provenance::CountingMeter`] (which uses `Rc` and
/// is single-threaded), this shares an `Arc<Mutex<…>>` so the accept-loop threads and the admin API
/// observe the same counters. The gateway still never prices — this is a read model for the external
/// (private) billing layer (§12.6).
#[derive(Debug, Default, Clone)]
pub struct UsageMeter {
    inner: Arc<Mutex<HashMap<String, DomainUsage>>>,
}

impl UsageMeter {
    /// A fresh, empty meter.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current usage for one domain (`0/0/0` if it has relayed nothing).
    pub fn usage(&self, domain: &str) -> DomainUsage {
        self.inner
            .lock()
            .expect("usage meter poisoned")
            .get(&domain.trim().to_ascii_lowercase())
            .copied()
            .unwrap_or_default()
    }

    /// A snapshot of every domain's usage, sorted by domain for a stable admin listing.
    pub fn snapshot(&self) -> Vec<(String, DomainUsage)> {
        let map = self.inner.lock().expect("usage meter poisoned");
        let mut v: Vec<(String, DomainUsage)> = map.iter().map(|(d, u)| (d.clone(), *u)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

impl GatewayMeter for UsageMeter {
    fn record(&self, event: &MeterEvent) {
        let mut map = self.inner.lock().expect("usage meter poisoned");
        let entry = map.entry(event.domain.to_ascii_lowercase()).or_default();
        match event.direction {
            BridgeDirection::Inbound => entry.inbound += 1,
            BridgeDirection::Outbound => entry.outbound += 1,
        }
        entry.messages += 1;
    }
}

// ── address helpers ───────────────────────────────────────────────────────────────────────────

/// Split `addr` into `(lowercased local-part, lowercased domain)`, or `None` if there is no `@` or
/// either side is empty. Angle brackets are stripped so a raw `<a@b>` from `RCPT TO` parses.
fn split_address(addr: &str) -> Option<(String, String)> {
    let a = addr.trim().trim_start_matches('<').trim_end_matches('>').trim();
    let (local, domain) = a.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some((local.to_ascii_lowercase(), domain.to_ascii_lowercase()))
}

/// The local-part of an address (everything before the last `@`), or the whole string if there is no
/// `@` (so `suspend_user("alice")` and `suspend_user("alice@d")` key the same local user).
fn local_part_of(user: &str) -> &str {
    let u = user.trim();
    u.rsplit_once('@').map(|(l, _)| l).unwrap_or(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::identity::IdentityKey;

    fn rkey(tag: u8) -> RecipientKey {
        RecipientKey { ik: vec![tag; 32], seal_pub: vec![tag.wrapping_add(1); 32] }
    }

    #[test]
    fn fresh_gateway_serves_nobody_fail_closed() {
        let mut gw = MultiDomainGateway::new();
        assert!(gw.domains().is_empty());
        // Every route is NoSuchDomain until a domain is added.
        assert_eq!(gw.route("a@gmail.com", "you@host.net", 0), Err(RouteError::NoSuchDomain));
        // DKIM refuses to sign for an unserved domain (never an open signer).
        assert!(gw.dkim_sign("host.net", b"From: a@b\r\n\r\nx", 0).is_none());
    }

    #[test]
    fn add_domain_is_fail_closed_on_invalid_and_duplicate() {
        let mut gw = MultiDomainGateway::new();
        assert!(gw.add_domain("host.net", None, "gw1").is_ok());
        assert!(gw.serves("HOST.NET"), "domain match is case-insensitive");
        // Duplicate is refused (no silent clobber of keys/aliases).
        assert!(matches!(
            gw.add_domain("host.net", None, "gw1"),
            Err(MultiDomainError::DomainExists(_))
        ));
        // A syntactically invalid domain is refused.
        assert!(matches!(
            gw.add_domain("not a domain", None, "gw1"),
            Err(MultiDomainError::InvalidDomain(_))
        ));
    }

    #[test]
    fn add_domain_returns_a_usable_dkim_key_and_signs_only_served_domains() {
        let mut gw = MultiDomainGateway::new();
        let seed = gw.add_domain("host.net", None, "sel9").unwrap();
        // Re-adding with the SAME seed (after removal) yields the same publishable public key —
        // the seed round-trips, so envoir-cloud can persist and re-supply it on restart.
        let pub1 = gw.tenant("host.net").unwrap().dkim_public_p_tag();
        gw.remove_domain("host.net");
        gw.add_domain("host.net", Some(seed), "sel9").unwrap();
        assert_eq!(gw.tenant("host.net").unwrap().dkim_public_p_tag(), pub1);
        assert_eq!(gw.tenant("host.net").unwrap().dkim_selector(), "sel9");

        // A real, verifiable signature is produced for the served domain and refused for another.
        let msg = b"From: user@host.net\r\nSubject: hi\r\n\r\nbody\r\n";
        let sig = gw.dkim_sign("host.net", msg, 1_700_000_000).expect("served domain signs");
        assert!(sig.starts_with("DKIM-Signature:"));
        assert!(gw.dkim_sign("other.net", msg, 1_700_000_000).is_none());
    }

    #[test]
    fn routes_directory_recipient_and_unmapped_fail_closed() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("host.net", None, "gw1").unwrap();
        gw.add_recipient("alice@host.net", rkey(1)).unwrap();

        assert_eq!(
            gw.route("bob@gmail.com", "alice@host.net", 0),
            Ok(Recipient::Directory(rkey(1)))
        );
        // Case-insensitive + angle brackets.
        assert_eq!(
            gw.route("bob@gmail.com", "<ALICE@HOST.NET>", 0),
            Ok(Recipient::Directory(rkey(1)))
        );
        // Unknown local user on a served domain is Unmapped (not NoSuchDomain).
        assert_eq!(gw.route("bob@gmail.com", "ghost@host.net", 0), Err(RouteError::Unmapped));
        // Adding a recipient to an unserved domain is refused.
        assert!(gw.add_recipient("x@nope.net", rkey(2)).is_err());
    }

    #[test]
    fn per_domain_isolation_directory_and_vanity_and_blocklist() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("a.com", None, "gw1").unwrap();
        gw.add_domain("b.com", None, "gw1").unwrap();
        let ka = IdentityKey::generate().public();
        let kb = IdentityKey::generate().public();

        // Same vanity "hello" on both domains resolves to DIFFERENT keys (isolation).
        assert_eq!(gw.allocate_vanity("a.com", &ka, "hello").unwrap(), "hello@a.com");
        assert_eq!(gw.allocate_vanity("b.com", &kb, "hello").unwrap(), "hello@b.com");
        assert_eq!(
            gw.route("s@x.net", "hello@a.com", 0),
            Ok(Recipient::Alias(AliasTarget::Identity(ka.clone())))
        );
        assert_eq!(
            gw.route("s@x.net", "hello@b.com", 0),
            Ok(Recipient::Alias(AliasTarget::Identity(kb.clone())))
        );

        // Blocking a sender on a.com does NOT block it on b.com (per-domain).
        gw.block_sender("a.com", "spammer@evil.net").unwrap();
        assert_eq!(gw.route("spammer@evil.net", "hello@a.com", 0), Err(RouteError::SenderBlocked));
        assert_eq!(
            gw.route("spammer@evil.net", "hello@b.com", 0),
            Ok(Recipient::Alias(AliasTarget::Identity(kb)))
        );

        // A global block hits every domain.
        gw.block_sender_global("spammer@evil.net");
        assert_eq!(gw.route("spammer@evil.net", "hello@b.com", 0), Err(RouteError::SenderBlocked));
    }

    #[test]
    fn vanity_cannot_shadow_a_directory_recipient() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("host.net", None, "gw1").unwrap();
        gw.add_recipient("alice@host.net", rkey(1)).unwrap();
        let other = IdentityKey::generate().public();
        // "alice" is reserved by the directory recipient → a vanity for it is refused (rule 5).
        assert!(matches!(
            gw.allocate_vanity("host.net", &other, "alice"),
            Err(MultiDomainError::Alias(AliasError::ShadowsDirectoryIdentity(_)))
        ));
    }

    #[test]
    fn random_alias_lifecycle_and_isolation() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("a.com", None, "gw1").unwrap();
        gw.add_domain("b.com", None, "gw1").unwrap();
        let target = AliasTarget::Native { local: "imran".into(), domain: "native.com".into() };
        let fq = gw.mint_random_alias("a.com", target.clone(), None, None, false, 0).unwrap();
        assert!(fq.ends_with("@a.com"));
        let token = fq.rsplit_once('@').unwrap().0.to_string();

        // Resolves on a.com...
        assert_eq!(gw.route("s@x.net", &fq, 0), Ok(Recipient::Alias(target)));
        // ...but the SAME token does NOT resolve on b.com (per-domain store isolation).
        assert_eq!(gw.route("s@x.net", &format!("{token}@b.com"), 0), Err(RouteError::Unmapped));
        // Burning it (by fq or bare token) makes it Unmapped fail-closed.
        assert!(gw.burn_random_alias("a.com", &fq).unwrap());
        assert_eq!(gw.route("s@x.net", &fq, 0), Err(RouteError::Unmapped));
    }

    #[test]
    fn suspended_user_routes_to_suspended_not_delivered() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("host.net", None, "gw1").unwrap();
        gw.add_recipient("alice@host.net", rkey(1)).unwrap();
        gw.suspend_user("host.net", "alice").unwrap();
        assert_eq!(gw.route("s@x.net", "alice@host.net", 0), Err(RouteError::UserSuspended));
        // Reinstating restores delivery.
        assert!(gw.unsuspend_user("host.net", "alice@host.net").unwrap());
        assert_eq!(gw.route("s@x.net", "alice@host.net", 0), Ok(Recipient::Directory(rkey(1))));
    }

    #[test]
    fn per_domain_quota_is_enforced_and_metered_fail_closed() {
        let mut gw = MultiDomainGateway::new();
        gw.add_domain("host.net", None, "gw1").unwrap();
        gw.set_domain_quota("host.net", Quota::messages(1, 2)).unwrap();
        let meter = UsageMeter::new();
        let msg = b"From: a@gmail.com\r\n\r\nbody\r\n";

        // Two relays fit under the cap of 2, each meters once.
        assert!(gw.charge_relay("host.net", BridgeDirection::Inbound, msg, 1, &meter).is_ok());
        assert!(gw.charge_relay("host.net", BridgeDirection::Inbound, msg, 2, &meter).is_ok());
        // The third exceeds the hard cap → refused, and NOTHING extra is metered.
        assert!(matches!(
            gw.charge_relay("host.net", BridgeDirection::Inbound, msg, 3, &meter),
            Err(ChargeError::Quota(_))
        ));
        assert_eq!(meter.usage("host.net").messages, 2);
        assert_eq!(meter.usage("host.net").inbound, 2);

        // Charging an unserved domain is fail-closed and meters nothing.
        assert!(matches!(
            gw.charge_relay("nope.net", BridgeDirection::Outbound, msg, 4, &meter),
            Err(ChargeError::NoSuchDomain(_))
        ));
        assert_eq!(meter.snapshot().len(), 1);
    }
}
