//! Gateway admission, quota, and local-part allocation — spec §7.9, §7.10, §9, §12.2.
//!
//! [`crate::provenance`] defines the *seams* — the [`GatewayAuthz`] policy trait, the
//! [`GatewayMeter`] billing seam, and the [`Bridge`] that ties authz+attestation+metering. This
//! module makes the **operator-facing policy** real on top of those seams, all in OSS (the gateway
//! never prices or bills — it only exposes the meter):
//!
//! - **Authorization modes** ([`AuthzMode`]): an operator runs the gateway either as an
//!   **open-public** relay (anyone may relay — a spam magnet, documented below, **not** the default)
//!   or in **key-registered** mode (the default), where a sender is admitted only after proving
//!   control of a registered DMTAP key by a challenge–response ([`IdentityRegistry::admit`], reusing
//!   `dmtap-core` Ed25519 sign/verify). [`IdentityRegistry`] also implements [`GatewayAuthz`], so it
//!   drops straight into a [`Bridge`] as the per-message policy gate.
//! - **Quota + usage tracking** ([`QuotaLedger`]): a per-registered-identity free allowance plus a
//!   **hard cap**, counted in-crate (messages **and** bytes). When the cap is hit the ledger
//!   **refuses fail-closed** (a normal gateway refusal) and records nothing; on an admitted charge it
//!   emits the usage through the [`GatewayMeter`] seam for the external billing layer to read. The
//!   gateway itself never turns usage into money.
//! - **Vanity local-parts** ([`AliasAllocator`], §7.10): the operator may allocate a chosen
//!   local-part for a registered key, while the **key-derived alias** ([`key_derived_localpart`])
//!   remains the stable default that always resolves — a vanity name is opt-in sugar on top of it,
//!   and collisions are refused fail-closed. The allocator **enforces the normative naming rules**:
//!   a vanity is dot-free (dotted local-parts are reserved for [`crate::forwarded_addr`]), is only
//!   ever meaningful **fully-qualified** as `vanity@<gatewaydomain>` (never a bare, un-anchored
//!   handle — the flat-namespace-consensus problem DMTAP does not solve), may not shadow the
//!   auto-derived namespace ([`RESERVED_ALIAS_PREFIX`] / a key-derived shape) nor an operator
//!   directory identity on the same domain, is **first-come + revocable**, and must pass basic
//!   hygiene. Every failure is a hard, fail-closed reject — the allocator never silently normalizes.
//!
//! Deterministic throughout: challenge freshness takes the clock as an explicit parameter and the
//! nonce is supplied by the caller (production draws it from the OS CSPRNG via [`random_nonce`]), so
//! the whole flow is exercised without a wall clock.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use dmtap_core::identity::verify_domain;
use dmtap_core::{ContentId, TimestampMs};

use crate::provenance::{
    AuthzDecision, BridgeDirection, GatewayAuthz, GatewayMeter, MeterEvent,
};

// ── Authorization modes (§7.9, §12.2) ─────────────────────────────────────────────────────────

/// How the operator admits senders to this gateway (§7.9).
///
/// The default is [`AuthzMode::KeyRegistered`]. **[`AuthzMode::OpenPublic`] is a spam magnet**: an
/// open outbound relay is what gets a gateway's IP blacklisted and an open inbound relay drowns its
/// recipients — run it only on a trusted, firewalled network segment, never on the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzMode {
    /// Anyone may relay — no key proof required. A documented spam risk; not the default.
    OpenPublic,
    /// A sender must prove control of a **registered** DMTAP key (challenge–response) to be admitted.
    /// The safe default.
    KeyRegistered,
}

impl Default for AuthzMode {
    fn default() -> Self {
        AuthzMode::KeyRegistered
    }
}

// ── Challenge–response admission (§9, DMTAP-Auth style) ────────────────────────────────────────

/// Domain-separation label for the admission challenge signature (§18.1.6 style): a distinct tag so
/// a signature proving key-control for gateway admission can never be replayed as any other DMTAP
/// object (an attestation, an identity op, …).
///
/// Public (like `dmtap_auth::AUTH_ASSERTION_DS`) so a legitimate sender — or a downstream
/// integration test — can produce an admission signature the gateway will accept without
/// hand-copying an internal byte string. Exposing the tag grants no authority: admission still
/// requires control of the DMTAP key that signs [`Challenge::signing_body`].
pub const ADMISSION_DS: &[u8] = b"DMTAP-v0/gateway-admission\x00";

/// A single-use admission challenge the gateway hands a connecting sender (§9 cost-for-cold-contact,
/// DMTAP-Auth handshake). The sender proves control of its DMTAP key by signing [`Self::signing_body`]
/// under [`ADMISSION_DS`]; the gateway verifies with `dmtap-core`'s Ed25519 [`verify_domain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// A fresh random nonce (anti-replay). Production draws it from the OS CSPRNG ([`random_nonce`]);
    /// tests supply a fixed value for determinism.
    pub nonce: [u8; 32],
    /// When the gateway issued the challenge (ms since epoch) — bounds its validity window.
    pub issued_at: TimestampMs,
}

impl Challenge {
    /// Create a challenge from an explicit nonce + issue time (deterministic; the clock is a
    /// parameter). Production calls `Challenge::new(random_nonce(), clock.now_ms())`.
    pub fn new(nonce: [u8; 32], issued_at: TimestampMs) -> Self {
        Challenge { nonce, issued_at }
    }

    /// The exact bytes a sender signs to prove key control: `nonce ‖ issued_at` (big-endian). Binding
    /// `issued_at` in means a signature for one challenge cannot be lifted onto a differently-timed one.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 8);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b
    }
}

/// Draw a fresh 32-byte admission nonce from the OS CSPRNG. Used only in production issuance; tests
/// pass a fixed nonce so the flow stays deterministic.
pub fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).expect("OS CSPRNG unavailable");
    n
}

/// A registered sender identity: the DMTAP public key that authenticates it, plus the billing
/// `account` and self-hosted `domain` the operator bound to it, and its [`Quota`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredIdentity {
    /// The Ed25519 DMTAP public key the sender proves control of (the admission credential).
    pub public_key: Vec<u8>,
    /// The billing subject metered against (§12.2 accountable token).
    pub account: String,
    /// The self-hosted domain this identity relays for.
    pub domain: String,
    /// The identity's free-allowance + hard-cap quota (§12.2).
    pub quota: Quota,
}

/// The result of admitting a sender: the resolved billing `account`, its `domain`, and the proven
/// `public_key`. A caller uses `account` to key quota and metering for the rest of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// The billing subject this admitted sender is metered against.
    pub account: String,
    /// The self-hosted domain the sender relays for (empty in open-public mode for an unregistered key).
    pub domain: String,
    /// The DMTAP public key the sender proved control of.
    pub public_key: Vec<u8>,
}

/// Why an admission attempt was refused — every one is a hard, fail-closed reject (§18.9.11).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// The challenge is older than the validity window (or future-dated) — replay/skew guard.
    #[error("admission challenge expired or not yet valid")]
    ChallengeExpired,
    /// The signature does not verify under the presented key: the sender does not control it (forged).
    #[error("admission signature does not prove control of the presented key")]
    BadSignature,
    /// Key-registered mode: the presented key is not on the operator's registry.
    #[error("presented key is not registered with this gateway")]
    UnknownKey,
    /// The presented challenge nonce was never issued by this gateway, or has already been consumed
    /// by a prior admission. Admission challenges are **single-use** (§9): a captured
    /// `(nonce, issued_at, key, sig)` tuple cannot be replayed, because the nonce is gone after the
    /// first admission and an un-issued nonce was never admissible to begin with.
    #[error("admission challenge was not issued by this gateway or has already been consumed")]
    UnknownOrConsumedChallenge,
}

/// The registry of admitted identities and the operator's [`AuthzMode`] (§7.9). It performs the
/// challenge–response admission ([`Self::admit`]) and also implements [`GatewayAuthz`] so it can be
/// the per-message policy gate inside a [`Bridge`]. Fail-closed by construction: in the default
/// key-registered mode an unknown key or a bad signature is refused.
#[derive(Debug, Clone)]
pub struct IdentityRegistry {
    mode: AuthzMode,
    challenge_ttl_ms: u64,
    entries: Vec<RegisteredIdentity>,
    /// The ledger of challenge nonces this gateway has **issued and not yet consumed** (nonce →
    /// issue time). [`Self::admit`] consumes-and-removes the presented nonce, so a challenge admits
    /// exactly once (§9, single-use): a replayed or never-issued nonce fails closed. Wrapped in an
    /// `Arc<Mutex<…>>` so the authoritative consumed-nonce set is shared across clones and updatable
    /// through the `&self` issue/admit calls.
    issued_nonces: Arc<Mutex<HashMap<[u8; 32], TimestampMs>>>,
}

impl IdentityRegistry {
    /// A key-registered registry (the safe default) with a 5-minute challenge validity window.
    pub fn key_registered() -> Self {
        IdentityRegistry {
            mode: AuthzMode::KeyRegistered,
            challenge_ttl_ms: 300_000,
            entries: Vec::new(),
            issued_nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// An **open-public** relay registry (documented spam risk — see [`AuthzMode`]). Still runs the
    /// challenge–response (so an admitted account is bound to a proven key), but does not require the
    /// key to be pre-registered.
    pub fn open_public() -> Self {
        IdentityRegistry {
            mode: AuthzMode::OpenPublic,
            challenge_ttl_ms: 300_000,
            entries: Vec::new(),
            issued_nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The operator's admission mode.
    pub fn mode(&self) -> AuthzMode {
        self.mode
    }

    /// Override the challenge validity window (ms).
    pub fn with_challenge_ttl(mut self, ttl_ms: u64) -> Self {
        self.challenge_ttl_ms = ttl_ms;
        self
    }

    /// Register an identity (its key → account/domain/quota). Re-registering the same key replaces
    /// the prior entry.
    pub fn register(mut self, identity: RegisteredIdentity) -> Self {
        self.entries.retain(|e| e.public_key != identity.public_key);
        self.entries.push(identity);
        self
    }

    /// Look up a registered identity by its public key.
    pub fn identity_for_key(&self, public_key: &[u8]) -> Option<&RegisteredIdentity> {
        self.entries.iter().find(|e| e.public_key == public_key)
    }

    /// Look up a registered identity by its self-hosted domain (case-insensitive).
    pub fn identity_for_domain(&self, domain: &str) -> Option<&RegisteredIdentity> {
        self.entries.iter().find(|e| e.domain.eq_ignore_ascii_case(domain))
    }

    /// Issue a challenge for a connecting sender (deterministic: nonce + issue time are parameters).
    /// The gateway **records** the issued nonce so [`Self::admit`] can verify it is one we minted and
    /// consume it single-use. Expired issued nonces (older than the freshness window at this issuance)
    /// are pruned so the ledger cannot grow without bound.
    pub fn issue_challenge(&self, nonce: [u8; 32], issued_at: TimestampMs) -> Challenge {
        let mut issued = self.issued_nonces.lock().expect("gateway nonce ledger poisoned");
        let cutoff = issued_at.saturating_sub(self.challenge_ttl_ms);
        issued.retain(|_, &mut t| t >= cutoff);
        issued.insert(nonce, issued_at);
        Challenge::new(nonce, issued_at)
    }

    /// The gateway's own record of when it issued `nonce` (a non-consuming peek), or `None` if the
    /// nonce was never issued or has already been spent. [`Self::admit`] uses this **authoritative**
    /// issue time — not the client-presented one — for the freshness window, so a sender cannot widen
    /// its own validity window by presenting a later `issued_at` (defense-in-depth on top of the
    /// signature, which already binds `issued_at`).
    fn peek_issued_at(&self, nonce: &[u8; 32]) -> Option<TimestampMs> {
        self.issued_nonces.lock().expect("gateway nonce ledger poisoned").get(nonce).copied()
    }

    /// Consume a single-use admission nonce. **Fail-closed** with
    /// [`AdmissionError::UnknownOrConsumedChallenge`] if the nonce was never issued, was already
    /// spent, **or** the client-presented `presented_issued_at` does not EQUAL the issue time the
    /// gateway recorded at issuance. Binding the presented issue time to the stored one closes an
    /// admission defense-in-depth gap: the nonce is only removed on an exact match, so a mismatched
    /// tuple is rejected without burning the live challenge. Returns the gateway's stored issue time
    /// on success. This is the anti-replay gate.
    fn consume_nonce(
        &self,
        nonce: &[u8; 32],
        presented_issued_at: TimestampMs,
    ) -> Result<TimestampMs, AdmissionError> {
        let mut issued = self.issued_nonces.lock().expect("gateway nonce ledger poisoned");
        match issued.get(nonce).copied() {
            // Only spend the nonce when the presented issue time matches what we stored at issuance.
            Some(stored) if stored == presented_issued_at => {
                issued.remove(nonce);
                Ok(stored)
            }
            // Never issued, already consumed, or a mismatched issued_at → reject, do NOT remove.
            _ => Err(AdmissionError::UnknownOrConsumedChallenge),
        }
    }

    /// Admit a sender that answered `challenge` by signing it with the private half of `presented_key`
    /// (§9, DMTAP-Auth). `now` is the current time (clock as a parameter). **Fail-closed**:
    ///
    /// - a stale or future-dated challenge → [`AdmissionError::ChallengeExpired`],
    /// - a signature that does not verify under the presented key → [`AdmissionError::BadSignature`]
    ///   (this is the forged-key rejection),
    /// - a nonce this gateway never issued, or one already spent by a prior admission →
    ///   [`AdmissionError::UnknownOrConsumedChallenge`] (single-use anti-replay),
    /// - key-registered mode with an unregistered key → [`AdmissionError::UnknownKey`].
    ///
    /// In open-public mode an unregistered but key-controlling sender is admitted with a
    /// key-derived account label and an empty domain.
    ///
    /// The single-use nonce is consumed **only on the success path** — after freshness, signature,
    /// and mode policy have all passed — so a forged-signature or unknown-key attempt cannot burn a
    /// legitimate sender's live challenge.
    pub fn admit(
        &self,
        challenge: &Challenge,
        presented_key: &[u8],
        sig: &[u8],
        now: TimestampMs,
    ) -> Result<Admission, AdmissionError> {
        // Freshness first (cheap, secondary replay bound) — reject stale and clock-skew-future
        // challenges. Prefer the gateway's OWN recorded issue time for this nonce over the
        // client-presented `challenge.issued_at`: a sender must not be able to stretch its validity
        // window by presenting a later timestamp. When we have no record (a never-issued nonce) we
        // fall back to the presented value so the request still flows to the single-use consume gate
        // below, which rejects it fail-closed rather than silently admitting it.
        let effective_issued_at = self.peek_issued_at(&challenge.nonce).unwrap_or(challenge.issued_at);
        if now < effective_issued_at || now.saturating_sub(effective_issued_at) > self.challenge_ttl_ms {
            return Err(AdmissionError::ChallengeExpired);
        }
        // Proof of key control: the signature MUST verify under the presented key. A forged answer
        // (any other key's signature, or a mutated one) fails here.
        verify_domain(presented_key, ADMISSION_DS, &challenge.signing_body(), sig)
            .map_err(|_| AdmissionError::BadSignature)?;

        // Resolve who this proven key is admitted as (mode policy) BEFORE spending the nonce.
        let admission = match self.mode {
            AuthzMode::KeyRegistered => match self.identity_for_key(presented_key) {
                Some(id) => Admission {
                    account: id.account.clone(),
                    domain: id.domain.clone(),
                    public_key: presented_key.to_vec(),
                },
                None => return Err(AdmissionError::UnknownKey),
            },
            AuthzMode::OpenPublic => match self.identity_for_key(presented_key) {
                Some(id) => Admission {
                    account: id.account.clone(),
                    domain: id.domain.clone(),
                    public_key: presented_key.to_vec(),
                },
                None => Admission {
                    account: format!("anon:{}", key_fingerprint(presented_key)),
                    domain: String::new(),
                    public_key: presented_key.to_vec(),
                },
            },
        };

        // Anti-replay gate: the presented nonce must be one this gateway issued, not already
        // consumed, AND carry the exact issue time we recorded at issuance. Removing it makes the
        // challenge single-use — a captured tuple fails the second time; a tampered issued_at fails
        // the equality check (defense-in-depth on top of the signature that already binds it).
        self.consume_nonce(&challenge.nonce, challenge.issued_at)?;
        Ok(admission)
    }
}

impl GatewayAuthz for IdentityRegistry {
    /// The coarse per-message policy gate a [`Bridge`] consults (§7.9). In open-public mode every
    /// domain is allowed (billed to a domain-scoped label); in key-registered mode only a registered
    /// domain is allowed, and the connection-establishment proof (challenge–response) is what bound
    /// that domain to a proven key in the first place.
    fn authorize(&self, _direction: BridgeDirection, domain: &str) -> AuthzDecision {
        match self.mode {
            AuthzMode::OpenPublic => AuthzDecision::Allowed { account: format!("public:{domain}") },
            AuthzMode::KeyRegistered => match self.identity_for_domain(domain) {
                Some(id) => AuthzDecision::Allowed { account: id.account.clone() },
                None => AuthzDecision::Denied {
                    reason: format!("domain {domain} is not registered with this gateway"),
                },
            },
        }
    }
}

// ── Quota + usage tracking (§12.2) ────────────────────────────────────────────────────────────

/// A per-identity usage allowance (§12.2). `free_*` is the included tier (informational for the
/// external billing layer); `hard_cap_*` is the absolute ceiling the gateway **enforces** — at the
/// cap the relay is refused fail-closed. A zero `hard_cap_*` means "not limited on that axis".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Included message count before overage pricing applies (billing metadata, not enforced here).
    pub free_messages: u64,
    /// Absolute message ceiling; a charge that would exceed it is refused. `0` ⇒ unlimited count.
    pub hard_cap_messages: u64,
    /// Included byte volume before overage pricing applies (billing metadata, not enforced here).
    pub free_bytes: u64,
    /// Absolute byte ceiling; a charge that would exceed it is refused. `0` ⇒ unlimited volume.
    pub hard_cap_bytes: u64,
}

impl Quota {
    /// A message-count + byte quota with matching free/cap on each axis.
    pub fn new(free_messages: u64, hard_cap_messages: u64, free_bytes: u64, hard_cap_bytes: u64) -> Self {
        Quota { free_messages, hard_cap_messages, free_bytes, hard_cap_bytes }
    }

    /// A simple message-count-only quota (no byte ceiling).
    pub fn messages(free_messages: u64, hard_cap_messages: u64) -> Self {
        Quota { free_messages, hard_cap_messages, free_bytes: 0, hard_cap_bytes: 0 }
    }
}

/// Running usage for one account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Messages relayed so far.
    pub messages: u64,
    /// Bytes relayed so far.
    pub bytes: u64,
}

impl Usage {
    /// True once usage has passed the identity's free allowance (i.e. into billable overage).
    pub fn over_free_allowance(&self, quota: &Quota) -> bool {
        self.messages > quota.free_messages
            || (quota.free_bytes != 0 && self.bytes > quota.free_bytes)
    }
}

/// Why a metered charge was refused (fail-closed) — a normal gateway refusal, surfaced to the caller
/// as e.g. an SMTP `452`/`552` over-quota reply.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QuotaError {
    /// No quota is configured for the account — in key-registered mode an unknown account is denied.
    #[error("account {0} has no quota configured (unregistered)")]
    Unregistered(String),
    /// The message hard cap would be exceeded by this relay.
    #[error("account {0} is at its message cap ({1}); relay refused")]
    MessageCapExceeded(String, u64),
    /// The byte hard cap would be exceeded by this relay.
    #[error("account {0} is at its volume cap ({1} bytes); relay refused")]
    VolumeCapExceeded(String, u64),
}

/// The in-crate quota ledger (§12.2): per-account [`Quota`] + running [`Usage`]. It enforces the
/// hard cap fail-closed and, on an admitted charge, emits the usage through the [`GatewayMeter`] seam
/// the external (private) billing layer reads. The gateway never prices — it only counts and meters.
#[derive(Debug, Default)]
pub struct QuotaLedger {
    limits: HashMap<String, Quota>,
    usage: Mutex<HashMap<String, Usage>>,
}

impl QuotaLedger {
    /// An empty ledger. Add quotas with [`Self::set_quota`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure (or replace) the quota for `account`.
    pub fn set_quota(mut self, account: impl Into<String>, quota: Quota) -> Self {
        self.limits.insert(account.into(), quota);
        self
    }

    /// Set/replace a quota after construction (for a dynamically-registered account).
    pub fn upsert_quota(&mut self, account: impl Into<String>, quota: Quota) {
        self.limits.insert(account.into(), quota);
    }

    /// A snapshot of the account's usage so far (`0/0` if it has relayed nothing).
    pub fn usage(&self, account: &str) -> Usage {
        self.usage.lock().expect("quota ledger poisoned").get(account).copied().unwrap_or_default()
    }

    /// Attempt to charge one relayed message of `msg_bytes` to `account`, **fail-closed** against the
    /// hard cap: if either ceiling would be exceeded the usage is **not** advanced and a
    /// [`QuotaError`] is returned (the caller turns it into a refusal). On success the usage is
    /// advanced and the updated snapshot returned. Does **not** meter — see [`Self::charge_and_meter`].
    pub fn try_charge(&self, account: &str, msg_bytes: u64) -> Result<Usage, QuotaError> {
        let quota = *self
            .limits
            .get(account)
            .ok_or_else(|| QuotaError::Unregistered(account.to_string()))?;
        let mut usage = self.usage.lock().expect("quota ledger poisoned");
        let cur = usage.entry(account.to_string()).or_default();

        let next_messages = cur.messages.saturating_add(1);
        if quota.hard_cap_messages != 0 && next_messages > quota.hard_cap_messages {
            return Err(QuotaError::MessageCapExceeded(account.to_string(), quota.hard_cap_messages));
        }
        let next_bytes = cur.bytes.saturating_add(msg_bytes);
        if quota.hard_cap_bytes != 0 && next_bytes > quota.hard_cap_bytes {
            return Err(QuotaError::VolumeCapExceeded(account.to_string(), quota.hard_cap_bytes));
        }

        cur.messages = next_messages;
        cur.bytes = next_bytes;
        Ok(*cur)
    }

    /// Charge the relay **and**, on success, emit the billable [`MeterEvent`] through `meter` for the
    /// external billing layer (§12.6). This is the single call a bridge makes per relayed message:
    /// over the cap ⇒ `Err` and nothing metered (fail-closed); under the cap ⇒ usage advanced and
    /// exactly one meter event recorded, carrying the `msg_digest` that links the bill to the message
    /// (the §12.7 audit loop). `rfc5322_bytes` are the exact relayed bytes (for both the byte charge
    /// and the digest).
    #[allow(clippy::too_many_arguments)]
    pub fn charge_and_meter(
        &self,
        account: &str,
        domain: &str,
        direction: BridgeDirection,
        rfc5322_bytes: &[u8],
        at: TimestampMs,
        meter: &dyn GatewayMeter,
    ) -> Result<Usage, QuotaError> {
        let usage = self.try_charge(account, rfc5322_bytes.len() as u64)?;
        meter.record(&MeterEvent {
            direction,
            account: account.to_string(),
            domain: domain.to_string(),
            msg_digest: crate::provenance::msg_digest(rfc5322_bytes),
            at,
        });
        Ok(usage)
    }
}

// ── Vanity + key-derived local-parts (§7.10) ──────────────────────────────────────────────────

/// RFC 4648 base32 lowercase alphabet (`a–z2–7`) — every character is a valid RFC 5321 dot-atom
/// local-part character, so a key-derived alias needs no quoting.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes as lowercase base32 (RFC 4648, no padding).
fn base32_lower(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    for &b in input {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(BASE32_LOWER[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(BASE32_LOWER[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// A short, stable fingerprint of a public key (first **10** bytes of its content address, 80 bits,
/// base32) — used for open-public `anon:<fp>` account labels and internal identification. 80 bits
/// (matching [`key_derived_localpart`]) keeps birthday collisions negligible, so two distinct keys
/// cannot share a quota / reputation bucket; a 48-bit label would not.
fn key_fingerprint(public_key: &[u8]) -> String {
    base32_lower(&ContentId::of(public_key).digest()[..10])
}

/// The **stable, key-derived** local-part for a DMTAP key (§7.10): `k` + base32 of the first 10 bytes
/// of the key's content address. This is the default alias — it is deterministic, collision-resistant,
/// and always resolves, so a sender always has a working address even without a vanity name.
pub fn key_derived_localpart(public_key: &[u8]) -> String {
    format!("k{}", base32_lower(&ContentId::of(public_key).digest()[..10]))
}

/// The reserved prefix that anchors the human-facing spelling of the auto-derived, key-derived
/// namespace (§7.10, the normative naming model). A chosen vanity local-part MUST NOT begin with it,
/// so a vanity can never shadow or impersonate an auto-derived alias. This is enforced **in addition
/// to** the compact `k<base32>` [`key_derived_localpart`] shape (see [`is_key_derived_form`]): both
/// spellings of the auto-derived namespace are reserved against vanity capture.
pub const RESERVED_ALIAS_PREFIX: &str = "dmtap1-";

/// The RFC 5321 §4.5.3.1.1 local-part octet limit — the ceiling for a vanity local-part.
const MAX_VANITY_LEN: usize = 64;

/// Why a chosen vanity local-part could not be allocated on the gateway domain (fail-closed). Every
/// variant is a hard reject with a clear reason — the allocator **never silently normalizes** a name
/// into something acceptable (spec §7.10, the normative vanity-alias rules).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AliasError {
    /// Hygiene (rule 6): the local-part is empty, over-length, or contains whitespace / CR / LF /
    /// NUL / any byte outside the dot-free dot-atom charset (letters, digits, `- _ +`).
    #[error("vanity local-part {0:?} is empty, over-length, or contains a disallowed character")]
    InvalidLocalPart(String),
    /// Rule 1 (DOT-FREE): the local-part contains a `.`. Dotted local-parts are **reserved** for the
    /// forwarded-address encoding ([`crate::forwarded_addr`], `local.nativedomain@gateway`), so a
    /// vanity must be dot-free to keep dot-free-vanity vs dotted-forwarded unambiguous. Refused, not
    /// stripped.
    #[error("vanity local-part {0:?} contains a '.' — dotted local-parts are reserved for forwarded addresses")]
    ContainsDot(String),
    /// Rule 4 (FIRST-COME): the local-part is already allocated to a **different** identity on this
    /// gateway domain. Release it first (see [`AliasAllocator::release_vanity`]) to free the name.
    #[error("vanity local-part {0:?} is already taken by another identity on this gateway")]
    Taken(String),
    /// Rule 3 (RESERVED-PREFIX / auto-derived namespace): the local-part would shadow or parse as an
    /// auto-derived alias — it begins with [`RESERVED_ALIAS_PREFIX`] or matches the `k<base32>`
    /// key-derived shape ([`is_key_derived_form`]).
    #[error("vanity local-part {0:?} collides with the reserved auto-derived (key-derived) namespace")]
    ReservedCollision(String),
    /// Rule 5 (NETWORK-NAME non-shadow): the local-part is already claimed by one of the operator's
    /// own directory identities on this same gateway domain, so a vanity may not shadow the real
    /// account.
    #[error("vanity local-part {0:?} would shadow an existing directory identity on this gateway")]
    ShadowsDirectoryIdentity(String),
    /// Rule 2 (construction): the gateway domain the allocator is anchored to is not a syntactically
    /// valid DNS domain, so no fully-qualified `vanity@<gatewaydomain>` could ever be formed.
    #[error("gateway domain {0:?} is not a valid DNS domain")]
    InvalidGatewayDomain(String),
}

/// Allocates **fully-qualified** vanity local-parts on a single gateway domain (§7.10). The operator
/// may grant a chosen vanity name to a registered key, while the [`key_derived_localpart`] stays the
/// stable default that always resolves.
///
/// The allocator is **anchored to the gateway's own domain** ([`Self::for_domain`]): a vanity is only
/// ever meaningful as `vanity@<gatewaydomain>`, so both what it stores and what it returns is that
/// fully-qualified form — it never hands out or accepts a bare, un-anchored handle (rule 2). The
/// anchoring domain is also *why* a vanity cannot shadow a real network name (`x@otherdomain`,
/// `x.eth`): those are structurally different strings from `vanity@<gatewaydomain>`. On top of that
/// structural guarantee, the allocator additionally refuses a vanity that would shadow one of the
/// operator's **own** directory identities on the same domain (rule 5) — reserve those with
/// [`Self::reserve_localpart`] / [`Self::reserve_directory_address`].
///
/// [`Self::allocate_vanity`] enforces every naming rule fail-closed and returns the bound
/// `vanity@<gatewaydomain>`; [`Self::alias_for`] returns the fully-qualified vanity if allocated,
/// else the fully-qualified key-derived default; [`Self::resolve`] accepts only a fully-qualified
/// address on this gateway's domain; [`Self::release_vanity`] revokes an allocation so the name can
/// be reused ("yours only as long as you hold the registration").
#[derive(Debug, Clone)]
pub struct AliasAllocator {
    /// The gateway's own domain (lowercased), the anchor every vanity is qualified against (rule 2).
    domain: String,
    /// vanity local-part (lowercased) → public key
    vanity: HashMap<String, Vec<u8>>,
    /// public key → its allocated vanity local-part (lowercased)
    reverse: Vec<(Vec<u8>, String)>,
    /// local-parts (lowercased) claimed by the operator's own directory identities on this domain: a
    /// vanity that collides with one is refused (rule 5, network-name non-shadow).
    reserved: HashSet<String>,
}

impl AliasAllocator {
    /// A fresh allocator anchored to the gateway's own `domain` (rule 2). **Fail-closed**: rejects a
    /// syntactically invalid gateway domain, since no fully-qualified vanity could be formed against
    /// it. Every key then resolves by its fully-qualified key-derived default until a vanity is
    /// allocated.
    pub fn for_domain(domain: impl AsRef<str>) -> Result<Self, AliasError> {
        let raw = domain.as_ref();
        let d = raw.trim().to_ascii_lowercase();
        if !is_valid_dns_domain(&d) {
            return Err(AliasError::InvalidGatewayDomain(raw.to_string()));
        }
        Ok(AliasAllocator {
            domain: d,
            vanity: HashMap::new(),
            reverse: Vec::new(),
            reserved: HashSet::new(),
        })
    }

    /// The gateway domain this allocator qualifies vanity names against.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Reserve `local_part` as an operator directory identity on this gateway domain (rule 5): a
    /// vanity that collides with it is refused, so a chosen name can never shadow a real account.
    /// Idempotent; the value is lowercased for a case-insensitive match.
    pub fn reserve_localpart(&mut self, local_part: impl AsRef<str>) {
        self.reserved.insert(local_part.as_ref().trim().to_ascii_lowercase());
    }

    /// Reserve the local-part of a full directory address `email` **iff** it is on this gateway's own
    /// domain (rule 5). Addresses on other domains are ignored — a vanity is structurally distinct
    /// from `x@otherdomain` and cannot shadow it. Returns whether the address was on-domain and thus
    /// reserved. The personal run-mode feeds the operator's directory through this so the same file
    /// that resolves inbound recipients also blocks a vanity from shadowing one of them.
    pub fn reserve_directory_address(&mut self, email: &str) -> bool {
        match email.rsplit_once('@') {
            Some((lp, dom)) if dom.trim().eq_ignore_ascii_case(&self.domain) => {
                self.reserve_localpart(lp);
                true
            }
            _ => false,
        }
    }

    /// Allocate `local_part` as a vanity alias for `public_key`, returning the bound
    /// **fully-qualified** address `vanity@<gatewaydomain>` (§7.10, rule 2). **Fail-closed** — each
    /// normative rule is a hard reject, never a silent normalization:
    ///
    /// - rule 1 [`AliasError::ContainsDot`] — a `.` is reserved for forwarded addresses;
    /// - rule 6 [`AliasError::InvalidLocalPart`] — empty / whitespace / CRLF / NUL / over-length /
    ///   out-of-charset;
    /// - rule 3 [`AliasError::ReservedCollision`] — the auto-derived (key-derived) namespace;
    /// - rule 5 [`AliasError::ShadowsDirectoryIdentity`] — an operator directory identity;
    /// - rule 4 [`AliasError::Taken`] — already held by a *different* identity.
    ///
    /// Idempotent for the **same** key (re-allocating its current name returns the same FQ address).
    /// One vanity per key: allocating a new name drops the key's prior one (the key-derived default
    /// always remains, so the identity stays reachable).
    pub fn allocate_vanity(
        &mut self,
        public_key: &[u8],
        local_part: &str,
    ) -> Result<String, AliasError> {
        // Rules 1, 3, 5, 6 (all the stateless, name-only checks). Returns the normalized local-part.
        let lp = self.check_vanity(local_part)?;

        // Rule 4 (FIRST-COME): a name held by a *different* identity is refused; the same key is
        // idempotent.
        if let Some(existing) = self.vanity.get(&lp) {
            if existing == public_key {
                return Ok(self.qualify(&lp)); // idempotent re-allocation of the same name/key
            }
            return Err(AliasError::Taken(local_part.to_string()));
        }

        // One vanity per key: drop any prior name for this key (the key-derived default remains).
        if let Some(pos) = self.reverse.iter().position(|(k, _)| k == public_key) {
            let (_, old) = self.reverse.remove(pos);
            self.vanity.remove(&old);
        }
        self.vanity.insert(lp.clone(), public_key.to_vec());
        self.reverse.push((public_key.to_vec(), lp.clone()));
        Ok(self.qualify(&lp))
    }

    /// Release (revoke) the vanity currently held by `public_key`, freeing the name for another
    /// identity to claim (rule 4, revocable — *"yours only as long as you hold the registration"*).
    /// Returns the freed **fully-qualified** address, or `None` if the key held no vanity. The
    /// key-derived default always remains, so the identity stays reachable after a release.
    pub fn release_vanity(&mut self, public_key: &[u8]) -> Option<String> {
        let pos = self.reverse.iter().position(|(k, _)| k == public_key)?;
        let (_, lp) = self.reverse.remove(pos);
        self.vanity.remove(&lp);
        Some(self.qualify(&lp))
    }

    /// The **fully-qualified** address to present for `public_key`: its `vanity@<gatewaydomain>` if
    /// one is allocated, else the fully-qualified [`key_derived_localpart`] default (§7.10, rule 2 —
    /// never a bare local-part).
    pub fn alias_for(&self, public_key: &[u8]) -> String {
        let lp = self
            .reverse
            .iter()
            .find(|(k, _)| k == public_key)
            .map(|(_, lp)| lp.clone())
            .unwrap_or_else(|| key_derived_localpart(public_key));
        self.qualify(&lp)
    }

    /// Resolve a **fully-qualified** address (either a vanity name or a key-derived alias, always
    /// `local@<gatewaydomain>`) back to its public key. Rule 2: a bare, un-anchored handle (no `@`)
    /// or an address on any other domain is refused (`None`) — the allocator never accepts an
    /// un-anchored name. A vanity resolves via the allocation table; a key-derived alias resolves by
    /// matching it against each registered key's derived form.
    pub fn resolve(&self, address: &str, registered_keys: &[Vec<u8>]) -> Option<Vec<u8>> {
        let addr = address.trim().to_ascii_lowercase();
        let (lp, dom) = addr.rsplit_once('@')?; // a bare handle (no '@') is never accepted (rule 2)
        if dom != self.domain {
            return None; // only this gateway's own fully-qualified aliases resolve here
        }
        if let Some(k) = self.vanity.get(lp) {
            return Some(k.clone());
        }
        registered_keys.iter().find(|k| key_derived_localpart(k) == lp).cloned()
    }

    /// Qualify a bare local-part into `local@<gatewaydomain>` — the one place the anchoring suffix is
    /// appended, so stored/returned/resolved forms are all consistently fully-qualified (rule 2).
    fn qualify(&self, local_part: &str) -> String {
        format!("{local_part}@{}", self.domain)
    }

    /// Run the stateless naming rules on `local_part` (rules 1, 3, 5, 6) and return the normalized
    /// (lowercased) local-part, WITHOUT touching allocation state (rule 4 / first-come lives in
    /// [`Self::allocate_vanity`]). Fail-closed, in check order.
    fn check_vanity(&self, local_part: &str) -> Result<String, AliasError> {
        // Rule 1 (DOT-FREE): checked on the RAW input, before any case-folding, so a dot is refused
        // rather than normalized away. Because a vanity is dot-free, it can never spell a forwarded
        // address (whose one bare separator dot is structurally required), so the forwarded-alias
        // "would otherwise parse as" guard of rule 3 is satisfied structurally by this check.
        if local_part.contains('.') {
            return Err(AliasError::ContainsDot(local_part.to_string()));
        }
        // Rule 6 (hygiene): lowercase-fold for the case-insensitive namespace, then require a
        // non-empty, in-length, dot-free dot-atom. Whitespace, CR, LF, NUL, and any control or
        // out-of-charset byte are rejected here (they are not in the charset) — we do NOT trim.
        let lp = local_part.to_ascii_lowercase();
        if !is_valid_vanity_charset(&lp) {
            return Err(AliasError::InvalidLocalPart(local_part.to_string()));
        }
        // Rule 3 (RESERVED-PREFIX / auto-derived namespace): a vanity must not shadow or parse as an
        // auto-derived alias — neither the human `dmtap1-…` prefix nor the compact `k<base32>` shape.
        if lp.starts_with(RESERVED_ALIAS_PREFIX) || is_key_derived_form(&lp) {
            return Err(AliasError::ReservedCollision(local_part.to_string()));
        }
        // Rule 5 (NETWORK-NAME non-shadow): a vanity must not shadow an operator directory identity
        // already claimed on this same gateway domain.
        if self.reserved.contains(&lp) {
            return Err(AliasError::ShadowsDirectoryIdentity(local_part.to_string()));
        }
        Ok(lp)
    }
}

/// Whether `lp` matches the reserved key-derived shape (`k` + 16 base32 chars) so a vanity request
/// for that exact shape is treated as reserved (rule 3).
fn is_key_derived_form(lp: &str) -> bool {
    let Some(rest) = lp.strip_prefix('k') else { return false };
    rest.len() == 16 && rest.bytes().all(|c| BASE32_LOWER.contains(&c))
}

/// A conservative **dot-free** RFC 5321 dot-atom local-part check for a vanity: non-empty, within the
/// 64-octet cap, and every byte an ASCII alphanumeric or one of `- _ +`. A `.` is intentionally NOT
/// permitted (rule 1 — dotted local-parts are reserved for forwarded addresses), and because the
/// charset is a strict allow-list, whitespace / CR / LF / NUL / control bytes are all rejected too
/// (rule 6). Kept dot-free-strict here on purpose; the dotted forwarded-address form has its own
/// validator in [`crate::forwarded_addr`].
fn is_valid_vanity_charset(lp: &str) -> bool {
    if lp.is_empty() || lp.len() > MAX_VANITY_LEN {
        return false;
    }
    lp.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'+'))
}

/// A conservative RFC 1035 / RFC 5321 domain-syntax check for the gateway's own anchoring domain:
/// one or more dot-separated labels, each 1..=63 bytes of ASCII alphanumerics and `-` (no
/// leading/trailing hyphen), total 1..=253 bytes. Used only to validate the [`AliasAllocator`]
/// anchor at construction (rule 2), so a fully-qualified `vanity@<gatewaydomain>` is always a legal
/// address.
fn is_valid_dns_domain(domain: &str) -> bool {
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
    use crate::provenance::{CountingMeter, StaticGatewayAuthz};
    use dmtap_core::identity::IdentityKey;

    fn signed_answer(key: &IdentityKey, challenge: &Challenge) -> Vec<u8> {
        key.sign_domain(ADMISSION_DS, &challenge.signing_body())
    }

    // ── Authorization modes / admission ──────────────────────────────────────────────────────

    #[test]
    fn key_registered_admits_a_valid_registered_key_and_rejects_a_forgery() {
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
            public_key: alice.public(),
            account: "acct-alice".into(),
            domain: "alice.host.net".into(),
            quota: Quota::messages(100, 1000),
        });
        let ch = reg.issue_challenge([7u8; 32], 1_000_000);

        // Valid: alice signs the challenge with her own registered key → admitted, bound to her account.
        let sig = signed_answer(&alice, &ch);
        let adm = reg.admit(&ch, &alice.public(), &sig, 1_000_100).expect("admitted");
        assert_eq!(adm.account, "acct-alice");
        assert_eq!(adm.domain, "alice.host.net");

        // Forged: a signature made by a DIFFERENT key, presented as alice's key → BadSignature.
        let mallory = IdentityKey::generate();
        let forged = signed_answer(&mallory, &ch);
        assert_eq!(
            reg.admit(&ch, &alice.public(), &forged, 1_000_100),
            Err(AdmissionError::BadSignature)
        );

        // A key that controls its own signature but is not registered → UnknownKey (fail-closed).
        let sig_m = signed_answer(&mallory, &ch);
        assert_eq!(
            reg.admit(&ch, &mallory.public(), &sig_m, 1_000_100),
            Err(AdmissionError::UnknownKey)
        );
    }

    #[test]
    fn admission_challenge_expiry_is_enforced_fail_closed() {
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered()
            .with_challenge_ttl(60_000)
            .register(RegisteredIdentity {
                public_key: alice.public(),
                account: "a".into(),
                domain: "a.net".into(),
                quota: Quota::messages(10, 10),
            });
        let ch = reg.issue_challenge([1u8; 32], 1_000_000);
        let sig = signed_answer(&alice, &ch);

        // Within the window: fine.
        assert!(reg.admit(&ch, &alice.public(), &sig, 1_030_000).is_ok());
        // Past the TTL: expired.
        assert_eq!(
            reg.admit(&ch, &alice.public(), &sig, 1_000_000 + 60_001),
            Err(AdmissionError::ChallengeExpired)
        );
        // Future-dated (clock skew before issue): also refused.
        assert_eq!(
            reg.admit(&ch, &alice.public(), &sig, 999_999),
            Err(AdmissionError::ChallengeExpired)
        );
    }

    #[test]
    fn admission_nonce_is_single_use_replay_and_forged_nonce_rejected() {
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
            public_key: alice.public(),
            account: "acct-alice".into(),
            domain: "alice.net".into(),
            quota: Quota::messages(10, 10),
        });

        // A gateway-issued nonce admits exactly once.
        let ch = reg.issue_challenge([42u8; 32], 1_000_000);
        let sig = signed_answer(&alice, &ch);
        assert!(
            reg.admit(&ch, &alice.public(), &sig, 1_000_100).is_ok(),
            "a fresh issued nonce is admitted once",
        );

        // Replaying the exact captured (nonce, issued_at, key, sig) tuple within the TTL is REJECTED:
        // the nonce was consumed, so it is no longer a live challenge. (Old behavior re-admitted it.)
        assert_eq!(
            reg.admit(&ch, &alice.public(), &sig, 1_000_200),
            Err(AdmissionError::UnknownOrConsumedChallenge),
            "a captured admission tuple cannot be replayed",
        );

        // A challenge whose nonce the gateway never issued is refused even with a valid signature —
        // only gateway-minted nonces admit. (Old behavior admitted any well-signed self-made challenge.)
        let never_issued = Challenge::new([99u8; 32], 1_000_000);
        let ni_sig = signed_answer(&alice, &never_issued);
        assert_eq!(
            reg.admit(&never_issued, &alice.public(), &ni_sig, 1_000_100),
            Err(AdmissionError::UnknownOrConsumedChallenge),
            "a never-issued nonce is not admissible",
        );

        // Single-use, not one-shot-ever: a freshly issued nonce for the same key admits again.
        let ch2 = reg.issue_challenge([43u8; 32], 1_000_300);
        let sig2 = signed_answer(&alice, &ch2);
        assert!(
            reg.admit(&ch2, &alice.public(), &sig2, 1_000_400).is_ok(),
            "a newly issued nonce admits",
        );
    }

    #[test]
    fn admission_rejects_a_mismatched_issued_at_even_with_a_valid_signature() {
        // Defense-in-depth (the signature already binds issued_at): a challenge presenting a nonce the
        // gateway issued but a DIFFERENT issued_at than the one recorded at issuance is rejected, and
        // the equality mismatch does NOT burn the live nonce, so the correctly-timed challenge still
        // admits afterwards.
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
            public_key: alice.public(),
            account: "acct-alice".into(),
            domain: "alice.net".into(),
            quota: Quota::messages(10, 10),
        });

        // Gateway issues nonce N at issue time 1_000_000.
        let issued = reg.issue_challenge([55u8; 32], 1_000_000);

        // The sender presents the SAME nonce but a tampered issued_at (1_000_050), and signs THAT
        // (so the signature genuinely verifies over the presented body — the signature guard does not
        // catch this; the stored-vs-presented equality guard must).
        let tampered = Challenge::new(issued.nonce, 1_000_050);
        let sig = signed_answer(&alice, &tampered);
        assert_eq!(
            reg.admit(&tampered, &alice.public(), &sig, 1_000_100),
            Err(AdmissionError::UnknownOrConsumedChallenge),
            "a nonce presented with an issued_at that differs from the recorded one is refused",
        );

        // The live nonce survived the mismatch: the correctly-timed challenge still admits once.
        let sig_ok = signed_answer(&alice, &issued);
        assert!(
            reg.admit(&issued, &alice.public(), &sig_ok, 1_000_100).is_ok(),
            "the correctly-timed challenge for the same nonce still admits (mismatch didn't burn it)",
        );
    }

    #[test]
    fn a_forged_signature_does_not_consume_a_live_nonce() {
        // The nonce is spent only on the success path, so a bad-signature attempt cannot burn a
        // legitimate sender's live challenge (denial-of-service guard).
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
            public_key: alice.public(),
            account: "acct-alice".into(),
            domain: "alice.net".into(),
            quota: Quota::messages(10, 10),
        });
        let ch = reg.issue_challenge([7u8; 32], 1_000_000);
        let mallory = IdentityKey::generate();
        let forged = signed_answer(&mallory, &ch);
        assert_eq!(
            reg.admit(&ch, &alice.public(), &forged, 1_000_100),
            Err(AdmissionError::BadSignature),
        );
        // The nonce survived the forged attempt: alice can still admit with it.
        let sig = signed_answer(&alice, &ch);
        assert!(reg.admit(&ch, &alice.public(), &sig, 1_000_100).is_ok());
    }

    #[test]
    fn anon_fingerprint_is_at_least_80_bits_wide() {
        // The open-public `anon:<fp>` label must be wide enough that birthday collisions don't share
        // a quota / reputation bucket: >=10 bytes (80 bits), matching the key-derived local-part.
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let fa = key_fingerprint(&a.public());
        let fb = key_fingerprint(&b.public());
        // base32 of 10 bytes = 16 chars (no padding). The old 6-byte fingerprint was only 10 chars.
        assert_eq!(fa.len(), 16, "fingerprint encodes >=10 bytes (80 bits), not 48");
        assert_ne!(fa, fb, "distinct keys get distinct anon labels");
    }

    #[test]
    fn open_public_admits_any_key_controller_but_is_the_non_default() {
        assert_eq!(AuthzMode::default(), AuthzMode::KeyRegistered);
        let reg = IdentityRegistry::open_public();
        let bob = IdentityKey::generate();
        let ch = reg.issue_challenge([9u8; 32], 5_000);
        let sig = signed_answer(&bob, &ch);
        let adm = reg.admit(&ch, &bob.public(), &sig, 5_050).expect("open relay admits any proof");
        assert!(adm.account.starts_with("anon:"));
        // Even open-public still requires a real proof of key control (forgery rejected).
        let evil = IdentityKey::generate();
        let forged = signed_answer(&evil, &ch);
        assert_eq!(reg.admit(&ch, &bob.public(), &forged, 5_050), Err(AdmissionError::BadSignature));
    }

    #[test]
    fn registry_is_a_gateway_authz_gate() {
        let alice = IdentityKey::generate();
        let reg = IdentityRegistry::key_registered().register(RegisteredIdentity {
            public_key: alice.public(),
            account: "acct-alice".into(),
            domain: "alice.net".into(),
            quota: Quota::messages(10, 10),
        });
        assert_eq!(
            reg.authorize(BridgeDirection::Outbound, "alice.net"),
            AuthzDecision::Allowed { account: "acct-alice".into() }
        );
        assert!(matches!(
            reg.authorize(BridgeDirection::Outbound, "stranger.net"),
            AuthzDecision::Denied { .. }
        ));
    }

    // ── Quota + usage tracking + meter seam ──────────────────────────────────────────────────

    #[test]
    fn quota_refuses_past_the_cap_and_meters_only_admitted_charges() {
        let meter = CountingMeter::new();
        let ledger = QuotaLedger::new().set_quota("acct", Quota::messages(1, 2));
        let rfc = b"From: a@x.net\r\nTo: b@y.com\r\n\r\nhi\r\n";

        // Two charges are within the hard cap of 2 → both succeed and both meter.
        ledger
            .charge_and_meter("acct", "x.net", BridgeDirection::Outbound, rfc, 10, &meter)
            .unwrap();
        let u2 = ledger
            .charge_and_meter("acct", "x.net", BridgeDirection::Outbound, rfc, 20, &meter)
            .unwrap();
        assert_eq!(u2.messages, 2);
        assert!(u2.over_free_allowance(&Quota::messages(1, 2)), "past the free allowance of 1");
        assert_eq!(meter.count(), 2);

        // The third charge is AT the cap → refused fail-closed, usage NOT advanced, NOT metered.
        let denied = ledger.charge_and_meter("acct", "x.net", BridgeDirection::Outbound, rfc, 5, &meter);
        assert_eq!(denied, Err(QuotaError::MessageCapExceeded("acct".into(), 2)));
        assert_eq!(ledger.usage("acct").messages, 2, "refused charge did not advance usage");
        assert_eq!(meter.count(), 2, "refused charge did not meter");
    }

    #[test]
    fn quota_enforces_the_byte_volume_cap() {
        let meter = CountingMeter::new();
        let ledger = QuotaLedger::new().set_quota("acct", Quota::new(100, 100, 50, 100));
        // 60 bytes is fine; another 60 would exceed the 100-byte cap → refused, nothing metered.
        ledger.charge_and_meter("acct", "d", BridgeDirection::Inbound, &vec![0u8; 60], 1, &meter).unwrap();
        let denied =
            ledger.charge_and_meter("acct", "d", BridgeDirection::Inbound, &vec![0u8; 60], 2, &meter);
        assert_eq!(denied, Err(QuotaError::VolumeCapExceeded("acct".into(), 100)));
        assert_eq!(meter.count(), 1);
    }

    #[test]
    fn unregistered_account_is_denied_a_charge_fail_closed() {
        let meter = NullMeterDouble;
        let ledger = QuotaLedger::new();
        assert_eq!(
            ledger.try_charge("nobody", 1),
            Err(QuotaError::Unregistered("nobody".into()))
        );
        // And through the meter path it still refuses and never meters.
        assert!(ledger
            .charge_and_meter("nobody", "d", BridgeDirection::Outbound, b"x", 0, &meter)
            .is_err());
    }

    struct NullMeterDouble;
    impl GatewayMeter for NullMeterDouble {
        fn record(&self, _: &MeterEvent) {
            panic!("must not meter a refused charge");
        }
    }

    // A quick sanity check that the existing StaticGatewayAuthz still composes as a GatewayAuthz.
    #[test]
    fn static_authz_still_usable_alongside_registry() {
        let a = StaticGatewayAuthz::new().allow("host.net", "acct");
        assert!(matches!(
            a.authorize(BridgeDirection::Inbound, "host.net"),
            AuthzDecision::Allowed { .. }
        ));
    }

    // ── Vanity + key-derived local-parts (§7.10) ─────────────────────────────────────────────

    const GW: &str = "gw.example";

    #[test]
    fn key_derived_alias_is_stable_and_fully_qualified_by_default() {
        let k = IdentityKey::generate();
        let a1 = key_derived_localpart(&k.public());
        let a2 = key_derived_localpart(&k.public());
        assert_eq!(a1, a2, "deterministic");
        assert!(a1.starts_with('k') && a1.len() == 17);
        assert!(is_key_derived_form(&a1));

        // With no vanity allocated, alias_for returns the FULLY-QUALIFIED key-derived default (rule 2).
        let alloc = AliasAllocator::for_domain(GW).unwrap();
        assert_eq!(alloc.alias_for(&k.public()), format!("{a1}@{GW}"));
        // ...and its fully-qualified form resolves back to the key.
        assert_eq!(alloc.resolve(&format!("{a1}@{GW}"), &[k.public()]), Some(k.public()));
    }

    // ── Rule 2: fully-qualified only (bind/return/accept only `vanity@<gatewaydomain>`) ──────────

    #[test]
    fn rule2_allocation_binds_and_returns_the_fully_qualified_form_and_rejects_bare_handles() {
        let k = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();

        // allocate_vanity returns the FQ address, not a bare handle.
        let fq = alloc.allocate_vanity(&k.public(), "Alice").unwrap();
        assert_eq!(fq, format!("alice@{GW}"), "the stored/returned form is fully-qualified (lowercased)");
        // alias_for presents the FQ vanity.
        assert_eq!(alloc.alias_for(&k.public()), format!("alice@{GW}"));

        // resolve accepts ONLY a fully-qualified address on this gateway domain.
        assert_eq!(alloc.resolve(&format!("alice@{GW}"), &[k.public()]), Some(k.public()));
        // A bare, un-anchored handle (no '@') is refused (rule 2 — never accept an un-anchored name).
        assert_eq!(alloc.resolve("alice", &[k.public()]), None);
        // The same local-part on some OTHER domain does not resolve here (structurally different).
        assert_eq!(alloc.resolve("alice@other.net", &[k.public()]), None);
        // The stable key-derived default still resolves, fully-qualified.
        assert_eq!(
            alloc.resolve(&format!("{}@{GW}", key_derived_localpart(&k.public())), &[k.public()]),
            Some(k.public())
        );
    }

    #[test]
    fn rule2_construction_rejects_an_invalid_gateway_domain_fail_closed() {
        assert!(AliasAllocator::for_domain("gw.example").is_ok());
        for bad in ["", " ", "no_underscores.example", "-lead.example", "trail-.example", "a..b"] {
            assert!(
                matches!(AliasAllocator::for_domain(bad), Err(AliasError::InvalidGatewayDomain(_))),
                "gateway domain {bad:?} must be rejected"
            );
        }
    }

    // ── Rule 1: dot-free (dotted local-parts reserved for forwarded addresses) ───────────────────

    #[test]
    fn rule1_dotted_vanity_is_rejected_not_normalized() {
        let k = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();
        for dotted in ["first.last", ".lead", "trail.", "a.b.c", "imran.mydomain-.com"] {
            assert_eq!(
                alloc.allocate_vanity(&k.public(), dotted),
                Err(AliasError::ContainsDot(dotted.to_string())),
                "dotted vanity {dotted:?} must be refused (reserved for forwarded encoding), not stripped"
            );
        }
        // And nothing was silently allocated as a side effect.
        assert_eq!(alloc.alias_for(&k.public()), format!("{}@{GW}", key_derived_localpart(&k.public())));
    }

    // ── Rule 3: reserved-prefix / auto-derived namespace guard ───────────────────────────────────

    #[test]
    fn rule3_reserved_prefix_and_key_derived_shapes_are_rejected() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();

        // The human `dmtap1-…` reserved prefix is refused (case-insensitive).
        assert!(matches!(
            alloc.allocate_vanity(&a.public(), "dmtap1-anything"),
            Err(AliasError::ReservedCollision(_))
        ));
        assert!(matches!(
            alloc.allocate_vanity(&a.public(), "DMTAP1-Upper"),
            Err(AliasError::ReservedCollision(_))
        ));
        // A key's OWN key-derived shape may not be claimed as a vanity either (no shadowing at all).
        let own = key_derived_localpart(&a.public());
        assert!(matches!(
            alloc.allocate_vanity(&a.public(), &own),
            Err(AliasError::ReservedCollision(_))
        ));
        // Another key's key-derived shape is likewise refused.
        let other = key_derived_localpart(&b.public());
        assert!(matches!(
            alloc.allocate_vanity(&a.public(), &other),
            Err(AliasError::ReservedCollision(_))
        ));
    }

    // ── Rule 4: first-come + revocable ───────────────────────────────────────────────────────────

    #[test]
    fn rule4_duplicate_allocation_is_refused_but_same_key_is_idempotent() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();
        assert_eq!(alloc.allocate_vanity(&a.public(), "team").unwrap(), format!("team@{GW}"));

        // Same name for a DIFFERENT identity → Taken (first-come).
        assert_eq!(
            alloc.allocate_vanity(&b.public(), "team"),
            Err(AliasError::Taken("team".into()))
        );
        // Re-allocating the same name to the SAME key is idempotent and returns the FQ form.
        assert_eq!(alloc.allocate_vanity(&a.public(), "team").unwrap(), format!("team@{GW}"));
        // The name still resolves to the first-comer, not the challenger.
        assert_eq!(alloc.resolve(&format!("team@{GW}"), &[a.public(), b.public()]), Some(a.public()));
    }

    #[test]
    fn rule4_release_then_reallocate_to_a_different_identity_works() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();
        alloc.allocate_vanity(&a.public(), "team").unwrap();

        // While held, b cannot take it.
        assert!(matches!(alloc.allocate_vanity(&b.public(), "team"), Err(AliasError::Taken(_))));

        // a releases (revokes) the registration — the freed FQ name is returned.
        assert_eq!(alloc.release_vanity(&a.public()), Some(format!("team@{GW}")));
        // a now falls back to its key-derived default; the vanity no longer resolves to anyone until reclaimed.
        assert_eq!(alloc.alias_for(&a.public()), format!("{}@{GW}", key_derived_localpart(&a.public())));
        assert_eq!(alloc.resolve(&format!("team@{GW}"), &[a.public(), b.public()]), None);

        // Now b can claim the freed name ("yours only as long as you hold the registration").
        assert_eq!(alloc.allocate_vanity(&b.public(), "team").unwrap(), format!("team@{GW}"));
        assert_eq!(alloc.resolve(&format!("team@{GW}"), &[a.public(), b.public()]), Some(b.public()));

        // Releasing a key that holds no vanity is a no-op.
        let c = IdentityKey::generate();
        assert_eq!(alloc.release_vanity(&c.public()), None);
    }

    // ── Rule 5: network-name / directory non-shadow ──────────────────────────────────────────────

    #[test]
    fn rule5_vanity_cannot_shadow_an_operator_directory_identity() {
        let a = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();

        // Operator's own directory identities on this domain are reserved.
        alloc.reserve_localpart("postmaster");
        // A full on-domain address reserves just its local-part; an off-domain one is ignored.
        assert!(alloc.reserve_directory_address(&format!("founder@{GW}")));
        assert!(!alloc.reserve_directory_address("someone@other.net"));

        assert!(matches!(
            alloc.allocate_vanity(&a.public(), "postmaster"),
            Err(AliasError::ShadowsDirectoryIdentity(_))
        ));
        // Case-insensitive: the folded form still collides.
        assert!(matches!(
            alloc.allocate_vanity(&a.public(), "Founder"),
            Err(AliasError::ShadowsDirectoryIdentity(_))
        ));
        // A non-colliding vanity is still fine.
        assert_eq!(alloc.allocate_vanity(&a.public(), "founderx").unwrap(), format!("founderx@{GW}"));
    }

    // ── Rule 6: basic hygiene ────────────────────────────────────────────────────────────────────

    #[test]
    fn rule6_hygiene_rejections_fail_closed() {
        let k = IdentityKey::generate();
        let mut alloc = AliasAllocator::for_domain(GW).unwrap();
        let long = "a".repeat(65);
        for bad in [
            "",            // empty
            " ",           // whitespace only
            "with space",  // embedded whitespace
            "line\r\nbreak", // CRLF injection
            "nul\0byte",   // NUL
            "tab\tchar",   // control
            "bad!name",    // out-of-charset punctuation
            "emoji😀",     // non-ASCII
            long.as_str(), // over the 64-octet cap
        ] {
            assert!(
                matches!(alloc.allocate_vanity(&k.public(), bad), Err(AliasError::InvalidLocalPart(_))),
                "hygiene must reject {bad:?}"
            );
        }
        // A clean dot-free dot-atom is accepted (letters/digits/-/_/+).
        assert_eq!(alloc.allocate_vanity(&k.public(), "user_name-01+tag").unwrap(), format!("user_name-01+tag@{GW}"));
    }

    #[test]
    fn base32_lower_is_a_valid_vanity_charset() {
        let s = base32_lower(&[0xff, 0x00, 0x99, 0x12, 0x34]);
        assert!(!s.is_empty());
        assert!(is_valid_vanity_charset(&s));
    }
}
