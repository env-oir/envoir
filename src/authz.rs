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
//!   and collisions are refused fail-closed.
//!
//! Deterministic throughout: challenge freshness takes the clock as an explicit parameter and the
//! nonce is supplied by the caller (production draws it from the OS CSPRNG via [`random_nonce`]), so
//! the whole flow is exercised without a wall clock.

use std::collections::HashMap;
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

/// Why a vanity local-part could not be allocated (fail-closed).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AliasError {
    /// The requested local-part is empty or contains characters outside an RFC 5321 dot-atom.
    #[error("vanity local-part {0:?} is empty or not a valid dot-atom local-part")]
    InvalidLocalPart(String),
    /// The requested local-part is already allocated to a **different** key.
    #[error("vanity local-part {0:?} is already taken")]
    Taken(String),
    /// The requested local-part collides with the reserved key-derived form of another key.
    #[error("vanity local-part {0:?} collides with a reserved key-derived alias")]
    ReservedCollision(String),
}

/// Allocates local-parts for one domain (§7.10): the operator may grant a chosen **vanity** name to a
/// registered key, while the [`key_derived_localpart`] stays the stable default that always resolves.
/// [`Self::resolve`] accepts either form; [`Self::alias_for`] returns the vanity if one was allocated,
/// otherwise the key-derived default.
#[derive(Debug, Default, Clone)]
pub struct AliasAllocator {
    /// vanity local-part (lowercased) → public key
    vanity: HashMap<String, Vec<u8>>,
    /// public key → its allocated vanity local-part (lowercased)
    reverse: Vec<(Vec<u8>, String)>,
}

impl AliasAllocator {
    /// A fresh allocator with no vanity names (every key resolves by its key-derived default).
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate `local_part` as a vanity alias for `public_key` (§7.10). **Fail-closed**: rejects an
    /// invalid local-part, one already taken by a different key, or one that collides with the
    /// reserved key-derived alias of some *other* key (so a vanity name can never shadow another
    /// sender's stable default). Idempotent for the same key.
    pub fn allocate_vanity(&mut self, public_key: &[u8], local_part: &str) -> Result<(), AliasError> {
        let lp = local_part.trim().to_ascii_lowercase();
        if !is_valid_local_part(&lp) {
            return Err(AliasError::InvalidLocalPart(local_part.to_string()));
        }
        if let Some(existing) = self.vanity.get(&lp) {
            if existing == public_key {
                return Ok(()); // idempotent re-allocation of the same name to the same key
            }
            return Err(AliasError::Taken(local_part.to_string()));
        }
        // A vanity name must not shadow the reserved key-derived alias of a *different* key.
        if lp != key_derived_localpart(public_key) && is_key_derived_form(&lp) {
            return Err(AliasError::ReservedCollision(local_part.to_string()));
        }
        // Drop any prior vanity for this key (one vanity per key; the key-derived default remains).
        if let Some(pos) = self.reverse.iter().position(|(k, _)| k == public_key) {
            let (_, old) = self.reverse.remove(pos);
            self.vanity.remove(&old);
        }
        self.vanity.insert(lp.clone(), public_key.to_vec());
        self.reverse.push((public_key.to_vec(), lp));
        Ok(())
    }

    /// The address local-part to present for `public_key`: its vanity name if allocated, else the
    /// stable [`key_derived_localpart`] default (§7.10).
    pub fn alias_for(&self, public_key: &[u8]) -> String {
        self.reverse
            .iter()
            .find(|(k, _)| k == public_key)
            .map(|(_, lp)| lp.clone())
            .unwrap_or_else(|| key_derived_localpart(public_key))
    }

    /// Resolve a local-part (either a vanity name or a key-derived alias) back to its public key,
    /// checking against the registered set. A vanity name resolves via the allocation table; a
    /// key-derived alias resolves by matching it against each registered key's derived form.
    pub fn resolve(&self, local_part: &str, registered_keys: &[Vec<u8>]) -> Option<Vec<u8>> {
        let lp = local_part.trim().to_ascii_lowercase();
        if let Some(k) = self.vanity.get(&lp) {
            return Some(k.clone());
        }
        registered_keys.iter().find(|k| key_derived_localpart(k) == lp).cloned()
    }
}

/// Whether `lp` matches the reserved key-derived shape (`k` + 16 base32 chars) so a vanity request
/// for that exact shape is treated as reserved.
fn is_key_derived_form(lp: &str) -> bool {
    let Some(rest) = lp.strip_prefix('k') else { return false };
    rest.len() == 16 && rest.bytes().all(|c| BASE32_LOWER.contains(&c))
}

/// A conservative RFC 5321 dot-atom local-part check (letters, digits, and `.-_+`), non-empty, no
/// leading/trailing/double dot — enough to keep a vanity name safe as an SMTP address without quoting.
fn is_valid_local_part(lp: &str) -> bool {
    if lp.is_empty() || lp.len() > 64 || lp.starts_with('.') || lp.ends_with('.') || lp.contains("..") {
        return false;
    }
    lp.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'+'))
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

    #[test]
    fn key_derived_alias_is_stable_and_the_default() {
        let k = IdentityKey::generate();
        let a1 = key_derived_localpart(&k.public());
        let a2 = key_derived_localpart(&k.public());
        assert_eq!(a1, a2, "deterministic");
        assert!(a1.starts_with('k') && a1.len() == 17);
        assert!(is_key_derived_form(&a1));

        // With no vanity allocated, alias_for returns the key-derived default.
        let alloc = AliasAllocator::new();
        assert_eq!(alloc.alias_for(&k.public()), a1);
        // ...and it resolves back to the key.
        assert_eq!(alloc.resolve(&a1, &[k.public()]), Some(k.public()));
    }

    #[test]
    fn vanity_allocation_overrides_the_default_but_default_still_resolves() {
        let k = IdentityKey::generate();
        let mut alloc = AliasAllocator::new();
        alloc.allocate_vanity(&k.public(), "Alice").unwrap();

        // The presented alias is now the vanity form (lowercased)...
        assert_eq!(alloc.alias_for(&k.public()), "alice");
        // ...both the vanity and the stable key-derived default resolve to the key.
        assert_eq!(alloc.resolve("alice", &[k.public()]), Some(k.public()));
        assert_eq!(
            alloc.resolve(&key_derived_localpart(&k.public()), &[k.public()]),
            Some(k.public())
        );
    }

    #[test]
    fn vanity_collisions_and_invalid_names_fail_closed() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        let mut alloc = AliasAllocator::new();
        alloc.allocate_vanity(&a.public(), "team").unwrap();

        // Same name for a different key → Taken.
        assert_eq!(alloc.allocate_vanity(&b.public(), "team"), Err(AliasError::Taken("team".into())));
        // Re-allocating the same name to the same key is idempotent.
        alloc.allocate_vanity(&a.public(), "team").unwrap();
        // An invalid local-part → InvalidLocalPart.
        assert!(matches!(
            alloc.allocate_vanity(&b.public(), "bad name!"),
            Err(AliasError::InvalidLocalPart(_))
        ));
        // Trying to claim ANOTHER key's reserved key-derived alias as a vanity → ReservedCollision.
        let reserved = key_derived_localpart(&a.public());
        assert!(matches!(
            alloc.allocate_vanity(&b.public(), &reserved),
            Err(AliasError::ReservedCollision(_))
        ));
    }

    #[test]
    fn base32_lower_is_a_valid_local_part_charset() {
        let s = base32_lower(&[0xff, 0x00, 0x99, 0x12, 0x34]);
        assert!(!s.is_empty());
        assert!(is_valid_local_part(&s));
    }
}
