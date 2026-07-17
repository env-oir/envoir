//! API keys as **capability tokens** — the identity/authorization core of Envoir Send.
//!
//! An Envoir Send API key is a scoped, rotatable, independently-revocable
//! [`dmtap_core::capability::CapabilityToken`] (spec §13.5.1) rooted at the service owner's DMTAP
//! identity and granting exactly one least-privilege [`crate::scope::SendScope`] — *"send mail on
//! behalf of this identity"*. The bearer string the developer copies is a high-entropy secret
//! (`envoir_live_…`/`envoir_test_…`); the service stores only its content-address
//! ([`ContentId::of`]) → the backing token, never the secret itself. Verification is **offline and
//! fail-closed**: the token's own Ed25519 signature, its delegation chain + attenuation invariant
//! (§18.7.3), its validity window, and the published-revocation set are all checked before a key is
//! honored.
//!
//! ## The model
//! - [`SendService::issue_key`] mints a root capability (`iss = aud = owner`) for a scope → a fresh
//!   [`ApiKey`]. Multiple keys per identity (prod/test/per-service) each get a distinct nonce, hence
//!   a distinct token content-address, hence independent revocation.
//! - [`SendService::attenuate_key`] sub-delegates an existing key to a *narrower* scope, producing a
//!   real parent→child chain the core's attenuation invariant (§18.7.3) enforces — a widening is
//!   rejected fail-closed.
//! - [`SendService::rotate_key`] mints a replacement at the same scope/chain position and revokes
//!   the old one.
//! - [`SendService::revoke_key`] marks the key revoked locally **and** emits a real signed
//!   [`CapabilityRevocation`] (§18.7.3) for publication to the transparency log / status endpoint.
//! - [`SendService::verify_key`] resolves a bearer secret to an [`Authorization`] (the on-behalf-of
//!   identity + scope) or a fail-closed [`SendError`].

use std::collections::HashMap;
use std::fmt::Write as _;

use dmtap_core::capability::{CapabilityError, CapabilityRevocation, CapabilityToken};
use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::Hpke;
use dmtap_core::{ContentId, TimestampMs};
use rand_core::{OsRng, RngCore};

use crate::scope::{Environment, SendScope};

/// A fail-closed Envoir Send failure. Every authorization failure resolves to one of these — never
/// a silent accept. [`SendError::http_status`] maps each to its `POST /v1/send` status code.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SendError {
    /// No key with this secret is known (unknown/typo'd/deleted key). Fail closed.
    #[error("unauthorized: unknown API key")]
    Unauthorized,
    /// The key's backing capability (or a chain ancestor) is revoked (§18.7.3, `0x050B`).
    #[error("unauthorized: API key is revoked")]
    Revoked,
    /// The key's capability has expired — no eternal capability (§18.7.3).
    #[error("unauthorized: API key has expired")]
    Expired,
    /// The key's capability is not yet valid (`now < nbf`).
    #[error("unauthorized: API key is not yet valid")]
    NotYetValid,
    /// The backing token is rooted at a different identity than this service owns — a foreign
    /// capability the service must not honor.
    #[error("unauthorized: capability is not rooted at this service's owner identity")]
    WrongIssuer,
    /// The requested send is outside the key's scope (wrong sending domain, or not a send grant).
    #[error("forbidden: request is out of the key's scope")]
    OutOfScope,
    /// The key's per-minute rate ceiling (a signed caveat) is exhausted for the current window.
    #[error("rate limited: the key's per-minute ceiling is exhausted")]
    RateLimited,
    /// A capability-chain / attenuation / signature failure (§18.7.3, `0x0508`).
    #[error("capability chain invalid: {0}")]
    Capability(#[from] CapabilityError),
    /// The recipient could not be resolved by the [`crate::seam::Resolver`] seam.
    #[error("recipient resolution failed: {0}")]
    Resolve(String),
    /// The [`crate::seam::Delivery`] transport rejected the sealed MOTE.
    #[error("delivery failed: {0}")]
    Delivery(String),
    /// The MOTE could not be built/sealed (bad recipient key material, etc.).
    #[error("mote build failed: {0}")]
    Build(String),
}

impl SendError {
    /// The `POST /v1/send` HTTP status code for this failure.
    pub fn http_status(&self) -> u16 {
        match self {
            SendError::Unauthorized
            | SendError::Revoked
            | SendError::Expired
            | SendError::NotYetValid
            | SendError::WrongIssuer
            | SendError::Capability(_) => 401,
            SendError::OutOfScope => 403,
            SendError::RateLimited => 429,
            SendError::Resolve(_) => 422,
            SendError::Delivery(_) => 502,
            SendError::Build(_) => 500,
        }
    }
}

/// Map a core [`CapabilityError`] onto the fail-closed [`SendError`], surfacing the window/revocation
/// cases as their own variants and keeping structural failures as [`SendError::Capability`].
fn map_cap(e: CapabilityError) -> SendError {
    match e {
        CapabilityError::Expired => SendError::Expired,
        CapabilityError::NotYetValid => SendError::NotYetValid,
        CapabilityError::Revoked => SendError::Revoked,
        other => SendError::Capability(other),
    }
}

/// A freshly minted API key. The `secret` is returned **once** at creation (the service never stores
/// it in the clear — only its content-address); the caller must persist it. The backing capability
/// token (and its ancestor chain, if attenuated) is exposed for inspection/publication.
#[derive(Debug, Clone)]
pub struct ApiKey {
    secret: String,
    hash: ContentId,
    token: CapabilityToken,
    chain: Vec<CapabilityToken>,
    environment: Environment,
}

impl ApiKey {
    /// The bearer secret the developer sends as `Authorization: Bearer <secret>`. Available only on
    /// the freshly minted key.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The content-address the service keys this secret under (never reveals the secret).
    pub fn hash(&self) -> &ContentId {
        &self.hash
    }

    /// The backing capability token (§18.7.3).
    pub fn token(&self) -> &CapabilityToken {
        &self.token
    }

    /// The token's ancestor chain (nearest-parent first); empty for a root key.
    pub fn chain(&self) -> &[CapabilityToken] {
        &self.chain
    }

    /// The token's content-address — the value a [`CapabilityRevocation`] names to revoke it.
    pub fn content_id(&self) -> ContentId {
        self.token.content_id()
    }

    /// The prod/test partition of this key.
    pub fn environment(&self) -> Environment {
        self.environment
    }
}

/// The authorization a verified API key resolves to: the on-behalf-of identity and the granted
/// scope. Returned by [`SendService::verify_key`] only after every fail-closed check has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The identity the send acts on behalf of — the capability's root issuer (the service owner).
    pub identity: Vec<u8>,
    /// The least-privilege grant this key carries.
    pub scope: SendScope,
    /// The prod/test partition.
    pub environment: Environment,
    /// The service's internal key handle (content-address of the secret) — for rate accounting.
    pub key_hash: ContentId,
}

/// The internal record the service keeps per key. Only the content-address of the secret is stored,
/// never the secret. Holds the backing token + its chain (for offline attenuation verification), the
/// scope, revocation flag, and the fixed-window rate-limit counter.
#[derive(Debug, Clone)]
struct KeyRecord {
    token: CapabilityToken,
    chain: Vec<CapabilityToken>,
    scope: SendScope,
    revoked: bool,
    rl_window: u64,
    rl_count: u64,
}

/// The Envoir Send service: the owner identity (which signs both capabilities and outgoing MOTEs),
/// the suite-`0x01` payload sealer, the key store, and the published-revocation set.
///
/// The service owner's [`IdentityKey`] is bound at construction: it is the single on-behalf-of
/// identity every key this service mints delegates from, and the identity every MOTE this service
/// sends is signed under. This is the sovereign posture — *you* run the send service with *your*
/// key, and API keys are scoped, revocable delegations of the right to trigger sends.
pub struct SendService {
    signing: IdentityKey,
    seal: Hpke,
    keys: HashMap<ContentId, KeyRecord>,
    revocations: Vec<ContentId>,
    published: Vec<CapabilityRevocation>,
}

impl SendService {
    /// Construct a service owned by `owner`. `owner` is the on-behalf-of identity for every key and
    /// MOTE.
    pub fn new(owner: IdentityKey) -> Self {
        SendService {
            signing: owner,
            seal: Hpke,
            keys: HashMap::new(),
            revocations: Vec::new(),
            published: Vec::new(),
        }
    }

    /// The owner identity's public key (the on-behalf-of identity).
    pub fn owner_identity(&self) -> Vec<u8> {
        self.signing.public()
    }

    /// The suite-`0x01` payload sealer (crate-internal, used by the send pipeline).
    pub(crate) fn sealer(&self) -> &Hpke {
        &self.seal
    }

    /// The owner signing key (crate-internal, used by the send pipeline to sign MOTEs).
    pub(crate) fn signer(&self) -> &IdentityKey {
        &self.signing
    }

    /// The revocations this service has published (real signed [`CapabilityRevocation`] objects,
    /// §18.7.3) — for appending to the transparency log / status endpoint.
    pub fn published_revocations(&self) -> &[CapabilityRevocation] {
        &self.published
    }

    /// Mint a **root** API key for `scope`: a capability rooted at (and delegated to) the owner
    /// identity, valid for `[now, now + ttl_ms)`. Each call gets a fresh nonce, so distinct keys —
    /// e.g. a prod and a test key — are independently revocable.
    pub fn issue_key(&mut self, scope: SendScope, now: TimestampMs, ttl_ms: u64) -> ApiKey {
        let caps = vec![scope.to_capability()];
        let token = CapabilityToken::issue(
            &self.signing,
            self.signing.public(),
            caps,
            now,
            now.saturating_add(ttl_ms),
            random_bytes(16),
            None,
        );
        self.store_key(token, Vec::new(), scope)
    }

    /// Sub-delegate an existing key (`parent_secret`) to a **narrower** `child_scope` — a real
    /// attenuated child capability. The core's attenuation invariant is enforced *before* the child
    /// is stored ([`CapabilityToken::verify_chain`]): a `child_scope` that widens the parent (a
    /// broader domain, an added ability, a loosened caveat) is rejected fail-closed as
    /// [`SendError::Capability`] and no key is created.
    pub fn attenuate_key(
        &mut self,
        parent_secret: &str,
        child_scope: SendScope,
        now: TimestampMs,
        ttl_ms: u64,
    ) -> Result<ApiKey, SendError> {
        let phash = ContentId::of(parent_secret.as_bytes());
        let prec = self.keys.get(&phash).ok_or(SendError::Unauthorized)?;
        if prec.revoked {
            return Err(SendError::Revoked);
        }
        let parent = prec.token.clone();
        let mut chain = Vec::with_capacity(prec.chain.len() + 1);
        chain.push(parent.clone());
        chain.extend(prec.chain.iter().cloned());

        let caps = vec![child_scope.to_capability()];
        // A delegated child MUST NOT outlive its delegator (§18.7.3 window nesting): clamp the
        // child's expiry to the parent's and its not-before to ≥ the parent's, so the minted chain
        // is always window-nested and `verify_chain` accepts it.
        let nbf = now.max(parent.nbf);
        let exp = now.saturating_add(ttl_ms).min(parent.exp);
        let token = CapabilityToken::issue(
            &self.signing,
            self.signing.public(),
            caps,
            nbf,
            exp,
            random_bytes(16),
            Some(parent.content_id()),
        );
        // Enforce the §18.7.3 attenuation invariant now — a widening never becomes a live key.
        token.verify_chain(&chain).map_err(map_cap)?;
        Ok(self.store_key(token, chain, child_scope))
    }

    /// Rotate a key: mint a replacement at the same scope and chain position (a fresh secret + fresh
    /// token nonce), then **revoke the old one**. Returns the new [`ApiKey`]; the old secret stops
    /// verifying immediately.
    pub fn rotate_key(
        &mut self,
        secret: &str,
        now: TimestampMs,
        ttl_ms: u64,
    ) -> Result<ApiKey, SendError> {
        let hash = ContentId::of(secret.as_bytes());
        let rec = self.keys.get(&hash).ok_or(SendError::Unauthorized)?;
        // A revoked key must NOT be rotatable — otherwise a holder of a leaked-then-revoked secret
        // could mint a fresh, unrevoked token at the same scope (the new token has a new content_id
        // absent from the revocation set), defeating the kill-switch. Mirror attenuate_key's guard.
        if rec.revoked {
            return Err(SendError::Revoked);
        }
        let scope = rec.scope.clone();
        let chain = rec.chain.clone();
        let prnt = rec.token.prnt.clone();

        let caps = vec![scope.to_capability()];
        // Keep the rotated key window-nested inside its (unchanged) parent (§18.7.3): a rotation
        // must not let a child outlive the delegator it descends from. For a root key (empty chain)
        // there is no parent to clamp against.
        let (nbf, exp) = match chain.first() {
            Some(parent) => (now.max(parent.nbf), now.saturating_add(ttl_ms).min(parent.exp)),
            None => (now, now.saturating_add(ttl_ms)),
        };
        let token = CapabilityToken::issue(
            &self.signing,
            self.signing.public(),
            caps,
            nbf,
            exp,
            random_bytes(16),
            prnt,
        );
        if !chain.is_empty() {
            token.verify_chain(&chain).map_err(map_cap)?;
        }
        let new_key = self.store_key(token, chain, scope);
        self.revoke_key(secret, now)?;
        Ok(new_key)
    }

    /// Revoke a key: mark it revoked locally **and** emit a real signed [`CapabilityRevocation`]
    /// (§18.7.3), naming the backing token's content-address, for publication. After this the secret
    /// fails closed, and any child attenuated from it fails closed too (a revoked chain-root revokes
    /// its descendants, checked in [`verify_key`](SendService::verify_key)).
    pub fn revoke_key(
        &mut self,
        secret: &str,
        now: TimestampMs,
    ) -> Result<CapabilityRevocation, SendError> {
        let hash = ContentId::of(secret.as_bytes());
        let target = {
            let rec = self.keys.get_mut(&hash).ok_or(SendError::Unauthorized)?;
            rec.revoked = true;
            rec.token.content_id()
        };
        let rev = CapabilityRevocation::issue(&self.signing, target.clone(), now);
        self.revocations.push(target);
        self.published.push(rev.clone());
        Ok(rev)
    }

    /// Verify a bearer secret and resolve it to an [`Authorization`], or a fail-closed
    /// [`SendError`]. Checks, in order: the key is known; not locally revoked; rooted at this
    /// service's owner; the token's own signature + delegation chain + attenuation invariant
    /// ([`CapabilityToken::verify_chain`]); and the validity window + published-revocation set for
    /// the token **and every chain ancestor** ([`CapabilityToken::verify_at`]).
    pub fn verify_key(&self, api_key: &str, now: TimestampMs) -> Result<Authorization, SendError> {
        let hash = ContentId::of(api_key.as_bytes());
        let rec = self.keys.get(&hash).ok_or(SendError::Unauthorized)?;
        if rec.revoked {
            return Err(SendError::Revoked);
        }
        if rec.token.iss != self.signing.public() {
            return Err(SendError::WrongIssuer);
        }
        // Signature + chain continuity + attenuation invariant (offline, §18.7.3).
        rec.token.verify_chain(&rec.chain).map_err(map_cap)?;
        // Validity window + revocation, for the token and each ancestor (a revoked ancestor
        // revokes this descendant, §18.7.3).
        rec.token.verify_at(now, &self.revocations).map_err(map_cap)?;
        for anc in &rec.chain {
            anc.verify_at(now, &self.revocations).map_err(map_cap)?;
        }
        Ok(Authorization {
            identity: rec.token.iss.clone(),
            scope: rec.scope.clone(),
            environment: rec.scope.environment,
            key_hash: hash,
        })
    }

    /// Charge one send against a key's per-minute rate ceiling (a signed `rate_per_min` caveat),
    /// using a deterministic fixed 60 s window driven by the `now` parameter (no wall clock, §16.1).
    /// A key with no ceiling is unlimited. Called by the send pipeline after authorization.
    pub(crate) fn charge_rate(&mut self, key_hash: &ContentId, now: TimestampMs) -> Result<(), SendError> {
        let rec = self.keys.get_mut(key_hash).ok_or(SendError::Unauthorized)?;
        let per_min = match rec.scope.rate_per_min {
            Some(n) => n,
            None => return Ok(()),
        };
        let window = now / 60_000;
        if rec.rl_window != window {
            rec.rl_window = window;
            rec.rl_count = 0;
        }
        if rec.rl_count >= per_min {
            return Err(SendError::RateLimited);
        }
        rec.rl_count += 1;
        Ok(())
    }

    /// Insert a minted token under a fresh high-entropy secret and return the one-time [`ApiKey`].
    fn store_key(&mut self, token: CapabilityToken, chain: Vec<CapabilityToken>, scope: SendScope) -> ApiKey {
        let environment = scope.environment;
        let secret = random_secret(environment);
        let hash = ContentId::of(secret.as_bytes());
        self.keys.insert(
            hash.clone(),
            KeyRecord { token: token.clone(), chain: chain.clone(), scope, revoked: false, rl_window: 0, rl_count: 0 },
        );
        ApiKey { secret, hash, token, chain, environment }
    }
}

/// A high-entropy bearer secret: the environment prefix + 32 random hex bytes.
fn random_secret(env: Environment) -> String {
    format!("{}{}", env.secret_prefix(), hex(&random_bytes(32)))
}

/// `n` bytes from the OS CSPRNG.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Lowercase hex encoding (no extra crate).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> IdentityKey {
        IdentityKey::from_seed(&[0x42; 32])
    }

    const YEAR: u64 = 365 * 24 * 60 * 60 * 1000;

    #[test]
    fn issue_and_verify_round_trip() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        assert!(key.secret().starts_with("envoir_live_"));
        let auth = svc.verify_key(key.secret(), now).unwrap();
        assert_eq!(auth.identity, svc.owner_identity());
        assert_eq!(auth.scope, SendScope::account(Environment::Prod));
        assert_eq!(auth.environment, Environment::Prod);
    }

    #[test]
    fn unknown_key_fails_closed() {
        let svc = SendService::new(owner());
        assert_eq!(svc.verify_key("envoir_live_deadbeef", 1), Err(SendError::Unauthorized));
    }

    #[test]
    fn expired_key_fails_closed() {
        let mut svc = SendService::new(owner());
        let now = 1_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, 60_000);
        assert!(svc.verify_key(key.secret(), now + 30_000).is_ok());
        assert_eq!(svc.verify_key(key.secret(), now + 60_000), Err(SendError::Expired));
    }

    #[test]
    fn not_yet_valid_key_fails_closed() {
        let mut svc = SendService::new(owner());
        let now = 1_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, 60_000);
        assert_eq!(svc.verify_key(key.secret(), now - 1), Err(SendError::NotYetValid));
    }

    #[test]
    fn revoked_key_fails_closed_and_publishes_revocation() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        assert!(svc.verify_key(key.secret(), now).is_ok());
        let rev = svc.revoke_key(key.secret(), now + 1).unwrap();
        // The revocation is a real signed object naming the token's content-address.
        assert!(rev.verify().is_ok());
        assert_eq!(rev.token, key.content_id());
        assert_eq!(svc.published_revocations().len(), 1);
        assert_eq!(svc.verify_key(key.secret(), now + 2), Err(SendError::Revoked));
    }

    #[test]
    fn rotate_mints_new_and_revokes_old() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let old = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let new = svc.rotate_key(old.secret(), now + 1, YEAR).unwrap();
        assert_ne!(old.secret(), new.secret());
        // Old rejected, new accepted.
        assert_eq!(svc.verify_key(old.secret(), now + 2), Err(SendError::Revoked));
        assert!(svc.verify_key(new.secret(), now + 2).is_ok());
    }

    #[test]
    fn revoked_key_cannot_be_rotated_back_to_life() {
        // A leaked-then-revoked key must not be resurrectable via rotate_key (kill-switch bypass).
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        svc.revoke_key(key.secret(), now + 1).unwrap();
        assert!(matches!(svc.rotate_key(key.secret(), now + 2, YEAR), Err(SendError::Revoked)));
        // Still revoked — no fresh live token was minted.
        assert_eq!(svc.verify_key(key.secret(), now + 3), Err(SendError::Revoked));
    }

    #[test]
    fn multiple_keys_are_independently_revocable() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let prod = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let test = svc.issue_key(SendScope::account(Environment::Test), now, YEAR);
        assert_ne!(prod.content_id(), test.content_id());
        svc.revoke_key(prod.secret(), now + 1).unwrap();
        assert_eq!(svc.verify_key(prod.secret(), now + 2), Err(SendError::Revoked));
        // The test key is untouched.
        assert!(svc.verify_key(test.secret(), now + 2).is_ok());
    }

    #[test]
    fn attenuated_child_verifies_and_narrows() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        // Parent: whole account, no rate ceiling.
        let parent = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        // Child: narrowed to one domain + a rate ceiling — a valid attenuation.
        let child_scope = SendScope::domain("example.com", Environment::Prod).with_rate_per_min(30);
        let child = svc.attenuate_key(parent.secret(), child_scope.clone(), now, YEAR).unwrap();
        assert_eq!(child.chain().len(), 1);
        let auth = svc.verify_key(child.secret(), now).unwrap();
        assert_eq!(auth.scope, child_scope);
    }

    #[test]
    fn widening_attenuation_is_rejected() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        // Parent narrowed to one domain.
        let parent = svc.issue_key(SendScope::domain("example.com", Environment::Prod), now, YEAR);
        // Child tries to WIDEN back to the whole account — a privilege escalation.
        let widen = SendScope::account(Environment::Prod);
        let err = svc.attenuate_key(parent.secret(), widen, now, YEAR).unwrap_err();
        assert!(matches!(err, SendError::Capability(CapabilityError::AttenuationViolation)));
    }

    #[test]
    fn revoking_parent_revokes_attenuated_child() {
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let parent = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        let child = svc
            .attenuate_key(parent.secret(), SendScope::domain("example.com", Environment::Prod), now, YEAR)
            .unwrap();
        assert!(svc.verify_key(child.secret(), now).is_ok());
        // Revoke the PARENT; the child's chain check hits the revoked ancestor → fail closed.
        svc.revoke_key(parent.secret(), now + 1).unwrap();
        assert_eq!(svc.verify_key(child.secret(), now + 2), Err(SendError::Revoked));
    }

    #[test]
    fn foreign_capability_is_not_honored() {
        // A capability rooted at a DIFFERENT identity, injected into the store, must be rejected.
        let mut svc = SendService::new(owner());
        let now = 1_700_000_000_000;
        let key = svc.issue_key(SendScope::account(Environment::Prod), now, YEAR);
        // Re-key the service to a different owner; the previously issued key is now foreign.
        svc.signing = IdentityKey::from_seed(&[0x99; 32]);
        assert_eq!(svc.verify_key(key.secret(), now), Err(SendError::WrongIssuer));
    }
}
