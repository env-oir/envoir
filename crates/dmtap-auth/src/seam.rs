//! Seams (§13.3.1, §13.4): the injectable boundaries where a real WebAuthn/PRF front-end, a real
//! HTTP/DB layer, and a real `name → key` resolver slot into the crypto core. The library ships
//! in-memory / stub implementations so the ceremony is fully testable; production replaces them.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use dmtap_core::identity::DeviceCert;
use dmtap_core::TimestampMs;

use crate::error::AuthError;

// ── Time ─────────────────────────────────────────────────────────────────────────────────────

/// A clock seam. DMTAP transports timestamps explicitly and never relies on synchronized clocks
/// for correctness (§16.1); the RP reads *its own* clock to judge expiry and freshness.
pub trait Clock {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> TimestampMs;
}

/// The production clock: the host wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> TimestampMs {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ── Single-use store ─────────────────────────────────────────────────────────────────────────

/// A single-use / replay-prevention store (§18.7.1 nonce cache; §13.4 DPoP `jti`). Production
/// backs this with a shared DB/Redis keyed by the value with a TTL; the reference ships an
/// in-memory map.
pub trait ReplayCache {
    /// Atomically check-and-reserve `id` until `expiry_ms`. Returns `true` if `id` was previously
    /// unseen (now reserved), `false` if it was already reserved — i.e. a replay. `now_ms` lets
    /// the store prune expired entries. Reservation is the **final** gate in verification, so an
    /// invalid attempt never burns a nonce.
    fn check_and_reserve(&mut self, id: &[u8], expiry_ms: TimestampMs, now_ms: TimestampMs) -> bool;
}

/// A simple in-memory [`ReplayCache`] for tests and single-process RPs.
#[derive(Debug, Default)]
pub struct InMemoryReplayCache {
    seen: HashMap<Vec<u8>, TimestampMs>,
}

impl InMemoryReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_reserve(&mut self, id: &[u8], expiry_ms: TimestampMs, now_ms: TimestampMs) -> bool {
        self.seen.retain(|_, exp| *exp > now_ms); // prune expired reservations
        if self.seen.contains_key(id) {
            return false; // replay
        }
        self.seen.insert(id.to_vec(), expiry_ms);
        true
    }
}

// ── Trusted client (WebAuthn/PRF/companion) ──────────────────────────────────────────────────

/// The **trusted client** seam (§13.3.1) — the load-bearing anti-phishing component. In a
/// browser this is **WebAuthn**: it writes the *machine-observed* origin into `clientDataJSON`
/// and scopes credentials by `rpId`, so an assertion produced at `alice-yourdomain.evil.com`
/// cannot validate for `yourdomain`. The crypto core NEVER trusts an origin handed to it by the
/// RP; it takes the origin from this seam.
///
/// A real implementation is a WebAuthn/PRF authenticator or an authenticated paired companion
/// client (§13.3.1). [`TrustedClientStub`] is a test double, not for production.
pub trait TrustedClient {
    /// The origin this client actually observes — the machine truth (navigated origin), not a
    /// value from the RP. The client compares it against the challenge and refuses on mismatch.
    fn observed_origin(&self) -> &str;

    /// Run user-verification (biometric/PIN/passkey PRF) and gate signing on it. Real impl = the
    /// WebAuthn ceremony; returns [`AuthError::UnauthorizedSigner`] if the user declines.
    fn user_verify(&self) -> Result<(), AuthError>;
}

/// A test/stub [`TrustedClient`]: a fixed observed origin and a settable user-verification
/// outcome. **Not for production** — a real deployment MUST use WebAuthn/PRF or an authenticated
/// companion (§13.3.1); this double lets the ceremony tests exercise the origin-binding seam.
#[derive(Debug, Clone)]
pub struct TrustedClientStub {
    /// The origin the stub pretends the machine observed.
    pub observed_origin: String,
    /// Whether user-verification succeeds.
    pub uv_ok: bool,
}

impl TrustedClientStub {
    /// A stub that observes `origin` and passes user-verification.
    pub fn new(origin: impl Into<String>) -> Self {
        TrustedClientStub { observed_origin: origin.into(), uv_ok: true }
    }
}

impl TrustedClient for TrustedClientStub {
    fn observed_origin(&self) -> &str {
        &self.observed_origin
    }
    fn user_verify(&self) -> Result<(), AuthError> {
        if self.uv_ok {
            Ok(())
        } else {
            Err(AuthError::UnauthorizedSigner)
        }
    }
}

// ── Device authorization (§3.4 name → key) ───────────────────────────────────────────────────

/// Resolves whether a login signer (`Assertion.from`) is an `IK`-authorized signer for the pinned
/// identity (§3.4, §13.3 step 6). Production resolves `name → key` via DNS + key transparency and
/// checks the published device certs / KeyPackage; [`DeviceCertAuthorizer`] does it from
/// in-memory [`DeviceCert`]s.
pub trait DeviceAuthorizer {
    /// Is `signer_pub` either the pinned `ik_pub` itself, or a device key authorized by it and
    /// unexpired at `now_ms`? (§1.2)
    fn is_authorized(&self, ik_pub: &[u8], signer_pub: &[u8], now_ms: TimestampMs) -> bool;
}

/// A [`DeviceAuthorizer`] backed by real [`dmtap_core`] device certs. It accepts the login signer
/// iff it is the pinned `IK` itself, **or** a device key carried by a cert that (a) is
/// self-consistent and signed by that same pinned `IK`, (b) names `signer_pub` as its device key,
/// and (c) has not expired. A cert signed by some *other* IK is ignored — that is the
/// wrong-identity-key rejection.
#[derive(Debug, Clone, Default)]
pub struct DeviceCertAuthorizer {
    certs: Vec<DeviceCert>,
}

impl DeviceCertAuthorizer {
    /// An authorizer with no device certs (only IK-direct signing is authorized).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a device cert to the authorized set. The cert's signature is re-verified on every
    /// [`DeviceAuthorizer::is_authorized`] call, so an untrusted caller cannot inject a forged one.
    pub fn with_cert(mut self, cert: DeviceCert) -> Self {
        self.certs.push(cert);
        self
    }
}

impl DeviceAuthorizer for DeviceCertAuthorizer {
    fn is_authorized(&self, ik_pub: &[u8], signer_pub: &[u8], now_ms: TimestampMs) -> bool {
        // IK signing on its own authority (§1.2 permits IK-direct logins).
        if signer_pub == ik_pub {
            return true;
        }
        self.certs.iter().any(|c| {
            c.ik == ik_pub                       // authorized by THIS pinned identity, not another
                && c.device_key == signer_pub    // this cert authorizes exactly this signer
                && c.expires.map(|e| e > now_ms).unwrap_or(true) // unexpired
                && c.verify().is_ok() // IK's signature over the cert re-checked (fail closed)
        })
    }
}
