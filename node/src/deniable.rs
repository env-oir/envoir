//! Deniable 1:1 messaging — the node's optional repudiable pairwise channel (spec §5.2.1).
//!
//! Alongside the signed 1:1 HPKE path ([`crate::node`]) and the MLS group path ([`crate::group`]),
//! a node can open a **deniable** 1:1 session: an X3DH handshake over a dedicated, `IK`-certified
//! X25519 `idk`, then a Double Ratchet whose only authentication is the AEAD tag (a shared-key MAC).
//! Because either party could have produced any transcript, neither can prove the other authored a
//! message — cryptographic repudiation (§5.2.1). This module wires the workspace-shared
//! [`dmtap_deniable`] crate into the [`Node`](crate::node::Node) and routes a real
//! [`DeniablePayload`] (a MOTE with its identity signature removed, §18.3.10) through it.
//!
//! ## Distinct from MLS (spec §5.2.1)
//! This is **not** an MLS group: no committer, no epoch log, no roster. It is a pairwise ratchet
//! keyed off the peer's published [`DeniablePrekeyBundle`]. The node keys live sessions by the
//! **peer's deniable identity key** so subsequent messages route to the right ratchet.
//!
//! ## What is real
//! - **X3DH root derivation**, the Double Ratchet, per-message forward secrecy, and the
//!   shared-key-MAC authentication — the full seal→open round-trip of a [`DeniablePayload`] — all
//!   run via [`dmtap_deniable`]. A tampered/rewound message fails closed.
//! - **Identity-bound deniable prekey (§5.2.1(a), §1.2).** §5.2.1 mandates a **dedicated** long-term
//!   key set so the sign-only root `IK` never does DH. The node provisions a distinct
//!   [`DeniableIdentity`] (its own Ed25519 key certifying a fresh X25519 `idk`) — and that deniable
//!   Ed25519 key is now itself bound to the node's **root `IK`** by a [`DeviceCert`] (§1.2). The
//!   published unit is therefore a [`CertifiedBundle`] / [`CertifiedInit`]: the deniable prekeys plus
//!   the root-IK cert over the deniable identity key. A peer resolves the claimed identity via KT and
//!   **verifies** that cert (`cert.ik == KT-resolved root IK` and `cert.device_key == the presented
//!   deniable IK`) before trusting the session; any mismatch fails closed. The full certification
//!   chain is `root IK ──DeviceCert──▶ deniable Ed25519 IK ──idk_sig──▶ idk`, so `root IK` only ever
//!   *signs* (never does DH), and the peer can prove the deniable prekey belongs to the claimed
//!   identity.
//!
//! ## Repudiation is preserved
//! The [`DeviceCert`] certifies a **key**, never a message. Message authentication remains solely the
//! Double-Ratchet shared-key MAC (the AEAD tag), which *either* party can compute — so the
//! transcript stays repudiable ([`DeniableSession::forge_peer_message`]). Binding the prekey to the
//! identity lets a peer trust *who* the deniable identity is; it does not make any message
//! non-repudiable *content*.

use std::collections::HashMap;

use dmtap_core::deniable::{DeniableInit, DeniableMessage, DeniablePayload, DeniablePrekeyBundle};
use dmtap_core::identity::{Cap, DeviceCert, IdentityKey};
use dmtap_core::TimestampMs;

pub use self::admission::{DeniableAcceptLimits, DeniableAdmission, DeniableAdmissionSnapshot};

pub use dmtap_deniable::{DeniableError, DeniableIdentity, DeniableResponder, DeniableSession};

/// The `DeviceCert` label for the root-IK certification of a deniable identity key (§5.2.1, §1.2).
const DENIABLE_DEVICE_LABEL: &str = "deniable-1to1";

/// A published deniable prekey bundle together with the root-IK [`DeviceCert`] that binds its
/// dedicated deniable identity key (`bundle.ik`) to the publisher's **root identity** (§5.2.1(a),
/// §1.2). This is the advertised unit: a peer verifies `cert` against the publisher's KT-resolved
/// root IK before opening a session ([`Node::deniable_open`](crate::node::Node::deniable_open)).
#[derive(Debug, Clone)]
pub struct CertifiedBundle {
    /// The signed X3DH prekey bundle (its `ik` is the *deniable* Ed25519 key, not the root IK).
    pub bundle: DeniablePrekeyBundle,
    /// Root-IK cert over `bundle.ik` (`device_key == bundle.ik`, `ik == publisher's root IK`).
    pub cert: DeviceCert,
}

/// A deniable X3DH init together with the root-IK [`DeviceCert`] binding the initiator's dedicated
/// deniable identity key (`init.ik_a`) to their **root identity** (§5.2.1(a), §1.2). The responder
/// verifies `cert` against the initiator's KT-resolved root IK before accepting.
#[derive(Debug, Clone)]
pub struct CertifiedInit {
    /// The X3DH first message (its `ik_a` is the *deniable* Ed25519 key, not the root IK).
    pub init: DeniableInit,
    /// Root-IK cert over `init.ik_a` (`device_key == init.ik_a`, `ik == initiator's root IK`).
    pub cert: DeviceCert,
}

/// Issue the root-IK [`DeviceCert`] that binds a dedicated deniable identity key to the root
/// identity (§5.2.1(a), §1.2). The `root_ik` signs over the deniable Ed25519 public `deniable_ik`
/// — a certification of a **key**, never a message, so it is deniability-neutral.
pub(crate) fn issue_deniable_binding(
    root_ik: &IdentityKey,
    deniable_ik: &[u8],
    ts: TimestampMs,
) -> DeviceCert {
    DeviceCert::issue(
        root_ik,
        deniable_ik.to_vec(),
        DENIABLE_DEVICE_LABEL,
        ts,
        None,
        vec![Cap::Send, Cap::Recv],
    )
}

/// Verify, **fail-closed**, that `cert` binds `deniable_ik` to the peer's KT-resolved root identity
/// `peer_root_ik` (§5.2.1(a), §1.2). Three independent checks, any of which rejects:
///
/// 1. `cert` is self-consistent — its signature verifies under `cert.ik` ([`DeviceCert::verify`]).
/// 2. `cert.ik` is exactly the peer's **KT-resolved root IK** (not some attacker-chosen root).
/// 3. `cert.device_key` is exactly the **presented deniable IK** (`bundle.ik` / `init.ik_a`) — so a
///    valid cert cannot be replayed to vouch for a *different* deniable key.
///
/// Combined with `dmtap_deniable`'s existing `idk`/`idk_a` certification under that deniable IK, the
/// whole chain `root IK ▶ deniable IK ▶ idk` is verified. Certifying the key never touches messages,
/// so repudiation is untouched.
pub(crate) fn verify_deniable_binding(
    peer_root_ik: &[u8],
    deniable_ik: &[u8],
    cert: &DeviceCert,
) -> Result<(), DeniableRouteError> {
    cert.verify().map_err(|_| DeniableRouteError::UncertifiedIdentity)?;
    if cert.ik.as_slice() != peer_root_ik {
        return Err(DeniableRouteError::UncertifiedIdentity);
    }
    if cert.device_key.as_slice() != deniable_ik {
        return Err(DeniableRouteError::UncertifiedIdentity);
    }
    Ok(())
}

/// The default number of one-time prekeys a node offers in its published bundle (§5.2.1 replay
/// defense: an initiator prefers an opk, so more opks = more replay-resistant first messages).
pub const DEFAULT_OPKS: usize = 8;

/// A node-level deniable-routing failure (spec §5.2.1): either the underlying session crypto
/// ([`DeniableError`]), or a node-level routing precondition (no session / not a responder yet).
#[derive(Debug)]
pub enum DeniableRouteError {
    /// The underlying deniable session layer rejected the operation (bad certification, MAC
    /// failure, replayed init, unsupported suite, …) — the fail-closed crypto outcome.
    Session(DeniableError),
    /// No live deniable session for this peer — open one first ([`Node::deniable_open`] as the
    /// initiator, or [`Node::deniable_accept`] as the responder).
    ///
    /// [`Node::deniable_open`]: crate::node::Node::deniable_open
    /// [`Node::deniable_accept`]: crate::node::Node::deniable_accept
    NoSession,
    /// This node has not published a prekey bundle, so it cannot accept an incoming init — call
    /// [`Node::deniable_publish_bundle`](crate::node::Node::deniable_publish_bundle) first (§5.2.1).
    NotResponder,
    /// The peer's deniable identity key is **not** certified by their KT-resolved root identity — the
    /// [`DeviceCert`] failed its own signature, named a root IK other than the KT-resolved one, or
    /// certified a different deniable key than the one presented. Fail-closed (§5.2.1(a), §1.2): a
    /// deniable session is never established with an identity the peer cannot vouch for.
    UncertifiedIdentity,
    /// The inbound deniable-init admission gate ([`DeniableAdmission`]) throttled this init before
    /// any one-time prekey was consumed (audit #4 — OPK-depletion defense). A `DeniableInit`
    /// authenticates only *after* X3DH consumes a prekey, so an unsolicited flood of self-signed
    /// inits could otherwise burn the responder's OPK pool and force the weak last-resort path. The
    /// node throttles accepts (per-source + global token buckets) *before* touching a prekey, so the
    /// pool is preserved; the initiator's own retry re-offers once the bucket refills.
    RateLimited,
}

impl From<DeniableError> for DeniableRouteError {
    fn from(e: DeniableError) -> Self {
        DeniableRouteError::Session(e)
    }
}

impl std::fmt::Display for DeniableRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeniableRouteError::Session(e) => write!(f, "deniable session error: {e}"),
            DeniableRouteError::NoSession => f.write_str("no live deniable session for this peer"),
            DeniableRouteError::NotResponder => {
                f.write_str("node has no published deniable prekey bundle (not a responder yet)")
            }
            DeniableRouteError::UncertifiedIdentity => f.write_str(
                "peer's deniable identity key is not certified by its KT-resolved root identity",
            ),
            DeniableRouteError::RateLimited => f.write_str(
                "inbound deniable init throttled by the accept admission gate (OPK-depletion \
                 defense) — no one-time prekey was consumed",
            ),
        }
    }
}
impl std::error::Error for DeniableRouteError {}

/// The node's deniable-1:1 subsystem state (spec §5.2.1): a dedicated initiator identity (lazy), an
/// optional responder half (its own identity + published bundle), and the live sessions keyed by the
/// **peer's** deniable identity key. Held inside the [`Node`](crate::node::Node).
#[derive(Default)]
pub struct DeniableState {
    /// This node's dedicated deniable identity for the **initiator** role (lazy: provisioned on the
    /// first [`ensure_identity`](Self::ensure_identity)). Separate Ed25519 key + certified `idk`.
    identity: Option<DeniableIdentity>,
    /// The **responder** half (its own dedicated identity + a published prekey bundle), present once
    /// [`publish_bundle`](Self::publish_bundle) has been called.
    responder: Option<DeniableResponder>,
    /// Live ratchet sessions, keyed by the peer's deniable identity key (`bundle.ik` when we
    /// initiated, `init.ik_a` when we accepted).
    sessions: HashMap<Vec<u8>, DeniableSession>,
}

impl DeniableState {
    /// Lazily provision (once) and return this node's initiator deniable identity's public IK.
    pub fn ensure_identity(&mut self) -> &DeniableIdentity {
        self.identity.get_or_insert_with(|| {
            DeniableIdentity::new(dmtap_core::identity::IdentityKey::generate())
        })
    }

    /// Provision the responder half with `num_opks` one-time prekeys and return the published,
    /// signed [`DeniablePrekeyBundle`] a peer consumes to open a session to this node (§5.2.1). The
    /// node layer wraps this into a [`CertifiedBundle`] (root-IK cert over `bundle.ik`).
    pub(crate) fn publish_bundle(
        &mut self,
        num_opks: usize,
        version: u64,
        ts: dmtap_core::TimestampMs,
    ) -> DeniablePrekeyBundle {
        let id = DeniableIdentity::new(dmtap_core::identity::IdentityKey::generate());
        let responder = DeniableResponder::new(id, num_opks, version, ts);
        let bundle = responder.bundle().clone();
        self.responder = Some(responder);
        bundle
    }

    /// Initiator: run X3DH against `peer_bundle`, embedding `first` as the first ratchet message.
    /// Stores the live session keyed by the peer's deniable IK and returns the [`DeniableInit`] to
    /// hand to the peer (§5.2.1(a)). The node layer verifies the peer's [`CertifiedBundle`] cert
    /// *before* calling this, and wraps the returned init into a [`CertifiedInit`].
    pub(crate) fn open(
        &mut self,
        peer_bundle: &DeniablePrekeyBundle,
        first: &DeniablePayload,
    ) -> Result<DeniableInit, DeniableRouteError> {
        let me = self
            .identity
            .get_or_insert_with(|| {
                DeniableIdentity::new(dmtap_core::identity::IdentityKey::generate())
            });
        let (session, init) = dmtap_deniable::initiate(me, peer_bundle, first)?;
        self.sessions.insert(peer_bundle.ik.clone(), session);
        Ok(init)
    }

    /// Responder: accept an incoming [`DeniableInit`], establishing a session and decrypting the
    /// embedded first payload. Stores the session keyed by the initiator's deniable IK (§5.2.1(a)).
    /// The node layer verifies the initiator's [`CertifiedInit`] cert *before* calling this, so a
    /// one-time prekey is never consumed for an uncertified identity.
    pub(crate) fn accept(
        &mut self,
        init: &DeniableInit,
    ) -> Result<DeniablePayload, DeniableRouteError> {
        let responder = self.responder.as_mut().ok_or(DeniableRouteError::NotResponder)?;
        let (session, payload) = responder.accept(init)?;
        self.sessions.insert(init.ik_a.clone(), session);
        Ok(payload)
    }

    /// Seal `payload` into a [`DeniableMessage`] on the live session with `peer_ik` (§5.2.1(b)).
    pub fn send(
        &mut self,
        peer_ik: &[u8],
        payload: &DeniablePayload,
    ) -> Result<DeniableMessage, DeniableRouteError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(DeniableRouteError::NoSession)?;
        Ok(session.encrypt(payload))
    }

    /// Open a [`DeniableMessage`] back into a [`DeniablePayload`] on the session with `peer_ik`.
    /// A tampered header/ciphertext, a wrong key, or a rewound message fails closed (§5.2.1).
    pub fn recv(
        &mut self,
        peer_ik: &[u8],
        msg: &DeniableMessage,
    ) -> Result<DeniablePayload, DeniableRouteError> {
        let session = self.sessions.get_mut(peer_ik).ok_or(DeniableRouteError::NoSession)?;
        Ok(session.decrypt(msg)?)
    }

    /// This node's initiator deniable identity public IK, if one has been provisioned.
    pub fn identity_public(&self) -> Option<Vec<u8>> {
        self.identity.as_ref().map(|i| i.ik_public())
    }

    /// The number of unspent one-time prekeys remaining in the published responder bundle, or `None`
    /// if this node has not published one. The OPK-depletion defense ([`DeniableAdmission`]) exists
    /// to keep this from being cheaply driven to zero (which forces the weak last-resort prekey).
    pub fn opks_remaining(&self) -> Option<usize> {
        self.responder.as_ref().map(|r| r.opks_remaining())
    }

    /// Whether a live session exists for `peer_ik`.
    pub fn has_session(&self, peer_ik: &[u8]) -> bool {
        self.sessions.contains_key(peer_ik)
    }

    /// Snapshot the live session with `peer_ik` (a clone of its ratchet state). This is the
    /// **constructive-repudiation demonstration surface** (§5.2.1(e)): from the snapshot a recipient
    /// can [`DeniableSession::forge_peer_message`] a message that opens as peer-authored, with no
    /// signing key — the property the IK-certification of the *key* deliberately does not remove.
    /// Returns `None` if no session exists for `peer_ik`.
    pub fn session_snapshot(&self, peer_ik: &[u8]) -> Option<DeniableSession> {
        self.sessions.get(peer_ik).map(|s| s.snapshot())
    }
}

/// The inbound deniable-init **admission gate** (audit #4 — one-time-prekey depletion defense).
///
/// ## The attack
/// X3DH `accept` consumes a one-time prekey (OPK) from the responder's published bundle *before* the
/// first message can be authenticated — a `DeniableInit` is only authenticated by the ratchet MAC it
/// establishes, and its `idk_a_cert` chain is **self-signable** (an attacker mints their own root IK
/// + deniable IK and self-certifies a valid [`CertifiedInit`]). So a burst of unsolicited inits from
/// throwaway identities can burn every OPK, forcing legitimate initiators onto the reused
/// **last-resort** prekey (weaker replay properties, §5.2.1).
///
/// ## The gate
/// A node-layer, wall-clock-free (driven by the node's injected clock) **token-bucket** rate limit
/// applied *before* an OPK is consumed:
/// - a **global** bucket bounds the total accept rate — this is the bucket that actually protects the
///   shared OPK pool, because a Sybil attacker mints a fresh identity per init and so is invisible to
///   any per-source accounting;
/// - a **per-source** bucket (keyed on the claimed initiator root IK) stops a *single* identity from
///   dominating the global budget, so an honest peer's legitimate retry is not starved by one noisy
///   source.
///
/// Both buckets refill deterministically from the node clock; an init is admitted only when **both**
/// have a token (consumed atomically). A throttled init returns
/// [`DeniableRouteError::RateLimited`](super::DeniableRouteError::RateLimited) having consumed no
/// prekey; the initiator's normal retry succeeds once the bucket refills. Legitimate low-rate flows
/// (well under the burst capacity) are never affected.
mod admission {
    use super::TimestampMs;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// A deterministic token bucket: `capacity` tokens, one refilled per `refill_ms`, clocked off an
    /// externally supplied timestamp (no wall clock, §16.1) so behavior is reproducible in tests.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TokenBucket {
        capacity: u32,
        refill_ms: u64,
        tokens: u32,
        /// The timestamp at which `tokens` was last accurate; advanced by whole refill intervals only
        /// (the sub-interval remainder is preserved so tokens accrue smoothly).
        last_ms: TimestampMs,
    }

    impl TokenBucket {
        fn new(capacity: u32, refill_ms: u64, now: TimestampMs) -> Self {
            TokenBucket { capacity, refill_ms, tokens: capacity, last_ms: now }
        }

        /// Credit whole refill-intervals elapsed since `last_ms` (saturating at `capacity`).
        fn refill(&mut self, now: TimestampMs) {
            if self.refill_ms == 0 || now <= self.last_ms {
                return; // a zero interval = no refill; a non-advancing/backwards clock adds nothing.
            }
            let elapsed = now - self.last_ms;
            let earned = elapsed / self.refill_ms;
            if earned == 0 {
                return;
            }
            let earned_u32 = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.capacity.min(self.tokens.saturating_add(earned_u32));
            // Advance only by the consumed whole intervals, keeping the sub-interval remainder.
            self.last_ms += earned.saturating_mul(self.refill_ms);
        }

        /// Whether a token is available *after* refilling to `now` (no consumption).
        fn available(&mut self, now: TimestampMs) -> bool {
            self.refill(now);
            self.tokens > 0
        }
    }

    /// Tunable capacities for [`DeniableAdmission`]. Defaults keep an unsolicited burst well under the
    /// default OPK pool while never throttling a legitimate low-rate initiator.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct DeniableAcceptLimits {
        /// Global burst capacity — the max accepts admitted before any refill. Kept *below* the
        /// published OPK count so no single burst can drain the pool to the last-resort prekey.
        pub global_burst: u32,
        /// Milliseconds to refill one global token.
        pub global_refill_ms: u64,
        /// Per-source (per claimed root IK) burst capacity.
        pub source_burst: u32,
        /// Milliseconds to refill one per-source token.
        pub source_refill_ms: u64,
    }

    impl Default for DeniableAcceptLimits {
        fn default() -> Self {
            // global_burst (4) < DEFAULT_OPKS (8): a full unsolicited burst leaves OPKs to spare, so
            // the last-resort prekey is never forced. One global token per 30 s ⇒ ~2 accepts/min
            // sustained; a legitimate peer opens a session far under this.
            DeniableAcceptLimits {
                global_burst: 4,
                global_refill_ms: 30_000,
                source_burst: 2,
                source_refill_ms: 60_000,
            }
        }
    }

    /// The node-held inbound-init admission gate. See the [module docs](self).
    #[derive(Debug, Clone)]
    pub struct DeniableAdmission {
        limits: DeniableAcceptLimits,
        global: TokenBucket,
        /// Per claimed-root-IK buckets, created lazily. Pruned of fully-refilled (idle) entries once
        /// the map grows past [`Self::PRUNE_AT`], so a Sybil flood cannot grow it without bound.
        per_source: HashMap<Vec<u8>, TokenBucket>,
    }

    impl DeniableAdmission {
        /// Prune idle (full-capacity) per-source buckets once the map exceeds this many entries.
        const PRUNE_AT: usize = 1024;

        /// A gate with the given limits, its buckets seeded full at `now`.
        pub fn new(limits: DeniableAcceptLimits, now: TimestampMs) -> Self {
            DeniableAdmission {
                global: TokenBucket::new(limits.global_burst, limits.global_refill_ms, now),
                per_source: HashMap::new(),
                limits,
            }
        }

        /// Reconfigure the limits, resetting the buckets full at `now` (the previous accounting is
        /// discarded — intended for setup/tests, not per-init tuning).
        pub fn configure(&mut self, limits: DeniableAcceptLimits, now: TimestampMs) {
            *self = DeniableAdmission::new(limits, now);
        }

        /// Try to admit one inbound init from `source` (the claimed initiator root IK) at `now`.
        /// Returns `true` (a global **and** a per-source token were consumed) iff the init may proceed
        /// to consume an OPK; `false` throttles it with **no** token consumed on either bucket.
        pub fn admit(&mut self, source: &[u8], now: TimestampMs) -> bool {
            let source_burst = self.limits.source_burst;
            let source_refill_ms = self.limits.source_refill_ms;
            let global_ok = self.global.available(now);
            let src = self
                .per_source
                .entry(source.to_vec())
                .or_insert_with(|| TokenBucket::new(source_burst, source_refill_ms, now));
            let source_ok = src.available(now);
            let admitted = global_ok && source_ok;
            if admitted {
                // Consume atomically only when both were available (never strand one bucket's token).
                self.global.tokens -= 1;
                src.tokens -= 1;
            }
            if self.per_source.len() > Self::PRUNE_AT {
                self.prune(now);
            }
            admitted
        }

        /// Drop per-source buckets that have refilled back to full — they carry no state a fresh
        /// bucket would not reproduce, so this bounds memory under a distinct-source flood.
        fn prune(&mut self, now: TimestampMs) {
            let cap = self.limits.source_burst;
            self.per_source.retain(|_, b| {
                b.refill(now);
                b.tokens < cap
            });
        }

        /// Capture the gate's live token-bucket state as a serializable snapshot, so the anti-abuse
        /// accounting survives a restart (audit #4 — otherwise a restart hands an attacker a fresh,
        /// full burst against the OPK pool). The per-source map is flattened to a `Vec` so it
        /// round-trips through JSON (byte-vector keys are not JSON object keys — mirrors [`Snapshot`
        /// ](crate::journal::Snapshot)'s `seen`).
        pub fn snapshot(&self) -> DeniableAdmissionSnapshot {
            DeniableAdmissionSnapshot {
                limits: self.limits,
                global: self.global.clone(),
                per_source: self
                    .per_source
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            }
        }

        /// Rebuild a gate from a [`snapshot`](Self::snapshot) — the drained/partially-refilled buckets
        /// are restored verbatim, so the rate limit picks up exactly where the pre-restart node left
        /// off (refill then resumes off the node's clock as usual).
        pub fn restore(snap: DeniableAdmissionSnapshot) -> Self {
            DeniableAdmission {
                limits: snap.limits,
                global: snap.global,
                per_source: snap.per_source.into_iter().collect(),
            }
        }
    }

    /// A serializable snapshot of a [`DeniableAdmission`] gate's token-bucket state (audit #4
    /// persistence, §5.2.1). Opaque by design — construct it with [`DeniableAdmission::snapshot`] and
    /// rebuild with [`DeniableAdmission::restore`].
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeniableAdmissionSnapshot {
        limits: DeniableAcceptLimits,
        global: TokenBucket,
        per_source: Vec<(Vec<u8>, TokenBucket)>,
    }

    impl Default for DeniableAdmission {
        fn default() -> Self {
            // Seeded at the node's default epoch clock; the node reseeds on construction anyway.
            DeniableAdmission::new(DeniableAcceptLimits::default(), 1_700_000_000_000)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn global_bucket_throttles_a_burst_then_refills() {
            let now = 1_000_000;
            let mut gate = DeniableAdmission::new(
                DeniableAcceptLimits {
                    global_burst: 3,
                    global_refill_ms: 10_000,
                    source_burst: 100,
                    source_refill_ms: 10_000,
                },
                now,
            );
            // Each init from a DISTINCT source (Sybil) — per-source never binds; global caps at 3.
            let mut admitted = 0;
            for i in 0..10u8 {
                if gate.admit(&[i], now) {
                    admitted += 1;
                }
            }
            assert_eq!(admitted, 3, "global burst capacity bounds a distinct-source flood");
            // No refill yet ⇒ still throttled.
            assert!(!gate.admit(&[200], now));
            // After one refill interval, exactly one more is admitted.
            assert!(gate.admit(&[201], now + 10_000));
            assert!(!gate.admit(&[202], now + 10_000));
        }

        #[test]
        fn per_source_bucket_stops_one_identity_hogging() {
            let now = 5;
            let mut gate = DeniableAdmission::new(
                DeniableAcceptLimits {
                    global_burst: 100,
                    global_refill_ms: 1,
                    source_burst: 2,
                    source_refill_ms: 1_000,
                },
                now,
            );
            let noisy = b"one-loud-identity".to_vec();
            assert!(gate.admit(&noisy, now));
            assert!(gate.admit(&noisy, now));
            assert!(!gate.admit(&noisy, now), "a single source is capped by its per-source bucket");
            // A different source is unaffected (global still has budget).
            assert!(gate.admit(b"someone-else", now));
        }

        #[test]
        fn snapshot_restore_preserves_drained_buckets() {
            // Persistence primitive (audit #4): a drained gate that round-trips through
            // snapshot()→restore() stays drained — a restart must not refill it to a fresh burst.
            let now = 2_000_000;
            let mut gate = DeniableAdmission::new(
                DeniableAcceptLimits {
                    global_burst: 2,
                    global_refill_ms: 1_000_000,
                    source_burst: 100,
                    source_refill_ms: 1_000_000,
                },
                now,
            );
            assert!(gate.admit(&[1], now));
            assert!(gate.admit(&[2], now));
            assert!(!gate.admit(&[3], now), "global burst spent");

            // Round-trip the state (as the journal would) and confirm it resumes drained.
            let restored = DeniableAdmission::restore(gate.snapshot());
            let mut restored = restored;
            assert!(
                !restored.admit(&[4], now),
                "restored gate is still drained — no fresh burst after restart"
            );
            // Once enough time passes it refills exactly as a live gate would (state, not a reset).
            assert!(restored.admit(&[5], now + 1_000_000));
        }

        #[test]
        fn a_rejected_init_consumes_no_token_on_either_bucket() {
            let now = 0;
            let mut gate = DeniableAdmission::new(
                DeniableAcceptLimits {
                    global_burst: 1,
                    global_refill_ms: 1_000,
                    source_burst: 5,
                    source_refill_ms: 1_000,
                },
                now,
            );
            assert!(gate.admit(b"a", now)); // drains the only global token
            assert!(!gate.admit(b"b", now)); // global empty ⇒ throttled
                                             // `b`'s per-source token must NOT have been spent: once
                                             // global refills, `b` still has its full per-source burst.
            assert!(gate.admit(b"b", now + 1_000));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A binding cert whose `ik` matches the KT-resolved root IK but whose `device_key` is a
    // DIFFERENT deniable key than the one presented MUST be rejected — a valid cert cannot be
    // replayed to vouch for another deniable identity key (§5.2.1(a), §1.2).
    #[test]
    fn verify_binding_rejects_cert_for_a_different_deniable_key() {
        let root = IdentityKey::from_seed(&[0x42; 32]);
        let deniable_ik = vec![0x11u8; 32];
        let other_ik = vec![0x22u8; 32];
        // Genuine cert over `other_ik` under the real root: self-consistent and correct root IK…
        let cert = issue_deniable_binding(&root, &other_ik, 1);
        assert!(verify_deniable_binding(&root.public(), &other_ik, &cert).is_ok());
        // …but presented alongside a DIFFERENT deniable key ⇒ fail closed on the device_key check.
        assert!(matches!(
            verify_deniable_binding(&root.public(), &deniable_ik, &cert),
            Err(DeniableRouteError::UncertifiedIdentity)
        ));
    }

    #[test]
    fn verify_binding_accepts_the_genuine_chain() {
        let root = IdentityKey::from_seed(&[0x7; 32]);
        let deniable_ik = vec![0x33u8; 32];
        let cert = issue_deniable_binding(&root, &deniable_ik, 42);
        assert!(verify_deniable_binding(&root.public(), &deniable_ik, &cert).is_ok());
        // A wrong KT-resolved root IK fails closed even though the cert is internally valid.
        let other_root = IdentityKey::from_seed(&[0x8; 32]).public();
        assert!(matches!(
            verify_deniable_binding(&other_root, &deniable_ik, &cert),
            Err(DeniableRouteError::UncertifiedIdentity)
        ));
    }
}
