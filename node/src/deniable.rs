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
