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
//! ## What is real vs. a documented seam
//! - **Real:** X3DH root derivation, the Double Ratchet, per-message forward secrecy, and the
//!   shared-key-MAC authentication — the full seal→open round-trip of a [`DeniablePayload`] — all
//!   run via [`dmtap_deniable`]. A tampered/rewound message fails closed.
//! - **Seam (dedicated deniable identity):** §5.2.1 mandates a **dedicated** long-term key set so
//!   the sign-only root `IK` never does DH. The node therefore provisions a distinct
//!   [`DeniableIdentity`] (its own Ed25519 key certifying a fresh X25519 `idk`) rather than reusing
//!   the root `IK`. Certifying that deniable identity *under* the node's root `IK` via a `DeviceCert`
//!   (§1.2) is a documented later step, not done here — the deniable IK is standalone in this
//!   reference. This is a documented narrowing, not a silent stub.

use std::collections::HashMap;

use dmtap_core::deniable::{DeniableInit, DeniableMessage, DeniablePayload, DeniablePrekeyBundle};

pub use dmtap_deniable::{DeniableError, DeniableIdentity, DeniableResponder, DeniableSession};

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
    /// signed [`DeniablePrekeyBundle`] a peer consumes to open a session to this node (§5.2.1).
    pub fn publish_bundle(
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
    /// hand to the peer (§5.2.1(a)).
    pub fn open(
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
    pub fn accept(
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
}
