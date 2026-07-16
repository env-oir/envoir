//! Group messaging — the node's MLS group surface (spec §5).
//!
//! The reference node historically shipped only a **1:1 HPKE** path. This module wires the
//! workspace-shared [`dmtap_mls`] crate (real RFC 9420 MLS via `openmls`) into the [`Node`], so a
//! node can found and join **real MLS groups** alongside the 1:1 path: 1:1, group chat,
//! mailing-lists, multi-device clusters, and shared folders are all MLS groups (§5.1). The 1:1
//! MOTE pipeline is untouched.
//!
//! ## What routes where (spec §5.1)
//! MLS trusts the Delivery Service for exactly one thing — a **total order on epochs**. DMTAP
//! realizes that with the **committer**: an append-only, ordered per-group handshake log. This
//! module models it with [`dmtap_mls::Committer`], the DS ordering seam:
//! - **Handshakes** — Add/Remove **Commits** (kind `0x06` `group_event`) — travel over the
//!   committer log, never the reordering mesh (§5.1). [`Node::group_add_member`] /
//!   [`Node::group_remove_member`] submit a Commit to the committer; every member advances by
//!   applying the log in order ([`Node::apply_committed`]).
//! - **Application messages** — mail/chat/file content — travel over the mesh transport as
//!   [`Frame::Group`](crate::transport::Frame::Group), fanned out by [`Node::group_broadcast`]
//!   and decrypted by [`Node::poll_group_messages`].
//!
//! The `Node`'s DMTAP identity key binds to its MLS leaf via the leaf **credential identity**
//! `ik_public ‖ "#" ‖ device_label` (so a group roster maps back to owners, §5.6); the leaf's own
//! MLS signature key is generated inside [`dmtap_mls::Member`].

use dmtap_core::mote::Kind;

pub use dmtap_mls::{Committer, Handshake, MlsError};

/// A **group MOTE** (spec §5.4): the routing object for a group session's traffic. A `group_event`
/// (`kind = 0x06`) carries an MLS handshake (Commit/Welcome); an application `kind` (chat/mail)
/// carries the MLS-encrypted content ciphertext. Its `body` is opaque MLS wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMote {
    /// The group this MOTE belongs to (the MLS group id).
    pub group_id: Vec<u8>,
    /// Message kind (§2.3): [`Kind::GroupEvent`] for a handshake, an application kind
    /// ([`Kind::Chat`]/[`Kind::Mail`]) for content.
    pub kind: Kind,
    /// The group's MLS epoch this MOTE was produced at (§5.2) — advisory, for ordering/inspection.
    pub epoch: u64,
    /// The MLS wire bytes: a serialized Commit/Welcome (`group_event`) or an application-message
    /// ciphertext (content kinds).
    pub body: Vec<u8>,
}

impl GroupMote {
    /// Encode to a self-describing byte frame: `u8 kind ‖ u64be epoch ‖ u32be gid_len ‖ group_id ‖
    /// body`. Used as the [`Frame::Group`](crate::transport::Frame::Group) body over the mesh.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 4 + self.group_id.len() + self.body.len());
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.group_id.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.body);
        out
    }

    /// Decode a [`GroupMote`] from [`encode`](Self::encode)'s frame, failing closed on truncation
    /// or an unknown kind byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() < 13 {
            return Err(GroupError::Malformed);
        }
        let kind = Kind::from_u8(bytes[0]).ok_or(GroupError::Malformed)?;
        let epoch = u64::from_be_bytes(bytes[1..9].try_into().expect("9-1 == 8 bytes"));
        let gid_len = u32::from_be_bytes(bytes[9..13].try_into().expect("13-9 == 4 bytes")) as usize;
        if bytes.len() < 13 + gid_len {
            return Err(GroupError::Malformed);
        }
        let group_id = bytes[13..13 + gid_len].to_vec();
        let body = bytes[13 + gid_len..].to_vec();
        Ok(GroupMote { group_id, kind, epoch, body })
    }
}

/// The artifacts of an **Add** (spec §5.3): the ordered handshake plus the Welcome the new member
/// bootstraps from, and the committer sequence at which it was ordered.
#[derive(Debug, Clone)]
pub struct GroupAdd {
    /// The Add **Commit** as a `group_event` MOTE (kind `0x06`), for audit/inspection — the
    /// authoritative copy also lives in the committer log.
    pub event: GroupMote,
    /// The **Welcome** bytes to hand to the added member so it can join (§5.3).
    pub welcome: Vec<u8>,
    /// The committer sequence this Add was ordered at.
    pub seq: u64,
}

/// Why a node-level group operation failed (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// The named group is not one this node has a session for (found/join it first).
    UnknownGroup,
    /// No pre-published leaf to join with — call
    /// [`publish_group_keypackage`](crate::Node::publish_group_keypackage) first (§5.3).
    NoPendingLeaf,
    /// A group MOTE frame did not decode.
    Malformed,
    /// The underlying MLS layer rejected the operation (bad epoch, forged handshake, decrypt
    /// failure — the fail-closed outcome, e.g. for a removed member, §5.2).
    Mls(MlsError),
}

impl From<MlsError> for GroupError {
    fn from(e: MlsError) -> Self {
        GroupError::Mls(e)
    }
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::UnknownGroup => f.write_str("no such group session on this node"),
            GroupError::NoPendingLeaf => f.write_str("no pre-published leaf to join with (§5.3)"),
            GroupError::Malformed => f.write_str("malformed group MOTE frame"),
            GroupError::Mls(e) => write!(f, "MLS error: {e}"),
        }
    }
}

impl std::error::Error for GroupError {}
