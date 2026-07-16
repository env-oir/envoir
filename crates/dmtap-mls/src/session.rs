//! A [`Session`] — one device's live view of an MLS group (spec §5.1), plus the [`Handshake`]
//! bundle a membership change produces.
//!
//! A `Session` owns a [`Member`] (its device key material + provider) and the `openmls`
//! [`MlsGroup`] for this device's view of one group. Membership changes (**Add**/**Remove**)
//! produce a [`Handshake`] — the Commit (and, for an Add, the Welcome) — which is **not merged
//! immediately**. Instead the author submits it to the [`Committer`](crate::Committer), which
//! assigns it a total-order position; every member then advances by applying committed handshakes
//! in that order (§5.1). This split is deliberate: it is exactly the epoch-ordering seam MLS
//! delegates to the Delivery Service, and DMTAP realizes with the committer.

use openmls::prelude::{
    tls_codec::*, LeafNodeIndex, MlsMessageIn, ProcessedMessageContent, ProtocolMessage,
};

use crate::error::MlsError;
use crate::member::{decode_key_package, Member};

/// The MLS handshake artifacts produced by a membership change (spec §5.4 `group_event`), ready
/// to be **ordered** by the committer and then applied by every member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The serialized MLS **Commit** message (the epoch-advancing handshake).
    pub commit: Vec<u8>,
    /// The serialized MLS **Welcome**, present iff this handshake **adds** a member — the added
    /// device bootstraps from it (§5.3). Absent for a Remove/Update.
    pub welcome: Option<Vec<u8>>,
    /// The leaf identity of the member who authored this Commit (`owner ‖ "#" ‖ label`), so the
    /// committer log records "who committed" (the group analog of KT, §5.8.2).
    pub author: Vec<u8>,
}

/// One device's live MLS group view (spec §5.1). Tracks how far this view has advanced along the
/// committer's ordered log so it can apply newly-ordered Commits exactly once, in order.
pub struct Session {
    /// This device's key material + `openmls` provider.
    member: Member,
    /// The `openmls` group state for this device's view.
    group: openmls::group::MlsGroup,
    /// The committer-log sequence this view has applied up to (0 = nothing applied yet). A Commit
    /// authored by *this* device leaves a *pending* commit in `openmls`; when the committer orders
    /// it at `seq`, [`Session::advance`] merges the pending commit rather than re-processing it.
    applied_seq: u64,
    /// Set to the committer sequence of a Commit this device authored and submitted but has not yet
    /// merged. Distinguishes "merge my own pending commit" from "process someone else's commit"
    /// when advancing (§5.1: the author merges, everyone else processes).
    pending_seq: Option<u64>,
}

impl Session {
    pub(crate) fn new(member: Member, group: openmls::group::MlsGroup) -> Self {
        Session { member, group, applied_seq: 0, pending_seq: None }
    }

    /// The owner identity this device belongs to (§5.6).
    pub fn owner(&self) -> &[u8] {
        self.member.owner()
    }

    /// This device's label.
    pub fn label(&self) -> &str {
        self.member.label()
    }

    /// This device's leaf identity in the roster (`owner ‖ "#" ‖ label`).
    pub fn leaf_identity(&self) -> Vec<u8> {
        self.member.leaf_identity()
    }

    /// The group's current MLS **epoch** (spec §5.2 — forward secrecy comes from epoch
    /// advancement; each applied Commit bumps this).
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// This device's own leaf index in the ratchet tree.
    pub fn own_leaf_index(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// How far this view has advanced along the committer's ordered log (§5.1).
    pub fn applied_seq(&self) -> u64 {
        self.applied_seq
    }

    /// Whether this device is still an active member (i.e. has not been removed from the group).
    pub fn is_active(&self) -> bool {
        self.group.is_active()
    }

    /// The current roster as `(leaf_index, leaf_identity)` pairs. `leaf_identity` is
    /// `owner ‖ "#" ‖ label`; use [`Member::owner_of_identity`](crate::Member::owner_of_identity)
    /// to group leaves back to owners (§5.6).
    pub fn roster(&self) -> Vec<(u32, Vec<u8>)> {
        self.group
            .members()
            .map(|m| (m.index.u32(), m.credential.serialized_content().to_vec()))
            .collect()
    }

    /// The group's **epoch authenticator** — a value all correctly-synced members share at a given
    /// epoch (spec §5.1). Equal across two `Session`s iff they have converged on the same group
    /// state; the test-visible proof of "all members on the same epoch secret".
    pub fn epoch_authenticator(&self) -> Vec<u8> {
        self.group.epoch_authenticator().as_slice().to_vec()
    }

    // --- membership changes (produce a Handshake for the committer to order) ----------------

    /// **Add** the device whose published KeyPackage is `key_package_bytes` (spec §5.3): produce
    /// the Add **Commit** + **Welcome** as a [`Handshake`]. This leaves a *pending* commit in this
    /// device's group state — it is **not** applied until the committer orders it and
    /// [`Session::advance`] merges it. Authorization/roles (§5.8.2) are out of scope for this seam.
    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<Handshake, MlsError> {
        let key_package = decode_key_package(self.member.provider(), key_package_bytes)?;
        let (commit, welcome, _group_info) = self
            .group
            .add_members(
                self.member.provider(),
                self.member.signer(),
                std::slice::from_ref(&key_package),
            )
            .map_err(|e| MlsError::Group(e.to_string()))?;
        Ok(Handshake {
            commit: to_bytes(&commit)?,
            welcome: Some(to_bytes(&welcome)?),
            author: self.member.leaf_identity(),
        })
    }

    /// **Remove** the member at `leaf_index` (spec §5.8.2): produce the Remove **Commit** as a
    /// [`Handshake`]. Once ordered and applied, MLS's TreeKEM re-keys every path secret, so the
    /// removed leaf's key opens **nothing** in the new epoch — this is the post-compromise
    /// security the removed member can no longer defeat (§5.2). Not merged until [`advance`].
    ///
    /// [`advance`]: Session::advance
    pub fn remove_member(&mut self, leaf_index: u32) -> Result<Handshake, MlsError> {
        let (commit, welcome, _group_info) = self
            .group
            .remove_members(
                self.member.provider(),
                self.member.signer(),
                &[LeafNodeIndex::new(leaf_index)],
            )
            .map_err(|e| MlsError::Group(e.to_string()))?;
        Ok(Handshake {
            commit: to_bytes(&commit)?,
            // A Remove yields no Welcome (nobody joins); an Update-style commit might, hence Option.
            welcome: welcome.map(|w| to_bytes(&w)).transpose()?,
            author: self.member.leaf_identity(),
        })
    }

    // --- application messages (§5.4) --------------------------------------------------------

    /// Encrypt `plaintext` as an MLS **application message** under the group's current epoch secret
    /// (spec §5.4 — mail/chat/file content). Returns the serialized ciphertext to route over the
    /// mesh (application messages MAY travel the reordering mixnet, §5.1).
    pub fn create_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let out = self
            .group
            .create_message(self.member.provider(), self.member.signer(), plaintext)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        to_bytes(&out)
    }

    /// Decrypt an inbound MLS **application message** (`bytes`) to its plaintext. Errors
    /// ([`MlsError::Process`]) if this device cannot read it — e.g. a **removed** member handed a
    /// message from an epoch it was rekeyed out of (post-compromise security, §5.2) — or
    /// ([`MlsError::UnexpectedContent`]) if the message is a handshake rather than content.
    pub fn receive_message(&mut self, bytes: &[u8]) -> Result<Vec<u8>, MlsError> {
        let processed = self.process(bytes)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err(MlsError::UnexpectedContent),
        }
    }

    // --- committer ordering seam (§5.1) -----------------------------------------------------

    /// Advance this device's group state to the committer log's head, applying every ordered
    /// [`Handshake`] this view has not yet applied, **in order** (spec §5.1). For each entry:
    /// - if this device **authored** it (its `pending_seq` matches), merge the pending commit;
    /// - otherwise **process** the commit message and merge the staged commit.
    ///
    /// This is the member side of the epoch-ordering seam: MLS produces Commits, the committer
    /// totally-orders them, and members apply them here so every member converges on the same
    /// epoch chain. Returns the number of entries newly applied.
    ///
    /// ## Concurrent proposers (§5.1)
    /// On a leaderless mesh two members can each build a Commit off the *same* base epoch before
    /// either sees the other's — a genuine race, not hostile input. The committer gives them a
    /// total order, so only the earlier one can validly land: applying an *earlier* entry first
    /// advances this device's epoch out from under its *own* still-pending Commit (built against
    /// the now-stale base epoch). `openmls`'s `merge_pending_commit` treats "no pending commit
    /// left to merge" as a silent no-op **success**, which would otherwise make this method report
    /// `Ok` for a Commit that was actually discarded. This is checked for explicitly below and
    /// surfaced as [`MlsError::StaleCommit`] so the caller knows to re-derive and resubmit —
    /// never a silent, unnoticed loss.
    pub fn advance(&mut self, committer: &crate::Committer) -> Result<usize, MlsError> {
        let mut applied = 0;
        for entry in committer.entries_after(self.applied_seq) {
            if self.pending_seq == Some(entry.seq) {
                // We authored this Commit; merge our own pending commit (§5.1 author path) — but
                // only if it is still actually pending (see "Concurrent proposers" above).
                if self.group.pending_commit().is_none() {
                    self.pending_seq = None;
                    self.applied_seq = entry.seq;
                    return Err(MlsError::StaleCommit);
                }
                self.group
                    .merge_pending_commit(self.member.provider())
                    .map_err(|e| MlsError::Group(e.to_string()))?;
                self.pending_seq = None;
            } else {
                // Someone else's Commit: process + merge the staged commit (§5.1 member path).
                let processed = self.process(&entry.handshake.commit)?;
                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged) => {
                        self.group
                            .merge_staged_commit(self.member.provider(), *staged)
                            .map_err(|e| MlsError::Group(e.to_string()))?;
                    }
                    _ => return Err(MlsError::UnexpectedContent),
                }
            }
            self.applied_seq = entry.seq;
            applied += 1;
        }
        Ok(applied)
    }

    /// Record that a [`Handshake`] this device authored was ordered by the committer at `seq`, so
    /// the next [`advance`](Session::advance) merges the pending commit instead of processing it.
    /// Called by the caller right after submitting to the committer (see the crate/test flow).
    pub fn note_authored(&mut self, seq: u64) {
        self.pending_seq = Some(seq);
    }

    /// Set this freshly-joined device's committer **baseline** to `seq` — the log head at the time
    /// it bootstrapped from a Welcome (spec §5.3). The Welcome already carries the group state at
    /// the epoch of the Add Commit, so the new member must not re-apply that Commit (nor the
    /// membership history before it); [`advance`](Session::advance) then only applies Commits
    /// ordered *after* `seq`. Call this immediately after [`Member::join_from_welcome`].
    ///
    /// [`Member::join_from_welcome`]: crate::Member::join_from_welcome
    pub fn note_joined_at(&mut self, seq: u64) {
        self.applied_seq = seq;
    }

    // --- internals --------------------------------------------------------------------------

    /// Deserialize + process one inbound MLS message against this group, returning the processed
    /// message (content not yet extracted). Fails closed on any codec/processing error, and on
    /// **any panic** raised while `openmls` processes untrusted bytes (see [`catch_decrypt_panic`]).
    fn process(
        &mut self,
        bytes: &[u8],
    ) -> Result<openmls::prelude::ProcessedMessage, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let protocol: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let group = &mut self.group;
        let provider = self.member.provider();
        catch_decrypt_panic(std::panic::AssertUnwindSafe(move || {
            group.process_message(provider, protocol).map_err(|e| MlsError::Process(e.to_string()))
        }))
    }
}

/// Run `f` (an `openmls` call that decrypts/validates an untrusted wire message), converting a
/// **panic** into [`MlsError::Process`] instead of letting it unwind out of this crate.
///
/// This defends against a known footgun in `openmls` 0.8's `PrivateMessageIn::decrypt`
/// (`framing/private_message_in.rs`): on **any** AEAD tag mismatch — e.g. a bit-flipped/tampered
/// ciphertext from a hostile sender — it runs `debug_assert!(false, "Ciphertext decryption
/// failed")` before returning its normal `Err(MessageDecryptionError::AeadError)`. In a
/// `debug_assertions`-enabled build (the default `cargo test`/dev profile most callers run) that
/// `debug_assert!` **panics** instead of just logging, even though the surrounding code is already
/// written to treat this as an ordinary, recoverable decryption failure (a release build never
/// panics here). This crate's whole contract is fail-closed-on-hostile-input (spec §5), so a
/// tampered ciphertext must yield an `Err`, never a crash — regardless of build profile.
///
/// This is safe to paper over here (rather than something we should leave unhandled): the secret
/// tree ratchet consumes/advances the target generation's key material *before* the AEAD check
/// runs, identically in debug and release builds; the `debug_assert!` fires strictly *after* that
/// mutation, right where `openmls` already intends to return a plain `Err` in production. Catching
/// the panic and mapping it to the same [`MlsError::Process`] the release build would have produced
/// changes no group state beyond what already happens on every build profile.
///
/// Deliberately does **not** touch the global panic hook: this crate may be linked into a
/// multi-threaded host (`envoir-node`) where other threads' panics must still print normally;
/// muting/restoring a process-wide hook around this call would race with them. The cost is that a
/// caught panic still logs its default backtrace to stderr — noise, not a correctness issue.
fn catch_decrypt_panic(
    f: impl std::panic::UnwindSafe
        + FnOnce() -> Result<openmls::prelude::ProcessedMessage, MlsError>,
) -> Result<openmls::prelude::ProcessedMessage, MlsError> {
    std::panic::catch_unwind(f).unwrap_or_else(|_| {
        Err(MlsError::Process(
            "panicked while processing a message (treated as a decryption/validation failure)"
                .to_string(),
        ))
    })
}

/// Serialize any `MlsMessageOut` to its TLS wire bytes (fail-closed on codec error).
fn to_bytes(msg: &openmls::prelude::MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    msg.tls_serialize_detached().map_err(|e| MlsError::Codec(e.to_string()))
}
