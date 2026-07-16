//! Inbound delivery — the recipient-side validation disposition (spec §2.7, §2.7a, §19.3.1, §20.2).
//!
//! The cryptographic pipeline itself — the ordered, cheapest-and-anonymous-first checks of §2.7
//! (version/suite → content address → `sender_sig` → resolve `to` → cold-sender gate → decrypt →
//! `Payload.sig`) — is implemented once, in the shared core, as
//! [`dmtap_core::mote::validate`]. This module names the **terminal dispositions** of that
//! pipeline (§20.2's `ACKED`/`DEFERRED`/`DROPPED`) and the reasons a MOTE is dropped, so the
//! node ([`crate::node::Node::receive_mote`]) can wrap `validate` with the two node-level
//! concerns the core deliberately leaves to the caller: **dedup** (§2.6) and **ack** (§19.3.2).
//!
//! ## The three terminal states (§19.3.1 "there is no fourth, undefined outcome")
//! - **Stored + acked** — decrypted, authenticated, filed to the inbox.
//! - **Deferred + UNacked** — an under-proven cold sender's MOTE held in the requests area (§2.7a),
//!   durably retained (30 days) but NOT acked: acking would confirm receipt to an unproven sender
//!   and falsely signal *delivered* (the requests area is not the inbox), so the sender's own retry
//!   simply EXPIREs. §19.3.1 step 9, §2.7a, and §20.2 now agree — the ack axis is binary: ack iff
//!   delivered to the inbox.
//! - **Dropped + unacked** — silent discard, only for cryptographically invalid/forged input.

use dmtap_core::ContentId;

/// Why an inbound MOTE was silently dropped (§2.7a "invalid or forged" → no ack). Each maps to a
/// row of §19.3.1's failure-mode table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Envelope bytes did not decode as canonical §18 CBOR.
    Malformed,
    /// Unknown `v` / unsupported `suite` (§2.7 step 1).
    BadVersionOrSuite,
    /// `id` ≠ content address of `ciphertext` (§2.7 step 2).
    BadContentAddress,
    /// `sender_sig` failed under the envelope's ephemeral key (§2.7 step 3).
    BadSenderSig,
    /// `to` does not resolve to this node (§2.7 step 4).
    NotForUs,
    /// Decryption failed — wrong key/epoch or corrupt ciphertext (§2.7 step 7).
    DecryptFailed,
    /// `Payload.sig` failed under `Payload.from`, or a known contact's `from` did not match its
    /// pin (§2.7 step 8) — a passed anti-abuse gate does not substitute for payload authenticity.
    BadPayloadSig,
}

/// The terminal disposition of one received MOTE (spec §20.2). Exactly one is reached per input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundOutcome {
    /// Accepted, decrypted, filed to the inbox at IMAP `uid`; an `ack(id)` was sent. (§2.7 step 9)
    Stored { id: ContentId, uid: u32 },
    /// A well-formed but under-proven cold-sender MOTE held in the requests area — durably retained
    /// (30 days, §16.5) but **NOT** acked: acking would confirm receipt to an unproven sender and
    /// falsely signal *delivered*; the sender's own retry reaches EXPIRED (§2.7a, §19.3.1 step 9,
    /// §20.2). The ack axis is binary — ack iff delivered to the inbox.
    Deferred { id: ContentId },
    /// `id` already held — acked immediately without reprocessing (dedup, §2.6).
    Duplicate { id: ContentId },
    /// Cryptographically invalid/forged — discarded silently, **no** ack (§2.7a).
    Dropped(DropReason),
}

impl InboundOutcome {
    /// Whether this disposition sent an `ack` back to the sender. Ack is owed **only** for inbox
    /// delivery (`Stored`) or a dedup of one already held (`Duplicate`); a `Deferred` cold MOTE and
    /// a `Dropped` one are both unacked, differing only in retention (§19.3.1 step 9, §2.7a, §20.2).
    pub fn acked(&self) -> bool {
        matches!(self, InboundOutcome::Stored { .. } | InboundOutcome::Duplicate { .. })
    }
}
