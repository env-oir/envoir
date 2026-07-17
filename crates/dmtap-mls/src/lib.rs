//! # dmtap-mls — the DMTAP MLS group layer (spec §5)
//!
//! DMTAP standardizes on **MLS (RFC 9420) as the unifying crypto primitive** (spec §5.1):
//! 1:1, group chat, mailing-lists, multi-device clusters, and shared folders are **all MLS
//! groups**. The reference node historically shipped only a 1:1 HPKE path; this crate closes
//! that gap by wrapping **[openmls]** — the canonical RFC 9420 Rust implementation — behind a
//! small, DMTAP-shaped API, and by modeling DMTAP's **committer** (§5.1) as the epoch-ordering
//! seam that sits *on top of* MLS.
//!
//! ## What is real here (vs. the old 1:1-HPKE-only node)
//! - Real MLS groups over ciphersuite `0x0001`
//!   (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, spec §5.1 v0), via `openmls` +
//!   `openmls_rust_crypto` (RustCrypto backend) + `openmls_basic_credential`.
//! - **Async session initiation** (§5.3): each device publishes a signed **KeyPackage**; a member
//!   is added with an **Add Commit** and bootstraps from the **Welcome**.
//! - **Add / Remove** membership changes as MLS Commits. Remove gives **post-compromise security**
//!   (TreeKEM re-keys; the removed leaf's key opens nothing in later epochs).
//! - **Application messages** (mail/chat/file content, §5.4) encrypted under the group's current
//!   epoch secret; **epoch advancement** on every Commit.
//! - **Multi-device** (§5.6): each of an owner's devices is its own MLS **leaf** ([`Member`]),
//!   added to the same group — MLS handles the cluster where pairwise ratchets get messy.
//!
//! ## The committer seam (spec §5.1)
//! MLS trusts the Delivery Service for exactly one thing: **a total order on epochs** — Commits
//! MUST be applied in one agreed order per group. On a leaderless mesh that ordering is the hard
//! part, so DMTAP puts a **committer** on top of MLS: a node that serializes handshake messages
//! into an append-only, hash-chained per-group log. This crate models that with an in-process
//! [`Committer`] (a simple ordered log): a member that produces a Commit **submits** it to the
//! committer, which assigns a sequence position; every member then **advances** its own MLS state
//! by applying log entries in that order (the author merges its pending commit; everyone else
//! processes the commit message). The real mesh committer — deterministic succession, `> n/2`
//! takeover, fork detection (§5.1) — is a separate concern; the ordering *contract* it provides
//! is exactly what [`Committer`] stands in for.
//!
//! [openmls]: https://docs.rs/openmls

mod ciphersuite;
mod committer;
mod error;
mod member;
mod session;

pub use ciphersuite::{
    all_members_pq, is_pq_ciphersuite, security_level, MemberPqCapability, MlsCiphersuiteError,
    MlsCiphersuiteRatchet,
};
pub use committer::{
    CommitStatus, Committer, ForkEvidence, LogEntry, OrderOutcome, SuspendedError,
};
pub use error::MlsError;
pub use member::Member;
pub use session::{Handshake, Session};

use openmls::prelude::Ciphersuite;

/// The DMTAP v0 MLS ciphersuite (spec §5.1): `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
/// (MLS ciphersuite `0x0001`) — X25519 for the TreeKEM DH, AES-128-GCM AEAD, SHA-256, Ed25519
/// signatures. This mirrors DMTAP's own classical suite `0x01` KEM/hash/signature choices, so an
/// MLS group and a 1:1 MOTE share the same primitive family.
pub const DMTAP_MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
