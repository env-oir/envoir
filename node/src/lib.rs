//! # DMTAP — Decentralized Message Transfer & Access Protocol (reference node library)
//!
//! This crate is a **reference implementation**, not normative. The normative source of
//! truth is the specification in the DMTAP spec repo (`../dmtap/`). Where this code and the
//! spec disagree, the spec governs (spec §10.4).
//!
//! One substrate carries mail, chat, and files over a P2P mesh + mixnet, with an optional
//! legacy SMTP gateway (a separate crate). See `../dmtap/00-overview.md`.
//!
//! ## Layering
//! The protocol **core** — crypto suites, content addressing, the identity lifecycle, the
//! 8-word key-name, and the MOTE object (spec §1, §2, §3.9) — now lives in the workspace-shared
//! [`dmtap_core`] crate so it can be reused by the gateway. This node crate re-exports it and
//! adds the node-only subsystems (mesh, transport, delivery, client protocols, abuse).

// Re-export the shared core so existing paths (`dmtap::Suite`, `dmtap::identity`,
// `dmtap::mote`, …) keep working after the move into `dmtap-core`.
pub use dmtap_core::{self, id, identity, keyname, mote, ContentId, Suite, TimestampMs};

// The client-access surface (spec §8): IMAP/POP/SMTP-submission + JMAP + autodiscovery, all
// projecting the one MOTE store. Implemented in the workspace-shared `dmtap-mail` crate and
// re-exported here as `dmtap::clients`.
pub use dmtap_mail as clients;

// --- Node delivery engine -------------------------------------------------------------------
// The running client side that wires the shared crates into an end-to-end MOTE delivery path:
// identity + store + outbound retry queue (§20.1) + inbound validation (§20.2) + transport (§4),
// culminating in two in-process nodes exchanging a real end-to-end-encrypted MOTE (§2, §19.3).
pub mod group;
pub mod inbound;
pub mod journal;
pub mod node;
pub mod outbound;
pub mod transport;

pub use journal::{FileJournal, Journal, JournalError, MemoryJournal, NullJournal, Snapshot};
pub use node::{Node, SendError};

// Real MLS group messaging (spec §5): the node wraps the workspace-shared `dmtap-mls` crate
// (openmls / RFC 9420) and re-exports its group types here as `dmtap::groups` for callers.
pub use dmtap_mls as groups;
pub use group::{Committer, GroupAdd, GroupError, GroupMote, Handshake};

// Node-only planned modules (see README): the rest of the client side that *is* the mesh.
// pub mod naming;      // §3 — name→key resolution, TOFU pinning, key transparency
// pub mod privacy;     // §6 — sealed sender, cover traffic, padding, tiers
