//! # DMTAP — Decentralized Message Transfer & Access Protocol (reference node library)
//!
//! This crate is a **reference implementation**, not normative. The normative source of
//! truth is the specification in the DMTAP spec repo (`../dmtap/`). Where this code and the
//! spec disagree, the spec governs (spec §10.4).
//!
//! One substrate carries mail, chat, and files over a P2P mesh + mixnet. The node is native-only
//! (spec §8.5): its client surface is JMAP (§8.1); the legacy IMAP/POP/SMTP protocols live only on
//! the separate gateway crate. See `../dmtap/00-overview.md`.
//!
//! ## Layering
//! The protocol **core** — crypto suites, content addressing, the identity lifecycle, the
//! 8-word key-name, and the MOTE object (spec §1, §2, §3.9) — now lives in the workspace-shared
//! [`dmtap_core`] crate so it can be reused by the gateway. This node crate re-exports it and
//! adds the node-only subsystems (mesh, transport, delivery, client protocols, abuse).

// Re-export the shared core so existing paths (`dmtap::Suite`, `dmtap::identity`,
// `dmtap::mote`, …) keep working after the move into `dmtap-core`.
pub use dmtap_core::{self, id, identity, keyname, mote, ContentId, Suite, TimestampMs};

// The node's native client-access surface is JMAP (spec §8.1) — the node is native-only (§8.5),
// so it projects the one MOTE store to JMAP and does NOT serve the legacy IMAP/POP/SMTP-submission
// protocols (those live only on the separate gateway, spec §7). The MOTE store + JMAP + the shared
// mail types are implemented in the workspace `dmtap-mail` crate, re-exported here as `dmtap::clients`.
pub use dmtap_mail as clients;

// --- Node delivery engine -------------------------------------------------------------------
// The running client side that wires the shared crates into an end-to-end MOTE delivery path:
// identity + store + outbound retry queue (§20.1) + inbound validation (§20.2) + transport (§4),
// culminating in two in-process nodes exchanging a real end-to-end-encrypted MOTE (§2, §19.3).
pub mod auth;
pub mod config;
pub mod daemon;
pub mod deniable;
pub mod group;
pub mod inbound;
pub mod journal;
pub mod keystore;
pub mod mixdir;
pub mod naming;
pub mod node;
pub mod outbound;
pub mod seen;
pub mod send_api;
pub mod transport;
pub mod usage;

pub use journal::{FileJournal, Journal, JournalError, MemoryJournal, NullJournal, Snapshot};
pub use node::{Node, SendError};

// The persistent daemon (spec §0.2): durable keystore, env/flag config, and the long-running
// serve loop with graceful shutdown that turns the reference node into a real process.
pub use config::NodeConfig;
pub use daemon::{dmtap_txt_record, run_loop, serve, DaemonError, LoopStats};
pub use keystore::{Keystore, KeystoreError};

// The Envoir Send HTTP API (spec §13.5.1): the capability-token send service exposed over a bound
// HTTP listener, routing capability-authorized sends into the node's real §20.1 outbound path.
pub use send_api::{run_loop_with_send_api, SendApi};

// Real MLS group messaging (spec §5): the node wraps the workspace-shared `dmtap-mls` crate
// (openmls / RFC 9420) and re-exports its group types here as `dmtap::groups` for callers.
pub use dmtap_mls as groups;
pub use group::{Committer, GroupAdd, GroupError, GroupMote, Handshake};

// Real name→key resolution (spec §3): the node wraps the workspace-shared `dmtap-naming` crate
// (DNS `_dmtap` parsing + RFC 6962 KT-verified, fail-closed resolution) and re-exports it here as
// `dmtap::names`, with the node-facing `AddressError` for name-addressed sends.
pub use dmtap_naming as names;
pub use naming::{AddressError, KeyPackageSource, PinnedResolution, ResolveError, Resolver};

// Real DMTAP-Auth login/session (spec §13): the node signs an RP challenge with its root IK to
// establish its own key-bound session, re-exported here as `dmtap::dmtap_auth`.
pub use auth::{BoundSession, Challenge, Login, SignedAssertion};
pub use dmtap_auth;

// Real deniable 1:1 messaging (spec §5.2.1): X3DH + Double Ratchet, distinct from the MLS group
// path, re-exported here as `dmtap::dmtap_deniable`.
pub use deniable::{
    CertifiedBundle, CertifiedInit, DeniableAcceptLimits, DeniableAdmission, DeniableRouteError,
    DeniableState,
};
pub use dmtap_deniable;

// Node-layer mix-directory anti-rollback (spec §4.4.2, §18.5.3): the per-authority monotonic
// high-water-mark that rejects a replayed/stale mix-fleet snapshot at the node.
pub use mixdir::{MixDirError, MixDirectoryTracker};

// The hosted-node **storage** seam (spec §12.2, §12.3, §12.4): the OSS half of the "node usage"
// (hosted-mailbox storage) meter. Two traits — a `StorageQuota` Policy decision and an append-only
// `NodeUsageMeter` — with unlimited/no-op self-host defaults, so the node runs identically with the
// cloud off and links no billing crate. A cloud impl drops into these from the outside.
pub use usage::{
    CountingUsageMeter, NodeUsageMeter, NullUsageMeter, QuotaDecision, StorageQuota, UnlimitedStorage,
    UsageEvent,
};

// Node-only planned modules (see README): the rest of the client side that *is* the mesh.
// pub mod privacy;     // §6 — sealed sender, cover traffic, padding, tiers
