//! # dmtap-core — DMTAP core primitives
//!
//! Shared building blocks for the **Decentralized Message Transfer & Access Protocol**
//! (DMTAP), used by the Envoir reference node and gateway. This crate is a **reference
//! implementation, not normative** — the normative source of truth is the DMTAP spec repo
//! (`../../../dmtap/`). Where this code and the spec disagree, the spec governs (spec §10.4).
//!
//! ## Modules
//! - [`suite`] — algorithm suites & crypto-agility (spec §1.1, §16.7); fail-closed decoding.
//! - [`id`] — content addressing: `[0x1e] || BLAKE3-256(bytes)` with an agility prefix (§2.2).
//! - [`identity`] — the identity lifecycle: `IdentityKey` (Ed25519), `Identity` (multi-suite
//!   set), `DeviceCert`, `RecoveryPolicy`, `MoveRecord` — real signatures (§1).
//! - [`keyname`] — the zero-authority **8-word key-name** derived from `BLAKE3(pubkey)`, with a
//!   checksum word (§3.9.1, §16.2).
//! - [`safety`] — out-of-band **safety numbers**: a deterministic, order-independent fingerprint
//!   of a *pair* of identity keys for OOB key verification (§3.4.1).
//! - [`mote`] — the **MOTE** object: `Envelope` + `Payload`, HPKE payload sealing, and the
//!   ordered recipient validation of §2.7 (anonymous checks before decryption).
//!
//! ## Crypto suite `0x01` (v0 REQUIRED)
//! Ed25519 signatures, HPKE `DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305`, BLAKE3-256 hashing.
//! Suite `0x02` (PQ) is reserved and **fails closed** everywhere it is offered.

pub mod id;
pub mod identity;
pub mod keyname;
pub mod mote;
pub mod safety;
pub mod suite;

pub use suite::Suite;

/// Unsigned milliseconds since the Unix epoch. Transported explicitly; nodes MUST NOT rely on
/// synchronized clocks for correctness (spec §16.1).
pub type TimestampMs = u64;

pub use id::ContentId;
