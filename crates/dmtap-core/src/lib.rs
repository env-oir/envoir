//! # dmtap-core — DMTAP core primitives
//!
//! Shared building blocks for the **Decentralized Message Transfer & Access Protocol**
//! (DMTAP), used by the Envoir reference node and gateway. This crate is a **reference
//! implementation, not normative** — the normative source of truth is the DMTAP spec repo
//! (`../../../dmtap/`). Where this code and the spec disagree, the spec governs (spec §10.4).
//!
//! ## Modules
//! - [`cbor`] — canonical **integer-keyed** deterministic CBOR (spec §18.1.1/§18.1.2); the single
//!   wire/signing/content-address codec (serde/`ciborium` text-keyed encodings are NOT the wire).
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
//! - [`mixnet`] — the mixnet directory objects: `MixNodeDescriptor` + `MixDirectory` (§18.5.2/.3),
//!   signed per §18.9.9.
//! - [`directory`] — the org directory: `DomainDirectory` + `DirEntry` (§18.4.7), signed per
//!   §18.9.3.
//! - [`deniable`] — the optional deniable 1:1 mode objects: `DeniablePrekeyBundle` (§18.4.8),
//!   `DeniableFrame`/`DeniableInit`/`DeniableMessage` (§18.3.9), `DeniablePayload` (§18.3.10);
//!   asymmetric signing per §18.9.10, incl. the dedicated deniable-identity DH key (`idk`).
//! - [`kt`] — key-transparency objects: `SignedTreeHead` (§18.4.9, signed per §18.9.13),
//!   `InclusionProof`/`ConsistencyProof` (§18.4.10/.11, unsigned RFC-6962 proofs) + the Identity
//!   leaf-hash rule.
//! - [`capability`] — delegated `CapabilityToken`/`Capability`/`CapabilityRevocation` (§18.7.3,
//!   a UCAN v1.0 profile), signed per §18.9.14.
//! - [`profile`] — the signed human display data `Profile` + `Avatar` (§18.4.12), signed per
//!   §18.9.3 (DS-tag `DMTAP-v0/profile`); avatar content-address tamper-evidence.
//! - [`push`] — the push wake-signaling objects `PushSubscription` (signed per §18.9.15) and the
//!   content-free `WakePing` (§18.5.5/.6, §4.9).
//! - [`policy`] — caller-policy predicates for the §2.6/§2.7 recipient pipeline (dedup, clock-skew,
//!   expiry, pinned-identity re-pin), each mapped to its §21 code — additive to [`mote::validate`].
//! - [`attestation`] — the advisory §1.2a device key-attestation evaluator (`0x0116`/`0x0118`),
//!   never a §1.4 authority override.
//! - [`sphinx`] — the fixed-length Sphinx byte layouts `SphinxCell`/`RoutingCommand`/`Surb`/
//!   `SphinxFragmentHeader` (§18.5.4) — the one mixnet wire object that is NOT CBOR.
//!
//! ## Crypto suite `0x01` (v0 REQUIRED)
//! Ed25519 signatures, HPKE `DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305`, BLAKE3-256 hashing.
//! Suite `0x02` (PQ) is reserved and **fails closed** everywhere it is offered.

pub mod attestation;
pub mod capability;
pub mod cbor;
pub mod deniable;
pub mod directory;
pub mod id;
pub mod identity;
pub mod kt;
pub mod keyname;
pub mod mixnet;
pub mod mote;
pub mod policy;
pub mod profile;
pub mod push;
pub mod safety;
pub mod sphinx;
pub mod suite;

pub use suite::Suite;

/// Unsigned milliseconds since the Unix epoch. Transported explicitly; nodes MUST NOT rely on
/// synchronized clocks for correctness (spec §16.1).
pub type TimestampMs = u64;

pub use id::ContentId;
