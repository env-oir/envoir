//! # dmtap-auth — DMTAP-Auth: sovereign, decentralized web login (spec §13)
//!
//! Your DMTAP identity is a keypair (§1) with a human name resolvable to that key (§3). The same
//! key that receives your mail logs you in **everywhere**, with **no central identity provider**
//! (spec §13). This crate implements the **native login ceremony** (§13.3) and the **key-bound
//! session** (§13.4) as a real, testable library — the relying-party (RP) side and the client
//! side of the crypto core.
//!
//! ## What is real here (the crypto core)
//! - [`Challenge`] — the RP-side origin-scoped, single-use-nonce, audience-bound challenge
//!   (§13.3 step 3, wire object §18.7.1).
//! - [`create_login`] — the client side: generates a fresh **per-RP, per-device session
//!   keypair**, computes `cnf = H(session_pubkey)` **before** signing (§13.3 step 4), and signs
//!   the domain-separated §18.9.8 preimage under an `IK`-authorized device key. Produces a
//!   [`SignedAssertion`] (wire object §18.7.2) plus the retained [`SessionKey`].
//! - [`verify_login`] — the RP side: verifies the assertion signature against the pinned identity
//!   key, checks `rp_origin`/`aud`, single-use nonce (replay cache), expiry, and binds the
//!   session **only** to `cnf` (§13.3 step 6, §13.4). Returns a [`BoundSession`].
//! - [`session`] — the **DPoP-style** (RFC 9449) per-request proof-of-possession: the client
//!   signs each request context with the session key; the RP verifies it against the bound
//!   `cnf`'s public key. A stolen assertion **without** the session key is useless (§13.4).
//!
//! ## What is stubbed (the seams — §13.3.1 / §13.4)
//! Origin binding is only as strong as the **trusted client** that enforces it (§13.3.1). This
//! crate does not ship a WebAuthn/PRF authenticator or an HTTP stack; it exposes them as seams so
//! a real front-end slots in later:
//! - [`TrustedClient`] — the WebAuthn/OS/companion component that supplies the **machine-observed
//!   origin** (never a value trusted from the RP) and gates signing on user-verification.
//! - [`Clock`], [`ReplayCache`] — injectable time and single-use stores (an HTTP/DB layer
//!   provides the production impls; in-memory + manual impls ship for tests).
//! - [`DeviceAuthorizer`] — resolves whether the login signer is an `IK`-authorized device key
//!   (§3.4 `name → key`); [`DeviceCertAuthorizer`] does it from real [`dmtap_core`] `DeviceCert`s.
//!
//! This crate is a **reference implementation, not normative** — where it and the DMTAP spec
//! (`../../../dmtap/`) disagree, the spec governs (spec §10.4).

mod assertion;
mod challenge;
mod error;
mod seam;
pub mod session;
mod verify;

pub use assertion::{create_login, Login, SignedAssertion};
pub use challenge::Challenge;
pub use error::AuthError;
pub use seam::{
    Clock, DeviceAuthorizer, DeviceCertAuthorizer, InMemoryReplayCache, ReplayCache, SystemClock,
    TrustedClient, TrustedClientStub,
};
pub use session::{BoundSession, DpopProof, SessionKey};
pub use verify::verify_login;

/// Domain-separation tag for the auth assertion signature (§18.9.1 table, §18.9.8). Every DMTAP
/// signature is domain-separated so an assertion can never be confused with any other signed
/// object (§18.1.6). ASCII string terminated by one `0x00` byte, matching the `sign_domain`
/// convention in [`dmtap_core::identity`].
pub const AUTH_ASSERTION_DS: &[u8] = b"DMTAP-v0/auth-assertion\x00";

/// Domain-separation tag for the DPoP-style session proof-of-possession (§13.4). The spec
/// mandates a key-bound session (DPoP RFC 9449 / GNAP RFC 9635) but does not fix this preimage,
/// so this DS-tag is an **implementation choice** of the reference core — distinct from
/// [`AUTH_ASSERTION_DS`] so a session proof can never be replayed as a login assertion.
pub const DPOP_DS: &[u8] = b"DMTAP-v0/auth-dpop\x00";
