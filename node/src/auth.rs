//! The node's own login/session — DMTAP-Auth (spec §13).
//!
//! Your DMTAP identity is a keypair (§1) with a KT-resolvable name (§3); the same root `IK` that
//! receives your mail logs you in **everywhere**, with no central identity provider (§13). This
//! module wires the workspace-shared [`dmtap_auth`] crate into the [`Node`](crate::node::Node) so a
//! node can run the **client side** of the native login ceremony (§13.3) against a relying party:
//! its root `IK` signs the RP's origin-bound [`Challenge`], yielding the [`SignedAssertion`] to
//! transmit plus a retained per-RP [`SessionKey`] for DPoP-style proof-of-possession on every
//! subsequent request (§13.4).
//!
//! ## What is real vs. a documented seam
//! - **Real:** [`Node::login`](crate::node::Node::login) runs [`create_login`] with the node's own
//!   `IK` as the identity-revealing login signer, producing the §18.7.2 assertion (with `cnf =
//!   H(session_pubkey)` committed *before* signing) and the retained session key. The RP side
//!   ([`verify_login`] → [`BoundSession`] → [`BoundSession::verify_request`]) is the crate's real
//!   crypto, exercised end-to-end in the node tests.
//! - **Seam (§13.3.1):** origin binding is only as strong as the **trusted client** that enforces
//!   it — the [`TrustedClient`] seam (WebAuthn/PRF authenticator or paired companion). The node
//!   drives it through the trait; [`TrustedClientStub`] stands in for tests. This is a documented
//!   boundary, not a silent stub: the crypto core signs over the client's machine-observed origin,
//!   never a value trusted from the RP.

pub use dmtap_auth::{
    create_login, verify_login, AuthError, BoundSession, Challenge, Clock, DeviceAuthorizer,
    DeviceCertAuthorizer, DpopProof, InMemoryReplayCache, Login, ReplayCache, SessionKey,
    SignedAssertion, SystemClock, TrustedClient, TrustedClientStub,
};
