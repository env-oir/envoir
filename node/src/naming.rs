//! Name resolution — the node's real `name@domain → key` path (spec §3).
//!
//! The reference node historically resolved a recipient by looking their identity key up in a local
//! `directory` HashMap — a stand-in with no verification. This module wires the workspace-shared
//! [`dmtap_naming`] resolver (real DNS `_dmtap` parsing + RFC 6962 key-transparency verification)
//! into the [`Node`](crate::node::Node) so an outbound MOTE is addressed to a **KT-verified, pinned**
//! key, exactly as spec §3.3 requires — and **fail-closed**: an unreachable / sub-quorum / stale /
//! equivocating / proof-invalid KT returns the typed [`ResolveError`] and pins **nothing** (never a
//! TOFU pin on unverifiable KT, §3.3).
//!
//! ## What is real vs. a documented seam
//! - **Real:** the whole §3.3 verification core runs — DNS record parsing, the fetched `Identity`
//!   signature/chain check, the DNS⇄Identity cross-check, RFC 6962 inclusion-proof folding, STH
//!   signatures, leaf-hash binding, the v1 `> n/2` quorum, split-view/freshness gates — all via the
//!   [`Resolver`] seam. Its verdict flows straight into the node's pin cache.
//! - **Seam (network I/O):** the actual DNS queries / mesh fetches / HTTP KT clients are the
//!   [`Resolver`] + [`KeyPackageSource`] trait boundaries; the node drives them through the trait, so
//!   the in-memory harnesses ([`dmtap_naming::InMemoryResolver`] / [`InMemoryKeyPackages`]) exercise
//!   the *identical* verification path a networked resolver will, with the socket layer a later swap.
//! - **Seam (the sealing KeyPackage):** in this reference, a fetched, content-addressed KeyPackage
//!   bundle carries exactly the recipient's 32-byte X25519 **sealing** public key — the §5.3 KEM
//!   public the 1:1 HPKE path seals to. A production bundle is a full signed MLS KeyPackage; here it
//!   is the sealing key alone, still content-verified (§2.2) and KT-gated. This is a *documented*
//!   narrowing of the bundle, not a silent stub — [`seal_key_from_bundle`] fails closed on any other
//!   shape.

use crate::node::SendError;

pub use dmtap_naming::{
    InMemoryKeyPackages, InMemoryResolver, KeyPackageSource, PinnedResolution, ResolveError,
    Resolver,
};

/// Encode a recipient's X25519 sealing public key as the reference KeyPackage bundle bytes (the
/// §5.3 KEM public the 1:1 HPKE path seals to). The inverse of [`seal_key_from_bundle`]. A node
/// publishes this under its `Identity.keypkgs` locator so a resolver can content-verify + fetch it.
pub fn seal_key_bundle(seal_pub: &[u8; 32]) -> Vec<u8> {
    seal_pub.to_vec()
}

/// Extract the recipient's 32-byte X25519 sealing key from a fetched, already-content-verified
/// KeyPackage bundle (§5.3). Fails closed ([`ResolveError::KeyPackage`]) on any other length — a
/// relay cannot smuggle a malformed sealing key past this even after the content-address check.
pub fn seal_key_from_bundle(bundle: &[u8]) -> Result<[u8; 32], ResolveError> {
    bundle
        .try_into()
        .map_err(|_| ResolveError::KeyPackage("bundle is not a 32-byte sealing key"))
}

/// Why addressing outbound mail *by name* failed: either §3.3 resolution/KT verification, or the
/// subsequent build/seal. Keeps the two fail-closed stages distinguishable to the caller — a KT
/// failure (`Resolve`) is a discovery/verification problem, a `Send` failure is a local seal one.
#[derive(Debug)]
pub enum AddressError {
    /// Name resolution or KT verification failed (fail-closed, §3.3) — nothing was pinned.
    Resolve(ResolveError),
    /// The recipient resolved + pinned, but building/sealing the MOTE to them failed (§2.4).
    Send(SendError),
}

impl From<ResolveError> for AddressError {
    fn from(e: ResolveError) -> Self {
        AddressError::Resolve(e)
    }
}
impl From<SendError> for AddressError {
    fn from(e: SendError) -> Self {
        AddressError::Send(e)
    }
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressError::Resolve(e) => write!(f, "resolve/KT-verify failed: {e}"),
            AddressError::Send(e) => write!(f, "seal/dispatch failed: {e}"),
        }
    }
}
impl std::error::Error for AddressError {}
