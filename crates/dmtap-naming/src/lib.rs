//! # dmtap-naming — the DMTAP `name → key` resolver (spec §3)
//!
//! Resolves a human `name@domain` to a **KT-verified, pinned identity key**, exactly as spec §3
//! layers it: **DNS is discovery, the key is proof, KT makes the binding tamper-evident, pinning
//! makes discovery a one-time event.** This crate is the real, testable resolver the node needs in
//! place of its HashMap stub — a reference implementation over `dmtap-core`'s KT objects, not
//! normative (the spec governs, §10.4).
//!
//! ## What it does
//! - [`canonical`] — the **canonical name form** every entry point funnels through (i18n
//!   hardening): local part = Unicode **NFC + lowercase**; domain = **UTS-46/IDNA** with the
//!   canonical stored/compared form being the **A-label** (punycode) form and DNS qnames always
//!   built from A-labels; every label **single-script** (UTS-39, with the Common/Inherited and
//!   Han+kana/Hangul/Bopomofo exemptions — `ERR_NAME_LABEL_MIXED_SCRIPT`, `0x0121`); plus the
//!   pin-time UTS-39 **skeleton** confusables gate (`ERR_NAME_CONFUSABLE_WITH_PIN`, `0x0122`).
//!   Parse, classify, `Identity.names` comparison, KT leaf computation, and pin/petname keys all
//!   route through it — one spelling, one identity, everywhere.
//! - [`dns`] — parse the §3.2 `_dmtap` **TXT** and **SVCB** records into fail-closed structs.
//! - [`merkle`] — RFC 6962 inclusion-proof verification + a tree builder (§18.4.10, §18.9.5); the
//!   arithmetic `dmtap-core`'s unsigned [`InclusionProof`](dmtap_core::kt::InclusionProof) needs.
//! - [`kt`] — turn a fetched `Identity` + `SignedTreeHead` + `InclusionProof` into a verified
//!   binding: STH signed by the pinned log key, inclusion folds to the root, committed leaf equals
//!   the leaf recomputed from the identity (§18.4.9), plus the §3.5.2 v1 `> n/2` multi-log quorum,
//!   split-view equivocation detection, and STH freshness. All fail-closed (§3.3): **unreachable KT
//!   blocks, it never TOFU-pins**.
//! - [`resolver`] — the §3.3 flow behind a [`Resolver`](resolver::Resolver) trait, with a fully
//!   in-memory harness ([`InMemoryResolver`](resolver::InMemoryResolver)) so the whole path is
//!   unit-testable offline; a real DNS/mesh/KT network layer is a thin later swap.
//! - [`keypackage`] — the §5.3 async-join KeyPackage bundle fetch seam + in-memory impl,
//!   content-address-checked.
//! - [`restype`] — the §3.12 **pluggable resolver-type framework**: form-based dispatch
//!   ([`classify`](restype::classify) / [`ResolverRegistry`](restype::ResolverRegistry)) routing a
//!   name to `self` / `petname` / `dns` / `name-chain`, the derived key-name
//!   [`SelfResolver`](restype::SelfResolver) and local [`PetnameBook`](restype::PetnameBook), and the
//!   fail-closed `ERR_RESOLVER_TYPE_UNSUPPORTED` (`0x011F`) "unknown ⇒ reject, never guess" rule.
//! - [`namechain`] — the OPTIONAL `name-chain` resolver (ENS `.eth` / SNS `.sol`, §3.12.5): a
//!   [`NameChainClient`](namechain::NameChainClient) RPC seam (mock-backed here) plus the
//!   §3.12.5(b) bidirectional key↔name binding enforcement (`ERR_NAMECHAIN_BINDING_UNVERIFIED`,
//!   `0x011E`).
//! - [`reconcile`] — the §3.12.3 **multi-resolver cross-check**: resolvers are mutual auditors, so
//!   several answers for one name are reconciled by [`reconcile`](reconcile::reconcile) and MUST agree
//!   on `ik`; disagreement fails closed (`ERR_RESOLVER_DISAGREEMENT`, `0x0120`, HALT_ALERT) while an
//!   abstaining resolver simply does not vote.
//!
//! ## What is real vs. seam
//! DNS **parsing**, KT **verification** (RFC 6962 folding, STH signatures, leaf binding, quorum,
//! equivocation, freshness), and the `Identity`/chain checks are real cryptographic code exercised
//! by the tests. **Network I/O** (actual DNS queries, mesh fetches, HTTP KT clients) is deliberately
//! left as a trait seam ([`Resolver`](resolver::Resolver), [`KtLog`](kt::KtLog),
//! [`KeyPackageSource`](keypackage::KeyPackageSource)) so a later layer can implement it without
//! touching the verification core.

#![forbid(unsafe_code)]

pub mod base64url;
pub mod canonical;
pub mod dns;
pub mod error;
pub mod keypackage;
pub mod kt;
pub mod merkle;
pub mod namechain;
pub mod reconcile;
pub mod resolver;
pub mod restype;

pub use canonical::{canonical_domain, canonical_local, canonical_name, find_confusable, skeleton};
pub use dns::{DmtapSvcbRecord, DmtapTxtRecord};
pub use error::ResolveError;
pub use keypackage::{InMemoryKeyPackages, KeyPackageSource};
pub use kt::{
    check_freshness, detect_equivocation, verify_attestation, verify_quorum,
    verify_sth_consistency, InMemoryKtLog, KtLog, KtProof, UnreachableLog,
};
pub use merkle::{verify_inclusion, MerkleTree};
pub use namechain::{InMemoryNameChain, NameChainClient, NameChainResolver};
pub use reconcile::{reconcile, reconcile_bindings, ReconciledResolution, ResolverAnswer};
pub use resolver::{DmtapName, InMemoryResolver, KtMode, PinnedResolution, Resolver};
pub use restype::{
    classify, Chain, PetnameBook, ResolvedBinding, ResolverKind, ResolverRegistry, ResolverType,
    SelfResolver, Verification,
};
