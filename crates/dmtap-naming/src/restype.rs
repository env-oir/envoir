//! The pluggable **resolver-type framework** — spec §3.12, §3.13, §21.18.
//!
//! §3.12 states one mechanism generically: resolving a name is *always* two steps — **(1) discover**
//! a `name → identity` pointer via a *resolver*, then **(2) verify** that pointer against key
//! transparency and pin it (§3.5). DMTAP does not pick a winning naming system; it fixes an
//! invariant — **`identity ≠ name`, the key is the identity** (§1.2, §3) — and lets naming systems
//! compete *below* it. Every resolver type resolves to a **key**; a name is only a label.
//!
//! This module is the **dispatch layer**: it routes a name to its resolver type *by form* (§3.12.4),
//! and gates that against the set of types this node actually implements (§3.12.2). A name in a type
//! the node does not implement — or an unregistered type — is **undiscovered by this node, not
//! invalid**, and **fails closed** ([`ResolveError::ResolverTypeUnsupported`], `0x011F`): the node
//! **never guesses** a binding, and the identity stays reachable via any type it *does* implement,
//! always including the key-name floor (§3.9.6).
//!
//! The concrete resolvers:
//! - [`SelfResolver`] — resolver-type `self` (§3.9.6): the key-name is a **local derivation** from
//!   the key (`BLAKE3-256(ik)` → word-name, [`dmtap_core::keyname`]); step 2 is **vacuous** — the
//!   binding *is* the key. No network, no authority.
//! - [`PetnameBook`] — resolver-type `petname` (§3.9.3): a **local** label bound to an
//!   already-pinned key; vacuous KT, no global lookup.
//! - `dns` — the existing DNS + KT path ([`crate::resolver::InMemoryResolver`], §3.2–§3.5).
//! - `name-chain` — the OPTIONAL ENS `.eth` / SNS `.sol` path ([`crate::namechain`], §3.12.5), whose
//!   step-1 pointer is a read-only on-chain record and whose §3.12.5(b) bidirectional binding is the
//!   name-chain-specific guardrail.

use std::collections::HashSet;

use dmtap_core::keyname;

use crate::canonical;
use crate::error::ResolveError;

/// A crypto **name-chain** admitted as a `name-chain` resolver (§3.12.5). DMTAP hard-wires none — a
/// chain is added purely by registration in §21.18; these two are the ones supported today. The
/// chain is only a *discovery* substrate: authenticity is always the key, KT-audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// ENS — Ethereum Name Service, the `.eth` namespace (§3.12.5).
    Ens,
    /// SNS — Solana Name Service, the `.sol` namespace (§3.12.5).
    Sns,
}

impl Chain {
    /// The namespace suffix that identifies this chain (`.eth` / `.sol`).
    pub fn tld(self) -> &'static str {
        match self {
            Chain::Ens => ".eth",
            Chain::Sns => ".sol",
        }
    }

    /// The short registry tag for this chain (`ens` / `sns`).
    pub fn tag(self) -> &'static str {
        match self {
            Chain::Ens => "ens",
            Chain::Sns => "sns",
        }
    }
}

/// A resolver type as identified **by the form of a name** (§3.12.4). This is what step 1 of §3.12.1
/// routes on: the name's shape selects the discovery mechanism; the key it resolves to is then
/// verified the same way for every type (§3.12.1 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverType {
    /// `self` — the key-name floor (§3.9.6): derived, zero-authority, no `@`, no lookup.
    SelfKeyName,
    /// `petname` — a local label bound to an already-pinned key (§3.9.3): no `@`, no global lookup.
    Petname,
    /// `dns` — the default `local@domain` DNS + KT resolver (§3.2–§3.5).
    Dns,
    /// `name-chain` — an OPTIONAL crypto chain resolver (§3.12.5), carrying which chain.
    NameChain(Chain),
}

impl ResolverType {
    /// The chain-agnostic [`ResolverKind`] this type belongs to — what the registry gates on.
    pub fn kind(self) -> ResolverKind {
        match self {
            ResolverType::SelfKeyName => ResolverKind::SelfKeyName,
            ResolverType::Petname => ResolverKind::Petname,
            ResolverType::Dns => ResolverKind::Dns,
            ResolverType::NameChain(_) => ResolverKind::NameChain,
        }
    }
}

/// The chain-agnostic discriminant of a resolver type — the granularity the §21.18 registry and this
/// node's *implemented-types* set track (all name-chains share one `name-chain` type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolverKind {
    /// `self` (§3.9.6).
    SelfKeyName,
    /// `petname` (§3.9.3).
    Petname,
    /// `dns` (§3.2).
    Dns,
    /// `name-chain` (§3.12.5).
    NameChain,
}

/// Classify a name to its [`ResolverType`] **by form** (§3.12.4), independent of what any node
/// implements. Fails closed with [`ResolveError::ResolverTypeUnsupported`] (`0x011F`) for a form
/// that belongs to no resolver type this reference set recognizes (an unregistered/unknown chain
/// namespace, or the opt-in `@handle` directory this build does not carry) — the "unknown ⇒ reject,
/// never guess" discipline (§3.12.2).
///
/// Form rules (§3.12.4, §3.13):
/// - `@handle` (a leading `@`) → the opt-in `directory` type (§3.9.2), **not implemented here** ⇒
///   `0x011F`.
/// - `local@<ns>` with `<ns>` ending `.eth`/`.sol` → `name-chain` (the §3.13 `alice@.eth` form).
/// - `local@<ns>` with `<ns>` a dotted DNS domain → `dns`.
/// - `local@<ns>` with `<ns>` some other `.`-prefixed / label-less namespace → an unregistered
///   name-chain / non-domain namespace ⇒ `0x011F`.
/// - bare `local.eth` / `local.sol` (no `@`) → `name-chain` (the mission's bare chain form).
/// - a bare word-list that checksum-verifies as a key-name → `self` (§3.9.6).
/// - any other bare label → `petname` (a local name, §3.9.3).
///
/// Classification also runs the name through the [`crate::canonical`] chokepoint: a name whose
/// form is recognized but that cannot **canonicalize** — a domain UTS-46/IDNA rejects, or any
/// mixed-script label (`0x0121`) — is rejected here, before any resolver is consulted, so an
/// unnormalizable/homograph name is unresolvable under every resolver type at once.
pub fn classify(name: &str) -> Result<ResolverType, ResolveError> {
    let ty = classify_form(name)?;
    canonical::canonical_name(name)?;
    Ok(ty)
}

/// The pure §3.12.4 form dispatch (see [`classify`], which adds the canonicalization gate).
fn classify_form(name: &str) -> Result<ResolverType, ResolveError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ResolveError::ResolverTypeUnsupported("empty name"));
    }

    // The opt-in `@handle` directory (§3.9.2): the `@` is the *marker*, the local part is empty. It
    // is a registered type, but this reference build does not implement it — fail closed, never
    // guess (§3.12.2).
    if let Some(rest) = name.strip_prefix('@') {
        let _ = rest;
        return Err(ResolveError::ResolverTypeUnsupported(
            "@handle directory resolver not implemented by this node",
        ));
    }

    if let Some((local, ns)) = name.split_once('@') {
        if local.is_empty() {
            return Err(ResolveError::ResolverTypeUnsupported("empty local part before '@'"));
        }
        let ns = ns.to_ascii_lowercase();
        if ns.ends_with(".eth") {
            return Ok(ResolverType::NameChain(Chain::Ens));
        }
        if ns.ends_with(".sol") {
            return Ok(ResolverType::NameChain(Chain::Sns));
        }
        // A `.`-led namespace that is not a chain we carry is an unregistered / unimplemented
        // name-chain (e.g. `@.hns`) — unresolvable, never guessed (§3.12.2).
        if ns.starts_with('.') {
            return Err(ResolveError::ResolverTypeUnsupported(
                "unregistered name-chain namespace",
            ));
        }
        // A dotted, non-chain namespace is a DNS domain — the default resolver (§3.2).
        if ns.contains('.') {
            return Ok(ResolverType::Dns);
        }
        return Err(ResolveError::ResolverTypeUnsupported(
            "namespace is neither a DNS domain nor a known name-chain",
        ));
    }

    // No `@`: a zero-authority (self / petname) or a bare-form name-chain.
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".eth") {
        return Ok(ResolverType::NameChain(Chain::Ens));
    }
    if lower.ends_with(".sol") {
        return Ok(ResolverType::NameChain(Chain::Sns));
    }
    // A key-name is a checksum-verifiable word-list (§3.9.6); anything else is a local petname.
    if keyname::verify(name) {
        Ok(ResolverType::SelfKeyName)
    } else {
        Ok(ResolverType::Petname)
    }
}

/// The set of resolver types a node implements — its live slice of the §21.18 registry. `route`
/// gates a form-classified name against it so a type this node does **not** implement fails closed
/// (`0x011F`), exactly as §3.12.2 mandates. The `name-chain` type is **OPTIONAL** (§3.12.5(a)) and is
/// therefore **off by default**: a deployment that admits no chain is fully conformant.
#[derive(Debug, Clone)]
pub struct ResolverRegistry {
    enabled: HashSet<ResolverKind>,
}

impl Default for ResolverRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl ResolverRegistry {
    /// The default implemented set: the two zero-authority types (`self`, `petname`) plus the
    /// default `dns` resolver. `name-chain` is OPTIONAL (§3.12.5(a)) and left **disabled** until
    /// explicitly enabled.
    pub fn with_defaults() -> Self {
        let mut enabled = HashSet::new();
        enabled.insert(ResolverKind::SelfKeyName);
        enabled.insert(ResolverKind::Petname);
        enabled.insert(ResolverKind::Dns);
        ResolverRegistry { enabled }
    }

    /// Enable a resolver kind (e.g. opt into `name-chain`, §3.12.5).
    pub fn enable(mut self, kind: ResolverKind) -> Self {
        self.enabled.insert(kind);
        self
    }

    /// Whether this node implements `kind`.
    pub fn implements(&self, kind: ResolverKind) -> bool {
        self.enabled.contains(&kind)
    }

    /// Route a name to the resolver type that will handle it, or fail closed. Classifies by form
    /// (§3.12.4) and then requires that this node implements the resulting type (§3.12.2); an
    /// unimplemented or unrecognized type yields [`ResolveError::ResolverTypeUnsupported`]
    /// (`0x011F`) — the node treats the name as unresolvable and **never guesses** a binding.
    pub fn route(&self, name: &str) -> Result<ResolverType, ResolveError> {
        let ty = classify(name)?;
        if self.implements(ty.kind()) {
            Ok(ty)
        } else {
            Err(ResolveError::ResolverTypeUnsupported(
                "resolver type not implemented by this node",
            ))
        }
    }
}

/// How a [`ResolvedBinding`] was proven — the per-type instantiation of §3.12.1 step 2. Discovery is
/// never proof (§3.1); this records what made the binding trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// `self` (§3.9.6): the binding **is** the key — a local derivation, KT step vacuous.
    DerivedSelf,
    /// `petname` (§3.9.3): bound to an **already-pinned** key; vacuous KT, local only.
    LocalPetname,
    /// `name-chain` (§3.12.5(b)): the read-only on-chain pointer and the key's self-asserted claim
    /// were checked to **agree bidirectionally**. The chain is a discovery pointer KT then audits
    /// like any other (§3.3–§3.5) — never a trust root.
    ChainBound,
}

/// A resolved `name → key` binding produced by the pluggable framework. Uniform across resolver
/// types because **everything resolves to a key** (§1.2, §3): a name is only a label on `ik`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinding {
    /// The name that was resolved (canonical form for its type).
    pub name: String,
    /// The identity key the name resolves to — the *identity*; the name is just its label.
    pub ik: Vec<u8>,
    /// Which resolver type produced the binding (§3.12.4).
    pub resolver_type: ResolverType,
    /// How the binding was verified (§3.12.1 step 2).
    pub verification: Verification,
}

/// The `self` resolver — resolver-type `self`, the key-name floor (§3.9.6). Resolution is a **local
/// derivation** from the key (`BLAKE3-256(ik)` word-encoded, [`dmtap_core::keyname`]), never a
/// network lookup, and its KT step is **vacuous**: the binding *is* the key. A mistyped/misheard
/// key-name **fails closed** (checksum, §3.9.6) rather than resolving to a *different* key — the
/// resolver derives, it never guesses.
pub struct SelfResolver;

impl SelfResolver {
    /// Derive the key-name for `ik` (§3.9.6 encoding) — the forward direction, no authority.
    pub fn derive(ik: &[u8]) -> String {
        keyname::encode(ik)
    }

    /// Resolve a key-name against a candidate key: the name MUST checksum-verify (§3.9.6, typo/
    /// mishear defense) **and** derive from `candidate_ik`. Either failure is fail-closed
    /// ([`ResolveError::KeyNameUnverified`]) — the binding is the key, so a name that does not derive
    /// from *this* key does not resolve to it. No network.
    pub fn resolve(key_name: &str, candidate_ik: &[u8]) -> Result<ResolvedBinding, ResolveError> {
        // 1. Internal checksum — a mistyped/truncated name fails closed, never resolves elsewhere.
        if !keyname::verify(key_name) {
            return Err(ResolveError::KeyNameUnverified(
                "key-name checksum failed — typo/mishear, fail closed",
            ));
        }
        // 2. Full binding — the name must be exactly the derivation of the candidate key.
        if keyname::encode(candidate_ik) != key_name {
            return Err(ResolveError::KeyNameUnverified(
                "key-name does not derive from the candidate key",
            ));
        }
        Ok(ResolvedBinding {
            name: key_name.to_owned(),
            ik: candidate_ik.to_vec(),
            resolver_type: ResolverType::SelfKeyName,
            verification: Verification::DerivedSelf,
        })
    }
}

/// The `petname` resolver — a **local** book of labels a user assigned to already-pinned keys
/// (§3.9.3). No global lookup, no `@`, vacuous KT: a petname resolves only to a key the user has
/// already established out-of-band, so there is nothing to attest — it is a private alias over a
/// pin. An unknown petname is a local `NameResolution` miss, not a protocol failure.
#[derive(Debug, Default, Clone)]
pub struct PetnameBook {
    map: std::collections::HashMap<String, Vec<u8>>,
}

impl PetnameBook {
    /// An empty local petname book.
    pub fn new() -> Self {
        PetnameBook::default()
    }

    /// Assign `petname` to an **already-pinned** key `ik` (the local labeling step, §3.9.3).
    ///
    /// The petname is stored in **canonical form** ([`crate::canonical`]: NFC + lowercase,
    /// single-script labels, `0x0121` on a homograph mix) and gated by the UTS-39 **skeleton**
    /// check: a new petname confusable with a *different* existing one (`mum` beside Cyrillic
    /// `мum` — or, since that mix is already `0x0121`, an all-confusable-script look-alike) is
    /// rejected (`0x0122`) rather than silently shadowing the label the user already trusts.
    /// Re-assigning the exact same canonical petname (rebinding it to a new key) stays allowed —
    /// that is the user's own explicit relabeling, not a spoof.
    pub fn assign(
        &mut self,
        petname: impl Into<String>,
        ik: impl Into<Vec<u8>>,
    ) -> Result<(), ResolveError> {
        let pet = canonical::canonical_name(&petname.into())?;
        if canonical::find_confusable(&pet, self.map.keys().map(String::as_str)).is_some() {
            return Err(ResolveError::ConfusableName(
                "petname skeleton-collides with a different existing petname",
            ));
        }
        self.map.insert(pet, ik.into());
        Ok(())
    }

    /// Resolve a local `petname` to its pinned key, or a `NameResolution` miss if unassigned.
    /// Lookup is by canonical form, so `Mum` finds the book's `mum` — one label, one identity.
    pub fn resolve(&self, petname: &str) -> Result<ResolvedBinding, ResolveError> {
        let pet = canonical::canonical_name(petname)?;
        match self.map.get(&pet) {
            Some(ik) => Ok(ResolvedBinding {
                name: pet,
                ik: ik.clone(),
                resolver_type: ResolverType::Petname,
                verification: Verification::LocalPetname,
            }),
            None => Err(ResolveError::NameResolution("no such petname in the local book")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::identity::IdentityKey;

    #[test]
    fn form_dispatch_routes_each_type() {
        // dns: local@domain.
        assert_eq!(classify("alice@example.com").unwrap(), ResolverType::Dns);
        // name-chain: the §3.13 `alice@.eth` form and bare `vitalik.eth` / `foo.sol` forms.
        assert_eq!(classify("alice@.eth").unwrap(), ResolverType::NameChain(Chain::Ens));
        assert_eq!(classify("bob@.sol").unwrap(), ResolverType::NameChain(Chain::Sns));
        assert_eq!(classify("vitalik.eth").unwrap(), ResolverType::NameChain(Chain::Ens));
        assert_eq!(classify("toly.sol").unwrap(), ResolverType::NameChain(Chain::Sns));
        // self: a real derived key-name checksum-verifies.
        let kn = SelfResolver::derive(&IdentityKey::from_seed(&[3; 32]).public());
        assert_eq!(classify(&kn).unwrap(), ResolverType::SelfKeyName);
        // petname: any other bare label.
        assert_eq!(classify("mum").unwrap(), ResolverType::Petname);
    }

    #[test]
    fn unknown_or_unregistered_type_fails_closed_011f() {
        // An unregistered name-chain namespace (a chain this build does not carry).
        assert_eq!(
            classify("carol@.hns"),
            Err(ResolveError::ResolverTypeUnsupported("unregistered name-chain namespace"))
        );
        assert_eq!(classify("carol@.hns").unwrap_err().code(), 0x011F);
        // The opt-in @handle directory is not implemented here.
        assert!(matches!(
            classify("@carol"),
            Err(ResolveError::ResolverTypeUnsupported(_))
        ));
        // A label-less namespace after '@' is neither a DNS domain nor a known chain.
        assert!(matches!(
            classify("alice@localhost"),
            Err(ResolveError::ResolverTypeUnsupported(_))
        ));
    }

    #[test]
    fn registry_gates_optional_name_chain() {
        // name-chain is OPTIONAL and off by default — an `.eth` name is unresolvable until enabled.
        let default = ResolverRegistry::with_defaults();
        assert_eq!(
            default.route("alice@.eth"),
            Err(ResolveError::ResolverTypeUnsupported(
                "resolver type not implemented by this node"
            ))
        );
        assert_eq!(default.route("alice@.eth").unwrap_err().code(), 0x011F);
        // The default types still route.
        assert_eq!(default.route("alice@example.com").unwrap(), ResolverType::Dns);

        // Opt into name-chain and the same name now routes.
        let with_chain = ResolverRegistry::with_defaults().enable(ResolverKind::NameChain);
        assert_eq!(
            with_chain.route("alice@.eth").unwrap(),
            ResolverType::NameChain(Chain::Ens)
        );
    }

    #[test]
    fn self_resolver_derives_and_verifies() {
        let ik = IdentityKey::from_seed(&[5; 32]).public();
        let kn = SelfResolver::derive(&ik);
        let b = SelfResolver::resolve(&kn, &ik).unwrap();
        assert_eq!(b.ik, ik);
        assert_eq!(b.resolver_type, ResolverType::SelfKeyName);
        assert_eq!(b.verification, Verification::DerivedSelf);
    }

    #[test]
    fn self_resolver_fails_closed_on_typo_and_wrong_key() {
        let ik = IdentityKey::from_seed(&[5; 32]).public();
        let kn = SelfResolver::derive(&ik);

        // A mistyped key-name (corrupt one word) fails the checksum — never resolves elsewhere.
        let mut words: Vec<String> = kn.split('-').map(str::to_owned).collect();
        words[0] = if words[0] == "kada" { "kadu".into() } else { "kada".into() };
        let typo = words.join("-");
        assert!(matches!(
            SelfResolver::resolve(&typo, &ik),
            Err(ResolveError::KeyNameUnverified(_))
        ));

        // A well-formed key-name that belongs to a DIFFERENT key does not resolve to this one.
        let other = IdentityKey::from_seed(&[6; 32]).public();
        let err = SelfResolver::resolve(&kn, &other).unwrap_err();
        assert!(matches!(err, ResolveError::KeyNameUnverified(_)));
        assert_eq!(err.code(), 0x0109);
    }

    #[test]
    fn classify_rejects_mixed_script_and_folds_case_insensitively() {
        // Form is recognized (dns), but the label mixes Latin + Cyrillic — rejected at the same
        // chokepoint (0x0121), before any resolver is consulted.
        let err = classify("alice@p\u{0430}ypal.com").unwrap_err();
        assert!(matches!(err, ResolveError::MixedScriptLabel(_)));
        assert_eq!(err.code(), 0x0121);
        // The CJK exemptions pass classification.
        assert_eq!(classify("alice@東京テスト.example").unwrap(), ResolverType::Dns);
        // A single-script Cyrillic domain classifies fine.
        assert_eq!(classify("иван@почта.рф").unwrap(), ResolverType::Dns);
    }

    #[test]
    fn petname_book_folds_case_and_rejects_confusables_0x0122() {
        let ik = IdentityKey::from_seed(&[7; 32]).public();
        let mut book = PetnameBook::new();
        book.assign("Cop", ik.clone()).unwrap();
        // Canonical fold: `Cop` and `cop` are one label.
        assert_eq!(book.resolve("cop").unwrap().ik, ik);
        // Re-assigning the SAME canonical petname (user relabeling) stays allowed…
        let ik2 = IdentityKey::from_seed(&[8; 32]).public();
        book.assign("cop", ik2.clone()).unwrap();
        assert_eq!(book.resolve("COP").unwrap().ik, ik2);
        // …but a *different* petname whose skeleton collides is refused: Cyrillic `сор`
        // (с-о-р, U+0441 U+043E U+0440) is single-script, so only the skeleton gate can catch it.
        let err = book.assign("сор", ik).unwrap_err();
        assert!(matches!(err, ResolveError::ConfusableName(_)));
        assert_eq!(err.code(), 0x0122);
    }

    #[test]
    fn petname_book_resolves_pinned_and_misses_unknown() {
        let ik = IdentityKey::from_seed(&[7; 32]).public();
        let mut book = PetnameBook::new();
        book.assign("mum", ik.clone()).unwrap();
        let b = book.resolve("mum").unwrap();
        assert_eq!(b.ik, ik);
        assert_eq!(b.verification, Verification::LocalPetname);
        assert!(matches!(
            book.resolve("stranger"),
            Err(ResolveError::NameResolution(_))
        ));
    }
}
