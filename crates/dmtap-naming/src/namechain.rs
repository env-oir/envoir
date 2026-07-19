//! The **`name-chain`** resolver type — spec §3.6, §3.12.5 (OPTIONAL, four guardrails).
//!
//! A crypto name-chain is offered for the one thing DNS and key-names cannot give: a **bare,
//! globally-unique, human-*chosen* username**. Two are registered today (§21.18) and modeled here —
//! **ENS `.eth`** and **SNS `.sol`**. A name-chain is admitted **only** as one resolver among several
//! (§3.12.5(a)); nothing in DMTAP requires a chain, and a deployment that admits none is fully
//! conformant.
//!
//! ## What is real vs. the RPC seam (honest, §6.6)
//! The [`NameChainClient`] trait is the **network seam**: `resolve` returns a chain's on-chain
//! `name → ik` record. A **real** ENS resolution is an Ethereum JSON-RPC / CCIP-Read (ENSIP-10)
//! read; a **real** SNS resolution is a Solana RPC account read — deliberately **not** pulled in here
//! (no heavy web3 dependency), left as the documented network layer a later crate implements behind
//! this exact trait. [`InMemoryNameChain`] is the offline mock the tests drive. Everything **above**
//! the trait — the §3.12.5(b) bidirectional-binding enforcement — is real code exercised by tests.
//!
//! ## The binding this resolver enforces (§3.12.5(b), normative)
//! A chain name is a **label pointing at the DMTAP key**, not the identity. The binding MUST be
//! **bidirectional**:
//! 1. **the key claims the name** — the name appears in the owner's self-asserted `Identity.names`
//!    and the identity verifies (§3.9.4); *and*
//! 2. **the chain record points at the key** — the on-chain `name → ik` record resolves to that same
//!    classical `IK`.
//!
//! If the two directions disagree — a chain record naming a key that does not claim the name, or a
//! claimed name whose chain record names a different key — resolution **fails closed**
//! ([`ResolveError::NameChainBindingUnverified`], `0x011E`); the name is rendered **unverified** and
//! MUST NOT be used to address mail. The chain, like DNS, is a **discovery pointer that KT audits**
//! (§3.3–§3.5), never a trust root. Resolving is **read-only** (§3.12.5(c)): looking someone up
//! needs no wallet, token, or transaction — only the registrant ever pays, once, to *claim* the
//! name. DMTAP defines **no token of its own** (§3.12.5(d)).

use std::collections::HashMap;

use dmtap_core::identity::Identity;
use dmtap_core::Suite;

use crate::error::ResolveError;
use crate::restype::{Chain, ResolvedBinding, ResolverType, Verification};

/// The name-chain **network seam** (§3.12.5): a read-only reader of a chain's on-chain `name → ik`
/// record. A real implementation performs an Ethereum JSON-RPC / CCIP-Read (ENS) or Solana RPC (SNS)
/// lookup; this trait is the boundary so the verification above it needs no chain client to test.
/// `resolve` returning `None` models "no such on-chain record" (unregistered name / not found).
pub trait NameChainClient {
    /// Which chain this client reads (§3.12.5).
    fn chain(&self) -> Chain;

    /// Read the on-chain `name → ik` record, read-only (§3.12.5(c)). `Some(ik)` is the key the chain
    /// record points at; `None` means no record exists for `name`. This is **discovery, not proof**
    /// (§3.1) — the returned key is only a pointer the bidirectional binding then verifies.
    fn resolve(&self, name: &str) -> Option<Vec<u8>>;
}

/// An in-memory [`NameChainClient`] for offline tests — the mock standing in for a live chain RPC.
/// `register` models the one paid, on-chain *claim* (§3.12.5(c)); `resolve` is the free, read-only
/// lookup every correspondent uses.
#[derive(Debug, Clone)]
pub struct InMemoryNameChain {
    chain: Chain,
    records: HashMap<String, Vec<u8>>,
}

impl InMemoryNameChain {
    /// An empty chain of kind `chain`.
    pub fn new(chain: Chain) -> Self {
        InMemoryNameChain { chain, records: HashMap::new() }
    }

    /// Model the registrant's one on-chain claim of `name → ik` (§3.12.5(c)). Test-only stand-in for
    /// a real registration transaction; resolution itself never writes.
    pub fn register(&mut self, name: impl Into<String>, ik: impl Into<Vec<u8>>) {
        self.records.insert(name.into(), ik.into());
    }
}

impl NameChainClient for InMemoryNameChain {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn resolve(&self, name: &str) -> Option<Vec<u8>> {
        self.records.get(name).cloned()
    }
}

/// The `name-chain` resolver (§3.12.5): reads a chain's `name → ik` pointer via a [`NameChainClient`]
/// and enforces the §3.12.5(b) **bidirectional key↔name binding** against the owner's signed
/// `Identity`. Resolution is read-only and fails closed on any mismatch (`0x011E`).
pub struct NameChainResolver<C: NameChainClient> {
    client: C,
}

impl<C: NameChainClient> NameChainResolver<C> {
    /// Wrap a chain client (real RPC or the in-memory mock).
    pub fn new(client: C) -> Self {
        NameChainResolver { client }
    }

    /// The chain this resolver reads.
    pub fn chain(&self) -> Chain {
        self.client.chain()
    }

    /// Resolve `name` on the chain and verify the §3.12.5(b) bidirectional binding against the
    /// owner's self-asserted `Identity`.
    ///
    /// Steps, all fail-closed:
    /// 1. **Discover** (read-only): the on-chain `name → ik` record, else a `NameResolution` miss.
    /// 2. The `claimed` identity MUST verify on its own (signature/chain, §1.3).
    /// 3. **Key claims name**: `name` MUST appear in `claimed.names` (§3.9.4) — else `0x011E`.
    /// 4. **Chain points at key**: the chain record's `ik` MUST equal the identity's classical `IK`
    ///    — else `0x011E` (the chain names a *different* key than the one claiming the name).
    ///
    /// On success the resolved key is the identity's classical `IK`; the caller pins it and MAY
    /// KT-audit it exactly as the DNS path does (§3.3–§3.5) — the chain is only the discovery pointer.
    pub fn resolve(
        &self,
        name: &str,
        claimed: &Identity,
    ) -> Result<ResolvedBinding, ResolveError> {
        // 0. Canonicalize at the chokepoint ([`crate::canonical`]): chain names fold to NFC +
        // lowercase with single-script labels (`0x0121` on a homograph mix), exactly as a real
        // ENS/SNS client normalizes before its own lookup — so `Vitalik.ETH` and `vitalik.eth`
        // are ONE on-chain identity, and a mixed-script chain label never even reaches the RPC.
        let name = crate::canonical::canonical_name(name)?;

        // 1. Discover the on-chain pointer (read-only, §3.12.5(c)). Discovery is never proof (§3.1).
        let chain_ik = self
            .client
            .resolve(&name)
            .ok_or(ResolveError::NameResolution("no on-chain name→ik record"))?;

        // 2. The claimed identity must stand on its own signed chain before we trust any field of it.
        claimed.verify(None)?;

        // 3. Bidirectional direction A — the key claims the name (§3.9.4 forward check), compared
        // in canonical form on both sides (an uncanonicalizable `Identity.names` entry never
        // matches — fail-closed).
        if !claimed
            .names
            .iter()
            .any(|n| crate::canonical::canonical_name(n).is_ok_and(|c| c == name))
        {
            return Err(ResolveError::NameChainBindingUnverified(
                "chain names a key that does not claim the name in Identity.names",
            ));
        }

        // The identity's classical IK — the key a name-chain label may point at.
        let classical = claimed.iks.get(&Suite::Classical.as_u8()).ok_or(
            ResolveError::NameChainBindingUnverified("claimed identity has no classical ik"),
        )?;

        // 4. Bidirectional direction B — the chain record points at that same key.
        if classical.as_slice() != chain_ik.as_slice() {
            return Err(ResolveError::NameChainBindingUnverified(
                "on-chain record names a different key than the one claiming the name",
            ));
        }

        Ok(ResolvedBinding {
            name,
            ik: classical.clone(),
            resolver_type: ResolverType::NameChain(self.client.chain()),
            verification: Verification::ChainBound,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::id::ContentId;
    use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};

    const NOW: dmtap_core::TimestampMs = 1_700_000_000_000;

    /// Build a classical identity that self-asserts `names`.
    fn identity_with_names(seed: u8, names: Vec<String>) -> (Vec<u8>, Identity) {
        let ik = IdentityKey::from_seed(&[seed; 32]);
        let id = Identity::create_classical(
            &ik,
            0,
            vec![],
            KeyPackageBundleRef::new("/mesh/kp", ContentId::of(b"kp")),
            ContentId::of(b"recovery"),
            names,
            None,
            NOW,
        );
        (ik.public(), id)
    }

    #[test]
    fn ens_resolve_via_mock_client_bidirectional_ok() {
        let name = "vitalik@.eth";
        let (ik, id) = identity_with_names(1, vec![name.to_owned()]);

        let mut chain = InMemoryNameChain::new(Chain::Ens);
        chain.register(name, ik.clone()); // the registrant's one on-chain claim
        let r = NameChainResolver::new(chain);

        let b = r.resolve(name, &id).unwrap();
        assert_eq!(b.ik, ik);
        assert_eq!(b.resolver_type, ResolverType::NameChain(Chain::Ens));
        assert_eq!(b.verification, Verification::ChainBound);
    }

    #[test]
    fn sns_resolve_via_mock_client_ok() {
        let name = "toly@.sol";
        let (ik, id) = identity_with_names(2, vec![name.to_owned()]);
        let mut chain = InMemoryNameChain::new(Chain::Sns);
        chain.register(name, ik.clone());
        let r = NameChainResolver::new(chain);
        let b = r.resolve(name, &id).unwrap();
        assert_eq!(b.resolver_type, ResolverType::NameChain(Chain::Sns));
        assert_eq!(b.ik, ik);
    }

    #[test]
    fn binding_mismatch_chain_names_different_key_fails_011e() {
        // The identity legitimately claims the name, but the chain record points at a DIFFERENT key
        // (a captured/hijacked registrar contract) — the two directions disagree.
        let name = "alice@.eth";
        let (_ik, id) = identity_with_names(3, vec![name.to_owned()]);
        let attacker_ik = IdentityKey::from_seed(&[0xee; 32]).public();

        let mut chain = InMemoryNameChain::new(Chain::Ens);
        chain.register(name, attacker_ik); // chain points elsewhere
        let r = NameChainResolver::new(chain);

        let err = r.resolve(name, &id).unwrap_err();
        assert!(matches!(err, ResolveError::NameChainBindingUnverified(_)));
        assert_eq!(err.code(), 0x011E);
    }

    #[test]
    fn binding_mismatch_key_does_not_claim_name_fails_011e() {
        // The chain record points at the key, but that key's Identity does NOT list the name — the
        // reverse direction (key claims name) is missing.
        let name = "bob@.eth";
        let (ik, id) = identity_with_names(4, vec!["someone-else@.eth".to_owned()]);
        let mut chain = InMemoryNameChain::new(Chain::Ens);
        chain.register(name, ik); // chain → this key, but the key never claims `name`
        let r = NameChainResolver::new(chain);
        let err = r.resolve(name, &id).unwrap_err();
        assert!(matches!(err, ResolveError::NameChainBindingUnverified(_)));
        assert_eq!(err.code(), 0x011E);
    }

    #[test]
    fn no_on_chain_record_is_a_resolution_miss() {
        let name = "ghost@.eth";
        let (_ik, id) = identity_with_names(5, vec![name.to_owned()]);
        let chain = InMemoryNameChain::new(Chain::Ens); // nothing registered
        let r = NameChainResolver::new(chain);
        assert!(matches!(
            r.resolve(name, &id),
            Err(ResolveError::NameResolution(_))
        ));
    }
}
