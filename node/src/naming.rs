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

use dmtap_core::keyname;

use crate::node::SendError;

pub use dmtap_naming::{
    InMemoryKeyPackages, InMemoryResolver, KeyPackageSource, PinnedResolution, ResolveError,
    Resolver,
};

// --- name-FORM dispatch (spec §3.9) --------------------------------------------------------------

/// A blockchain **name-chain** namespace (§3.9): the DNS-alternative registries a name can live in.
/// These resolve through a chain RPC + on-chain KT, not the `_dmtap` DNS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// Ethereum Name Service — `name.eth`.
    Eth,
    /// Solana Name Service — `name.sol`.
    Sol,
}

impl Chain {
    /// The human label for the chain (for diagnostics / the seam's fail-closed message).
    pub fn label(self) -> &'static str {
        match self {
            Chain::Eth => "eth",
            Chain::Sol => "sol",
        }
    }
}

/// The syntactic **form** of a DMTAP recipient name (§3.9), which selects the resolver:
///
/// | form | example | resolver |
/// |------|---------|----------|
/// | [`Dns`](NameForm::Dns) | `alice@example.com` | the wired `_dmtap` DNS + RFC 6962 KT [`Resolver`] |
/// | [`KeyName`](NameForm::KeyName) | `bafu-dize-…-teka` | **derive** (self-authenticating key-name, §3.9.1) |
/// | [`NameChain`](NameForm::NameChain) | `alice.eth` / `alice.sol` | on-chain name registry |
///
/// [`classify`] buckets a name by form so [`Node::resolve_and_pin`](crate::node::Node::resolve_and_pin)
/// can route it. Only the DNS form has a wired resolver today; the other two are documented seams
/// ([`KeyNameResolver`] / [`NameChainResolver`]) that fail closed until a resolver is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameForm {
    /// `local@domain` — resolved via the real `_dmtap` DNS + KT [`Resolver`].
    Dns,
    /// A zero-authority 8-word (+checksum) **key-name** (§3.9.1): self-authenticating, derived
    /// directly from the identity key, needing no directory/registration.
    KeyName,
    /// A blockchain name-chain name (`name.eth` / `name.sol`).
    NameChain(Chain),
}

/// Classify `name` into its resolution [`NameForm`] (§3.9), **fail-closed** on an unrecognized
/// shape — an ambiguous/garbage name resolves to nothing rather than being coerced into a form.
///
/// Precedence (a name matches at most one form): an `@` ⇒ DNS; a `.eth`/`.sol` suffix ⇒ the
/// matching name-chain; otherwise a checksum-valid key-name ⇒ key-name; else
/// [`ResolveError::MalformedName`].
pub fn classify(name: &str) -> Result<NameForm, ResolveError> {
    if name.is_empty() {
        return Err(ResolveError::MalformedName("empty name"));
    }
    if name.contains('@') {
        return Ok(NameForm::Dns);
    }
    let lower = name.to_ascii_lowercase();
    if let Some(stem) = lower.strip_suffix(".eth") {
        if stem.is_empty() {
            return Err(ResolveError::MalformedName("empty .eth label"));
        }
        return Ok(NameForm::NameChain(Chain::Eth));
    }
    if let Some(stem) = lower.strip_suffix(".sol") {
        if stem.is_empty() {
            return Err(ResolveError::MalformedName("empty .sol label"));
        }
        return Ok(NameForm::NameChain(Chain::Sol));
    }
    // A checksum-valid key-name is self-describing (§3.9.1) — accept it only if it verifies, so a
    // mistyped/foreign token falls through to the fail-closed error rather than a wrong form.
    if keyname::verify(name) {
        return Ok(NameForm::KeyName);
    }
    Err(ResolveError::MalformedName("unrecognized name form"))
}

/// Resolve a self-authenticating **key-name** (§3.9.1) to a KT-verified, pinned binding.
///
/// SEAM: a key-name carries no locator, so resolving one to a *new* key needs a mesh reverse-lookup
/// (key-name → published `Identity`) plus the same KT gate the DNS path runs. That network layer is
/// being added in `dmtap-naming`; until a resolver is attached the node routes this form to a
/// fail-closed stub ([`resolve_key_name` unwired](KeyNameResolver::resolve_key_name)) so it is
/// **never** silently accepted. Mirrors the [`Resolver`] trait shape so it drops into the same
/// dispatch once wired.
pub trait KeyNameResolver {
    /// Resolve + KT-verify a key-name, or fail closed.
    fn resolve_key_name(&self, key_name: &str) -> Result<PinnedResolution, ResolveError>;
}

/// Resolve a blockchain **name-chain** name (`name.eth` / `name.sol`, §3.9) to a KT-verified,
/// pinned binding.
///
/// SEAM: name-chain resolution needs a chain RPC client (ENS/SNS registry read) plus KT
/// verification of the pointed-to `Identity`. That client is out of the current `dmtap-naming`
/// surface; the node routes this form to a fail-closed stub until one is attached, so an on-chain
/// name is **never** trusted without KT. Mirrors the [`Resolver`] trait shape.
pub trait NameChainResolver {
    /// Resolve + KT-verify a name-chain name on `chain`, or fail closed.
    fn resolve_chain(&self, chain: Chain, name: &str) -> Result<PinnedResolution, ResolveError>;
}

// --- key-derived legacy gateway alias (spec §3.9, §7) --------------------------------------------

/// Version tag + separator prefixing a [`gateway_alias_local`] local-part. Lets any gateway spot a
/// key-derived alias (vs. a registered mailbox) and pick the right decoder, and versions the
/// encoding for future suites. A hyphen keeps it inside RFC 5321 `atext` and dot-atom rules.
pub const GATEWAY_ALIAS_PREFIX: &str = "dmtap1-";

/// Lowercase RFC 4648 base32 alphabet (no padding). Chosen over base64url because SMTP local-parts
/// are widely normalized case-insensitively, so a **case-insensitive** alphabet survives the round
/// trip through legacy MTAs that base64url would not.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode `data` as lowercase unpadded RFC 4648 base32. Total function.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
        buf &= (1 << bits) - 1; // drop already-emitted high bits so `buf` can't overflow
    }
    if bits > 0 {
        // Left-pad the final partial group with zero bits (canonical unpadded base32).
        out.push(BASE32_ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode lowercase-or-uppercase unpadded RFC 4648 base32, **failing closed** on any non-alphabet
/// character or non-zero trailing padding bits (so an alias has exactly one canonical spelling).
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        let lc = (c as u8).to_ascii_lowercase();
        if !c.is_ascii() {
            return None;
        }
        let idx = BASE32_ALPHABET.iter().position(|&x| x == lc)? as u32;
        buf = (buf << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    // Any leftover bits are padding and MUST be zero — otherwise two spellings could decode alike.
    if buf != 0 {
        return None;
    }
    Some(out)
}

/// The node's **key-derived legacy gateway alias** local-part (§3.9, §7): a stable, stateless
/// address any SMTP↔DMTAP gateway can bridge with **no registration**.
///
/// Unlike the memorable [`keyname`] (an 80-bit *hash* of the key — not reversible), this alias
/// carries the **whole** identity public key, base32-encoded under [`GATEWAY_ALIAS_PREFIX`], so it
/// is:
/// - **deterministic** — a pure function of the key, identical at every gateway (no shared state);
/// - **stateless-decodable** — [`ik_from_gateway_alias`] recovers the exact 32-byte key with no
///   directory lookup, so any gateway can route inbound legacy mail into the mesh un-provisioned.
///
/// For a 32-byte Ed25519 key this is `dmtap1-` + 52 base32 chars = 59 octets, inside the RFC 5321
/// 64-octet local-part limit.
pub fn gateway_alias_local(ik_pub: &[u8]) -> String {
    format!("{GATEWAY_ALIAS_PREFIX}{}", base32_encode(ik_pub))
}

/// Recover the identity public key from a [`gateway_alias_local`] local-part, or `None` if it is not
/// a well-formed key-derived alias. **Fail-closed**: wrong prefix, non-base32 body, or non-canonical
/// padding all yield `None` — a gateway never routes to a mis-decoded key. Case-insensitive on the
/// base32 body (SMTP local-parts are widely case-folded); the prefix is matched case-insensitively
/// too so a normalizing MTA cannot break the bridge.
pub fn ik_from_gateway_alias(local_part: &str) -> Option<Vec<u8>> {
    let lower = local_part.to_ascii_lowercase();
    let body = lower.strip_prefix(GATEWAY_ALIAS_PREFIX)?;
    if body.is_empty() {
        return None;
    }
    base32_decode(body)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_core::identity::IdentityKey;

    #[test]
    fn classify_routes_each_form() {
        assert_eq!(classify("alice@example.com").unwrap(), NameForm::Dns);
        assert_eq!(classify("alice.eth").unwrap(), NameForm::NameChain(Chain::Eth));
        assert_eq!(classify("alice.SOL").unwrap(), NameForm::NameChain(Chain::Sol));

        // A real, checksum-valid key-name classifies as the derive form.
        let kn = keyname::encode(&IdentityKey::from_seed(&[3u8; 32]).public());
        assert_eq!(classify(&kn).unwrap(), NameForm::KeyName);
    }

    #[test]
    fn classify_fails_closed_on_garbage() {
        // Neither an address, a name-chain, nor a checksum-valid key-name.
        assert!(matches!(classify("just-a-token"), Err(ResolveError::MalformedName(_))));
        assert!(matches!(classify(""), Err(ResolveError::MalformedName(_))));
        assert!(matches!(classify(".eth"), Err(ResolveError::MalformedName(_))));
        // A key-name shape with a busted checksum must NOT be coerced into the key-name form.
        let mut kn = keyname::encode(&IdentityKey::from_seed(&[4u8; 32]).public());
        kn.push_str("-zzzz");
        assert!(matches!(classify(&kn), Err(ResolveError::MalformedName(_))));
    }

    #[test]
    fn base32_round_trips_arbitrary_lengths() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
            let enc = base32_encode(&data);
            assert_eq!(base32_decode(&enc).unwrap(), data, "round trip len={len}");
        }
    }

    #[test]
    fn base32_decode_fails_closed() {
        // Non-alphabet chars (base32 excludes 0/1/8/9) fail closed.
        assert!(base32_decode("018").is_none());
        // Two chars = 10 bits = 1 byte + 2 padding bits that MUST be zero. 'a'=0,'a'=0 ⇒ canonical;
        // 'a','b' (b=1) leaves the low padding bit set ⇒ non-canonical ⇒ fail closed.
        assert_eq!(base32_decode("aa").unwrap(), vec![0u8]);
        assert!(base32_decode("ab").is_none());
    }

    #[test]
    fn gateway_alias_is_key_derived_stateless_and_reversible() {
        let ik = IdentityKey::from_seed(&[7u8; 32]).public();

        // Two independent "gateways" derive the SAME local-part from the same key — no shared state.
        let at_gateway_a = gateway_alias_local(&ik);
        let at_gateway_b = gateway_alias_local(&ik);
        assert_eq!(at_gateway_a, at_gateway_b, "alias must be identical at every gateway");
        assert!(at_gateway_a.starts_with(GATEWAY_ALIAS_PREFIX));
        assert!(at_gateway_a.len() <= 64, "must fit an RFC 5321 local-part");

        // Any gateway decodes it back to the exact key with no registration/lookup.
        assert_eq!(ik_from_gateway_alias(&at_gateway_a).unwrap(), ik);

        // Distinct keys ⇒ distinct aliases.
        let other = IdentityKey::from_seed(&[8u8; 32]).public();
        assert_ne!(gateway_alias_local(&other), at_gateway_a);
    }

    #[test]
    fn gateway_alias_survives_case_folding_and_fails_closed() {
        let ik = IdentityKey::from_seed(&[9u8; 32]).public();
        let alias = gateway_alias_local(&ik);
        // A case-normalizing MTA must not break the bridge.
        assert_eq!(ik_from_gateway_alias(&alias.to_uppercase()).unwrap(), ik);
        // A non-alias local-part (a registered mailbox) decodes to nothing — fail closed.
        assert!(ik_from_gateway_alias("alice").is_none());
        assert!(ik_from_gateway_alias(GATEWAY_ALIAS_PREFIX).is_none());
        assert!(ik_from_gateway_alias("dmtap1-01").is_none()); // non-base32 body
    }
}
