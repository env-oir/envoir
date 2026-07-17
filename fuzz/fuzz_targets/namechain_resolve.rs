#![no_main]
use libfuzzer_sys::fuzz_target;

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_naming::namechain::{InMemoryNameChain, NameChainClient, NameChainResolver};
use dmtap_naming::restype::Chain;

/// `dmtap-naming`'s `name-chain` resolver (§3.12.5) has no on-chain wire format of its own in this
/// reference build — [`NameChainClient::resolve`] is a documented network *seam* (a real Ethereum/
/// Solana RPC read lives behind it, not implemented here), so there is no byte-level record decoder
/// to fuzz directly the way `dmtap-core`'s CBOR objects have one. What IS real and load-bearing is
/// [`NameChainResolver::resolve`]'s §3.12.5(b) **bidirectional-binding** check that sits directly on
/// top of that seam's return value — every byte of the "on-chain record" (the `ik` pointer a chain
/// read hands back) is exactly as attacker-controlled as any wire-decoded field would be, since a
/// compromised/malicious RPC endpoint, a censoring relay, or a spoofed CCIP-Read response can return
/// *anything*. This target fuzzes exactly that boundary: an arbitrary-bytes chain record compared
/// against a real, validly-signed `Identity` — the fail-closed comparison (§3.12.5(b) direction B)
/// must never panic, and MUST only produce `Ok` when the record byte-for-byte equals the identity's
/// classical `IK`.
///
/// The `name` string and the on-chain record bytes are both taken from `data` (attacker-controlled);
/// the `Identity` is real (built once, validly Ed25519-signed by a fixed key) so `claimed.verify`
/// passes and the interesting §3.12.5(b) comparison logic actually runs on every input rather than
/// bailing out at the signature check — the "arbitrary bytes" attack surface here is the pointer the
/// chain seam returns, not the identity's own signature (that byte-level decode is already covered by
/// the `identity` fuzz target, which round-trip-checks `Identity::from_det_cbor`).
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte picks where to split the rest of `data` into a `name` string and the "on-chain
    // record" bytes — both fully attacker-controlled, exercising every possible pairing.
    let (split_byte, rest) = data.split_at(1);
    let split = (split_byte[0] as usize) % (rest.len() + 1);
    let (name_bytes, record_bytes) = rest.split_at(split);
    let name = String::from_utf8_lossy(name_bytes).into_owned();

    // A fixed, validly-signed classical Identity that claims exactly this fuzz iteration's `name`
    // (§3.9.4 direction A is always satisfied, so the fuzzed record bytes are what drives direction
    // B — the comparison this target exists to exercise).
    let ik = IdentityKey::from_seed(&[0x42; 32]);
    let claimed_ik = ik.public();
    let identity = Identity::create_classical(
        &ik,
        0,
        vec![],
        KeyPackageBundleRef::new("/mesh/kp", ContentId::of(b"kp")),
        ContentId::of(b"recovery"),
        vec![name.clone()],
        None,
        1_700_000_000_000,
    );

    let mut chain = InMemoryNameChain::new(Chain::Ens);
    chain.register(name.clone(), record_bytes.to_vec());
    let resolver = NameChainResolver::new(chain);

    // Fail-closed, no panic (the property this target checks): `resolve` must succeed if and only
    // if the fuzzed record bytes are exactly the identity's classical IK, and must never panic for
    // any other combination of name/record bytes.
    match resolver.resolve(&name, &identity) {
        Ok(binding) => {
            assert_eq!(record_bytes, claimed_ik.as_slice(), "resolve() Ok but record != claimed IK");
            assert_eq!(binding.ik, claimed_ik);
        }
        Err(_) => {
            // A mismatch, a resolution miss, or (impossible here since the seed key never changes)
            // a signature failure — any of these are fine; only a panic would be a bug.
        }
    }
});
