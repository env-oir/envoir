//! Stable (non-nightly, `cargo test`-only) property/round-trip tests mirroring the
//! `cargo-fuzz` targets added alongside this file (`naming_classify`, `namechain_resolve`,
//! `gateway_alias`) — see each target's doc comment in `fuzz_targets/` for the
//! full rationale. `cargo +nightly fuzz build`/`run` needs the nightly toolchain + libFuzzer
//! sanitizer instrumentation; this file re-checks the identical properties with a small dependency-
//! free pseudo-random driver so the same coverage is real on **any** stable toolchain, not only one
//! with `cargo-fuzz` installed (this package deliberately takes no `proptest`/`quickcheck`
//! dependency — see `fuzz/Cargo.toml`'s header comment on why this whole package stays a minimal,
//! detached, cargo-fuzz-convention crate).
//!
//! `run with: RUSTFLAGS="-D warnings" cargo test` from `fuzz/` (stable toolchain, no `+nightly`).

use dmtap_core::id::ContentId;
use dmtap_core::identity::{Identity, IdentityKey, KeyPackageBundleRef};
use dmtap_naming::namechain::{InMemoryNameChain, NameChainResolver};
use dmtap_naming::restype::{classify, Chain, ResolverType};

use dmtap::naming::{gateway_alias_local, ik_from_gateway_alias};

/// A tiny, dependency-free splitmix64-based PRNG — good enough to generate varied byte strings
/// deterministically (no external `rand`/`proptest` dependency; reproducible across runs from a
/// fixed seed, which is all a property-test driver needs here).
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// A random-length (0..=max_len) byte vector, byte values biased toward the "interesting" low
    /// range (ASCII / small values) about half the time and fully arbitrary the rest, so both
    /// text-like and raw-binary inputs get covered.
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max_len + 1);
        (0..len)
            .map(|_| {
                let r = self.next_u64();
                if r % 2 == 0 {
                    (r >> 8) as u8 & 0x7f // ASCII-range
                } else {
                    (r >> 8) as u8 // fully arbitrary byte
                }
            })
            .collect()
    }

    fn array32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        out
    }
}

const ITERS: usize = 20_000;

// --- `dmtap_naming::restype::classify` (mirrors fuzz_targets/naming_classify.rs) ----------------

#[test]
fn classify_never_panics_on_arbitrary_strings() {
    let mut rng = Rng(0xC1A55_1F0);
    for _ in 0..ITERS {
        let bytes = rng.bytes(64);
        let Ok(name) = std::str::from_utf8(&bytes) else { continue };
        let _ = classify(name); // must not panic
    }
}

#[test]
fn classify_never_puts_a_chain_suffixed_name_in_the_self_keyname_form() {
    let mut rng = Rng(0xC1A55_1FE);
    // Mix pure-random strings with ones deliberately suffixed `.eth`/`.sol` (so the interesting
    // overlap case is actually hit often, not just hoped-for from raw randomness).
    for i in 0..ITERS {
        let mut bytes = rng.bytes(48);
        if i % 3 == 0 {
            bytes.extend_from_slice(b".eth");
        } else if i % 3 == 1 {
            bytes.extend_from_slice(b".sol");
        }
        let Ok(name) = std::str::from_utf8(&bytes) else { continue };
        if let Ok(ty) = classify(name) {
            let trimmed_lower = name.trim().to_ascii_lowercase();
            if trimmed_lower.ends_with(".eth") || trimmed_lower.ends_with(".sol") {
                assert_ne!(ty, ResolverType::SelfKeyName, "chain-suffixed name classified as self: {name:?}");
            }
        }
    }
    // The two forms really do exist and are reachable (sanity check the driver isn't vacuous).
    assert_eq!(classify("vitalik.eth").unwrap(), ResolverType::NameChain(Chain::Ens));
    assert_eq!(classify("toly.sol").unwrap(), ResolverType::NameChain(Chain::Sns));
}

// --- `dmtap_naming::namechain::NameChainResolver::resolve` (mirrors namechain_resolve.rs) --------

#[test]
fn namechain_resolve_fails_closed_and_never_panics_on_arbitrary_records() {
    let mut rng = Rng(0xBEEF_C4A1);
    let ik = IdentityKey::from_seed(&[0x42; 32]);
    let claimed_ik = ik.public();

    for _ in 0..2_000 {
        let name_bytes = rng.bytes(16);
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let record_bytes = rng.bytes(48);

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
        chain.register(name.clone(), record_bytes.clone());
        let resolver = NameChainResolver::new(chain);

        match resolver.resolve(&name, &identity) {
            Ok(binding) => {
                assert_eq!(record_bytes, claimed_ik, "Ok but record != claimed IK");
                assert_eq!(binding.ik, claimed_ik);
            }
            Err(_) => {} // any fail-closed rejection is fine; only a panic would be a bug
        }
    }

    // Sanity check the driver can reach the success path too (deterministic positive case).
    let name = "alice@.eth".to_string();
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
    chain.register(name.clone(), claimed_ik.clone());
    let resolver = NameChainResolver::new(chain);
    assert!(resolver.resolve(&name, &identity).is_ok());
}

// --- node key-derived gateway alias (mirrors gateway_alias.rs) -----------------------------------

#[test]
fn gateway_alias_decode_never_panics_on_arbitrary_local_parts() {
    let mut rng = Rng(0x6A7E_A11A5);
    for _ in 0..ITERS {
        let bytes = rng.bytes(80);
        let local = String::from_utf8_lossy(&bytes).into_owned();
        let _ = ik_from_gateway_alias(&local); // must not panic
    }
}

#[test]
fn gateway_alias_round_trips_arbitrary_32_byte_keys() {
    let mut rng = Rng(0x6A7E_A11B6);
    for _ in 0..ITERS {
        let ik = rng.array32();
        let alias = gateway_alias_local(&ik);
        let recovered = ik_from_gateway_alias(&alias).expect("self-produced alias must decode");
        assert_eq!(recovered, ik, "encode/decode must be a bijection");

        let upper = alias.to_uppercase();
        assert_eq!(
            ik_from_gateway_alias(&upper).as_deref(),
            Some(ik.as_slice()),
            "case-folded alias must still decode to the same key"
        );
    }
}
