#![no_main]
use libfuzzer_sys::fuzz_target;
use dmtap_naming::restype::{classify, ResolverType};

/// `dmtap_naming::restype::classify` (§3.12.4) dispatches a name to its resolver type **by form**,
/// independent of what any node implements — every other resolver (`route`, `SelfResolver`,
/// `NameChainResolver`, …) trusts this dispatch to have picked the right bucket. It is fed a fully
/// attacker-controlled name (a hostile `MAIL FROM`, a hostile directory entry, a pasted address) and
/// MUST:
///
///  1. **never panic** on any input — the base property this harness checks by simply calling it, and
///  2. **never misclassify in a way that would let one form's guardrail be silently skipped** — the
///     specific residual risk this harness also checks: an input that could be read as *both* a
///     `name-chain` form (`.eth`/`.sol`) and a checksum-valid `self` key-name must not be accepted as
///     `SelfKeyName` (the key-name floor's checksum has no chain-suffix carve-out, so if the two
///     ever overlapped, a hostile `…-….eth` key-name look-alike could smuggle a name-chain name past
///     the self resolver's zero-authority, no-network path — this asserts that gap can't open).
///
/// `classify` is a total function over `&str`; any byte sequence that fails UTF-8 decoding is simply
/// outside its domain (never handed to it) rather than excluded from the fuzz corpus's mutation
/// space — `classify` itself never sees non-UTF-8 bytes in real use (every caller already holds a
/// `&str`), so this mirrors the real call boundary exactly.
fuzz_target!(|data: &[u8]| {
    let Ok(name) = std::str::from_utf8(data) else { return };

    let result = classify(name);

    // Property 2: a name-chain-suffixed input (`.eth`/`.sol`, case-insensitively, after trimming —
    // exactly the normalization `classify` itself performs before comparing) must never classify as
    // `SelfKeyName` — the two forms are meant to be mutually exclusive by construction (name-chain is
    // checked first in `classify`), so this is a regression guard on that ordering, not a new rule.
    if let Ok(ty) = result {
        let trimmed_lower = name.trim().to_ascii_lowercase();
        let is_chain_suffixed = trimmed_lower.ends_with(".eth") || trimmed_lower.ends_with(".sol");
        if is_chain_suffixed {
            assert_ne!(
                ty,
                ResolverType::SelfKeyName,
                "a .eth/.sol-suffixed input classified as the zero-authority self key-name form: {name:?}"
            );
        }
    }
});
