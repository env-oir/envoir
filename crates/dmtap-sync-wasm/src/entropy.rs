//! The `abi` surface's entropy backend: **there isn't one, and that is deliberate.**
//!
//! `dmtap-core` pulls three `getrandom` majors transitively (`ed25519-dalek`, `x-wing`, `ml-dsa`).
//! On `wasm32-unknown-unknown` none of them links unless it is told where entropy comes from. The
//! JS surface answers "the host's `crypto.getRandomValues`". This surface cannot give that answer:
//! the Go binding instantiates the module with **no host functions at all** — no clock, no
//! filesystem, no network, no imports of any kind — which is a large part of why it is easy to
//! reason about and cheap to instantiate.
//!
//! So the choice is between a backend that fabricates bytes and one that refuses. Fabricating —
//! zeros, a counter, a hash of a constant — links exactly as well and is the more dangerous option
//! by a wide margin: nothing on the reachable path needs entropy *today*, so the fake would never
//! be noticed, and the day someone wires up a code path that mints a key it would silently produce
//! a predictable one. There is no test that catches that, because the output looks like bytes.
//!
//! Refusing has the opposite failure mode. Nothing reachable calls it, so it costs nothing now; and
//! if a future change does reach for randomness, it fails loudly, at the call, with a code — instead
//! of returning a guessable key that verifies fine and is worthless.
//!
//! This is the same fail-closed reflex as the rest of the substrate (`SYNC.md` §12): when the honest
//! answer is "I cannot do this safely", say so rather than approximate it.

/// The `getrandom` 0.2 custom backend. Always fails.
///
/// `getrandom` 0.3/0.4 select their custom backend through a `--cfg getrandom_backend="custom"`
/// RUSTFLAG rather than a Cargo feature, so `build-abi.sh` sets that flag and
/// [`__getrandom_v03_custom`] below serves both of them.
#[cfg(all(target_arch = "wasm32", feature = "abi"))]
fn unavailable(_buf: &mut [u8]) -> Result<(), getrandom_02::Error> {
    Err(getrandom_02::Error::UNSUPPORTED)
}

#[cfg(all(target_arch = "wasm32", feature = "abi"))]
getrandom_02::register_custom_getrandom!(unavailable);

/// The 0.3/0.4 custom backend, same refusal.
///
/// # Safety
///
/// `getrandom` calls this with a valid, writable `dest`/`len`. It is never read from, because this
/// implementation never writes and always returns a non-zero (error) code.
#[cfg(all(target_arch = "wasm32", feature = "abi"))]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    _dest: *mut u8,
    _len: usize,
) -> Result<(), getrandom_03::Error> {
    Err(getrandom_03::Error::UNSUPPORTED)
}
