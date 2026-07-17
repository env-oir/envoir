//! Real, **network-backed** DMTAP name-chain resolvers — spec §3.12.5.
//!
//! [`dmtap_naming`] defines the [`NameChainClient`](dmtap_naming::namechain::NameChainClient) seam
//! and an offline [`InMemoryNameChain`](dmtap_naming::namechain::InMemoryNameChain) mock; this crate
//! is the **real client** behind that exact trait, so a live chain feeds the §3.12.5(b) bidirectional
//! key↔name binding that `dmtap-naming` enforces. Two chains are registered today (§21.18):
//!
//! * [`EnsClient`] — `.eth` over **Ethereum JSON-RPC**. `name.eth` → EIP-137 [`namehash`](ens::namehash)
//!   → `eth_call` the ENS registry `resolver(node)` → `eth_call` that resolver's `text(node,"dmtap")`
//!   → the classical `IK` bytes. Off-chain (**CCIP-Read / ENSIP-10**) resolvers that revert
//!   `OffchainLookup` are followed **structurally** to their HTTP gateway (see [`ens`]).
//! * [`SnsClient`] — `.sol` over **Solana JSON-RPC**. `name.sol` → self-derived Bonfida name-registry
//!   **PDA** → `getAccountInfo` → the classical `IK` bytes in the account payload (see [`sns`]).
//!
//! ## What is real vs. the live-RPC seam (honest, §6.6)
//! Everything that decides a binding is **real code, unit-tested offline against known-answer
//! vectors**: the EIP-137 namehash, the Ethereum ABI encode/decode + 4-byte selectors, the Solana
//! `create_program_address` / `find_program_address` (with the real ed25519 off-curve test), the
//! Bonfida record layout, and the JSON-RPC request/response shaping. Only the **bytes-over-TLS** step
//! is behind the injectable [`HttpTransport`] trait, so tests drive canned responses and never touch
//! the network. The single real transport, [`UreqTransport`], is a small blocking rustls client
//! ([`net`](crate#features) feature, on by default); exercising it against a real endpoint is an
//! `#[ignore]`d integration test that reads its URL from an env var — documented, not required for CI.
//!
//! ## Fail closed (§3.12.5, §3.3)
//! The trait's `resolve` returns `Option<Vec<u8>>`: **any** RPC error, malformed/absent record, or
//! decode failure collapses to `None` ("no on-chain record"), which `dmtap-naming` renders as a
//! resolution miss. The client is **read-only** (§3.12.5(c)) — a lookup issues only `eth_call` /
//! `getAccountInfo`, never a transaction — and it is only a **discovery pointer** (§3.1): the key it
//! returns is proven by the bidirectional binding and KT audit **above** this crate, never here.
//!
//! # Features
//! * `net` *(default)* — compile [`UreqTransport`], the real blocking-HTTPS transport.

#![forbid(unsafe_code)]

pub mod abi;
pub mod ens;
pub mod rpc;
pub mod sns;
mod ssrf;
pub mod transport;

pub use ens::EnsClient;
pub use sns::SnsClient;
pub use ssrf::GatewayAllowlist;
pub use transport::{HttpTransport, TransportError};

#[cfg(feature = "net")]
pub use transport::UreqTransport;

/// A fail-closed error from a name-chain RPC resolution (§3.12.5, §3.3). Every variant means the same
/// thing to the trait boundary — **no verified on-chain `name → ik` record** — and is surfaced there
/// as `None`; the richer typing exists for diagnostics and the crate's own tests.
#[derive(Debug, thiserror::Error)]
pub enum NamechainError {
    /// The transport (network / TLS / HTTP status) failed. Read-only lookups fail closed (§3.12.5(c)).
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// A JSON-RPC response carried an `error` object, or was not the JSON shape we require.
    #[error("json-rpc error: {0}")]
    Rpc(String),

    /// A DMTAP name is not a well-formed name for this chain (wrong TLD, empty label, …).
    #[error("malformed name: {0}")]
    MalformedName(&'static str),

    /// An on-chain record exists but does not decode to a classical `IK` under this chain's DMTAP
    /// convention (bad ABI/record layout, non-hex `dmtap` text, wrong length, …). Fail closed (§3.3).
    #[error("malformed on-chain record: {0}")]
    MalformedRecord(&'static str),

    /// No on-chain record for the name (unregistered / empty resolver / null account). Not an error
    /// condition per se, but modeled fallibly so callers can distinguish "miss" from "decode failure".
    #[error("no on-chain record for the name")]
    NotFound,

    /// A CCIP-Read (EIP-3668) gateway URL from an attacker-controlled `OffchainLookup` revert failed
    /// the gateway guard: a non-HTTPS scheme, a host that resolves into a loopback/private/link-local/
    /// metadata address, or — when the operator configured a [`GatewayAllowlist`] — a host not on that
    /// allowlist. Refused before any socket is opened — fail closed (§3.12.5(c)).
    #[error("ccip gateway url refused: {0}")]
    BlockedGatewayUrl(&'static str),
}
