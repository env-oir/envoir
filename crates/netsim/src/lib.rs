//! # netsim — DMTAP mixnet anonymity simulator
//!
//! A deterministic, seeded **model** of the routing/mixing/cover *mechanism* that DMTAP's
//! `private` tier specifies (spec `04-transport.md` §4.4, parameters `16-parameters.md`
//! §16.3, adversary framing `06-privacy.md` §6.4/§6.6) — built to empirically MEASURE the
//! quantitative privacy claims, Loopix/Nym-style, rather than take them on faith.
//!
//! **What this is not:** the real Sphinx wire format, a real libp2p mesh, or a queueing
//! network simulator. There is no packet encoding, no actual cryptography, and no per-mix
//! buffer/bandwidth contention — see the abstraction notes on [`sim::run`] for exactly what
//! is and isn't modeled. What IS modeled faithfully: stratified 3-/5-hop path selection with
//! pinned entry guards (§4.4.3/§4.4.8), independent per-hop Exponential/Poisson mixing delay
//! (§4.4.6), Poisson loop + drop cover traffic (§4.4.5), a global-passive adversary limited to
//! timing correlation except where it colludes across a path's entry+exit mix (§4.4.11), and
//! a global-active adversary that can additionally drop a fraction of what compromised mixes
//! carry, measured against the loop-cover detector (§4.4.7, §16.3's 20% loss threshold).
//!
//! See `tests/report.rs` for the qualitative claims this crate asserts, and
//! `src/main.rs` (`netsim-report` binary) for the full parameter-sweep report.

pub mod client;
pub mod metrics;
pub mod path;
pub mod profile;
pub mod sim;
pub mod topology;

pub use profile::Profile;
