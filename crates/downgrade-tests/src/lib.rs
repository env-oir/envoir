//! `downgrade-tests` — the DMTAP downgrade & fail-closed regression suite.
//!
//! This crate carries **no runtime code of its own**. It exists solely to hold
//! `tests/downgrade_invariants.rs`, an external integration-test file that drives
//! `dmtap-core`'s public API to prove every downgrade / fail-closed invariant claimed by spec
//! §10.7 ("Downgrade & Fail-Closed Invariants") that is testable at the library level. See that
//! file's module doc for the full invariant-by-invariant coverage map, including the honest list
//! of §10.7 rows that are **not yet** enforced by any public API in the reference implementation.
//!
//! Being an external `tests/` crate (rather than `#[cfg(test)]` modules inside `dmtap-core`
//! itself) matters: it can only see what any independent implementation or caller would see —
//! public types, public constructors, public `verify`/`validate` entry points — so a passing test
//! here is proof of the *public contract*, not of internals a caller can't actually rely on.
