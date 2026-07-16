//! Cross-component integration tests for the Envoir DMTAP reference stack.
//!
//! This crate has no library surface of its own — it exists to host end-to-end tests under
//! `tests/` that compose the **real** crates (`envoir-node`, `dmtap-mail`, `envoir-gateway`,
//! `dmtap-core`) with no mocks between components. See the individual test files:
//!
//! - `legacy_to_dmtap.rs` — an RFC 5322 message through the gateway inbound, sealed into a MOTE,
//!   delivered into a real node, and read back through a `dmtap-mail` JMAP view; the gateway
//!   attestation is verified end-to-end.
//! - `dmtap_to_dmtap.rs` — two real nodes exchange an encrypted MOTE + ack over the TCP transport.
//! - `adversarial.rs` — a tampered/forged MOTE is rejected before decryption; a deferred cold MOTE
//!   is held but not acked (matching the reconciled no-ack-for-deferred rule, §2.7a / §19.3.1).
