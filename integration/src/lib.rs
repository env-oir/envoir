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
//! - `p2p_delivery.rs` — the same DMTAP↔DMTAP delivery shape as `dmtap_to_dmtap.rs`, but over the
//!   REAL `dmtap-p2p` libp2p mesh transport (TCP + Noise + Yamux), with the delivered message
//!   visible through a real `dmtap-mail` JMAP view.
//! - `kt_resolution_and_delegation.rs` — `dmtap-naming` resolves a name to a KT-verified identity,
//!   a forged inclusion proof is rejected fail-closed, and the resolved key mints/verifies a real
//!   `dmtap-core::capability` delegation token.
//! - `deniable_repudiation.rs` — a `dmtap-deniable` 1:1 exchange proving the repudiation property
//!   holds after a real `dmtap-core::deniable::DeniableFrame` wire round trip, not just as an
//!   in-memory struct comparison.
