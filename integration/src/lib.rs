//! Cross-component integration tests for the Envoir DMTAP reference stack.
//!
//! This crate has no library surface of its own — it exists to host end-to-end tests under
//! `tests/` that compose the **real** crates (`envoir-node`, `dmtap-mail`, `dmtap-core`) with no
//! mocks between components. envoir is now node-only: the legacy SMTP/IMAP/POP3 gateway (spec §7,
//! `envoir-gateway`) moved out to the Ephor broker repo, taking its own gateway-composing
//! integration coverage (formerly `legacy_to_dmtap.rs`, `full_roundtrip.rs`, `gateway_provenance.rs`,
//! `gateway_authz_antispam.rs`) with it. What remains here is everything that exercises this
//! repo's own node/mesh/naming/deniable/MLS stack. See the individual test files:
//!
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
//! - `mls_group_over_real_mesh.rs` — a real RFC 9420 MLS group (`dmtap-mls`) forms and exchanges an
//!   application message over the real libp2p mesh (`dmtap-p2p`), a member is removed, and the
//!   removed member's stale state cannot decrypt a message created after removal (post-compromise
//!   security, §5.2) even when a network observer relays the exact ciphertext straight at them.
//! - `resolution_forms_e2e.rs` — the two name **forms** `full_roundtrip.rs`'s DNS/KT path doesn't
//!   cover: a real `dmtap-naming` **`self`** key-name resolution seals and delivers over the real
//!   libp2p mesh into a JMAP-readable inbox, and a real `dmtap-naming` **`name-chain`** resolution
//!   (`dmtap_naming::InMemoryNameChain`) does the same on a bidirectional binding match — while a
//!   hijacked/mismatched chain record fails closed (`NameChainBindingUnverified`, wire code `0x011E`)
//!   and is proven, concretely, to be delivered nowhere.
//! - `gateway_alias_roundtrip.rs` — a live `Node::gateway_alias()` local-part (the node's OWN
//!   key-derived alias codec, `node/src/naming.rs` — not the extracted `envoir-gateway` crate)
//!   decodes back to the exact identity key at two independently-constructed "gateways" (no shared
//!   state), and a real MOTE addressed via the decoded key reaches the node over the mesh.
//!
//! ## Scenarios considered and deliberately not added here
//! - **Suite-downgrade / capability-rollback rejection through a live node.** `dmtap_core::suite`'s
//!   `SuiteRatchet` and `dmtap_core::capability`'s `CapsVersionTracker`/`CapabilityAnnouncement` are
//!   real, and already unit-tested end-to-end at the library level in the `downgrade-tests` crate
//!   (`suite_high_water_mark_ratchet_should_reject_downgrade_below_pinned_floor`,
//!   `capability_announcement_anti_rollback_should_reject_stale_caps_version`), but neither is wired
//!   into `envoir-node`'s real `Node::receive_mote` accept path (grep confirms no reference to
//!   either type in `node/src`). A genuine *end-to-end* version — an established peer's downgrade
//!   rejected by a live node, honest path accepted — needs that wiring first.
//!   `// TODO(once Node::receive_mote consults SuiteRatchet/CapsVersionTracker): add an integration
//!   test that sends a real peer through a live node at a high-water suite/caps version, then a
//!   downgraded one, and asserts the node itself rejects it.`
//! - **KT equivocation surfaced through `Resolver::resolve`.** `dmtap_naming::kt::detect_equivocation`
//!   is real and already unit-tested directly (two conflicting `SignedTreeHead`s for one log).
//!   `InMemoryResolver`/the `Resolver` trait has no split-view simulation hook — each pinned `KtLog`
//!   returns one deterministic view, so nothing in the resolution pipeline can currently observe two
//!   disagreeing STHs for the same log within one `resolve()` call. `// TODO(once Resolver supports
//!   a per-observer/multi-fetch KtLog view): add an integration test where two fetches of the same
//!   pinned log return mutually inconsistent STHs and resolve() surfaces KtEquivocation /
//!   KtSthInconsistent.`
