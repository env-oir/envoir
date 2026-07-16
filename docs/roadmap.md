# Roadmap

This page is deliberately literal: what's real today, grounded in actual code and tests, versus
what the protocol specifies for later. If a claim isn't backed by something in this repository or
the spec's own roadmap markers, it doesn't belong here.

## What's real today

- **The MOTE delivery engine** (`dmtap::node` in `node/`) — real identity keys, real MLS/HPKE
  sealing, the full recipient-validation pipeline, and the sender-retry state machine,
  demonstrated end-to-end by `cargo run -p envoir-node -- run` over an in-process transport.
- **The client-protocol layer** (`crates/dmtap-mail`) — real IMAP (RFC 9051/3501, including
  CONDSTORE/QRESYNC, SEARCHRES, SORT/THREAD, BINARY), POP3, SMTP-submission, and JMAP Core/Mail
  servers, plus autodiscovery (Thunderbird, Apple, Microsoft), all runnable via
  `cargo run -p envoir-node -- serve-mail`. See the crate's own capability matrix in
  [`crates/dmtap-mail/README.md`](../crates/dmtap-mail/README.md) for exactly what's done vs.
  explicitly deferred (real TLS, DEFLATE compression, cross-server CATENATE URLFETCH, JMAP push
  transport).
- **The legacy gateway** (`gateway/`, backed by the `envoir-gateway` crate) — a real inbound MX
  listener with STARTTLS, a real pre-`DATA` anti-abuse gate, real gateway attestation sealing,
  real delegated-selector DKIM signing, real MX/MTA-STS resolution over DNS, and the
  ack-before-`250`/`451`-on-no-ack rule. The recipient directory and mesh-delivery hookup are left
  as operator-supplied seams — until wired to real infrastructure, inbound refuses (`550`) and
  outbound never durably acks (`451`), which are the safe defaults for an unconfigured gateway.
- **Cryptographic primitives** (`crates/dmtap-core`) — real Ed25519 signing, BLAKE3 content
  addressing, deterministic canonical CBOR, the 8-word key-name checksum, and safety-number
  derivation, all backed by byte-exact known-answer vectors.
- **The deniable 1:1 mode** (`crates/dmtap-deniable`) and **MLS groups** (`crates/dmtap-mls`) —
  implemented with dedicated crates; see [security.md](security.md#formal-proverif-models) for
  the formal proofs covering the deniable handshake specifically.
- **DMTAP-Auth** (`crates/dmtap-auth`) — the login ceremony's assertion/challenge/session/
  verification logic, formally modeled in `formal/dmtap_auth.pv`.
- **The web client, console, superadmin, and status apps** — fully functional UIs with real
  browser cryptography for identity/signing/safety numbers; network delivery is a clearly-labeled
  in-memory simulation in each. See each app's own README for its specific real-vs-simulated
  table.

## What's stubbed or deferred, and why

- **The libp2p mesh and mixnet transports** are not yet wired into the node binary — the delivery
  engine above runs over an in-process transport today. This is flagged directly in
  `node/src/main.rs`'s own doc comments as "a separate frontier task," not hidden.
- **Post-quantum suite `0x02`** (ML-DSA-65 / X-Wing hybrid) is reserved in the spec and correctly
  **fails closed** as an unknown/unimplemented suite — it is not yet implemented, and no code
  claims otherwise.
- **v1 key-transparency hardening** (federated multi-log gossip, quorum-audited bindings,
  equivocation halt) — v0's single-log, TOFU+pinning model is what's implemented; see
  [privacy.md](privacy.md#what-this-project-does-not-claim).
- **52 of 91 conformance cases** carry an exact construction recipe and expected error code but
  aren't yet byte-vectored (mostly mixnet, MLS handshake bytes, and gateway/auth subsystems not
  yet reduced to a fixed-input known-answer test) — see
  [security.md](security.md#conformance-suite).
- **Canonical-CBOR enforcement at decode time** — the low-level decoder doesn't yet reject
  non-shortest-form integers or out-of-order map keys, a real and tracked gap surfaced by fuzzing
  (see [security.md](security.md#fuzzing)).
- **Real TLS, JMAP push transport, and DEFLATE compression** in the mail-protocol layer —
  explicitly out of scope for the std-only protocol core, deferred to the node binary's transport
  layer.

## The protocol's own roadmap (spec §10.6)

- **v0** — Core + Private (minimal, TOFU-pinned key transparency) + Groups & Files + the legacy
  gateway. This is the version this repository targets.
- **v1 hardening** — federated, gossiped key transparency with equivocation detection;
  onion-routed bulk file transfer; anonymous tokens at scale; the post-quantum suite migration; an
  optional self-sovereign naming backend.
- **Later research** — stronger private contact discovery, scalable private retrieval for
  hostile-buffer scenarios, deniable-group properties, and metadata privacy for very large files.

## The one gate that has to happen before any of this is production-ready

An independent external cryptographic and code audit, as described in
[security.md](security.md#the-audit-gate). Nothing on this page changes that.
