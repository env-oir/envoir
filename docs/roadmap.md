# Roadmap

This page is deliberately literal: what's real today, grounded in actual code and tests, versus
what the protocol specifies for later. If a claim isn't backed by something in this repository or
the spec's own roadmap markers, it doesn't belong here.

## What's real today

- **The MOTE delivery engine** (`dmtap::node` in `node/`) — real identity keys, real MLS/HPKE
  sealing, the full recipient-validation pipeline, and the sender-retry state machine,
  demonstrated end-to-end by `cargo run -p envoir-node -- run` over an in-process transport. The
  delivery + anti-rollback/anti-abuse state (per-contact suite high-water-marks, journaled retry
  entries) is **restart-safe**: a `FileJournal` persists the whole snapshot and a node reopened
  from the same path resumes with rollback protection intact, not reset to a weaker
  post-restart baseline — see the `journal` module's own doc comments for exactly what is (and
  isn't) persisted.
- **A real libp2p mesh transport** (`crates/dmtap-p2p`) — live TCP/QUIC swarms secured by
  Noise/Yamux, a working Kademlia DHT (PUT/GET of location records), and a genuine Circuit-Relay-v2
  reservation that delivers a frame to a peer advertising no direct address at all, all proven on
  loopback by dedicated tests (oversized-frame hardening, connection-close/re-dial resilience, and
  large-message round-tripping included). DCUtR is wired and empirically attempts a hole-punch, but
  a real NAT-traversed upgrade needs two distinct NATs and isn't reproducible on loopback, so that
  one case stays an honest `#[ignore]`. This crate is not yet the transport `envoir-node`'s `run`/
  `serve-mail` commands use by default — see [architecture.md](architecture.md#the-mesh-and-mixnet).
- **The client-protocol layer** (`crates/dmtap-mail`) — real IMAP (RFC 9051/3501, including
  CONDSTORE/QRESYNC, SEARCHRES, SORT/THREAD, BINARY), POP3, SMTP-submission, and JMAP Core/Mail
  servers, plus autodiscovery (Thunderbird, Apple, Microsoft), all runnable via
  `cargo run -p envoir-node -- serve-mail`. See the crate's own capability matrix in
  [`crates/dmtap-mail/README.md`](../crates/dmtap-mail/README.md) for exactly what's done vs.
  explicitly deferred (real TLS, DEFLATE compression, cross-server CATENATE URLFETCH, JMAP push
  transport).
- **The legacy gateway** (the `envoir-gateway` crate, now in its own `env-oir/envoir-gateway` repo) — a real inbound MX
  listener with STARTTLS, a real pre-`DATA` anti-abuse gate (RBL/DNSBL, SPF, DMARC-`p=` awareness,
  greylisting, per-IP rate limits), real gateway attestation sealing, real delegated-selector DKIM
  signing (ed25519-sha256, RFC 8463/6376, with a hard refusal to sign an undelegated domain), real
  MX/MTA-STS resolution over DNS with cleartext-fallback refused, a fail-closed **SSRF guard** on
  outbound connections (rejects a destination that resolves only to loopback/private/link-local/
  cloud-metadata addresses, including IPv4-mapped IPv6, with an explicit pinned-address exemption),
  and the ack-before-`250`/`451`-on-no-ack rule. The recipient directory and mesh-delivery hookup
  are left as operator-supplied seams — until wired to real infrastructure, inbound refuses (`550`)
  and outbound never durably acks (`451`), which are the safe defaults for an unconfigured gateway.
- **Cryptographic primitives** (`crates/dmtap-core`) — real Ed25519 signing, BLAKE3 content
  addressing, deterministic canonical CBOR (now enforcing shortest-form integers, no
  indefinite-length items, and strictly-ascending map keys at decode time — see
  [security.md](security.md#fuzzing)), the key-name checksum, delegated/attenuable capability
  tokens, and safety-number derivation, all backed by byte-exact known-answer vectors.
- **The pluggable naming/resolver framework** (`crates/dmtap-naming`) — real DNS `_dmtap`
  TXT/SVCB parsing, RFC 6962 key-transparency verification (inclusion proofs, STH signatures,
  v1 multi-log quorum, split-view/equivocation detection, freshness), form-based resolver-type
  dispatch (`self`/`petname`/`dns`/`name-chain`), and the OPTIONAL `name-chain` (ENS/SNS)
  resolver's bidirectional key↔name binding enforcement — all real, tested code behind a network
  I/O seam. See [naming.md](naming.md).
- **The deniable 1:1 mode** (`crates/dmtap-deniable`) and **MLS groups** (`crates/dmtap-mls`) —
  implemented with dedicated crates; see [security.md](security.md#formal-proverif-models) for
  the formal proofs covering the deniable handshake specifically.
- **DMTAP-Auth** (`crates/dmtap-auth`) — the login ceremony's assertion/challenge/session/
  verification logic, formally modeled in `formal/dmtap_auth.pv`.
- **The web client, console, superadmin, and status apps** — fully functional UIs with real
  browser cryptography for identity/signing/safety numbers; network delivery is a clearly-labeled
  in-memory simulation in each. See each app's own README for its specific real-vs-simulated
  table. The client now covers **Calendar** (month/week/day + agenda, recurring events,
  meeting invitations/RSVP) and **Contacts** (per-contact key verification) at parity with Mail
  and Chat, plus an **avatar/profile standard** (public URL → opt-in Gravatar-style → key-derived
  identicon → initials; see [features/identity.md](features/identity.md#avatars-and-profile)) and
  a full **responsive** layout down to ~360px phones.
- **An installable PWA** (`client/manifest.webmanifest`, `client/sw.js`) — a real service worker
  precaches the app shell for offline load, and real browser **Web Push** APIs
  (`PushManager.subscribe`, the `push` event) drive a content-free "wake ping" notification with
  no real push backend behind it yet. See [pwa-and-push.md](pwa-and-push.md) for the full model
  and its one disclosed residual (iOS/APNs).

## What's stubbed or deferred, and why

- **The libp2p mesh transport isn't the node binary's default yet, and the mixnet isn't wired in at
  all.** `crates/dmtap-p2p` proves the libp2p transport works (see above), but `envoir-node`'s
  `run`/`serve-mail` commands still drive the delivery engine over an in-process transport today —
  flagged directly in `node/src/main.rs`'s own doc comments as "a separate frontier task," not
  hidden. The mixnet (Sphinx onion format, entry/mix/exit routing, cover traffic) exists as
  wire-format types and a mechanism simulator (`crates/netsim`), not as a running transport a node
  can send traffic over yet.
- **Post-quantum suite `0x02`** (ML-DSA-65 / X-Wing hybrid) is reserved in the spec and correctly
  **fails closed** as an unknown/unimplemented suite — it is not yet implemented, and no code
  claims otherwise.
- **v1 key-transparency hardening** (federated multi-log gossip, quorum-audited bindings,
  equivocation halt) — v0's single-log, TOFU+pinning model is what's implemented; see
  [privacy.md](privacy.md#what-this-project-does-not-claim).
- **14 of 124 conformance cases** carry an exact construction recipe and expected error code but
  aren't yet executed (mostly mixnet, MLS/group, gateway, auth, and device-sync subsystems not yet
  reduced to a fixed-input known-answer test in `dmtap-core`/`dmtap-naming`) — every skip ships
  with its own documented reason, and the runner reports 0 failures across the 110 cases that do
  execute. See [security.md](security.md#conformance-suite).
- **Envoir Send** — a Resend-style programmatic mail-sending API built on the delegated
  capability-token primitive (`crates/dmtap-core/src/capability.rs`, real and tested today) is the
  natural next application, but the dedicated send-service crate is not yet part of this
  workspace. See [protocol.md](protocol.md#delegated-capabilities-and-envoir-send).
- **Real TLS, JMAP push transport, and DEFLATE compression** in the mail-protocol layer —
  explicitly out of scope for the std-only protocol core, deferred to the node binary's transport
  layer.

## The protocol's own roadmap (spec §10.6)

- **v0** — Core + Private (minimal, TOFU-pinned key transparency) + Groups & Files + the legacy
  gateway. This is the version this repository targets.
- **v1 hardening** — federated, gossiped key transparency with equivocation detection;
  onion-routed bulk file transfer; anonymous tokens at scale; the post-quantum suite migration. (The
  optional `name-chain` resolver — ENS/SNS, off by default — is already implemented; see
  [naming.md](naming.md).)
- **Later research** — stronger private contact discovery, scalable private retrieval for
  hostile-buffer scenarios, deniable-group properties, and metadata privacy for very large files.

## The one gate that has to happen before any of this is production-ready

An independent external cryptographic and code audit, as described in
[security.md](security.md#the-audit-gate). Nothing on this page changes that.
