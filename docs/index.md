# Envoir

**Sovereign mail, chat, files & identity — your key is your identity, not an account.**

Envoir is the open-source reference implementation of **DMTAP** (the Decentralized Message
Transfer & Access Protocol): one keypair identity for mail, chat, calendar, contacts, files, and
groups, delivered peer-to-peer over a mesh and mixnet so that not even a global observer sees who
talks to whom. A human address like `you@envoir.org` is a *pointer* to your key, not the identity
itself — lose the provider, keep the key. An optional gateway bridges DMTAP to legacy SMTP so it
is useful on day one, and fades in importance as the network grows.

Envoir is to DMTAP what Element is to Matrix: the branded, MIT-licensed apps for an open protocol.

**Status: pre-alpha / reference implementation.** This is a preview build for demonstrating the
protocol end to end, not a production mail service. See [Security](security.md) for exactly what
has (and hasn't) been verified, and read the honesty notes throughout — this project deliberately
avoids overclaiming.

**No cryptocurrency, no blockchain, anywhere in this project.** Naming is pluggable — a key-name,
a local petname, and the default `name@domain` (DNS + key transparency) are the core ladder — and
the *only* place DMTAP admits anything chain-like at all is an OPTIONAL, off-by-default
`name-chain` resolver (ENS `.eth` / SNS `.sol`) bound by four guardrails: optional, key-is-identity
(a bidirectional binding, never a trust root), free to resolve, and no DMTAP token of its own. See
[naming.md](naming.md) for the full ladder. Anti-abuse for cold contact instead uses anonymous
Privacy-Pass-style rate-limit tokens, proof-of-work, and an optional real-money postage stamp —
never a coin. See [FAQ](faq.md).

## What you get

| Surface | What it gives you | Docs |
|---|---|---|
| Mail | Three-pane inbox, threading, labels, snooze, scheduled/undo send, per-message transport-path provenance | [features/mail.md](features/mail.md) |
| Chat | DMs (deniable X3DH + Double Ratchet) and channels (signed MLS groups) on the same MOTE substrate | [features/chat.md](features/chat.md) |
| Calendar | Month/week/day + agenda, recurring events, peer-to-peer meeting invitations + RSVP | [features/calendar.md](features/calendar.md) |
| Contacts | Per-contact key verification — TOFU-pinned vs. verified via safety number — not just a name and photo | [features/contacts.md](features/contacts.md) |
| Files | Content-addressed, end-to-end encrypted, any size; a shared folder *is* a group | [features/files.md](features/files.md) |
| Identity | Safety numbers, avatars/profile, linked devices, recovery phrase, decentralized login (DMTAP-Auth) | [features/identity.md](features/identity.md) |
| Transport provenance | Know which trust boundaries a message crossed, without weakening the mixnet | [features/transport-traceability.md](features/transport-traceability.md) |
| PWA & mobile | Installable app, offline app-shell load, content-free Web Push wake-pings, responsive to ~360px | [pwa-and-push.md](pwa-and-push.md) |
| Self-hosting | Run your own domain, node, and optionally your own gateway — for $0 | [features/self-hosting.md](features/self-hosting.md) |

Calendar and contacts ride the same substrate as additional MOTE kinds (JSCalendar/JSContact over
JMAP, with CalDAV/CardDAV compatibility) — see [protocol.md](protocol.md#messaging--files),
[features/calendar.md](features/calendar.md), and [features/contacts.md](features/contacts.md).

## Map of the docs

- [Getting started](getting-started.md) — build the workspace, run a node and gateway, open the client.
- [Architecture](architecture.md) — client ↔ node ↔ mesh/mixnet ↔ gateway, and where an operator's billing seam sits.
- [Privacy & threat model](privacy.md) — the honest guarantee, stated as a falsifiable claim with its residual.
- [Protocol](protocol.md) — DMTAP itself: MOTE, naming, MLS, mixnet, DMTAP-Auth, the gateway.
- [Naming](naming.md) — the naming ladder (key-name, petname, `name@domain`, optional name-chains), the pluggable resolver framework, and operation without DNS.
- [Security](security.md) — 6 formal ProVerif models, fuzzing, conformance suite, downgrade tests, the audit gate.
- [PWA & push](pwa-and-push.md) — installable/offline app shell, content-free Web Push, the honest iOS/APNs residual.
- Features: [Mail](features/mail.md) · [Chat](features/chat.md) · [Calendar](features/calendar.md) · [Contacts](features/contacts.md) · [Files](features/files.md) · [Identity](features/identity.md) · [Transport provenance](features/transport-traceability.md) · [Self-hosting](features/self-hosting.md)
- [FAQ](faq.md)
- [Contributing](contributing.md)
- [Roadmap](roadmap.md) — what's real today vs. planned.

## Repository map

| Path | What it is |
|---|---|
| `node/` | envoir-node — the whole client side: identity, mailbox, mesh, messaging, files, client protocol servers |
| `gateway/` | envoir-gateway — the optional legacy SMTP bridge |
| `crates/dmtap-core` | Identity, MOTE, content addressing, canonical CBOR |
| `crates/dmtap-auth` | DMTAP-Auth — decentralized, key-based sign-in |
| `crates/dmtap-deniable` | Deniable 1:1 messaging (X3DH + Double Ratchet) |
| `crates/dmtap-mls` | MLS group messaging (handshake ordering, committer) |
| `crates/dmtap-mail` | IMAP/POP3/SMTP-submission/JMAP client-protocol servers |
| `crates/dmtap-naming` | Naming/addressing + key transparency |
| `crates/dmtap-p2p` | The real libp2p mesh transport (TCP/QUIC+Noise+Yamux, Kademlia, Circuit Relay v2 + DCUtR), proven on loopback — not yet the node binary's default transport |
| `crates/dmtap-seam` | The operator seam — the contract a hosted operator implements |
| `crates/conformance-runner` | Runs the implementation against the spec's conformance catalog |
| `crates/netsim`, `crates/downgrade-tests` | Mixnet anonymity simulation + downgrade/fail-closed regression suite |
| `client/` | Web client — mail, chat, calendar, contacts, files, groups, identity |
| `console/` | Open-source domain-admin console |
| `status/` | Public + personal status page |
| `superadmin/` | Fleet operator console — content-blind by construction |
| `site/` | Marketing/landing page |
| `formal/`, `fuzz/`, `integration/` | ProVerif symbolic models, wire-decoder fuzzing, adversarial cross-component tests |

The normative specification lives in the sibling **env-oir/dmtap** repo (22 markdown sections plus
a compiled `dmtap.pdf`), not in this repository — see [protocol.md](protocol.md).
