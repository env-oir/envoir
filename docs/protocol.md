# Protocol

Envoir is one implementation of **DMTAP** — the Decentralized Message Transfer & Access Protocol.
The normative specification is **not** in this repository; it lives in the sibling
**[env-oir/dmtap](https://github.com/env-oir/dmtap)** repo as 22 markdown sections plus a compiled
`dmtap.pdf`, grounded against current standards (MLS, HPKE, JMAP, libp2p, Privacy Pass, WebAuthn,
and more). Conformance is checked mechanically by
[`crates/conformance-runner`](../crates/conformance-runner) against the spec's own conformance
catalog — see [security.md](security.md#conformance-suite).

This page is a map of the protocol, not a restatement of it. Follow the section references (`§N`)
into the spec repo for the normative text.

## The governing principle

> Your key is your identity. Your domain, your IP, and your provider are all replaceable pointers
> to it.

Everything else in the protocol exists to make that sentence literally true: reachable without a
static IP, recoverable without a central authority, and privacy-preserving without a trusted
intermediary.

## MOTE — the atomic unit

A **MOTE** is a signed, encrypted, content-addressed message object (spec §2). Mail, chat
messages, file-share announcements, group events, and identity announcements are all MOTEs — one
format, rendered differently by clients. A MOTE has three nested layers:

- **Outer** — what the mixnet and relays see: an onion-wrapped, constant-length packet with no
  cleartext sender.
- **Envelope** — signed for authenticity; carries a content-addressed `id` and an ephemeral,
  per-message `sender_key` used only for spam-gating (never identity).
- **Payload** — the MLS/HPKE-encrypted content: the real sender identity, headers, body,
  attachments, and (if it crossed a gateway) a sealed provenance record.

Only the recipient (or group members) can decrypt the payload, so sender identity, subject,
recipients, threading, and content are all hidden from the network.

## Naming & key transparency

A `name@domain` address resolves through DNS (or an optional self-sovereign name backend — the
*only* place DMTAP admits anything blockchain-like, and it's off by default) to a public key,
checked against a **key-transparency log** for tamper-evidence, and **pinned on first use
(TOFU)**. After that, correspondents route by key over the mesh, and DNS is never consulted again
for that relationship unless a signed rotation says to. See spec §3.

- **`name@domain` is the headline address form** — provider-issued (`you@envoir.org`, zero DNS
  work) or your own domain, both resolving through the same mechanism.
- **Safety numbers** (spec §3.4.1) let two people verify each other's key out-of-band — words,
  digits, or a scannable grid — closing the one gap TOFU leaves open (a first-contact MITM before
  verification).
- **v0 key transparency is a single append-only log** — tamper-evident after the fact, but not
  equivocation-proof; a federated, gossiped v1 hardening closes that gap. See
  [privacy.md](privacy.md).

## Identity, recovery, and DMTAP-Auth

Identity is rooted in a long-term signing keypair; day-to-day devices hold signed subkeys.
Recovery is a first-class, versioned, signed policy (phrase / devices / social guardians) rather
than something bolted on at setup. The same keypair that receives your mail logs you in to the
web — **DMTAP-Auth** — with no central identity provider, using WebAuthn-style origin binding for
phishing resistance and an OIDC bridge for legacy relying parties. See
[features/identity.md](features/identity.md) and spec §1 / §13.

## Messaging & files

Mail, chat, and files are all modes over one substrate: **MLS (RFC 9420)** for every session and
group, MLS KeyPackages for asynchronous session initiation, and content-addressed chunked blobs
for files (spec §5):

- **1:1** = a 2-member MLS group (with an optional deniable X3DH/PQXDH + Double Ratchet mode
  alongside it).
- **Group chat / mailing lists** = an MLS group with a posting model (broadcast vs. channel) and a
  membership-visibility policy.
- **Multi-device** = each of your own devices is a member of your personal MLS cluster, syncing
  an encrypted CRDT.
- **Shared file folder** = an MLS group over a set of content-addressed manifests.

See [features/chat.md](features/chat.md) and [features/files.md](features/files.md).

## Transport: mesh and mixnet

The node **is** the mesh. It builds on libp2p (Kademlia DHT, circuit relay, hole-punching) so a
node behind CGNAT or a dynamic IP is reachable by its key. On top, a **mixnet** — profiled from
the Sphinx packet format and the Loopix/Nym operational design — gives the `private` privacy tier
its strong metadata guarantees; a `fast` tier trades that away for sub-second, direct-path chat
when both parties are online. See [privacy.md](privacy.md) and spec §4.

## The legacy gateway

The gateway (spec §7) is the **only** component that speaks SMTP, and the only one that isn't
content-blind — the legacy leg is unavoidably plaintext. It's optional: a user with only DMTAP
correspondents never invokes one, and it MAY be self-hosted for $0. See
[features/self-hosting.md](features/self-hosting.md) and
[features/transport-traceability.md](features/transport-traceability.md) for how a recipient can
verify a message actually crossed a gateway (and thus why it's billed).

## Client access

Every client protocol is a *view* of one MOTE store on the node (spec §8): **JMAP** natively,
plus **IMAP/POP3/SMTP-submission** and **CalDAV/CardDAV** compatibility surfaces so existing
mail/calendar clients work unchanged, authenticated with app-passwords rather than the identity
keypair itself.

## Anti-abuse, honestly

Sealed sender hides who sent a message from intermediaries — which means the recipient still
needs a way to rate-limit strangers without deanonymizing them. DMTAP's answer (spec §9) is
**anonymous but accountable**: ARC-style Privacy Pass rate-limit tokens, a memory-hard
proof-of-work fallback, and an optional, real-money **postage** stamp that also funds gateway
operators. None of this is a cryptocurrency — see the
[FAQ](faq.md).

## Operators and the seam

DMTAP is deployed self-hosted (free, unrestricted) or via a hosted operator that implements the
**operator seam** (spec §12, [`crates/dmtap-seam`](../crates/dmtap-seam)) for billing and
multi-tenant management. The inviolable rule: privacy, cryptography, and recovery are never
behind that seam. See [architecture.md](architecture.md#where-an-operators-billing-sits).

## Conformance levels

| Level | Requires |
|---|---|
| **Core** | Identity, MOTE, naming + TOFU + fail-closed key transparency, mesh delivery, MLS 1:1, cold-sender anti-abuse gating |
| **Private** | Core + the full mixnet (Sphinx, directory, 3-hop stratified paths, key rotation) + sealed sender + cover traffic + anti-active-adversary mechanisms + fail-closed no-downgrade |
| **Groups & Files** | Core + MLS groups + content-addressed file transfer |
| **Legacy** | Core + gateway inbound/outbound + DKIM delegation |
| **Clients** | Core + JMAP (IMAP/POP/SMTP-submission compatibility recommended) |
| **Auth** | Core + DMTAP-Auth login with origin binding + key-bound sessions (OIDC bridge recommended) |

A production mail node is expected to implement **Private**, not just Core — `private` is the
protocol's own default privacy tier for mail, so a Core-only node can't operate at the protocol's
own default. See spec §10.3 and [security.md](security.md#conformance-suite).
