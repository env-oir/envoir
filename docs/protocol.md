# Protocol

Envoir is one implementation of **DMTAP** — the Decentralized Message Transfer & Access Protocol.
The normative specification is **not** in this repository; it lives in the sibling
**[env-oir/dmtap](https://github.com/vul-os/dmtap)** repo as 22 markdown sections plus a compiled
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

A name is never the identity — it's a discovery pointer the protocol resolves down to a key, then
verifies. DMTAP fixes that one invariant (§3, §1.2: **identity ≠ name**) and leaves the naming
system itself **pluggable** (§3.12): a **key-name** (derived straight from the key, zero
authority, no DNS, no `@`), a local **petname**, the default **`name@domain`** (DNS discovery +
key-transparency proof), and an OPTIONAL crypto **name-chain** (`.eth`/`.sol`, four guardrails —
optional, key-is-identity via a bidirectional binding, free to resolve, no DMTAP token) all
terminate at the same KT-verified, pinned key. See [naming.md](naming.md) for the full ladder,
the resolver-type framework, and what "operation without DNS" actually means.

- **`name@domain` is the headline address form** — provider-issued (`you@envoir.org`, zero DNS
  work) or your own domain, both resolving through DNS discovery + KT proof, **pinned on first use
  (TOFU)**: correspondents route by key over the mesh from then on, and DNS is never consulted
  again for that relationship unless a signed rotation record says to.
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
correspondents never invokes one, and it MAY be self-hosted for $0. It bridges addressing too: any
key can present a stable, **key-derived alias** at any gateway with zero registration, so a
legacy sender can already reach you before you've registered anywhere, and both directions of the
bridge (inbound legacy → DMTAP, outbound DMTAP → legacy) run their own anti-spam gate rather than
sharing one. See [features/self-hosting.md](features/self-hosting.md#the-gateway-address-mapping)
for the full model and
[features/transport-traceability.md](features/transport-traceability.md) for how a recipient can
verify a message actually crossed a gateway (and thus why it's billed). The gateway lives in this
monorepo today by design, with the boundary discipline kept clean for a future split into its own
`envoir-gateway` repository — see [`gateway/SEPARATION.md`](../gateway/SEPARATION.md).

## Client access

Every client protocol is a *view* of one MOTE store on the node (spec §8): **JMAP** natively,
plus **IMAP/POP3/SMTP-submission** and **CalDAV/CardDAV** compatibility surfaces so existing
mail/calendar clients work unchanged, authenticated with app-passwords rather than the identity
keypair itself.

## Delegated capabilities, and Envoir Send

A [`CapabilityToken`](../crates/dmtap-core/src/capability.rs) is a signed, offline-verifiable,
UCAN-profile grant of one narrow `(resource, ability, caveats)` right from an issuer key to an
audience key — chainable, and each link in the chain may only *narrow* what its parent granted,
never widen it. A grant is revoked by publishing a separate, KT-logged revocation, which reaches
its whole delegated subtree at once. This primitive is real and tested in `dmtap-core` today
(fuzzed as a wire object, exercised by `cargo test -p dmtap-core`), independent of any particular
application built on it.

The natural application is **Envoir Send** — a Resend-style programmatic mail-sending API built
entirely on rotating a narrowly-scoped, send-only capability per API key: issuing, attenuating,
and revoking a key never touches the account's root identity, and a compromised or retired key is
one revocation away from being worthless. Framed plainly, it's a sovereign, self-hostable
alternative to a hosted transactional-email API. This is a roadmap item grounded in the
capability primitive already shipped here, not a product surface in this repository yet — see
[roadmap.md](roadmap.md).

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
