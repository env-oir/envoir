# Naming

> **Your key is your identity. A name is only ever a label on it.**

This page is the map of how a human-readable name turns into a key — the full **naming ladder**,
the **pluggable resolver** framework that lets more than one naming system exist below the
protocol without any of them becoming the protocol, and the one invariant every rung obeys
without exception. It replaces the shorthand used elsewhere in this repo ("an optional
self-sovereign naming backend") with the real model: DMTAP does not pick one winning naming
system, it fixes what a name must ultimately resolve to and lets naming systems compete beneath
that fixed point. See spec §3 (naming & key transparency), §3.12 (the pluggable resolver-type
framework), and §3.13 (name forms) for the normative text; this repo's reference implementation
lives in [`crates/dmtap-naming`](../crates/dmtap-naming) (the resolver types) and
[`crates/dmtap-core/src/keyname.rs`](../crates/dmtap-core/src/keyname.rs) (the key-name codec).

## The invariant: identity ≠ name

Every rung of the ladder below reduces to the same fact: **the key is the identity; a name is a
discovery pointer to it, never proof of it.** Concretely:

- A name is *never itself* checked for authenticity — what gets checked is the **key** the name
  points at (by DNS + key transparency, by a local pin, or by an on-chain record's own
  bidirectional binding to a self-asserted claim).
- Losing a name (a domain lapses, a DNS record is dropped, a chain registrar changes hands) never
  loses the identity behind it. A signed **move record** rebinds the same key to a new name, and
  any correspondent who has already made first contact routes by the pinned key from then on —
  they never re-resolve the old name and are never fooled by whoever now controls it. See
  [features/identity.md](features/identity.md#addresses-are-pointers-not-the-identity).
- **Safety numbers verify the key, never a name.** Two correspondents comparing words/digits/a QR
  grid are checking each other's full keyset — the one thing that closes the gap between "TOFU-
  pinned" and "verified." No naming system, present or future, changes what a safety number
  checks.

Everything else on this page is detail under that one sentence.

## The naming ladder

| Rung | Form | Authority | Network lookup | Default? |
|---|---|---|---|---|
| **Key-name** | `bafu-koda-...-vez` (9 words) | None — a pure derivation from the key | None | Always available (the floor) |
| **Petname** | any local label, e.g. `mum` | The user's own device, only | None (local table) | Opt-in, per-contact |
| **`name@domain`** | `you@envoir.org` | DNS + key transparency | DNS `_dmtap` TXT/SVCB, KT log | **Yes — the headline form** |
| **`name-chain`** (`.eth` / `.sol`) | `vitalik@.eth`, `toly.sol` | ENS / SNS, read-only | Chain RPC (Ethereum / Solana) | Off by default, opt-in |
| *`@handle` directory* | `@alice` | An opt-in directory service | Directory lookup | Registered in the spec, **not implemented by this reference build** |

A name's **form** alone decides which resolver handles it — a leading `@` marks the directory
type, a bare checksum-verifying word-list is a key-name, anything ending `.eth`/`.sol` (with or
without an `@`) is a name-chain, and a dotted namespace after `@` is DNS. Classifying by form is
mechanical and happens *before* any node-specific configuration is consulted — see
[`restype::classify`](../crates/dmtap-naming/src/restype.rs).

### Key-name — the zero-authority floor

Every identity has a name computed **deterministically from its own key**, requiring no
directory, no DNS, no registration, and no consensus: `words(truncate(BLAKE3(IK), 80 bits))` — 8
data words plus one checksum word, hyphen-joined (9 words total), drawn from an embedded
1024-word pronounceable list. Two different keys yield different key-names by construction; a
mistyped or mis-heard word fails the checksum and refuses to resolve, rather than silently
landing on a different key ([`keyname::verify`](../crates/dmtap-core/src/keyname.rs)).

Resolution here is not a lookup at all — it's the forward derivation run again and compared:
[`SelfResolver::resolve`](../crates/dmtap-naming/src/restype.rs) checks the checksum, re-derives
the key-name from the candidate key, and only accepts an exact match. This is the rung that keeps
working with **no DNS, no chain, and no directory anywhere on the network** — see
["Operation without DNS"](#operation-without-dns) below.

### Petname — a local label over an already-pinned key

A petname (`mum`, `the landlord`) is a purely **local** alias a user assigns to a key they have
already pinned by some other means. There is nothing to verify beyond the local table lookup —
key transparency is vacuous here because the binding was already established out-of-band
([`PetnameBook`](../crates/dmtap-naming/src/restype.rs)). It never leaves the device and is never
a global identifier.

### `name@domain` — the default

`you@envoir.org` or your own domain is the address you actually give out. Resolution is DNS as
**discovery**, the key as **proof**: a `_dmtap` TXT/SVCB record points at a candidate `Identity`,
which is checked against a **key-transparency log** for tamper-evidence, and the result is
**pinned on first use (TOFU)**. After that, correspondents route by key over the mesh and never
re-consult DNS for that relationship unless a signed rotation record says to. See
[protocol.md](protocol.md#naming--key-transparency) for the full flow and
[`crates/dmtap-naming`](../crates/dmtap-naming)'s `dns`/`kt`/`resolver` modules for the
fail-closed verification core (an unreachable or sub-quorum KT log **never** falls back to a
TOFU pin — see spec §3.3).

### `name-chain` (`.eth` / `.sol`) — optional crypto name-chains, four guardrails

A crypto name-chain buys the one thing DNS and key-names cannot: a **bare, globally unique,
human-*chosen*** username with no registrar in the traditional sense. Two are registered in the
spec today — **ENS** (`.eth`) and **SNS** (`.sol`) — modeled by
[`crates/dmtap-naming/src/namechain.rs`](../crates/dmtap-naming/src/namechain.rs). Admitting a
name-chain at all is governed by four guardrails, none of them negotiable:

1. **Optional.** `name-chain` is off by default in the resolver registry
   ([`ResolverRegistry::with_defaults`](../crates/dmtap-naming/src/restype.rs) enables only
   `self`, `petname`, and `dns`); a node that enables no chain is fully conformant, and nothing
   else in the protocol depends on one existing.
2. **Key-is-identity, enforced as a *bidirectional* binding.** A chain record is a label pointing
   at a key, never the identity itself. Resolution only succeeds if **both** directions agree:
   the on-chain `name → ik` record names the key, **and** that key's own signed `Identity.names`
   self-asserts the same name. Either direction alone is not enough — a captured registrar
   pointing at the wrong key, or a name claimed by a key the chain doesn't recognize, both fail
   closed as `ERR_NAMECHAIN_BINDING_UNVERIFIED` (`0x011E`). See the mismatch tests in
   `namechain.rs` for both failure directions exercised directly.
3. **Free to resolve.** Looking someone up is a **read-only** on-chain query — no wallet, no
   token, no transaction. Only the *registrant* ever pays, once, to claim the name in the first
   place; every correspondent who later resolves it pays nothing.
4. **No DMTAP token.** DMTAP defines no cryptocurrency of its own here or anywhere else in the
   protocol — ENS and SNS are used exactly as they exist today, as a discovery substrate KT then
   audits like any other pointer (never a trust root).

Because the chain is only ever a discovery pointer, the resolved key is still pinned and
KT-audited exactly as the DNS path is (§3.3–§3.5) — a name-chain doesn't get to skip that step
just because the pointer came from a chain instead of DNS.

### `@handle` — registered, not implemented here

The spec's pluggable framework reserves an opt-in `@handle` directory resolver type (§3.9.2) as a
fourth naming system a deployment could add. This reference build does not implement it:
`classify("@alice")` fails closed with `ERR_RESOLVER_TYPE_UNSUPPORTED` (`0x011F`) rather than
guessing at a directory that doesn't exist here. This is the honest, disclosed edge of "the
resolver set is open" — registered in the framework, absent from this codebase.

## Canonical name form & confusables defense (i18n)

Names are identity-bearing strings — they key KT leaves, the `Identity.names` forward-check, and
the pin store — so **one identity must have exactly one spelling**. Every entry point (parse,
form classification, KT leaf computation, `Identity.names` comparison, pin and petname keys)
funnels through one chokepoint,
[`canonical::canonical_name`](../crates/dmtap-naming/src/canonical.rs). The canonical form,
precisely:

- **Local part** — Unicode **NFC**, then lowercased (simple case fold), then NFC again (casing
  can denormalize). `ALICE@…`, `alice@…`, and an NFD spelling are one identity — previously the
  ASCII case difference alone hard-failed the identity check after DNS happily resolved it.
- **Domain part** — full **UTS-46/IDNA** processing (the `idna` crate from the url/servo stack);
  the canonical stored/compared form is the **A-label (ASCII/punycode)** form, and DNS qnames are
  always built from A-labels. `bücher.example`, `BÜCHER.example`, an NFD spelling, and
  `xn--bcher-kva.example` are one identity.
- **Chain and bare forms** (`.eth`/`.sol`, key-names, petnames) — NFC + lowercase (their
  namespaces are not DNS, so no punycoding), same script rules.
- **Single script per label** (UTS-39): characters with script `Common`/`Inherited` are exempt,
  and the conventional **Han+Hiragana+Katakana**, **Han+Hangul**, and **Han+Bopomofo**
  combinations are admitted; any other multi-script label — the classic `pаypal.com` homograph
  (Latin + Cyrillic `а`) — **fails closed** with `ERR_NAME_LABEL_MIXED_SCRIPT` (`0x0121`,
  pending §21.3 spec registration) *before any resolver runs*.

The mixed-script rule cannot catch a **whole-label** substitution — all-Cyrillic `аррӏе.com` is
internally single-script and its DNS/KT chain can verify honestly (the attacker really owns the
spoof domain). That is caught at **pin time**: the resolver keeps its name-keyed pin store keyed
by a UTS-39-informed **skeleton** ([`canonical::skeleton`](../crates/dmtap-naming/src/canonical.rs)
— lowercase + NFD, then a confusables fold), and a new name whose skeleton collides with a
*different* already-pinned name (or petname, in the petname book) is rejected with
`ERR_NAME_CONFUSABLE_WITH_PIN` (`0x0122`, pending registration) instead of being silently pinned
as a second, visually identical identity. **Honesty:** the fold is a documented *subset* of
UTS-39's `confusables.txt` (the high-value Cyrillic/Greek/Latin look-alike sets plus `0`/`O`,
`1`/`l`), not the full ~6k-entry table — sufficient in v0 precisely because the mixed-script rule
already forbids mixing scripts *inside* a label, forcing an attacker all-in on one script, which
is what the folded sets cover. Honest single-script non-Latin names (`иван@почта.рф`) resolve and
pin normally.

## The pluggable resolver-type framework

Naming resolution is always the same two steps, whichever rung produced the pointer (spec
§3.12.1):

1. **Discover** a `name → identity` pointer via *some* resolver (DNS, a local table, a chain
   read, a derivation from the key itself).
2. **Verify** that pointer — against key transparency for `dns`, against a bidirectional on-chain
   check for `name-chain`, vacuously for `self`/`petname` because the binding either *is* the key
   or was already pinned out-of-band — and pin the result.

DMTAP does not pick a winning naming system; it fixes step 2's outcome (a KT-verified or
vacuously-verified **key**) and lets naming systems compete *below* that fixed point. A node
declares which resolver types it actually implements via a
[`ResolverRegistry`](../crates/dmtap-naming/src/restype.rs); a name whose form belongs to a type
the node hasn't enabled — or to no recognized type at all — is **undiscovered by this node, not
invalid**, and resolution fails closed (`0x011F`) rather than guessing. Critically, an identity
is never *only* reachable through one resolver type: the key-name floor (§3.9.6) always works
regardless of which of the richer types a given node has turned on, so disabling `name-chain` (the
default) never makes anyone unreachable — it only means that one convenience form doesn't resolve
on this node.

This is what makes the set genuinely **open and extensible**: adding a fifth resolver type in the
future (another chain, a future directory protocol) is a new `ResolverType` variant plus a
form-classification rule — it never requires changing what step 2 verifies, because every
resolver type still terminates at the same key.

## Operation without DNS

Because the key-name and petname rungs need **no DNS, no chain RPC, and no directory of any
kind**, the protocol's floor does not depend on DNS existing, resolving correctly, or being
trustworthy at all:

- Two people can exchange key-names (read aloud, scanned as a QR-style grid, pasted from a
  profile) and reach full first-contact addressing with zero network infrastructure beyond the
  mesh itself.
- A node with no domain, no registrar relationship, and no DNS resolver configured is still a
  complete, addressable DMTAP identity — this is explicitly Tier A of the self-hosting onboarding
  ladder ("a key plus a directory name; DMTAP-only, no legacy interop, no DNS work") — see
  [features/self-hosting.md](features/self-hosting.md#running-your-own-yourdomain).
- `name@domain` and `name-chain` are both **conveniences layered on top** of that floor — richer,
  more memorable, but neither is required for the protocol to function, and neither can ever
  become the identity itself. If a domain, registrar, or chain disappears tomorrow, the key (and
  everyone who has already pinned it) is unaffected.

## Honesty: what's real vs. seam here

DNS **record parsing**, key-transparency **verification** (RFC 6962 inclusion-proof folding, STH
signatures, leaf-hash binding, the v1 `> n/2` multi-log quorum, split-view/equivocation detection,
freshness gates), the key-name codec, and the `name-chain` bidirectional-binding check are real,
tested cryptographic code — not stubs. **Network I/O** — the actual DNS queries, a live ENS/SNS
RPC client, a real KT-log HTTP transport — is deliberately left behind trait seams
([`Resolver`](../crates/dmtap-naming/src/resolver.rs), [`KtLog`](../crates/dmtap-naming/src/kt.rs),
[`NameChainClient`](../crates/dmtap-naming/src/namechain.rs)) so the verification core is fully
unit-testable offline today, with a real network client a thin, later swap behind the identical
trait. See [security.md](security.md#conformance-suite) for how naming/resolution cases are
covered in the conformance suite.

## See also

- [protocol.md](protocol.md#naming--key-transparency) — naming in the context of the whole
  protocol.
- [features/identity.md](features/identity.md) — safety numbers, the key hierarchy, and why an
  address is only ever a pointer.
- [features/self-hosting.md](features/self-hosting.md) — the onboarding ladder from "just a key"
  to "your own domain," and the gateway's own key-derived alias for reaching the legacy world with
  no naming lookup at all.
- Spec §3, §3.12, §3.13, §21.3 (error codes `0x011E`/`0x011F`) in the sibling
  [env-oir/dmtap](https://github.com/env-oir/dmtap) repository.
