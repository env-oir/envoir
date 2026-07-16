# Privacy & Threat Model

Envoir implements DMTAP's privacy model exactly as the spec states it: **honest, not absolute.**
This page is the plain-language version of DMTAP spec §6 (Privacy & Threat Model) — read that
section, and its rich cross-references, if you need the normative wording.

## The headline guarantee

> DMTAP targets **strong metadata privacy against a global passive adversary** — one that can
> observe every link and every timing signal, everywhere, but cannot inject, drop, or delay
> packets. It does **not** claim to fully defeat a global *active* adversary with unlimited
> resources; that residual is bounded, detected, and disclosed rather than hidden.

Three things are always protected, against essentially any adversary:

- **Content** — end-to-end encrypted (MLS/HPKE). Only recipients decrypt.
- **Authenticity** — every message is signed, and content-addressed, so tampering is detectable.
- **Sender identity from intermediaries** — sealed sender: the sender's identity lives *inside*
  the encrypted payload, never in the outer packet.

Two things are protected **against the passive adversary specifically, with a quantified residual
against an active one**:

- **Social graph & timing** — a mixnet (onion routing + Poisson mixing delays) plus mandatory
  cover traffic and size padding.
- **Discovery** — name→key lookups are routed through the mixnet, so the directory never learns
  who is looking up whom.

## Global passive adversary: the chance floor

Against an adversary that can only *watch* — every link, all the timing, but nothing more —
Envoir's mixnet is designed to drive an attacker's best guess at "who sent this to whom" toward
**1/N**, a uniform random guess over the anonymity set. A mechanism-model simulation in
[`crates/netsim`](../crates/netsim) measures exactly this: as cover-traffic rate and hop count
increase, the simulated correlation probability converges toward that chance floor, not below it.

**Caveat, stated plainly:** this is a simulation of the *mechanism*, not a measurement of the
deployed network. It models Poisson mixing, loop/drop cover, stratified path selection, entry
guards, and operator diversity under an idealized traffic model — not real packet encoding, not a
real libp2p mesh, not real bandwidth contention. It is a sanity check that the design behaves as
intended in the abstract, and it does not substitute for the external audit gate described in
[security.md](security.md#the-audit-gate).

## Global active adversary: bounded, detected, disclosed — not defeated

An adversary who can inject, drop, or delay packets at will is harder to fully stop, and DMTAP
does not pretend otherwise. Concretely:

- **Drop/delay attacks are detected, not silent.** Every node emits a steady stream of cover
  "loop" packets that travel out and back to itself. If the fraction of loops returning on time
  drops below a threshold — **≈20% loss** in the reference parameters — the node infers an active
  attack, rotates away from the implicated mixes, raises a `HALT_ALERT`, and **fails closed**
  rather than silently continuing on a weaker path.
- **Colluding entry+exit mixes are the real residual, and hop count does not fix it.** If an
  adversary controls a fraction *f* of the mix fleet, the probability that both the entry and
  exit mix on a given path are adversarial tracks **≈ f²** — bounded by entry guards and
  *attested* operator diversity, not by adding more hops in the middle. The netsim measurements
  are explicit on this point: more hops defend against *timing correlation by an outside
  observer*, but leave the entry+exit collusion probability essentially unchanged. Claiming "just
  add more hops" defeats a colluding-endpoint adversary is a documented overclaim the spec
  explicitly refutes.
- **The floor is mathematical, not an engineering gap.** By the Anonymity Trilemma (Das, Meiser,
  Mohammadi & Kate, IEEE S&P 2018), strong anonymity provably cannot be had without paying in
  latency and/or bandwidth. A user-selectable **high-security profile** (5 hops instead of 3,
  constant-rate cover, tighter guards) is the lever that lets a deployment approach that floor —
  it does not eliminate it.
- **Key-transparency freshness and mix-directory freshness are both fail-closed.** A stale or
  frozen view of either is treated as an error, not silently accepted — see [security.md](security.md)
  for the full downgrade-invariant table.

## Endpoint and key compromise

- **Offline seizure is defended.** The local mailbox store is encrypted under a key released only
  on device unlock, so a powered-off or locked stolen device yields inert ciphertext.
- **Key exfiltration is defended where hardware allows.** Device keys SHOULD live in a hardware
  keystore (Secure Enclave / TPM / StrongBox / TEE) as non-exportable keys.
- **Single-device compromise heals.** Removing or rotating a device advances every group's
  cryptographic epoch (MLS post-compromise security), so the evicted key decrypts nothing
  further.
- **The one irreducible residual:** a device actively compromised *while unlocked and in use*
  sees exactly what the user sees. No protocol can prevent an authorized, unlocked endpoint from
  reading its own screen — Envoir shrinks endpoint compromise to precisely this floor rather than
  claiming to eliminate it.

## Recovery: phrase, device, and social guardians

Losing a device should never mean losing your identity, and DMTAP treats recovery as a
first-class, versioned, signed policy the owner composes and rotates:

- **Methods** — a recovery phrase, additional linked devices, and/or Shamir-shared social
  guardians, combined with an "any of" threshold (e.g. "1 phrase OR 2 devices OR 2 guardians").
- **Two thresholds, deliberately asymmetric.** The bar to *recover* access is always at or below
  the (higher) bar needed to *change* the recovery policy itself, so a single recovered factor
  can never rewrite recovery and lock the real owner out.
- **Weakening changes need a quorum, even when signed by the identity key itself**, plus an
  asymmetric veto window — this closes the "stolen root key rewrites recovery to evict the owner"
  attack.
- **The bottom turtle:** losing the root key *and* enough recovery factors simultaneously is
  unrecoverable; an attacker who obtains the root key *and* a rotation-quorum of factors can evict
  the owner outright — worse than loss. There is no way around this without a central recovery
  authority, which DMTAP deliberately does not have.

The web client's onboarding demo shows a 12-word phrase; the spec calls for the full **SLIP-0039**
word list in a production client. See [features/identity.md](features/identity.md).

## Deniability is optional and 1:1 only

The default messaging path (MLS) is **signature-based and non-repudiable by design** — this is a
property of MLS (RFC 9420), not an Envoir shortcoming, and it cannot be removed without breaking
the protocol it's built on. For 1:1 conversations that need cryptographic repudiation (a
whistleblower, a source, an off-record channel), Envoir offers an **optional, explicit,
capability-negotiated deniable mode** — a separate Signal-style X3DH/PQXDH + Double Ratchet
channel authenticated by a shared-key MAC rather than a signature. Groups of three or more always
stay on MLS and remain non-repudiable. See [features/chat.md](features/chat.md).

Deniability here means *cryptographic repudiation of the transcript* — it is not endpoint
protection. A device that logs its own plaintext as displayed still proves content regardless of
any repudiation protocol; no cryptography changes that.

## What this project does not claim

- **Not a global mixnet on day one.** At launch, the mix fleet is small and likely operator-run —
  closer to "Tor with few relays" than a mature global mixnet. Privacy strengthens as independent
  operators contribute mixes under disjoint control.
- **Not post-quantum yet.** v0's Sphinx onion and classical crypto suite are not post-quantum; a
  harvest-now-decrypt-later adversary could someday retroactively reconstruct routing metadata
  (not message content, which is separately migratable) recorded today. This is disclosed as an
  active, tracked frontier, not hidden.
- **Not equivocation-proof key transparency in v0.** A single, non-gossiped key-transparency log
  can in principle show different histories to different observers until the v1 federated/gossiped
  hardening lands. High-value contacts should still use out-of-band safety-number verification.
- **Not independently audited yet.** See [security.md](security.md) — an external cryptographic
  and code audit is a disclosed *gate* before any production deployment, not a checkbox already
  ticked.

## Further reading

- [security.md](security.md) — formal (ProVerif) proofs of the two hardest ceremonies, fuzzing,
  conformance, and the audit gate.
- [protocol.md](protocol.md) — the full DMTAP protocol this page summarizes.
- The spec itself: `06-privacy.md` in the sibling `dmtap` repository, especially §6.9 (falsifiable
  security-property table) and §6.10 (the netsim measurements).
