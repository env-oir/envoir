# Security

This page collects everything in the repository that lets you check Envoir's security claims
yourself, rather than take them on faith: machine-checked formal proofs, fuzzing of every wire
decoder, a byte-exact conformance suite, and a dedicated downgrade/fail-closed regression suite.
It closes with the honest gate that stands between this code and any production deployment.

## Formal (ProVerif) models

[`formal/`](../formal) contains machine-checkable **symbolic (Dolev-Yao) models**, in ProVerif, of
DMTAP's two most security-critical ceremonies — the same class of artifact used to audit TLS 1.3,
MLS, and Signal.

| File | Ceremony | Properties checked |
|---|---|---|
| `deniable_1to1.pv` | Deniable 1:1 handshake (X3DH + first ratchet message) | Secrecy, injective mutual authentication (replay-resistant), weak forward secrecy |
| `deniable_1to1_deniability.pv` | Deniable 1:1 repudiation | Observational-equivalence deniability — a judge holding *both* parties' long-term keys cannot distinguish a genuine transcript from one forged by the responder alone |
| `dmtap_auth.pv` | DMTAP-Auth login ceremony | Unforgeability, replay-resistance, origin-binding (as one injective correspondence), and session key-binding (a captured assertion is useless without the session private key) |

**Status: all queries verified with ProVerif 2.05 — every query holds, no attack found.** Run
them yourself:

```sh
cd formal
./run.sh                              # all three models
proverif deniable_1to1_deniability.pv # or invoke ProVerif directly (expect "true")
```

Stated honestly, per [`formal/README.md`](../formal/README.md): these are **symbolic**, not
computational, models — perfect-cryptography abstraction, no bit-level attacks or side channels.
Diffie-Hellman is modeled by a single commutativity equation, not X25519's small-subgroup
behavior. PQXDH (the post-quantum handshake) and the Double Ratchet's per-message healing beyond
the first exchange are out of scope. Deniability is proved **offline** only, matching the spec's
own stated limit — online (interactive, real-time-colluding-judge) deniability is weaker and not
claimed. These models prove the *ceremonies as specified* are sound; they don't prove any
particular line of Rust is bug-free.

## Fuzzing

[`fuzz/`](../fuzz) runs `cargo-fuzz` (libFuzzer) over every canonical-CBOR **decoder** in
`dmtap-core` — the real attack surface, since every one of these functions runs on fully
attacker-controlled bytes before any signature is checked. There's one target per wire object:
`Identity`, `DeviceCert`, `RecoveryPolicy`, `MoveRecord`, `Envelope`, `Payload`, `Manifest`,
mix-node/directory descriptors, the domain directory, deniable-mode objects, capability tokens,
key-transparency proofs, plus fixed-length Sphinx cell types and DNS TXT/SVCB presentation
parsing.

Every target proves, at minimum, that its decoder never panics or hits undefined behavior on
adversarial input. The CBOR targets additionally check that any accepted decode **re-encodes to
byte-identical input** (canonical-form idempotence) — a decoder that accepts two different byte
strings as "the same" object is a real bug two implementations could silently disagree about.

```sh
cd fuzz
cargo +nightly fuzz run envelope -- -max_total_time=5   # smoke run
cargo +nightly fuzz build                               # just prove it all builds
```

**Previously-disclosed finding, now closed:** the `DMTAP_FUZZ_STRICT_CANONICAL=1` mode exists
because canonical-form enforcement (shortest-form integers, no indefinite-length items, strictly
ascending map keys) used to be missing at decode time in the low-level CBOR decoder
(`dmtap-core::cbor`) — non-shortest-form integers and out-of-order map keys were accepted and still
produced a semantically valid object. That enforcement is now real: the decoder rejects all three
forms explicitly, the three matching conformance cases (`DMTAP-CBOR-05/06/07`) pass, and re-running
the fuzz target with the strict flag set finds nothing. See
[`fuzz/README.md`](../fuzz/README.md) for the harness details and history.

## Conformance suite

The [conformance suite](https://github.com/env-oir/dmtap/tree/main/conformance) in the spec repo
is the **operational definition** of "DMTAP-compatible" — an implementation conforms at a level
if and only if it passes that level's `MUST` cases, not if it merely "resembles the reference." It
ships as three coupled artifacts: a normative case catalog (`SUITE.md`), the same cases as
machine-readable data (`suite.json`), and byte-exact known-answer vectors
(`vectors/vectors.json`).

- **157 numbered cases** across the conformance levels (Core, Private, Groups & Files, Legacy,
  Clients, Auth, Public Objects).
- **148 execute and pass today** — 68 backed by committed byte-exact vectors covering content
  addressing, the 8-word key-name checksum, safety numbers, Ed25519 sign/verify (with two RFC 8032
  cross-checks), canonical CBOR of the four core signed objects, suite fail-closed behavior, and
  the MOTE content-address + signature validation order, plus the full **§22 DMTAP-PUB / §23 CAD**
  public-objects suite (recomputed from `dmtap_core::pubobj` + `dmtap_core::cad`) — plus the rest
  exercised directly against the reference crates' public API. Zero failures.
- **9 are skipped with a documented, per-case reason** (mixnet replay/cover-traffic, the MLS
  committer-fork detector, MOTE↔JMAP mapping, the deniable session gate, and one §22.7 client-UX
  attestation). There are **no listed gaps** — the previous 12 §22 `vectored` gaps are closed.

[`crates/conformance-runner`](../crates/conformance-runner) is the reference runner: it drives the
vector-dispatch loop plus a **drift guard** that fails the build if the committed vectors and what
the reference crate currently generates ever diverge. The vectors, once published, are normative —
a divergence between the reference implementation and the vectors is a bug to reconcile, not the
other way around.

```sh
cargo test -p dmtap-core   # self-checking test drives every vector + the drift guard
```

## Downgrade & fail-closed invariants

DMTAP's downgrade-resistance rules are deliberately collected into one auditable table in the
spec (§10.7), because scattering them (suite ratchets with identity, tier floors with the mixnet,
ack-before-`250` with the gateway) hides gaps — exactly two such gaps were found this way during
hardening review. [`crates/downgrade-tests`](../crates/downgrade-tests) exists solely to hold an
external integration test that drives `dmtap-core`'s **public API** against every invariant from
that table that's testable at the library level — an external `tests/` crate, not `#[cfg(test)]`
internals, so a passing test proves the *public contract* an independent implementation would
actually see.

The governing rule behind every row: **a security-relevant downgrade is either refused
(fail-closed) or an explicit, user-surfaced choice — never an automatic, silent reaction to
adversary pressure.** Examples: an unknown suite byte is rejected, never guessed; a contact's
suite can only ratchet up, never down; a `private`-tier message that can't build a path meeting
its profile's bar is held and retried, never silently sent over the weaker `fast` tier; a cold
sender's failed anti-abuse challenge gets silently dropped or deferred to a requests area, and is
never acked (which would falsely confirm delivery to an unproven sender).

## The mixnet anonymity simulator

[`crates/netsim`](../crates/netsim) is a deterministic, seeded model of the mixnet's
routing/mixing/cover *mechanism* — built to measure the privacy claims empirically
(Loopix/Nym-style) rather than assert them. See
[privacy.md](privacy.md#global-passive-adversary-the-chance-floor) for what it found and its
explicit "this is a mechanism model, not the deployed network" caveat.

## Reporting a vulnerability

Security reports go to **`security@envoir.org`** (see the spec repo's `SECURITY.md` for the PGP
key) or the repository's private security-advisory facility — never a public issue for an unfixed
vulnerability. Good-faith research against your own identity/node/deployment, with no access to
others' data and no service degradation, falls under a stated safe-harbour policy. There is no
pre-launch bug bounty (there's no live production target to price one against); coordinated
disclosure is the channel until one exists.

## The audit gate

**An independent external cryptographic and code audit MUST precede any production deployment.**
This is a disclosed *gate*, not aspirational box-ticking: a deployment carrying real user mail
before a qualified third party has reviewed the protocol and the reference implementation is
operating outside this project's own stated posture. Formal models, fuzzing, and conformance
testing are real, load-bearing evidence — none of them, individually or together, substitute for
that audit. Any major change to a crypto suite, the mixnet construction, or the deniable handshake
re-opens the gate for the affected surface.

Until that audit happens, treat everything in this repository as **pre-alpha** — a reference and
a proof of the protocol's shape, not a hardened mail service.
