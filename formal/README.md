# DMTAP formal (symbolic) models

> **Verification status: NOT run in this environment** â ProVerif is not installed here, so these models are **structurally complete but locally unverified**. Run `./run.sh` (or in CI) to obtain actual results; no property below is *proved* until ProVerif reports it.

Machine-checkable **symbolic (Dolev-Yao) models** of DMTAP's two
security-critical ceremonies, in the [ProVerif](https://proverif.inria.fr/)
process calculus. This is the same *class* of artifact used to audit TLS 1.3,
MLS, and Signal: a mechanized proof (or refutation) of named security
properties against an active network attacker, with perfect cryptography
abstracted as an equational theory.

Spec sources (read-only):

- `../../dmtap/05-messaging.md` §5.2.1 — optional **deniable 1:1 mode**
  (X3DH/PQXDH + Double Ratchet; dedicated IK-certified X25519 `idk`;
  shared-key-MAC authentication; `AD = IK_A ‖ IK_B`).
- `../../dmtap/13-identity-auth.md` §13.3 — **DMTAP-Auth** native login
  (origin-bound challenge; `cnf = H(session_pubkey)` bound before signing;
  RP binds the session only to `cnf`; DS-tag `DMTAP-v0/auth-assertion`).

## Files

| File | Ceremony | Analysis kind | Properties |
|------|----------|---------------|------------|
| `deniable_1to1.pv` | Deniable 1:1 X3DH + first ratchet msg | reachability | secrecy (S), mutual auth (A), weak forward secrecy (F) |
| `deniable_1to1_deniability.pv` | Deniable 1:1 — repudiation | observational equivalence | deniability (D) |
| `dmtap_auth.pv` | DMTAP-Auth login | reachability | unforgeability (U), replay-resistance (R), origin-binding (O), key-binding/DPoP (K) |

**Why deniability is a separate file.** Deniability is an
*indistinguishability* property, not a reachability one, so it is a ProVerif
**observational-equivalence** (biprocess) query, which cannot be mixed with the
reachability queries above. More fundamentally: proving deniability means
exhibiting a **forger** who holds the *responder's* key material and can
fabricate a transcript "from" the initiator. That same forger, if placed in the
authentication analysis, would break third-party-provable authentication **by
design** — that breakage *is* the deniability. So the authentication guarantee
(which assumes the honest parties' keys are not used to forge) and the
deniability guarantee (which assumes exactly the opposite) belong to two
different attacker worlds and two different files.

## What each model checks (precise property statements)

### `deniable_1to1.pv`

Models X3DH `suite = 0x01`: DH inputs `idk` (dedicated long-term X25519,
certified once by the Ed25519 `IK` via `idk_sig`), signed prekey `spk`,
one-time prekey `opk`, and initiator ephemeral `ek`. Session key
`SK = KDF(DH(idk_a,spk_b) ‖ DH(ek_a,idk_b) ‖ DH(ek_a,spk_b) ‖ DH(ek_a,opk_b))`.
Every message is authenticated by the AEAD tag (the shared-key MAC), with
`AD = IK_A ‖ IK_B`. **No signature ever covers content** (only `idk_sig` /
`spk_sig`, which sign *public keys*).

- **(S) Secrecy** — `query attacker(msgAB)`. The first-message plaintext (and
  hence `SK`) is not derivable by the attacker.
- **(A) Mutual authentication** — injective agreement on the derived session
  key, in both directions:
  `inj-event(RecvResp(a,b,k)) ==> inj-event(SendInit(a,b,k))` (B authenticates
  A via A's IK-certified `idk`) and
  `inj-event(AcceptA(a,b,k)) ==> inj-event(ConfirmB(a,b,k))` (A authenticates B
  via a key-confirmation reply). **Injectivity** encodes replay-freeness; it
  holds because the responder consumes a fresh **one-time prekey `opk`** per
  session (the spec's §5.2.1 first-message replay defense — a last-resort-only
  init would *not* be injective, exactly the documented caveat).
- **(F) Weak forward secrecy** — after the sessions run (`phase 1`), the
  attacker is handed **both parties' long-term secrets** (`idk_A, idk_B,
  IK_A, IK_B`); `ek` and `opk` are deleted, never revealed. A *proved* (S)
  under this phase-1 leak *is* weak forward secrecy: past traffic stays secret
  despite full long-term-key compromise.

### `deniable_1to1_deniability.pv`  — the headline

**Deniability query (stated precisely).** Observational equivalence between two
worlds, with the attacker/judge **given both parties' long-term secret keys**
(`idk_A, idk_B, IK_A, IK_B`) **and choosing the message content**:

- **LEFT** = transcript produced by the **genuine initiator A** (uses A's real
  `idk_A` and a real ephemeral);
- **RIGHT** = transcript **forged** using only the responder's session prekeys
  (`spk_B, opk_B`) and A's *public* `idk`/cert — **no secret of A**, a
  forger-chosen ephemeral.

If `LEFT ~ RIGHT`, then no transcript is a cryptographic proof that A authored
anything (the responder could have produced it) ⇒ **participation and message
repudiation**. **Negative control:** the equivalence is meaningful precisely
because nothing signs the content — add a `sign(m, IK_A)` and RIGHT can no
longer match, so ProVerif would report the equivalence *false*. A proved
equivalence therefore certifies "no long-term signature binds authorship".

**Honest scope.** This is *offline* deniability under full long-term-key
compromise (Vatandas–Gennaro–Ithurburn–Krawczyk, ACNS 2020). *Online*
(interactive, real-time-colluding-judge) deniability is weaker and is **not**
claimed — matching spec §5.2.1(e)(2).

### `dmtap_auth.pv`

Models the §13.3 six-step ceremony: RP-issued `Challenge{rp_origin, nonce, iat,
exp, aud}`; trusted client generates a fresh session keypair, sets
`cnf = H(session_pub)` before signing; `IK_U` signs
`DS_AUTH ‖ H(rp_origin ‖ nonce ‖ iat ‖ exp ‖ aud ‖ cnf)`; RP verifies against
the pinned `IK_U`, checks `rp_origin == own`, `aud == own`, `H(spub) == cnf`,
nonce freshness, and binds the session **only** to `cnf`.

- **(U) Unforgeability + (R) replay + (O) origin-binding**, together, as one
  injective agreement carrying `(origin, nonce, cnf)`:
  `inj-event(RPAccepts(u,o,n,cnf)) ==> inj-event(UserSigned(u,o,n,cnf))`.
  Same `u` ⇒ only the `IK_U` holder produced it (U). Same `o` ⇒ an assertion
  accepted at origin `o` was signed *for* `o`, so a cross-origin/phishing
  replay cannot be accepted (O). Injectivity ⇒ each acceptance maps to a
  distinct signing, so a captured assertion is never accepted twice (R). Two
  honest origins (`O_BANK`, `O_SHOP`) are present to exercise (O); the trusted
  client only signs a challenge whose `rp_origin` matches the origin it
  verified (`=O` pattern), which also closes the §13.3.1 remote-node relay hole.
- **(K) Session key-binding / DPoP** — `query attacker(secretResource)`. The RP
  releases the session-protected resource encrypted to the session public key
  (`cnf`'s preimage). Even though every assertion is public (the attacker, and
  per §13.6 the bridge, sees it), a bearer without the session private key
  cannot obtain the resource ⇒ a stolen assertion alone is useless.

## How to run

Requires **ProVerif** (`opam install proverif`) — or Docker, via the fallback
in `run.sh`.

```sh
./run.sh                              # all three models
./run.sh deniable_1to1.pv             # one model
proverif deniable_1to1.pv             # or invoke ProVerif directly
proverif deniable_1to1_deniability.pv # equivalence: expect "true"
proverif dmtap_auth.pv
```

Reading the output: for a reachability `query`, ProVerif prints
`RESULT ... is true` when the property holds (secrecy: secret; correspondence:
authenticated). For the equivalence model, expect
`RESULT Observational equivalence is true`. A `false` result comes with an
attack derivation — for these files that would be a **finding** (see below).

## Results

<!-- RESULTS-PLACEHOLDER -->

## Limitations of the symbolic model (honest)

- **Symbolic, not computational.** Cryptography is perfect and abstract
  (Dolev-Yao): no probabilities, no bit-level attacks, no side channels, no
  weak-randomness or nonce-reuse-at-the-primitive level. These models
  complement, but do not replace, computational proofs (CryptoVerif) or
  implementation review.
- **DH is abstracted** by a single commutativity equation
  (`dh(x,dhexp(y)) = dh(y,dhexp(x))`); it does not model small-subgroup /
  invalid-curve / identity-element behaviour of X25519.
- **PQXDH (`suite = 0x02`, ML-KEM)** is not modelled — only the classical X3DH
  DH structure. The KEM leg would need its own encapsulation abstraction.
- **Double Ratchet** is modelled only through its **first** message
  (handshake + first AEAD). Per-message ratchet forward secrecy / PCS across
  many messages is not exercised here.
- **Deniability is offline only** (see scope note above); online deniability
  and the endpoint-logging residual (§5.2.1(e)(1)) are out of symbolic scope.
- **DMTAP-Auth origin binding** models the trusted client's origin check as an
  exact `=origin` match. It does not model the §13.3.1 *companion-mode*
  weakening against homograph/look-alike origins (that TOFU-pin nuance is a
  UI/PKI property, not a protocol-message property), nor WebAuthn
  `clientDataJSON` at the byte level.
- These are **bounded well-formed models of the ceremonies as specified**, not
  of any particular implementation. An implementation can still be insecure
  while the protocol is sound.
