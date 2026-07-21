# DMTAP formal (symbolic) models

Machine-checkable **symbolic (Dolev-Yao) models** of DMTAP's
security-critical ceremonies and of the group / transparency / mixing
primitives it composes, in the [ProVerif](https://proverif.inria.fr/)
process calculus. This is the same *class* of artifact used to audit TLS 1.3,
MLS, and Signal: a mechanized proof (or refutation) of named security
properties against an active network attacker, with perfect cryptography
abstracted as an equational theory.

**Status: every query obtained a definitive result under ProVerif 2.05** — all
security queries hold; the five non-vacuity controls are deliberately, and
verifiably, *reachable* (see [Results](#results)). The verdicts are **gated**,
not merely printed: `./check.sh` compares a live run against `EXPECTED.txt` and
fails on any deviation *in either direction*.

Spec sources (read-only):

- `../../dmtap/05-messaging.md` §5.2.1 — optional **deniable 1:1 mode**
  (X3DH/PQXDH + Double Ratchet; dedicated IK-certified X25519 `idk`;
  shared-key-MAC authentication; `AD = IK_A ‖ IK_B`).
- `../../dmtap/13-identity-auth.md` §13.3 — **DMTAP-Auth** native login
  (origin-bound challenge; `cnf = H(session_pubkey)` bound before signing;
  RP binds the session only to `cnf`; DS-tag `DMTAP-v0/auth-assertion`).

- `../../dmtap/01-identity.md` §1.1, §1.3 — the **suite high-water-mark
  ratchet** that stops a PQ-capable peer being talked back down to the classical
  suite.
- `../../dmtap/05-messaging.md` §5.1 — the per-group **committer** and the
  fork evidence that indicts an equivocating one.

Three models (`mls_group_keys`, `kt_append_only`, `mixnet_unlinkability`) are
**tractable symbolic abstractions of the composed primitives** — an MLS-style
group key schedule, a Key-Transparency log, and one mixnet hop — not of a
specific DMTAP section; each honestly abstracts the one cryptographic property
it depends on (a one-way key schedule, a collision-resistant Merkle combine,
randomized onion encryption).

Two models (`suite_ratchet`, `committer_fork`) each prove **the cryptographic
half of a mechanism whose other half is local bookkeeping**, and say so in their
headers rather than dressing the bookkeeping in a proof. ProVerif's applied
pi-calculus has **no mutable state**, so a stored value evolving over time — the
ratchet's high-water mark, a `> n/2` roster quorum — is not expressible and is
not claimed. See [Limitations](#limitations-of-the-symbolic-model-honest).

## Files

| File | Ceremony | Analysis kind | Properties |
|------|----------|---------------|------------|
| `deniable_1to1.pv` | Deniable 1:1 X3DH + first ratchet msg | reachability | secrecy (S), mutual auth (A), weak forward secrecy (F) |
| `deniable_1to1_deniability.pv` | Deniable 1:1 — repudiation | observational equivalence | deniability (D) |
| `dmtap_auth.pv` | DMTAP-Auth login | reachability | unforgeability (U), replay-resistance (R), origin-binding (O), key-binding/DPoP (K) |
| `mls_group_keys.pv` | MLS-style group key schedule (3 epochs) | reachability (+ phase compromise) | group-key secrecy, forward secrecy (FS), post-compromise security (PCS) |
| `kt_append_only.pv` | Key-Transparency log + gossip auditor | reachability (correspondence) | inclusion soundness (I), no-rollback extension (X), split-view detection soundness (D) |
| `mixnet_unlinkability.pv` | One honest mixnet hop, 2 inputs | observational equivalence | passive input↔output unlinkability |
| `suite_ratchet.pv` | Suite high-water mark (§1.3) | reachability (correspondence) | authenticated mark advance, replay-resistance (A) — *not* monotonicity |
| `committer_fork.pv` | Group committer fork evidence (§5.1) | reachability (correspondence) | evidence soundness (S) — an honest committer cannot be framed |

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
- **(A) Mutual authentication** — injective agreement, in both directions:
  `inj-event(RecvResp(a,b,n)) ==> inj-event(SendInit(a,b,n))` (B authenticates
  A) and `inj-event(AcceptA(a,b,n)) ==> inj-event(ConfirmB(a,b,n))` (A
  authenticates B via a key-confirmation reply). **Injectivity** encodes
  replay-freeness; it holds because the responder consumes a fresh **one-time
  prekey `opk`** per session (the spec's §5.2.1 first-message replay defense —
  a last-resort-only init would *not* be injective, exactly the documented
  caveat).

  *Modelling note (authentication nonce).* The deniable handshake has no
  content signature, so authentication comes entirely from the shared DH key
  (only the two parties can compute it). ProVerif's DH-commutativity equation
  does **not** terminate on a correspondence phrased directly over the derived
  key term `SK`. The sound, standard workaround used here: each party places a
  **fresh authentication nonce inside the shared-key AEAD payload** (`na`, `nb`)
  and the events agree on that nonce. Since the nonce travels only under the
  AEAD keyed by `SK`, agreement on it *is* agreement on a session only the two
  key-holders could have produced — the mutual authentication we want — and the
  query terminates. (See [Limitations](#limitations-of-the-symbolic-model-honest).)
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

### `mls_group_keys.pv`

A **tractable abstraction of the RFC 9420 (MLS) TreeKEM + key schedule**, run as
a concrete bounded 3-epoch instance:

- epoch 1 — group `{A, B, R}`, `R` a full member (learns `es1`);
- epoch 2 — a Commit **removes `R`** → `{A, B}`, fresh Commit entropy `cs2`
  delivered *only* to `A, B`;
- epoch 3 — a Commit re-keys `{A, B}` with fresh `cs3`.

The **key schedule is abstracted by two one-way functions** — `es_n =
kdfEpoch(is_{n-1}, cs_n)` and `is_n = kdfInit(es_n)` (free constructors, no
inverse). One-wayness is the *only* property FS/PCS rely on: you cannot run the
schedule backwards, and you cannot get `es_n` without **both** `is_{n-1}`
**and** `cs_n`. **TreeKEM path distribution is abstracted** by public-key
encrypting `cs_n` to each *current* member's leaf key — exactly what a removed
member cannot open. Each epoch encrypts one application probe `appMsg_n` under
`es_n`, so secrecy of `appMsg_n` ⇔ secrecy of `es_n`.

Two phase-1 compromises are switched on **simultaneously** (the worst case for
epoch 2): the removed member `R` dumps *all* of its state (`skR`, `es1` ⇒
`is1`), **and** a later epoch is fully compromised (`es3` ⇒ `is3`).

- **Group-key secrecy + PCS + FS** — `query attacker(appMsg2)`. The epoch-2
  secret survives that combined leak. **PCS**: the removed `R` holds `es1`/`is1`
  but the fresh Commit entropy `cs2` was encrypted only to `A, B`, so `R` cannot
  form `es2`. **FS**: the later-epoch compromise (`es3`, `is3`) cannot be run
  backwards through the one-way schedule to recover `es2`. And *a fortiori* this
  is group-key secrecy against a **passive transcript observer**, who holds
  neither leaf keys nor any epoch secret.
- **Non-vacuity controls** — `query attacker(appMsg1)` and
  `query attacker(appMsg3)` are **deliberately false**: a party that legitimately
  holds an epoch's own secret can read that epoch (`R` reads epoch 1 it belonged
  to; the epoch-3 compromise reveals epoch-3 traffic). These false results
  *certify the leaks are real*, so epoch 2's secrecy is genuine cryptographic
  separation, not an artifact of handing the attacker nothing.

### `kt_append_only.pv`

A **Key-Transparency log with a gossip auditor**, with **Merkle hashing
abstracted as a collision-resistant hash** — the free binary function `H`,
which is injective and non-invertible in the symbolic model. A Signed Tree Head
is `sign((prev, root), logK)` with `root = H(prev, leaf)` the head after
appending `leaf` onto `prev`. **Tree size/position is abstracted by the
predecessor head `prev`**: two STHs sharing a `prev` are two views at the same
position, and a **fork** = two *different* roots at the same `prev`. The log is
offered as a service the Dolev-Yao attacker drives (it will append any leaf onto
any `prev`, forks included), but it cannot forge its own signature, so every STH
a client/auditor accepts traces to a genuine append.

- **(I) Inclusion soundness / no fake membership** —
  `event(ClientInclusion(prev,leaf,root)) ==> event(LogAppend(prev,leaf,root))`.
  A client that verifies an inclusion proof (STH signature valid *and*
  `root = H(prev,leaf)`) is guaranteed the log actually appended *that* leaf at
  *that* position. Collision-resistance of `H` forbids a second `(prev,leaf')`
  with the same root.
- **(X) Extension / no rollback** —
  `event(ClientExtend(oldRoot,leaf,newRoot)) ==> event(LogAppend(oldRoot,leaf,newRoot))`.
  A client that accepts a one-step consistency proof whose new `prev` equals the
  old root is guaranteed the new head was built by a genuine append **onto the
  exact old head**; the log cannot silently rewrite or drop history under it.
- **(D) Split-view detection soundness (no false alarm)** —
  `event(Equivocation(prev,r1,r2)) ==> event(LogAppend(prev,leaf1,r1)) && event(LogAppend(prev,leaf2,r2))`
  (leaves existentially quantified). The gossip auditor raises the equivocation
  alarm **only** when the log really signed two conflicting heads at the same
  position — every alarm is a real fork, never a false positive.
- **Reachability sanity (documented, expected reachable)** —
  `event(Equivocation(...))` and `event(ClientExtend(...))` are each reachable
  (ProVerif reports `not event(...) is false`), certifying that the split-view
  alarm *can* actually fire when the attacker forks the log, and that a genuine
  extension *is* accepted (liveness). Without these, (I)/(X)/(D) could hold
  vacuously.

### `mixnet_unlinkability.pv`

**One honest mix hop with two concurrent inputs**, as an
observational-equivalence (biprocess) model of **input↔output unlinkability for
a passive global observer**. Two honest senders each build a randomized 2-layer
onion (inner layer addressed to the next hop, outer layer to the mix); the hop
strips its outer layer and emits the two inner layers in a permuted order.

**Encryption is randomized** — `penc(m, pk, coins)` with fresh secret `coins`.
This is load-bearing: with *deterministic* encryption the observer could
re-encrypt an output under the mix's *public* key and byte-match it to an input,
trivially linking them; randomized encryption (the re-encryption / probabilistic
-onion property real mixes require) forbids that.

- **Unlinkability** — observational equivalence of two worlds that differ *only*
  in the mix's secret permutation: `out(choice[mA,mB]); out(choice[mB,mA])`, so
  LEFT emits `(innerA, innerB)` and RIGHT emits `(innerB, innerA)` while the two
  input onions are byte-identical across both worlds. If `LEFT ~ RIGHT`, no
  passive observer can decide which input produced which output ⇒ the honest hop
  **unlinks** input↔output. The payloads are secret and the inner layers are
  ciphertexts to a next hop the observer cannot open, which is what makes the two
  outputs interchangeable.

### `suite_ratchet.pv`

§1.1 makes the PQ-hybrid suite `0x02` the REQUIRED originating suite because
mail is the most archival medium there is and a harvest-now-decrypt-later
adversary is recording today. That argument is worth nothing unless a peer who
has once used `0x02` **cannot later be talked back down** to `0x01`. §1.3
supplies the guarantee with a per-contact high-water mark.

**Proved (A) — authenticated mark advance.** The mark moves only on a message
the genuine contact actually signed, and a **replay cannot count as a second
advance** (injective agreement, §2.6 content-address de-duplication). The attack
here is *not* forgery: once a contact has legitimately sent at the classical
suite, that signed artifact exists forever and verifies perfectly under their
key, so an attacker who captured it can offer it again after the contact
migrates. Signature checking cannot stop that; only the mark can.

**Not proved here — monotonicity**, i.e. the ratchet actually refusing a
below-mark suite. It is a statement about a stored value evolving over time.
Encoding it in ProVerif degenerates in *both* directions: write the rejection in
and the model proves the `if` that was just typed; leave it out and the
forbidden branch is trivially reachable, because the attacker really can deliver
a PQ message then a classical one — what a conformant node does at that point is
precisely the thing under test. It is a stateful invariant, wants Tamarin, and
is covered meanwhile by the SUITE high-water-mark conformance cases.

### `committer_fork.pv`

MLS (RFC 9420) trusts the Delivery Service for exactly one thing: a **total
order** on group Commits. A leaderless mesh has no natural serialization point,
so §5.1 elects a per-group **committer** that serializes handshake messages into
an append-only hash-chained log, and declares that two Commits at the same log
position with the same predecessor are proof of misbehavior — members **MUST
halt and alert**.

**Proved (S) — evidence soundness.** A halt implies the committer *really did*
sign both conflicting Commits. An equivocating committer signs its own
indictment; an honest one cannot be framed.

**Why soundness is the property that matters.** The naive reading is that
detection is the valuable half. But detection failing is a *liveness* problem —
the group runs on with a fork until someone notices. Evidence being **forgeable**
is a *safety* problem and strictly worse: any single malicious member could
manufacture two Commits, present them as a fork, and halt an entire group at
will, for the cost of one message and indistinguishably from the honest case the
halt exists to serve. §5.1's own phrase is "self-contained, transferable proof
of misbehavior" — and transferable proof is exactly what must not be forgeable.

**Not modelled — the takeover quorum (§5.1, §16.8) and partition healing.**
Deterministic successor selection plus a `> n/2` apply-ack roster quorum is a
*counting* property over accumulated per-member state, and "only one partition
can ever hold the quorum" is a statement about global state across a network
split. Both hit the no-mutable-state wall. **Do not read this model as covering
them.**

## How to run

Requires **ProVerif** (`opam install proverif`) — or Docker. `run.sh` resolves,
in order: a native `proverif` on `PATH`; else the local Docker image
`proverif-local:2.05`; else a throwaway `ocaml/opam` container that installs
ProVerif via opam.

```sh
./check.sh                            # run all eight, GATE against EXPECTED.txt
./run.sh                              # all eight models, print output only
./run.sh mls_group_keys.pv            # one model
proverif deniable_1to1.pv             # or invoke ProVerif directly
proverif deniable_1to1_deniability.pv # equivalence: expect "true"
proverif mixnet_unlinkability.pv      # equivalence: expect "true"
```

Reading the output: for a reachability `query`, ProVerif prints
`RESULT ... is true` when the property holds (secrecy: secret; correspondence:
authenticated). For the equivalence models, expect
`RESULT Observational equivalence is true`. A `false` result comes with an
attack derivation — which for a *deliberate non-vacuity control* (the two
`appMsg1/appMsg3` and the two `kt` reachability queries) is the intended,
documented outcome, not a security failure.

**Prefer `./check.sh` over reading the output.** `run.sh` invokes every model
with `|| true`, so it exits 0 whether every property holds or one silently
broke — an *executed* proof, not an *enforced* one. `check.sh` re-runs the
models, extracts every `RESULT` line, and diffs the verdicts against
`EXPECTED.txt`. A security query turning `false` is an obvious regression; a
non-vacuity control turning `true` is a silent and worse one, because it means
the model can no longer reach the state it reasons about and its other proofs
have gone vacuous *while still reporting success*. Both directions fail the
gate. `EXPECTED.txt` documents why each row is there; changing one is a
deliberate act that belongs in a commit message.

## Results

Obtained with **ProVerif 2.05** (run in the `proverif-local:2.05` Docker image;
see `run.sh`). **Every security query holds; the deliberate non-vacuity controls
are, as intended, reachable.** Verbatim verification summaries (copied from the
tool output):

**`deniable_1to1.pv`** (secrecy, mutual authentication, weak forward secrecy):

```
Query not attacker_p1(msgAB[]) is true.
Query inj-event(RecvResp(a,b,n)) ==> inj-event(SendInit(a,b,n)) is true.
Query inj-event(AcceptA(a,b,n)) ==> inj-event(ConfirmB(a,b,n)) is true.
```
- `not attacker_p1(msgAB[]) is true` — the first message stays secret **even in
  phase 1, after both parties' long-term keys are leaked** ⇒ secrecy **and**
  weak forward secrecy.
- both `inj-event ... ==> inj-event ...` — **injective** mutual authentication
  (replay-resistant) in both directions.

**`deniable_1to1_deniability.pv`** (deniability / repudiation):

```
RESULT Observational equivalence is true.
```
- A judge holding **both** parties' long-term secret keys and choosing the
  message cannot distinguish a genuine transcript from a responder-forged one ⇒
  **offline participation & message repudiation** proved.

**`dmtap_auth.pv`** (unforgeability, replay, origin-binding, key-binding):

```
RESULT inj-event(RPAccepts(u,o,n,cnf_4)) ==> inj-event(UserSigned(u,o,n,cnf_4)) is true.
RESULT not attacker(secretResource[]) is true.
```
- injective `RPAccepts ==> UserSigned` — **unforgeability + single-use nonce
  (replay resistance) + origin binding** (assertion accepted at origin `o` was
  signed for `o`; cross-origin phishing replay impossible).
- `not attacker(secretResource[]) is true` — **key-binding / DPoP**: a captured
  assertion without the session private key cannot unlock the session.

**`mls_group_keys.pv`** (group-key secrecy, forward secrecy, post-compromise
security):

```
Query not attacker_p1(appMsg2[]) is true.
Query not attacker_p1(appMsg1[]) is false.
Query not attacker_p1(appMsg3[]) is false.
```
- `not attacker_p1(appMsg2[]) is true` — the **epoch-2** secret stays secret in
  phase 1 **even with the removed member `R` dumping its entire epoch-1 state
  AND a later epoch fully compromised** ⇒ **post-compromise security** (fresh
  Commit entropy `cs2` was never delivered to `R`) **and forward secrecy** (the
  one-way schedule cannot be inverted from a future epoch); *a fortiori*
  group-key secrecy against a passive observer.
- `not attacker_p1(appMsg1[]) is false` and `... appMsg3[] ... is false` —
  **deliberate non-vacuity controls** (see the model section): a party holding
  an epoch's *own* secret can read that epoch. Their falsity proves the
  compromises are effective, so epoch 2's secrecy is genuine separation.

**`kt_append_only.pv`** (inclusion soundness, no-rollback extension, split-view
detection):

```
Query event(ClientInclusion(prev_2,leaf_3,root_2)) ==> event(LogAppend(prev_2,leaf_3,root_2)) is true.
Query event(ClientExtend(oldRoot_1,leaf_3,newRoot_1)) ==> event(LogAppend(oldRoot_1,leaf_3,newRoot_1)) is true.
Query event(Equivocation(prev_2,r1_1,r2_1)) ==> event(LogAppend(prev_2,leaf1,r1_1)) && event(LogAppend(prev_2,leaf2,r2_1)) is true.
Query not event(Equivocation(prev_2,r1_1,r2_1)) is false.
Query not event(ClientExtend(oldRoot_1,leaf_3,newRoot_1)) is false.
```
- the three `... is true` correspondences — **(I)** a verified inclusion implies
  a genuine append of that leaf at that position (collision-resistance of `H`);
  **(X)** an accepted extension implies a genuine append onto the exact old head
  (no rollback); **(D)** every raised equivocation alarm implies the log really
  signed two conflicting heads (no false alarm).
- the two `not event(...) is false` — **deliberate reachability sanities**: the
  split-view alarm **can** fire (attacker forks the log) and a genuine extension
  **is** accepted (liveness). `is false` here means *reachable*, i.e. the
  intended outcome — it certifies the model is not vacuous.

**`suite_ratchet.pv`** (authenticated high-water-mark advance):

```
RESULT inj-event(MarkAdvanced(cc,s,n)) ==> inj-event(ContactSent(cc,s,n)) is true.
```
- **injective** agreement — the per-contact mark advances only on something the
  genuine contact signed, and a captured earlier classical message replayed
  after the contact migrated to PQ cannot count as a fresh advance. Monotonicity
  itself is deliberately absent; see the model section above.

**`committer_fork.pv`** (fork-evidence soundness):

```
RESULT event(ForkDetected(k,pos_1,x,y)) ==> event(CommitterSigned(k,pos_1,prev_1,x)) && event(CommitterSigned(k,pos_1,prev_1,y)) is true.
RESULT not event(ForkDetected(k,pos_1,x,y)) is false.
```
- the `... is true` correspondence — **(S)** every §5.1 halt implies the
  committer genuinely signed both conflicting Commits at that position on that
  predecessor. Fork evidence cannot be fabricated, so the mandated HALT cannot
  be turned into a one-message group-wide denial of service.
- `not event(ForkDetected(...)) is false` — **deliberate non-vacuity control**:
  forks are *reachable*, i.e. an equivocating committer really can sign two
  conflicting Commits. Without this the soundness implication would hold over
  the empty set and prove nothing while reporting success.

**`mixnet_unlinkability.pv`** (passive input↔output unlinkability of one hop):

```
RESULT Observational equivalence is true.
```
- A passive global observer that sees both input onions and both mix outputs
  cannot decide which input produced which output ⇒ **one honest hop unlinks
  input↔output**. (ProVerif emitted `Termination warning`s while completing the
  disequality clauses of the biprocess, but still reached a **definitive**
  `Observational equivalence is true` — the equivalence is proved, not left
  open.)

## Limitations of the symbolic model (honest)

- **Symbolic, not computational.** Cryptography is perfect and abstract
  (Dolev-Yao): no probabilities, no bit-level attacks, no side channels, no
  weak-randomness or nonce-reuse-at-the-primitive level. These models
  complement, but do not replace, computational proofs (CryptoVerif) or
  implementation review.
- **DH is abstracted** by a single commutativity equation
  (`dh(x,dhexp(y)) = dh(y,dhexp(x))`); it does not model small-subgroup /
  invalid-curve / identity-element behaviour of X25519.
- **Authentication is proved via an in-AEAD authentication nonce**, not a
  correspondence phrased directly over the derived key `SK`. This is a sound
  encoding (the nonce is transported only under the shared-key AEAD, so
  agreement on it implies both parties computed the same `SK`); it is used
  because ProVerif's DH-equation handling does not terminate on the
  direct-over-`SK` correspondence. This is a *tool* limitation, not a protocol
  gap — the secrecy query does reason directly over `SK` and terminates.
- **PQXDH (`suite = 0x02`, ML-KEM)** is not modelled — only the classical X3DH
  DH structure. The KEM leg would need its own encapsulation abstraction.
- **Double Ratchet** is modelled only through its **first** message
  (handshake + first AEAD + one key-confirmation). Per-message ratchet forward
  secrecy / PCS across many messages is not exercised here.
- **Deniability is offline only** (see scope above); online deniability and the
  endpoint-logging residual (§5.2.1(e)(1)) are out of symbolic scope.
- **DMTAP-Auth origin binding** models the trusted client's origin check as an
  exact `=origin` match. It does not model the §13.3.1 *companion-mode*
  weakening against homograph/look-alike origins (a UI/PKI TOFU property, not a
  protocol-message property), nor WebAuthn `clientDataJSON` at the byte level.
- **MLS key schedule is abstracted to two one-way KDFs** (`kdfEpoch`,
  `kdfInit`); the real RFC 9420 schedule (`joiner_secret`, `welcome_secret`,
  `confirmation_key`, `PSK`s, exporter, `sender_data`) and the full TreeKEM tree
  (path secrets, parent-hash, blanking, unmerged leaves) are *not* modelled —
  path distribution is collapsed to a per-member public-key encryption of the
  Commit secret. Only a **bounded 3-epoch, single-removal** instance is run
  (`R` removed at epoch 2); PCS/FS are shown for exactly that shape, not for
  arbitrary membership sequences. Group-agreement, Welcome/join, external
  commits, and the transcript-hash authentication chain are out of scope.
- **KT model abstracts a Merkle tree to a hash chain** (`root = H(prev, leaf)`),
  and **"tree size / position" to the predecessor head `prev`** — an
  equivocation is modelled as two divergent appends onto the *same* predecessor.
  A fuller model would track a real leaf count and multi-level authentication
  paths / consistency proofs over sub-tree hashes. Collision-resistance is the
  *perfect* symbolic injectivity of `H` (no probabilistic collision); STH
  freshness/gossip is modelled by the auditor cross-checking two log-signed STHs
  rather than by wall-clock timestamps or a real gossip network; monitor-side
  auditing of the *whole* tree and rate/rollback bounds are out of scope.
- **Mixnet unlinkability is passive-observer only**, for **one honest hop with
  exactly two concurrent inputs** — the atomic mixing step. It is **not**
  anonymous-channel anonymity: active `n−1` / flooding / tagging / trickle
  attacks, timing- and volume-based traffic analysis, and compromised or
  colluding hops are all outside the Dolev-Yao symbolic model (they are the
  reason real mixnets need cover traffic, thresholds and multiple hops).
  Encryption is modelled as *randomized* `penc(m, pk, coins)`; without the fresh
  `coins` the equivalence would (correctly) fail, since a deterministic onion is
  linkable by re-encryption. ProVerif completes with `Termination warning`s on
  the biprocess disequality clauses but still returns a definitive result.
- **No mutable state, so no stateful invariants.** ProVerif's applied
  pi-calculus reasons about what an attacker can *derive* or *cause*, not about
  a stored value evolving over time. Three load-bearing DMTAP mechanisms are
  therefore only half-covered here, and each says so in its own header rather
  than quietly claiming the whole: the §1.3 **suite ratchet's monotonicity**
  (the mark never decreasing), the §5.1 **takeover quorum** (`> n/2` apply-acks,
  a counting property) and **partition healing** (a global-state property across
  a split). These want a stateful tool — Tamarin's multiset-rewriting state
  facts express exactly this shape — and are covered meanwhile by conformance
  cases against a real implementation, not by proof. A reader should not infer
  from "the ratchet is modelled" that the ratchet is proved.
- These are **bounded well-formed models of the ceremonies/primitives as
  specified**, not of any particular implementation. An implementation can still
  be insecure while the protocol is sound.
