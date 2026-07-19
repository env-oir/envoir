# dmtap-sync-wasm

**The first binding of the shared sync engine.** A `wasm-bindgen` wrapper that gives a JavaScript
product the *same compiled* CRDT algebra a Rust server runs — not a second implementation of
[`substrate/SYNC.md`](../../../dmtap/substrate/SYNC.md) that happens to agree most of the time.

This is surface #1 of the plan in [`substrate/BINDINGS.md`](../../../dmtap/substrate/BINDINGS.md)
§3. It was built first because every product that would adopt Sync already ships a JS/TS frontend
(ofisi's editor, kerf's frontend, vidmesh's `kernel-ts`), and because it sidesteps the
cgo-vs-pure-Go tension §5 flags for the Go path — a pure-Go host can later load this *same* `.wasm`
artifact through `wazero` with `CGO_ENABLED=0` intact.

---

## The proof, first

The reason to believe any of this is one command:

```sh
./build.sh                                            # compile the binding
cargo test -p dmtap-sync-wasm --test native_trace     # 22 vectors through NATIVE Rust
node --test 'crates/dmtap-sync-wasm/test/*.test.mjs'  # the same 22 through WASM, from JS
```

The JS suite drives the frozen conformance vectors
(`../../../dmtap/conformance/vectors/sync_vectors.json`) through the WASM build and asserts, per
vector, that every recomputed byte matches **both** the vector's frozen expectation **and** a trace
recorded from the native Rust engine. That second assertion is the one `BINDINGS.md` §4 calls
non-negotiable: without it, "the browser computes what the server computes" is a claim.

Current status: **22/22 vectors driven through both surfaces, byte-identical; 29 JS assertions,
7 native.** `NOT_COVERED` is empty — nothing is skipped. The §5.2.1 fast-join vectors looked like
pure transport at first, but the `FastJoin` encoding, the below-floor predicate and the caller-side
verification sequence are all algebra; only the fetch is transport, and the binding leaves that to
the host. So a browser replica can fast-join too.

Nothing here is a mock. The vectors' `signature_hex` is reproduced by `node:crypto` signing a
preimage the WASM module hands out — which simultaneously proves the detached signing protocol
below actually works.

---

## Key handling: no private key crosses this boundary

**There is no entry point that accepts a seed or a secret key, and this is deliberate.**

WASM linear memory is an ordinary `ArrayBuffer`. Any script sharing the page — an analytics tag, a
compromised transitive dependency, a devtools heap snapshot — can read every byte of it, and
neither `mlock`, guard pages, nor reliable zeroization exist in that address space. A
`sign_op(seed)` convenience would take a `CryptoKey` the browser *guarantees* is non-extractable
and turn it into bytes sitting in a readable buffer for the lifetime of the tab. That is a real
loss of a real protection, bought for the price of one `crypto.subtle.sign` call.

So signing is **detached** — three steps, key never in scope:

```js
import * as sync from 'dmtap-sync-wasm';

const op = sync.encode_op(JSON.stringify({
  kind: 3, ns: 'notes', target: 'doc-1', field: 'title',
  value: { tstr: 'Hello' }, hlc: JSON.parse(clock.tick(Date.now())),
}));

const { sig_structure } = JSON.parse(sync.op_signing_input(op));   // 1. preimage OUT
const signature = new Uint8Array(                                   // 2. sign wherever you like
  await crypto.subtle.sign('Ed25519', privateKey, hexToBytes(sig_structure)),
);                                                                  //    privateKey may be
                                                                    //    { extractable: false }
const envelope = sync.op_attach_signature(op, signature);           // 3. signature IN
```

Step 3 **verifies before it returns**: a signature made under the wrong key, over the wrong
preimage, or by a custodian that silently failed cannot leave the function as a well-formed op. A
binding that emitted unverifiable envelopes would just push the failure onto some other replica's
ingest path, hours later and with no context.

The insecure path is not "discouraged" here — it is **absent**, because a documented-but-present
footgun is still a footgun. Native Rust callers keep `dmtap_sync::cose::sign_op`; they have a
memory model in which holding a secret key is a defensible thing to do. Snapshots follow the same
protocol (`snapshot_signing_input` → `snapshot_assemble`). Verification needs only public keys, so
the ingest path is unaffected.

---

## The API

Small on purpose: enough to replace a product's hand-rolled engine, not a mirror of every internal.
Values and objects cross as **tagged JSON** (`{"tstr":"v"}`, `{"bstr":"6162"}`, `{"int":-3}`) —
plain JSON cannot tell a string from hex-spelled bytes, and the substrate's contract is that the
bytes *are* the semantics. Everything byte-shaped crosses as `Uint8Array`.

| Area | Exports |
|---|---|
| **Ops** | `encode_op` · `decode_op` · `op_id` · `validate_op` · `op_kinds` |
| **Values** | `encode_value` · `decode_value` · `is_ext_value` |
| **HLC** | `HlcClock` (`tick`, `observe`, `current`) · `encode_hlc` · `compare_hlc` |
| **Signing** | `op_signing_input` · `op_attach_signature` · `verify_signed_op` · `decode_signed_op` |
| **Engine** | `SyncEngine`: `ingest_signed` · `ingest_ambient_authenticated` · `has_op` · `merge` · `observable_state` · `observable_state_json` · `state_root` · `verify_root` · `version_vector` · `version_vector_cbor` · `lww_cell` · `set_contains` · `set_members` · `set_surviving_tags` · `counter_total` · `counter_entries` · `death_state` · `sequence` · `tree` · `prune_below` |
| **Snapshots** | `observable_state_root` · `encode_observable_state` · `decode_observable_state` · `snapshot_decode` · `snapshot_verify` · `snapshot_signing_input` · `snapshot_assemble` |
| **Fast-join (§5.2.1)** | `fastjoin_decode` · `fastjoin_encode` · `caller_is_below_floor` · `fastjoin_state_address` · `fastjoin_adopt` · `fastjoin_adopt_after` · `fastjoin_check_progress` · `fastjoin_check_covers` · `fastjoin_covers_carries_floor_author_mark` |
| **Reconciliation** | `fingerprint` · `summarize` · `reconcile` |
| **Policy / GC** | `check_admitted` · `check_counter_entry` · `check_ns_ref` · `scope_to_subscription` · `stability_cut` |
| **Meta** | `version` · `error_registry` |

### Two ingest paths, named honestly

`ingest_signed(cose, now)` is **the network path**: it verifies the `COSE_Sign1` envelope, then
validates and applies. `ingest_ambient_authenticated(op, now)` applies an op whose authenticity was
already established out of band — the §5.6 profile, where ops ride unsigned inside an MLS group.
The op is still fully validated; only the signature check is skipped, because there is no signature
to check. On a multi-author or untrusted path it is a hole, and it is named so you cannot reach for
it by accident.

### Errors are codes, not prose

A thrown `Error`'s `message` is JSON:

```js
try { engine.ingest_signed(bytes, Date.now()); }
catch (e) {
  const { code, name, action } = JSON.parse(e.message);
  // → 0x0A02 ERR_SYNC_OP_SIG_INVALID FAIL_CLOSED_BLOCK
}
```

`{"error":"sync"}` is a substrate refusal; `{"error":"binding"}` means the call itself was
malformed. Different bugs, different fixes — and a caller that has to regex-match prose to tell
`0x0A02` from `0x0A0A` will eventually take the wrong fail-closed path.

---

## What this does NOT cover

* **Transport.** No sockets, no HTTP, no discovery. §5.2's pull/push protocol is the host's job;
  this is the algebra and the envelope. Fast-join follows the same line: `fastjoin_adopt` verifies
  everything and tells you (via `fastjoin_state_address`) what to fetch, but **you** perform the
  `GET /sync/state/<root>` and hand the bytes back. Keeping the network out is also what keeps
  every call synchronous.
* **Persistence.** `SyncEngine` is in-memory. Bring your own store; replay or fast-join on load.
* **Identity and admission policy.** `check_admitted` tests membership in a list *you* supply. It
  does not resolve `DeviceCert` chains, namespace policy objects, or revocation — that is
  capability ①.
* **Async.** Every call is synchronous. Signing is the only step that is not, and it happens in
  your code, not ours.

---

## Size

| Artifact | Raw | Gzipped |
|---|---|---|
| `pkg-node/dmtap_sync_bg.wasm` (`--target nodejs`) | 395,912 B (387 KiB) | 154,657 B (151 KiB) |
| `pkg/dmtap_sync_bg.wasm` (`--target bundler`) | 395,912 B (387 KiB) | 154,657 B (151 KiB) |

Both targets emit the same `.wasm`; only the JS glue differs.

### A correction, and what actually costs the bytes

An earlier revision of this file blamed the size on `dmtap-core`'s suite-`0x02` post-quantum stack
(`ml-dsa`, `x-wing`, `hpke`) being linked in for want of feature gates, and proposed feature-gating
the core as the fix. **That was measured and found to be wrong**, and the claim is corrected here
rather than quietly dropped.

Two independent checks say so. Building the binding against a `dmtap-core` stripped of `mote`, `pq`,
`deniable`, `mixnet`, `sphinx` and their dependencies changed the artifact by **+256 bytes** — it
did not shrink. And attributing every function in the pre-`wasm-opt` module by symbol gives:

| Origin | Share of code |
|---|---|
| `alloc` (dominated by `BTreeMap` monomorphization) | 20.6% |
| `core` | 17.1% |
| `dmtap-sync-wasm` (this crate's JSON marshalling) | 16.7% |
| `dmtap-sync` (the algebra itself) | 13.0% |
| `curve25519` (Ed25519 verification — genuinely used) | 4.7% |
| `serde_json` | 4.3% |
| **`dmtap-core`** | **0.2%** (1,466 bytes) |
| `ml-dsa`, `x-wing`, `hpke`, `chacha20poly1305` | **0 bytes** |

Link-time dead-code elimination already removes the entire PQ/HPKE surface, because nothing
reachable from a `#[wasm_bindgen]` export touches it. `dmtap-core` contributes 0.2% of the module,
so feature-gating it could not have paid for the `cfg` complexity it would have added to a crate the
node, gateway, mail, clustersync, deniable, MLS, naming, p2p and conformance crates all depend on.
**No feature gates were added, and none should be added for this reason.**

The lever that did work is the build profile, applied in `build.sh` to the WASM build **only** so
that native binaries are compiled exactly as before:

| Setting | Raw | Gzipped |
|---|---|---|
| baseline (`release`, `opt-level=3`) | 600,776 | 231,552 |
| `lto=fat` + `codegen-units=1` alone | 600,005 | 231,989 |
| **`opt-level=z`** alone | 399,763 | 156,215 |
| `opt-level=z` + `lto=fat` + `codegen-units=1` | 391,657 | 153,092 |

`opt-level=z` is essentially the whole win: `release` inlines and unrolls the `BTreeMap`/CRDT
generics that dominate this module, and trading that speed for ~34% less download is the right call
for code that ships to a browser on every page load. (`panic=abort` was measured and deliberately
not set — `wasm32-unknown-unknown` already aborts on panic, so it changes nothing.)

The remaining bulk is the algebra and its marshalling, which is the code you are actually here for.
Shrinking it further means a leaner JSON boundary in *this* crate, not surgery on `dmtap-core`.

---

## Packaging

`./build.sh` emits two packages from one compiled core:

* `pkg/` — `--target bundler`: ESM + `.d.ts`, the npm-consumable artifact for a web product.
* `pkg-node/` — `--target nodejs`: CommonJS, synchronous init; what the test suite loads.

Both are build output and are git-ignored (wasm-pack writes its own `.gitignore`). Consume `pkg/`
via a path/workspace dependency, or publish it under your own scope — the generated `package.json`
carries the name, version and `types` from `Cargo.toml`. The `.d.ts` is generated from the Rust doc
comments, so the types and their documentation cannot drift from the implementation.

## CI

This repository has no CI configuration (no `.github/`, no other runner), so there is nothing to
wire into. The complete gate is three commands, in this order:

```sh
cargo test -p dmtap-sync-wasm                          # marshalling-layer unit tests
./crates/dmtap-sync-wasm/build.sh nodejs               # compile to wasm32-unknown-unknown
cargo test -p dmtap-sync-wasm --test native_trace      # native half of the parity proof
node --test 'crates/dmtap-sync-wasm/test/*.test.mjs'   # WASM half + the byte-for-byte diff
```

The last two are also available as `npm run test:sync-wasm` from the repo root. When CI is
introduced, that is the job.

---

## Adopting it

1. Depend on `pkg/` and delete your HLC, your op encoder, and your merge functions.
2. Keep your storage and your transport. Persist the canonical op bytes (`encode_op`) — they are
   the durable artifact; the engine is a fold over them.
3. Replace your signing with the detached protocol above, keeping keys in WebCrypto.
4. On join, either replay your ops through `ingest_signed`, or fast-join: pass the responder's
   `FastJoin` to `fastjoin_adopt_after` with whatever `GET /sync/state/<root>` returned. It verifies
   the signature, checks what §5.2.2 says is checkable about `covers`, enforces the step-5 progress
   MUST, and hashes the body against `Snapshot.root` before returning any state. **If it throws,
   keep your old vector and do not fall back to the responder's op suffix** — that fallback is a
   silent lost write. Two things to know, both of which look like bugs and are not:
   * Adopting `covers` **may move your vector backwards** for some author. That is intended and is
     not an error — step 5's re-pull re-ships every retained op above `covers`.
   * **Do not compare `floor` to `covers`.** `floor` is a single HLC, `covers` is a per-author
     vector; there is no ordering between them, and the natural-looking `covers.lacks(floor)`
     returns `true` for perfectly conformant responders (§5.2.2, correction C-07). The binding
     exposes that predicate only as `fastjoin_naive_covers_lacks_floor_rejected`, named so it cannot
     be mistaken for a verdict.
   Use `fastjoin_adopt_after` rather than `fastjoin_adopt` in a real pull loop: only the former
   enforces the progress MUST, and the loop it prevents (a responder re-offering the same
   `root`/`covers` forever) is otherwise unbounded.
5. Wire `sync_vectors.json` into your own test suite. Every implementation reproduces the same
   frozen bytes; that is what makes two independently built products interoperate.
