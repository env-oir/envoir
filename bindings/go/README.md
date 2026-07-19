# `dmtapsync` — the DMTAP Sync engine, callable from Go

The shared sync engine ([`substrate/SYNC.md`](../../../dmtap/substrate/SYNC.md)) as a Go package: the
six-kind CRDT algebra, COSE_Sign1-signed operations, HLC total order, observable-state snapshots,
version vectors and range-Merkle reconciliation — **without cgo**.

```go
import dmtapsync "github.com/vul-os/envoir/bindings/go"
```

It embeds the same Rust core every other surface runs, compiled to WebAssembly, and executes it with
[wazero](https://wazero.io), a WebAssembly runtime written in pure Go. No C toolchain, no
`CGO_ENABLED=1`, no shared library beside the binary, no sidecar to supervise. A product importing
this package still cross-compiles to a single static binary.

**This package does not implement the algebra.** It marshals arguments into the compiled core and
marshals results back. That is the point: byte-identical behaviour is a property of the toolchain
rather than of three teams reading a spec carefully.

---

## Why wazero and not cgo

flowstock ships as a single cross-compiled binary, and the Vulos OS carries an explicit
pure-Go/no-CGO architectural decision (`docs/decisions.md` item J / D23) — the same decision that
already correctly predicted the cr-sqlite dead end. cgo would break cross-compilation for exactly
the products this exists to serve: a `cdylib` per target OS/arch, a C toolchain at build time, and
a fresh class of memory-safety-at-the-boundary bugs.

[`BINDINGS.md` §5](../../../dmtap/substrate/BINDINGS.md) costs three options — cgo, a sidecar
process, and a pure-Go WASM runtime — and recommends the third for any product carrying a pure-Go
constraint. This is that option, built.

Two things turned out differently from the plan, both worth knowing:

- **The browser and Go surfaces do not load the same `.wasm` file.** §5 anticipated they would, and
  that would have been the strongest possible form of the guarantee. It is not achievable:
  `wasm-bindgen`'s artifact imports functions from its JS glue, and one of them returns an
  `externref` — a handle to a JavaScript object. wazero's host-function API is defined over
  `i32`/`i64`/`f32`/`f64` only, so a Go host cannot supply that import at all; there is no Go value
  that is a JS `Error`. Reverse-engineering wasm-bindgen's explicitly-internal calling convention
  would put the whole byte-equality property at the mercy of a minor version bump. So
  `crates/dmtap-sync-wasm` grows a **second boundary** (`src/abi.rs`) over the **same function
  bodies** — every dispatch arm delegates to the `lib.rs` entry point the JS export calls. One
  implementation of the algebra, two ways in. The conformance vectors below are what makes that
  claim checkable rather than aspirational.
- **No WASI.** §5 suggested `wasm32-wasi` as an option. The module is built for
  `wasm32-unknown-unknown` and imports **nothing at all** — no WASI, no host functions, no clock, no
  filesystem, no network, no randomness. `TestModuleImportsNothing` asserts it. That is a security
  property (the engine cannot reach anything it is not handed) as much as a portability one, and it
  is why instantiation costs ~90 µs.

---

## Getting started

The embedded module is **build output, not source** — it is gitignored. Generate it once:

```sh
crates/dmtap-sync-wasm/build-abi.sh     # or: go generate ./bindings/go
```

Requires `rustup target add wasm32-unknown-unknown`. `wasm-opt` (binaryen) is optional but roughly
halves the artifact; the script uses wasm-pack's cached copy if one is present.

```go
ctx := context.Background()

rt, err := dmtapsync.New(ctx)   // compile once — this is the expensive step
defer rt.Close(ctx)

in, err := rt.Instance(ctx)     // cheap; one per goroutine, or use a Pool
defer in.Close(ctx)

eng, err := in.NewEngine()
defer eng.Close()

isNew, err := eng.IngestSigned(coseBytes, receiverNowMS)
state, err := eng.ObservableState()
root, err := eng.StateRoot()
```

Refusals carry the [§12](../../../dmtap/substrate/SYNC.md) registry entry, so branch on the code
rather than on prose:

```go
if dmtapsync.IsRefusal(err, "0x0A09") {
        // divergence; §12 says HALT_ALERT
}

var se *dmtapsync.SyncError
if errors.As(err, &se) { log.Printf("%s %s %s", se.Code, se.Name, se.Action) }
```

A `*BindingError` means the call itself was malformed — bad hex, a stale handle. Kept distinct from
`*SyncError` on purpose: "the engine refused your data" and "you called the binding wrong" are
different bugs with different fixes.

---

## API

Mirrors the shapes the WASM/JS binding exposes, so the three surfaces stay recognisably one API.
`Instance.EntryPoints()` lists everything the module can dispatch; `Instance.Call` is the escape
hatch for anything without a typed method yet.

| Area | Methods |
|---|---|
| Introspection | `Version`, `ErrorRegistry`, `OpKinds`, `EntryPoints` |
| Values & ops | `EncodeValue`, `DecodeValue`, `IsExtValue`, `EncodeOp`, `EncodeOpJSON`, `DecodeOp`, `DecodeOpJSON`, `OpID`, `ValidateOp` |
| HLC (§3) | `NewClock` → `Tick`, `Observe`, `Current`; `EncodeHLC`, `CompareHLC` |
| Signing (§4.1) | `OpSigningInput`, `OpAttachSignature`, `SignOp`, `VerifySignedOp`, `DecodeSignedOp` |
| Engine (§4.3–§4.8) | `NewEngine` → `IngestSigned`, `IngestAmbientAuthenticated`, `HasOp`, `Merge`, `ObservableState`, `StateRoot`, `VerifyRoot`, `VersionVector`, `LWWCell`, `SetContains`, `SetMembers`, `SetSurvivingTags`, `CounterTotal`, `CounterEntries`, `DeathState`, `Sequence`, `Tree`, `PruneBelow` |
| Snapshots (§6.1) | `ObservableStateRoot`, `EncodeObservableState`, `DecodeObservableState`, `SnapshotDecode`, `SnapshotVerify`, `SnapshotSigningInput`, `SnapshotAssemble`, `SignSnapshot` |
| Fast-join (§5.2.1) | `FastJoinDecode`, `FastJoinEncode`, `CallerIsBelowFloor`, `FastJoinStateAddress`, `FastJoinAdopt`, `FastJoinAdoptAfter`, `FastJoinCheckProgress`, `FastJoinCheckCovers` |
| Reconciliation (§5.3) | `Fingerprint`, `Summarize`, `Reconcile` |
| Admission, namespaces, GC | `CheckAdmitted`, `CheckCounterEntry`, `CheckNsRef`, `ScopeToSubscription`, `StabilityCut` |

Not covered, deliberately: **transport** (§5.2's pull/push wire protocol is the host's job — no
sockets, no discovery), **persistence** (`Engine` is in-memory; supply your own store and replay or
fast-join on load), and **identity/admission policy** (`CheckAdmitted` evaluates an author list you
supply; it does not resolve `DeviceCert` chains — that is capability ①).

---

## The signer contract

**No entry point accepts a private key, and that is structural rather than advisory.**

The engine runs inside a WebAssembly module whose linear memory is an ordinary byte slice on the Go
heap: visible to anything that can read this process's memory, copied wholesale when the runtime
grows it, not `mlock`ed, and not reliably zeroable. Handing a raw Ed25519 seed across that boundary
would take a key that could have lived in an HSM and spread copies of it through a heap nothing is
defending.

So signing is **detached**, exactly as on the JS surface. The engine emits the RFC 9052
`Sig_structure`; your signer signs it wherever the key actually lives; the engine **verifies before
it will assemble an envelope**, so a wrong signature is caught here rather than on some other
replica's ingest path hours later.

```go
type Signer interface {
        Public() ed25519.PublicKey        // must match the op's author
        Sign(preimage []byte) ([]byte, error)  // raw 64-byte Ed25519 signature
}
```

The preimage is the exact bytes to sign — do not hash, prefix, or re-encode it. Three
implementations ship:

- **`CryptoSigner{Key: crypto.Signer}`** — the intended path for production keys. Any HSM, KMS, TPM
  or agent-backed `crypto.Signer` holding an Ed25519 key. The custodian keeps the key; this binding
  sees only signatures.
- **`SignerFunc{PublicKey, SignFunc}`** — for a custodian with no natural type.
- **`InMemorySigner{PrivateKey}`** — a legitimate choice where a native Go process holding a secret
  key is defensible, which is precisely the distinction that makes passing one *into* the module not
  defensible.

Whichever you choose, the key stays on the Go side. `TestNoEntryPointAcceptsKeyMaterial` asserts the
module's own dispatch table contains no entry point taking key material, so the property is checked
on every run rather than maintained by remembering to be careful — and it covers methods a future
change adds, because the Go API cannot offer a seed argument the module has no entry point for.

---

## Concurrency model

wazero module instances are **not** safe for concurrent use: a module's linear memory is shared
mutable state, and two goroutines allocating in it at once corrupt each other. Rather than leave
that as a caveat, this package answers for it:

| Type | Guarantee |
|---|---|
| `*Runtime` | **Safe for concurrent use.** Holds the compiled module. Compile once per process, share freely. |
| `*Instance` | **Correct but serialized.** Every call takes an internal mutex, so concurrent use is safe and simply queues — it is not parallel. Engines and clocks belong to the instance that created them. |
| `*Pool` | **How you get parallelism.** Each `Get` returns an instance no other goroutine holds; `Put` returns it for reuse. Safe for concurrent use. |

Instances share no state — separate linear memory, separate handle slabs, separate allocators — so
two of them cannot observe each other. That is what makes a `Pool` a legitimate way to parallelize
rather than a way to share replicas by accident.

State does not survive `Put`: close your engines before returning an instance to the pool. The pool
cannot know whether a handle is still wanted, so treat a pooled instance as scratch space for one
unit of work.

All of this is tested, under `-race`: `concurrency_test.go` covers concurrent instantiation from one
runtime, 12 goroutines × 40 iterations hammering a single shared `Instance`, instance isolation,
pooled parallelism converging on one state root, use-after-close, and — the one with teeth — the
**full 22-vector conformance run executed concurrently on four pooled instances**, each asserted
byte-identical to the native Rust trace.

---

## Cost

**Embedded artifact: 420,951 bytes (411 KiB), 162,426 bytes gzipped.** It lands in every binary that
imports this package; `dmtapsync.EngineWasmSize` exposes it so a product can check rather than trust.

| | |
|---|---|
| `New` (compile), no cache | 205–424 ms, **per process** |
| `New`, warm compilation cache | **~9 ms** (~24×) |
| `Instance` | ~90 µs |

Compiling is paid per process, not per sync. A daemon can ignore it — flowstock compiles once at
startup and amortizes it over the process lifetime. Anything invoked **on demand** should persist
compiled code:

```go
rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir("/var/cache/myapp/wasm"))
```

The directory is created on demand, keyed by module content and wazero version (so a rebuilt engine
misses rather than loading stale code), and always safe to delete — losing it degrades to a
recompile, never to a failure. Off by default: this package should not quietly start writing to disk
on behalf of a product that never asked.

Reproduce with `go test -bench 'Cold|Instance' ./bindings/go`.

---

## The proof

Three surfaces, one set of frozen bytes, zero divergence:

```
tests/native_trace.rs   native Rust — no wasm, no marshalling — records native-trace.json
test/vectors.test.mjs   the WASM binding, driven from JavaScript, diffed against it
vectors_test.go         the WASM binding, driven from Go through wazero, diffed against it
```

`trace_test.go` is a deliberate port of `crates/dmtap-sync-wasm/test/trace.mjs`, arm for arm, so all
three record the same observations under the same names. `vectors_test.go` asserts every traced
value against both the frozen vectors themselves and the native trace, byte for byte.

```sh
crates/dmtap-sync-wasm/build-abi.sh                    # the module
cargo test -p dmtap-sync-wasm --test native_trace      # native Rust, records the trace
node --test crates/dmtap-sync-wasm/test/               # the JS surface
go test ./bindings/go/...                              # this binding
```

**A failure here is never "the Go harness needs adjusting."** There is exactly one implementation of
the algebra for it to disagree with, so a divergence is a bug in the binding.

The suite refuses to skip itself when the sibling spec repo is not checked out — a proof that
quietly does not run is worse than no proof, because it reports success.

**Currently 22 of 24 vectors.** `SYNC-SNAP-03` and `SYNC-VAL-01` (corrections C-08/C-09) landed in
the spec repo on 2026-07-19 and are driven by **no surface yet**: C-09 redefines a `SnapshotBody` as
the minimal set of individually-signed ops whose fold equals the observable state, rather than
`det_cbor(ObservableState)`, and `dmtap-sync` has no such type and no fold. That is core substrate
work in Rust, not binding work. Both are listed in this harness's `notCovered` — guarded so an entry
is permitted **only while the native trace does not drive it either**, which means the moment the
native runner grows an executor, this binding goes red until it grows one too. Go cannot quietly
fall behind the other surfaces.

---

## Adopting it: replacing your own sync engine

For a product currently running a hand-rolled engine (flowstock's Go HLC+oplog, the OS's fabric
LWW/OR-set, whatsacc):

1. **Generate the artifact in your build.** Add `crates/dmtap-sync-wasm/build-abi.sh` to your build
   or CI step before `go build`. It is gitignored, so a fresh checkout does not compile without it —
   deliberately: a missing file is a build error you cannot ignore, a stale one is a bug you can
   ship.

2. **Create one `Runtime` at startup, not per operation.** This is the single biggest performance
   mistake available. If your process is short-lived, add `WithCompilationCacheDir`.

3. **Map your operations onto the six kinds** (`Instance.OpKinds()` — never hard-code the numbers).
   Most hand-rolled engines turn out to be an OR-Set and an LWW map, which is `SetAdd`/`SetRemove`
   and `LWWSet`.

4. **Move signing to a `Signer`.** If your keys are already in an HSM or agent, `CryptoSigner` wraps
   any `crypto.Signer`. If they are in process memory, `InMemorySigner` is honest about that. Either
   way you will not find a place to pass a seed, because there isn't one.

5. **Keep your own storage and transport.** The engine is in-memory and does no I/O by design. Your
   store persists ops (or snapshots); your transport does §5.2's pull/push. On load, replay your
   oplog through `IngestSigned` — or `FastJoinAdopt` from a snapshot, which is why that path exists.

6. **Branch on registry codes, not messages.** `IsRefusal(err, "0x0A02")`, not
   `strings.Contains(err.Error(), ...)`. Matching on prose is how a fail-closed engine eventually
   takes the wrong refusal path.

7. **Run your data through both engines before you cut over.** The vectors prove this binding
   matches the substrate; they cannot prove your old engine did. Expect real differences — that is
   the point of adopting a specified algebra, and each one is a convergence bug you had.

The migration is a swap of the *algebra*, not of your architecture: storage, transport, identity and
policy all stay yours.
