package dmtapsync

import _ "embed"

//go:generate ../../crates/dmtap-sync-wasm/build-abi.sh

// engineWasm is the sync engine: dmtap-sync and dmtap-core compiled to WebAssembly through the
// raw-ABI surface of crates/dmtap-sync-wasm (its src/abi.rs), with wasm-opt -Oz applied.
//
// # It is committed, and tied to its source by a test
//
// dmtap_sync_abi.wasm is checked in, so `go get` works and this module compiles from a plain proxy
// fetch. Rebuild it after changing the Rust with:
//
//	crates/dmtap-sync-wasm/build-abi.sh     # or: go generate ./bindings/go
//	go run ./bindings/go/internal/genprovenance
//
// Committing it was not the first choice. Gitignoring it was, on the reasoning that a missing file
// is a build error you cannot ignore while a stale one is a bug you can ship — and that reasoning
// came from a real incident: a committed module went stale against a fix in src/abi.rs, and every
// response whose Rust-side String capacity outran its length aborted the allocator on free. The
// drift was invisible because nothing in git ties a binary blob to the code that produced it.
//
// What overruled it is that a Go module has no build step. `go get` runs neither `go generate` nor
// build-abi.sh, so a gitignored artifact makes this package uncompilable for anyone consuming it
// the normal way. Both products that adopted the engine hit exactly that and vendored the file by
// hand — each re-accepting the same staleness risk, privately, with no shared guard.
//
// So the blob is tied to its source explicitly instead of implicitly. wasm_provenance.json records
// a digest over every Rust input; provenance_test.go recomputes it and fails when the source has
// moved. It hashes rather than rebuilds, so it needs no Rust toolchain, and it skips cleanly when
// the crates/ tree is absent (a standalone module fetch has nothing to check). Adopters no longer
// need to vendor, and the guard lives here once instead of in each of them.
//
// Do not substitute a module built any other way. The whole value of this binding is that these are
// the same bytes of algebra the native Rust runner and the browser binding execute, which
// vectors_test.go proves against the 22 frozen conformance vectors.
//
// The module imports nothing at all — no WASI, no host functions, no clock, no filesystem, no
// network. TestModuleImportsNothing asserts that, because it is a security property (the engine
// cannot reach anything it is not handed) as much as a portability one.
//
//go:embed dmtap_sync_abi.wasm
var engineWasm []byte

// EngineWasmSize is the size of the embedded module in bytes.
//
// Exposed because it is a real cost a Go consumer takes on — it lands in every binary that imports
// this package — and a number a product should be able to check rather than take on trust.
var EngineWasmSize = len(engineWasm)
