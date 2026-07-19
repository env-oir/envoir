package dmtapsync

import _ "embed"

//go:generate ../../crates/dmtap-sync-wasm/build-abi.sh

// engineWasm is the sync engine: dmtap-sync and dmtap-core compiled to WebAssembly through the
// raw-ABI surface of crates/dmtap-sync-wasm (its src/abi.rs), with wasm-opt -Oz applied.
//
// # It is generated, not committed
//
// dmtap_sync_abi.wasm is build output and is gitignored. Produce it with:
//
//	crates/dmtap-sync-wasm/build-abi.sh     # or: go generate ./bindings/go
//
// which writes straight to this path. A fresh checkout therefore does not compile until that script
// has run once — deliberately. The alternative, checking the module into git, was tried and cost a
// real bug: the committed module went stale against a fix in src/abi.rs, and every response whose
// Rust-side String capacity outran its length aborted the module's allocator on free. Nothing in
// git ties a binary blob to the source that produced it, so the drift was invisible until it
// crashed. A missing file is a build error you cannot ignore; a stale one is a bug you can ship.
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
