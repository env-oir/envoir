package dmtapsync

// Internal tests for properties of the embedded module itself, which need the unexported bytes.

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero"
)

// TestModuleImportsNothing is a security property before it is a portability one.
//
// A module with zero imports cannot reach anything it is not handed: no WASI, no host functions,
// no clock, no filesystem, no network, no randomness. The engine can only read and write its own
// linear memory, so "the sync engine exfiltrated something" is not a threat that needs mitigating
// — it is a shape the module cannot express.
//
// It is also why instantiation costs ~90 µs and why the Go host needs no glue: there is nothing to
// supply. An import appearing here would mean a dependency started reaching for the host
// environment, which must be a deliberate, reviewed change rather than a transitive surprise.
func TestModuleImportsNothing(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	compiled, err := rt.CompileModule(ctx, engineWasm)
	if err != nil {
		t.Fatal(err)
	}
	if fns := compiled.ImportedFunctions(); len(fns) != 0 {
		for _, f := range fns {
			mod, name, _ := f.Import()
			t.Errorf("the engine imports the host function %s.%s", mod, name)
		}
	}
	if mems := compiled.ImportedMemories(); len(mems) != 0 {
		t.Errorf("the engine imports %d memories; it must own its own", len(mems))
	}
}

// TestModuleExportsExactlyTheABI pins the boundary. Anything exported is reachable from the host,
// so the set has to be a decision rather than whatever the linker happened to keep.
func TestModuleExportsExactlyTheABI(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	compiled, err := rt.CompileModule(ctx, engineWasm)
	if err != nil {
		t.Fatal(err)
	}

	// The protocol: reserve memory, release it, make a call, list the entry points.
	required := map[string]bool{
		"dmtap_alloc": true, "dmtap_free": true, "dmtap_call": true, "dmtap_entry_points": true,
	}

	// Not protocol, but not a leak either. getrandom's custom-backend contract is an exported
	// symbol it resolves at link time, and dmtap-core pulls three getrandom majors transitively
	// (ed25519-dalek, x-wing, ml-dsa) that will not link for wasm32 without one. Both of these
	// unconditionally return UNSUPPORTED — see crates/dmtap-sync-wasm/src/entropy.rs for why
	// refusing is the safe direction and fabricating bytes is not. A host calling them gets an
	// error, never a guessable key, so their reachability is harmless.
	allowed := map[string]bool{
		"__getrandom_custom": true, "__getrandom_v03_custom": true,
	}

	for name := range compiled.ExportedFunctions() {
		if !required[name] && !allowed[name] {
			t.Errorf("the engine exports an unreviewed function %q — every export is host-reachable "+
				"surface, so a new one must be a deliberate decision", name)
		}
		delete(required, name)
	}
	for name := range required {
		t.Errorf("the engine does not export %q", name)
	}
}

// TestArtifactSizeIsReported keeps the cost a Go consumer takes on visible.
//
// The bound is generous and one-sided on purpose. It is not a performance target — it is a tripwire
// for the artifact doubling because something large got linked in, which is the failure mode that
// otherwise goes unnoticed until a product complains about its binary.
func TestArtifactSizeIsReported(t *testing.T) {
	const ceiling = 700 << 10
	t.Logf("embedded engine: %d bytes (%.0f KiB)", EngineWasmSize, float64(EngineWasmSize)/1024)
	if EngineWasmSize > ceiling {
		t.Errorf("the embedded engine is %d bytes, over the %d-byte tripwire — something large was "+
			"linked in; check build-abi.sh still applies wasm-opt -Oz", EngineWasmSize, ceiling)
	}
	if EngineWasmSize < 100<<10 {
		t.Errorf("the embedded engine is only %d bytes — that is not a whole CRDT engine, so the "+
			"build probably produced a stub", EngineWasmSize)
	}
}
