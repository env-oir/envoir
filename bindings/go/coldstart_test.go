package dmtapsync_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	dmtapsync "github.com/vul-os/envoir/bindings/go"
)

// The cost model this binding asks a product to reason about, measured rather than asserted.
//
//	go test -bench 'Cold|Instance' -benchtime 5x ./bindings/go
//
// The numbers in WithCompilationCacheDir's doc comment come from here. They are not asserted as
// thresholds: a benchmark that fails on a slow CI box teaches a team to ignore it, and the useful
// property is the ratio between these three, which is stable even when the absolute numbers are
// not.

// BenchmarkColdStart is a process's whole startup cost with no cache: compile the module.
func BenchmarkColdStart(b *testing.B) {
	ctx := context.Background()
	for b.Loop() {
		rt, err := dmtapsync.New(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := rt.Close(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkColdStartCached is the same startup for the second and later processes sharing a cache
// directory — the case an on-demand consumer actually pays.
func BenchmarkColdStartCached(b *testing.B) {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "dmtapsync-cache")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Warm it, exactly as a first process would, and leave that cost out of the measurement.
	rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir(dir))
	if err != nil {
		b.Fatal(err)
	}
	if err := rt.Close(ctx); err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir(dir))
		if err != nil {
			b.Fatal(err)
		}
		if err := rt.Close(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkInstance is the per-unit-of-work cost once a Runtime exists — the number that makes
// "compile once, instantiate freely" the right shape.
func BenchmarkInstance(b *testing.B) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close(ctx)

	for b.Loop() {
		in, err := rt.Instance(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := in.Close(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCompilationCacheIsUsedAndDisposable covers the two properties a caller depends on: a warm
// cache produces a working runtime (not merely a fast one), and the directory can be deleted at
// any time without breaking anything.
func TestCompilationCacheIsUsedAndDisposable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	for _, phase := range []string{"cold", "warm"} {
		rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir(dir))
		if err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
		in, err := rt.Instance(ctx)
		if err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
		// A real call, so this proves the cached code RUNS rather than merely loads.
		v, err := in.Version()
		if err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
		if v.Engine != "dmtap-sync" {
			t.Fatalf("%s: engine is %q", phase, v.Engine)
		}
		in.Close(ctx)
		rt.Close(ctx)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the cache directory is empty — nothing was persisted, so the warm path is a no-op")
	}

	// Deleting it mid-life must degrade to a recompile, never to a failure: this is a cache, and a
	// product that cannot survive losing it has a bug waiting for a full disk.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir(dir))
	if err != nil {
		t.Fatalf("a deleted cache directory must be recreated, not fatal: %v", err)
	}
	rt.Close(ctx)
}

// TestCompilationCacheDirIsCreated — the caller names a path, not a prepared directory.
func TestCompilationCacheDirIsCreated(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "does", "not", "exist", "yet")
	rt, err := dmtapsync.New(ctx, dmtapsync.WithCompilationCacheDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cache directory was not created: %v", err)
	}
}
