// The concurrency model, executed rather than described.
//
// wazero module instances are NOT safe for concurrent use — a module's linear memory is shared
// mutable state, and two goroutines allocating in it at once corrupt each other. That is a property
// of the runtime, so this binding has to answer for it explicitly rather than leave it as a caveat
// in a doc comment nobody reads at 2am. The answer has three parts, and each is tested here:
//
//	Runtime    safe for concurrent use. Compile once, share freely.
//	Instance   correct but serialized. Every call takes an internal mutex, so concurrent use is
//	           safe and simply queues. State (engines, clocks) belongs to the instance.
//	Pool       how you get actual parallelism: each Get hands out an instance nobody else holds.
//
// Run these with -race. Without it they exercise the paths but prove much less.
package dmtapsync_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	dmtapsync "github.com/vul-os/envoir/bindings/go"
)

// TestRuntimeIsSafeForConcurrentUse — many goroutines instantiating from one compiled module.
//
// This is the shape a server takes: one Runtime for the process, instances created per request.
func TestRuntimeIsSafeForConcurrentUse(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in, err := rt.Instance(ctx)
			if err != nil {
				errs <- err
				return
			}
			defer in.Close(ctx)
			if _, err := in.Version(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestInstanceSerializesConcurrentCalls is the one that matters most: sharing an Instance across
// goroutines must be CORRECT, because someone will do it whatever the documentation says.
//
// Every call goes through the instance's mutex, so the memory the wazero module owns is only ever
// touched by one goroutine at a time. Under -race, a missing lock shows up here as a data race
// rather than as corrupted state on a customer's replica months later.
func TestInstanceSerializesConcurrentCalls(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	in, err := rt.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close(ctx)

	// Allocation-heavy calls of differing sizes, so goroutines contend over the module's allocator
	// rather than over one cached buffer.
	const goroutines, iterations = 12, 40
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*iterations)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch (g + i) % 4 {
				case 0:
					if _, err := in.EntryPoints(); err != nil {
						errs <- err
					}
				case 1:
					if _, err := in.ErrorRegistry(); err != nil {
						errs <- err
					}
				case 2:
					// A refusal path, so error marshalling is contended too.
					if err := in.CheckNsRef("a", "b"); !dmtapsync.IsRefusal(err, "0x0A0A") {
						errs <- fmt.Errorf("want 0x0A0A, got %v", err)
					}
				case 3:
					b, err := in.EncodeValue(dmtapsync.Text(fmt.Sprintf("value-%d-%d", g, i)))
					if err != nil {
						errs <- err
						continue
					}
					back, err := in.DecodeValue(b)
					if err != nil {
						errs <- err
						continue
					}
					want := fmt.Sprintf(`{"tstr":"value-%d-%d"}`, g, i)
					if string(back) != want {
						errs <- fmt.Errorf("round-trip corrupted: got %s want %s", back, want)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestInstancesAreIsolated — two instances must not be able to observe each other.
//
// This is what makes a Pool a legitimate way to parallelize rather than a way to share state by
// accident. Handles are per-instance slab indices, so both engines below are handle 0; if the
// slabs were shared, the second engine would see the first one's op.
func TestInstancesAreIsolated(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	a, err := rt.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(ctx)
	b, err := rt.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)

	ea, err := a.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer ea.Close()
	eb, err := b.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer eb.Close()

	// Both engines start identical...
	rootA, err := ea.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := eb.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if hexs(rootA) != hexs(rootB) {
		t.Fatal("two empty engines have different roots")
	}

	// ...and applying an op to one must not move the other.
	op, err := a.EncodeOpJSON(`{"kind":3,"ns":"","target":"a","field":"x","value":{"tstr":"v"},` +
		`"hlc":{"wall":1700000100000,"counter":0,"author":"` + repeat32("11") + `"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ea.IngestAmbientAuthenticated(op, receiverNowMS); err != nil {
		t.Fatal(err)
	}

	movedA, err := ea.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	stillB, err := eb.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if hexs(movedA) == hexs(rootA) {
		t.Fatal("ingesting an op did not change the root")
	}
	if hexs(stillB) != hexs(rootB) {
		t.Fatal("state leaked between instances — a Pool would be sharing replicas by accident")
	}
}

// TestPoolGivesParallelismAndCorrectness — the intended way to use the binding under load.
//
// Each goroutine drives a full ingest through an instance it exclusively holds, and every one must
// arrive at the same state root: the algebra is deterministic, so any variation here is the pool
// handing the same instance to two callers.
func TestPoolGivesParallelismAndCorrectness(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	pool := dmtapsync.NewPool(rt)
	defer pool.Close(ctx)

	const goroutines = 16
	roots := make([]string, goroutines)
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			in, err := pool.Get(ctx)
			if err != nil {
				errs <- err
				return
			}
			// State does not survive Put, so the engine is closed before the instance goes back.
			defer pool.Put(in)

			eng, err := in.NewEngine()
			if err != nil {
				errs <- err
				return
			}
			defer eng.Close()

			op, err := in.EncodeOpJSON(`{"kind":3,"ns":"","target":"doc","field":"title",` +
				`"value":{"tstr":"shared"},"hlc":{"wall":1700000100000,"counter":0,"author":"` +
				repeat32("22") + `"}}`)
			if err != nil {
				errs <- err
				return
			}
			if _, err := eng.IngestAmbientAuthenticated(op, receiverNowMS); err != nil {
				errs <- err
				return
			}
			root, err := eng.StateRoot()
			if err != nil {
				errs <- err
				return
			}
			roots[g] = hexs(root)
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for g := 1; g < goroutines; g++ {
		if roots[g] != roots[0] {
			t.Fatalf("goroutine %d computed root %s, goroutine 0 computed %s — the pool handed one "+
				"instance to two callers", g, roots[g], roots[0])
		}
	}
}

// TestPoolReusesInstances — Get after Put must not compile or instantiate again, or the pool is
// costing more than it saves.
func TestPoolReusesInstances(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	pool := dmtapsync.NewPool(rt)
	defer pool.Close(ctx)

	first, err := pool.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pool.Put(first)
	second, err := pool.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("Put/Get did not reuse the instance")
	}
	pool.Put(second)
}

// TestClosedInstanceRefusesCalls — a use-after-close must be an error, never a call into freed
// memory.
func TestClosedInstanceRefusesCalls(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	in, err := rt.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Version(); err == nil {
		t.Error("a closed instance answered a call")
	}
	if _, err := in.EntryPoints(); err == nil {
		t.Error("a closed instance listed its entry points")
	}
	// Idempotent close, so a defer plus an explicit close is not a bug.
	if err := in.Close(ctx); err != nil {
		t.Errorf("closing twice must be a no-op: %v", err)
	}
}

// TestClosedRuntimeRefusesInstances — the same, one level up.
func TestClosedRuntimeRefusesInstances(t *testing.T) {
	ctx := context.Background()
	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Instance(ctx); err == nil {
		t.Error("a closed runtime handed out an instance")
	}
	if err := rt.Close(ctx); err != nil {
		t.Errorf("closing twice must be a no-op: %v", err)
	}
}

// TestConcurrentVectorRunsAgree is the load test with teeth: the full conformance run, in parallel,
// each on its own pooled instance. Byte-identical traces or the pool is not isolating.
func TestConcurrentVectorRunsAgree(t *testing.T) {
	f := load(t)
	ctx := context.Background()

	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)
	pool := dmtapsync.NewPool(rt)
	defer pool.Close(ctx)

	const goroutines = 4
	traces := make([]map[string]map[string]string, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			in, err := pool.Get(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer pool.Put(in)
			traces[g] = runVectors(in, f.file).trace
		}(g)
	}
	wg.Wait()

	for g := range traces {
		if d := diffTraces(traces[g], f.native); len(d) > 0 {
			t.Errorf("goroutine %d diverged from the native trace under concurrency:\n%s",
				g, joinLines(d))
		}
	}
}

func joinLines(s []string) string {
	out := ""
	for _, l := range s {
		out += l + "\n"
	}
	return out
}

func repeat32(pair string) string {
	out := ""
	for i := 0; i < 32; i++ {
		out += pair
	}
	return out
}
