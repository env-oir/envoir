// Package dmtapsync is the Go binding for the DMTAP Sync substrate (substrate/SYNC.md) — the
// shared sync engine, callable from Go without cgo.
//
// It embeds the same Rust core every other surface runs, compiled to WebAssembly, and executes it
// with [wazero], a WebAssembly runtime written in pure Go. There is no C toolchain, no shared
// library to ship alongside the binary, no CGO_ENABLED=1, and no sidecar process: a Go product
// importing this package still cross-compiles to a single static binary, which is exactly the
// constraint that made cgo the wrong answer here (see README.md, "Why wazero and not cgo").
//
// # The guarantee
//
// This binding does not re-implement the CRDT algebra, the canonical CBOR encoding, or the
// signature checks. It marshals arguments into the compiled core and marshals results back out.
// That is what makes byte-identical behavior a property of the toolchain rather than of three
// teams reading a spec carefully: vectors_test.go drives the 22 frozen conformance vectors through
// this binding and asserts the results are byte-identical to both the native Rust runner's trace
// and the JS/WASM binding's.
//
// # Getting started
//
//	rt, err := dmtapsync.New(ctx)      // compile once — this is the expensive step
//	defer rt.Close(ctx)
//
//	inst, err := rt.Instance(ctx)      // cheap; one instance per goroutine, or use a Pool
//	defer inst.Close(ctx)
//
//	eng, err := inst.NewEngine()
//	defer eng.Close()
//	_, err = eng.IngestSigned(coseBytes, receiverNowMs)
//	state := eng.ObservableState()
//
// # Concurrency
//
// See [Runtime], [Instance] and [Pool]. In short: a Runtime is safe for concurrent use, an
// Instance serializes calls internally, and a Pool is how you get real parallelism.
//
// # Keys
//
// No entry point accepts a private key, on purpose. Signing is detached: the core emits the
// RFC 9052 Sig_structure, your [Signer] signs it, and the core verifies before returning an
// envelope. See signer.go.
//
// [wazero]: https://wazero.io
package dmtapsync

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Runtime holds the compiled sync engine.
//
// Compiling the WebAssembly module is by far the most expensive step (tens of milliseconds;
// BenchmarkNew reports the current number). Instantiating from an already-compiled module is
// cheap (tens of microseconds), so the intended shape is one long-lived Runtime per process and as
// many [Instance] values as you need.
//
// A Runtime is safe for concurrent use by multiple goroutines.
type Runtime struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	cache    wazero.CompilationCache

	mu     sync.Mutex
	closed bool
	// Monotonic, so concurrently-instantiated modules never collide on a name.
	seq uint64
}

// Option configures a [Runtime]. See [WithCompilationCacheDir].
type Option func(*options)

type options struct {
	cacheDir string
}

// WithCompilationCacheDir persists compiled machine code under dir, so a process that starts,
// syncs and exits does not pay the compile again.
//
// # Which cost this removes, and which it does not
//
// New has two costs and they behave differently. Instantiating a Runtime from an already-compiled
// module is ~90 µs and never worth caching. Compiling the ~420 KiB module to native code is a few
// hundred milliseconds, once per process — invisible to a long-lived daemon, and the dominant cost
// for anything invoked on demand.
//
// With a cache directory the second and later processes reuse the first one's output. Measured on
// an M-series laptop across separate process launches, which is the case that matters — a
// benchmark loop recompiling inside one process reports worse and less meaningful numbers:
//
//	no cache      205-424 ms   every process, every time
//	cache, cold       195 ms   first process — the compile, plus writing it out
//	cache, warm         9 ms   every process after that (~24x)
//
// So: a daemon (flowstock, syncing on a timer) can ignore this entirely — it compiles once at
// startup and amortizes it over the process lifetime. A CLI or an on-demand path (the OS reaching
// for sync when a user acts) should pass a cache dir, because there it is a fifth of a second on
// the critical path of every single invocation.
//
// dir is created if it does not exist. wazero keys entries by module content and by its own
// version, so a rebuilt engine or an upgraded wazero misses the cache rather than loading stale
// code — the directory is a cache in the strict sense and is always safe to delete. Do not point
// two products at one directory unless they are happy to share a filesystem lock.
func WithCompilationCacheDir(dir string) Option {
	return func(o *options) { o.cacheDir = dir }
}

// New compiles the embedded sync engine.
//
// The module is instantiated with no host functions, no WASI, no filesystem, no clock and no
// network — it cannot reach anything outside its own linear memory, which is both a security
// property worth having and the reason instantiation is as cheap as it is.
//
// Compiling is the expensive step and is meant to happen once: hold the Runtime for the life of
// the process and take an [Instance] per unit of work. If your process is short-lived, see
// [WithCompilationCacheDir].
func New(ctx context.Context, opts ...Option) (*Runtime, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	// The interpreter is not chosen here: wazero picks its optimizing compiler on amd64/arm64 and
	// falls back to the interpreter elsewhere, which is the right default. NewRuntimeConfig()
	// keeps that choice.
	cfg := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)

	var cache wazero.CompilationCache
	if o.cacheDir != "" {
		var err error
		if cache, err = wazero.NewCompilationCacheWithDir(o.cacheDir); err != nil {
			return nil, fmt.Errorf("dmtapsync: opening the compilation cache in %s: %w", o.cacheDir, err)
		}
		cfg = cfg.WithCompilationCache(cache)
	}

	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	compiled, err := rt.CompileModule(ctx, engineWasm)
	if err != nil {
		_ = rt.Close(ctx)
		if cache != nil {
			_ = cache.Close(ctx)
		}
		return nil, fmt.Errorf("dmtapsync: compiling the embedded engine: %w", err)
	}
	return &Runtime{rt: rt, compiled: compiled, cache: cache}, nil
}

// Close releases the runtime and every instance created from it.
func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	err := r.rt.Close(ctx)
	// The cache is flushed after the runtime, so anything compiled during this process is on disk
	// for the next one. Its error is reported only if the runtime itself closed cleanly — a
	// failure to close the runtime is the more useful thing to surface.
	if r.cache != nil {
		if cerr := r.cache.Close(ctx); cerr != nil && err == nil {
			err = fmt.Errorf("dmtapsync: closing the compilation cache: %w", cerr)
		}
	}
	return err
}

// Instance creates an independent replica-side instance of the engine.
//
// Instances share no state: each has its own linear memory, its own engine and clock handles, and
// its own allocator. Two instances cannot observe each other, which is why a [Pool] of them is a
// valid way to parallelize and why one instance must not be shared without synchronization.
func (r *Runtime) Instance(ctx context.Context) (*Instance, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("dmtapsync: runtime is closed")
	}
	r.seq++
	name := fmt.Sprintf("dmtap-sync-%d", r.seq)
	r.mu.Unlock()

	cfg := wazero.NewModuleConfig().WithName(name).WithStartFunctions()
	mod, err := r.rt.InstantiateModule(ctx, r.compiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: instantiating the engine: %w", err)
	}
	in := &Instance{mod: mod}
	for _, f := range []struct {
		name string
		into *api.Function
	}{
		{"dmtap_alloc", &in.alloc},
		{"dmtap_free", &in.free},
		{"dmtap_call", &in.call},
		{"dmtap_entry_points", &in.entryPoints},
	} {
		fn := mod.ExportedFunction(f.name)
		if fn == nil {
			_ = mod.Close(ctx)
			return nil, fmt.Errorf("dmtapsync: the embedded module does not export %s", f.name)
		}
		*f.into = fn
	}
	in.mem = mod.Memory()
	if in.mem == nil {
		_ = mod.Close(ctx)
		return nil, fmt.Errorf("dmtapsync: the embedded module exports no memory")
	}
	return in, nil
}

// Instance is one instance of the sync engine: its own memory, its own engines and clocks.
//
// # Concurrency model
//
// A wazero module instance is not safe for concurrent use — its linear memory is shared mutable
// state, and two goroutines allocating in it at once corrupt each other. Rather than leave that as
// a caveat in a doc comment, an Instance serializes every call through an internal mutex, so
// concurrent use is *correct* but not *parallel*: calls queue.
//
// For parallelism, use a [Pool], which hands each caller its own instance. Engines and clocks
// belong to the instance that created them and must not be used with another.
type Instance struct {
	mod         api.Module
	mem         api.Memory
	alloc       api.Function
	free        api.Function
	call        api.Function
	entryPoints api.Function

	mu     sync.Mutex
	closed bool
}

// Close releases the instance and everything allocated inside it.
func (in *Instance) Close(ctx context.Context) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return nil
	}
	in.closed = true
	return in.mod.Close(ctx)
}

// request is the ABI's call envelope; see the Rust side's src/abi.rs for the protocol.
type request struct {
	Fn   string `json:"fn"`
	Args []any  `json:"a"`
}

// response is exactly one of Ok or Err. Err carries the same structured JSON message a JS caller
// reads off e.message, so both surfaces branch on the same registry code.
type response struct {
	Ok  json.RawMessage `json:"ok"`
	Err *string         `json:"err"`
}

// invoke performs one call into the module: marshal, copy in, call, copy out, free.
func (in *Instance) invoke(fn string, args ...any) (json.RawMessage, error) {
	if args == nil {
		args = []any{}
	}
	body, err := json.Marshal(request{Fn: fn, Args: args})
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: encoding the %s request: %w", fn, err)
	}

	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return nil, fmt.Errorf("dmtapsync: instance is closed")
	}
	ctx := context.Background()

	// Reserve module memory for the request and copy it in.
	res, err := in.alloc.Call(ctx, uint64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: allocating for %s: %w", fn, err)
	}
	reqPtr := uint32(res[0])
	if !in.mem.Write(reqPtr, body) {
		_, _ = in.free.Call(ctx, uint64(reqPtr), uint64(len(body)))
		return nil, fmt.Errorf("dmtapsync: request for %s does not fit in module memory", fn)
	}

	packed, err := in.call.Call(ctx, uint64(reqPtr), uint64(len(body)))
	// The request buffer is the module's to reuse either way.
	_, freeErr := in.free.Call(ctx, uint64(reqPtr), uint64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: calling %s: %w", fn, err)
	}
	if freeErr != nil {
		return nil, fmt.Errorf("dmtapsync: releasing the %s request: %w", fn, freeErr)
	}

	// The result packs (ptr << 32) | len.
	outPtr := uint32(packed[0] >> 32)
	outLen := uint32(packed[0])
	raw, ok := in.mem.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("dmtapsync: %s returned an out-of-range response", fn)
	}
	// Read returns a view into module memory; copy before freeing it.
	buf := make([]byte, len(raw))
	copy(buf, raw)
	if _, err := in.free.Call(ctx, uint64(outPtr), uint64(outLen)); err != nil {
		return nil, fmt.Errorf("dmtapsync: releasing the %s response: %w", fn, err)
	}

	var resp response
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("dmtapsync: decoding the %s response: %w", fn, err)
	}
	if resp.Err != nil {
		return nil, parseError(*resp.Err)
	}
	return resp.Ok, nil
}

// EntryPoints lists the names the embedded module can dispatch.
//
// Exposed so a test can assert this package and the module agree — a name added on one side
// without the other is then a test failure rather than a runtime surprise at a call site.
func (in *Instance) EntryPoints() ([]string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return nil, fmt.Errorf("dmtapsync: instance is closed")
	}
	ctx := context.Background()
	packed, err := in.entryPoints.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: listing entry points: %w", err)
	}
	ptr, length := uint32(packed[0]>>32), uint32(packed[0])
	raw, ok := in.mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("dmtapsync: entry-point list is out of range")
	}
	buf := make([]byte, len(raw))
	copy(buf, raw)
	if _, err := in.free.Call(ctx, uint64(ptr), uint64(length)); err != nil {
		return nil, fmt.Errorf("dmtapsync: releasing the entry-point list: %w", err)
	}
	var names []string
	if err := json.Unmarshal(buf, &names); err != nil {
		return nil, fmt.Errorf("dmtapsync: decoding the entry-point list: %w", err)
	}
	return names, nil
}

// Pool hands out instances to concurrent callers.
//
// An [Instance] serializes its calls, so N goroutines sharing one instance is correct but runs
// them one at a time. A Pool is the way to get parallelism: each Get returns an instance no other
// goroutine holds, and Put returns it for reuse. Instances are created lazily and never
// destroyed until [Pool.Close], because instantiation, while cheap, is not free.
//
// State does not survive Put: engines and clocks are per-instance, so a caller that opens an
// engine, uses it, and returns the instance to the pool must close that engine first. The pool
// does not police this — it cannot know whether a handle is still wanted — so treat a pooled
// instance as scratch space for one unit of work.
//
// A Pool is safe for concurrent use.
type Pool struct {
	rt *Runtime

	mu   sync.Mutex
	idle []*Instance
	all  []*Instance
}

// NewPool creates a pool drawing instances from rt.
func NewPool(rt *Runtime) *Pool { return &Pool{rt: rt} }

// Get returns an instance for this goroutine's exclusive use.
func (p *Pool) Get(ctx context.Context) (*Instance, error) {
	p.mu.Lock()
	if n := len(p.idle); n > 0 {
		in := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return in, nil
	}
	p.mu.Unlock()

	in, err := p.rt.Instance(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.all = append(p.all, in)
	p.mu.Unlock()
	return in, nil
}

// Put returns an instance to the pool.
func (p *Pool) Put(in *Instance) {
	if in == nil {
		return
	}
	p.mu.Lock()
	p.idle = append(p.idle, in)
	p.mu.Unlock()
}

// Close releases every instance the pool created.
func (p *Pool) Close(ctx context.Context) error {
	p.mu.Lock()
	all := p.all
	p.all, p.idle = nil, nil
	p.mu.Unlock()
	var firstErr error
	for _, in := range all {
		if err := in.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
