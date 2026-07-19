//! # The raw-ABI surface — the module the Go binding embeds and runs under `wazero`
//!
//! `substrate/BINDINGS.md` §5 costs three ways to get the sync engine into a Go product: cgo, a
//! sidecar process, or a pure-Go WASM runtime. This module is the third one's other half. It
//! exposes the **same entry points `lib.rs` exports to JavaScript**, over a boundary a Go runtime
//! can actually speak, so `bindings/go` embeds one `.wasm` file and needs no C toolchain, no
//! `CGO_ENABLED=1`, and no second process to supervise.
//!
//! ## Why not just load the wasm-bindgen artifact
//!
//! It was the first thing tried, and it does not work — for a structural reason, not a missing
//! feature. `pkg-node/dmtap_sync_bg.wasm` imports three functions from its JS glue, and one of them
//! (`__wbg_Error_…`) **returns an `externref`**: a handle to a JavaScript object. wazero's host
//! function API is defined over `i32`/`i64`/`f32`/`f64` only, so a Go host cannot supply that import
//! at all — there is no Go value that is a JS `Error`. The same applies to
//! `__wbindgen_init_externref_table`, which initialises a table of JS references there is nothing on
//! the Go side to populate. wasm-bindgen's ABI assumes a JavaScript host by construction; that is
//! its job, and it does it well. It is simply not a portable C-style ABI, and treating it as one
//! would mean reverse-engineering an explicitly-internal calling convention (`retptr` stack
//! discipline, `__wbindgen_add_to_stack_pointer`, the externref table) that is free to change on any
//! wasm-bindgen bump — a silent-breakage risk on the exact byte-equality property this whole
//! binding exists to guarantee.
//!
//! So this surface is a boundary of our own, with **zero imports** (verified by a test in the Go
//! binding): the module is a pure function of its linear memory, which is also why instantiating it
//! is cheap and why it can be given to a runtime with no filesystem, clock, or network at all.
//!
//! ## The rule this preserves
//!
//! **It is a second boundary, never a second implementation.** Every arm of [`dispatch`] calls the
//! *same* function in `lib.rs` that the `#[wasm_bindgen]` export calls — same marshalling in
//! `jsonval`, same refusal text in `err`, same `dmtap-sync` algebra underneath. That is what makes
//! the three-surface vector parity in `bindings/go/vectors_test.go` a real proof rather than a
//! coincidence: there is exactly one implementation of the algebra for the three surfaces to
//! disagree with.
//!
//! ## The protocol
//!
//! Three exports, and no others:
//!
//! * `dmtap_alloc(len) -> ptr` — reserve `len` bytes of linear memory for the host to write into.
//! * `dmtap_free(ptr, len)` — release a buffer (a request the host wrote, or a response it has read).
//! * `dmtap_call(ptr, len) -> u64` — execute one call. The argument is a UTF-8 JSON request; the
//!   result packs the response buffer's address and length as `(ptr << 32) | len`.
//!
//! A request is `{"fn":"<name>","a":[<args>]}` and a response is exactly one of `{"ok":<value>}` or
//! `{"err":"<message>"}`, where the message is the same structured JSON string a JS caller reads off
//! `e.message` — `{"error":"sync","code":"0x0A02",…}` for a substrate refusal,
//! `{"error":"binding",…}` for a misuse of the binding. Byte strings are lowercase hex on both
//! sides; a `null` argument is the absent `Option`.
//!
//! Statefuls ([`crate::SyncEngine`], [`crate::HlcClock`]) are reached by integer handle out of a
//! per-instance slab, created by `engine.new`/`hlc.new` and released by `engine.close`/`hlc.close`.
//! The slab is module-instance state, which is precisely why a wazero module instance is
//! single-owner — the Go binding's concurrency model documents and enforces that.
//!
//! ## Key material
//!
//! The dispatch table below is subject to the same rule as the JS surface: **there is no entry point
//! that accepts a private key.** Signing is detached here exactly as it is there — `op_signing_input`
//! out, signature in, `op_attach_signature` verifies before returning. A test at the bottom of this
//! file asserts the table stays that way, so the Go binding inherits the property structurally
//! rather than by having been careful once.

use serde_json::{json, Value};
use std::cell::RefCell;

use crate::err::BErr;
use crate::{HlcClock, SyncEngine};

// -------------------------------------------------------------------------------------------
// memory
// -------------------------------------------------------------------------------------------

/// Reserve `len` bytes and hand the host their address.
///
/// The buffer is leaked on purpose: ownership passes to the host, which writes a request into it,
/// passes it to [`dmtap_call`], and releases it with [`dmtap_free`].
#[no_mangle]
pub extern "C" fn dmtap_alloc(len: u32) -> u32 {
    // A boxed slice, not a `Vec`: its capacity is exactly its length. `dmtap_free` reconstructs the
    // allocation as `(ptr, len, len)`, and `Vec::with_capacity` is free to over-allocate — feeding a
    // wrong capacity back to the allocator aborts the module. Exact-sizing here makes the round trip
    // correct by construction rather than by the host guessing the capacity.
    let buf = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(buf) as *mut u8 as u32
}

/// Release a buffer previously returned by [`dmtap_alloc`] or [`dmtap_call`].
///
/// # Safety
///
/// `ptr`/`len` must name a live buffer this module handed out and has not already reclaimed.
/// Getting that wrong corrupts the module's allocator — which is contained to the one instance, but
/// is still a bug. The Go binding pairs every allocation with a `defer`, so the pairing is a
/// property of that code rather than of its callers' discipline.
#[no_mangle]
pub unsafe extern "C" fn dmtap_free(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len as usize);
    drop(Box::from_raw(slice));
}

/// Execute one call. See the module docs for the request/response shape.
///
/// Returns `(ptr << 32) | len` addressing a JSON response the host must read and then [`dmtap_free`].
///
/// # Safety
///
/// `ptr`/`len` must name a readable buffer of `len` bytes inside this module's linear memory.
#[no_mangle]
pub unsafe extern "C" fn dmtap_call(ptr: u32, len: u32) -> u64 {
    let req = std::slice::from_raw_parts(ptr as *const u8, len as usize);
    handoff(respond(req))
}

/// Move a response into linear memory as an exact-sized allocation and pack its address and length
/// into the single `u64` a wasm export can return.
///
/// Exact-sized for the same reason as [`dmtap_alloc`]: `String`/`Vec` capacity is not its length,
/// and [`dmtap_free`] reconstructs the allocation from the length alone.
fn handoff(body: String) -> u64 {
    let out = body.into_bytes().into_boxed_slice();
    let (p, l) = (out.as_ptr() as u64, out.len() as u64);
    std::mem::forget(out);
    (p << 32) | l
}

/// The pure part of [`dmtap_call`]: request bytes in, response JSON out. Split out so it is
/// testable on a native target, where there is no linear memory to hand pointers into.
fn respond(req: &[u8]) -> String {
    let parsed: Result<Value, _> = serde_json::from_slice(req);
    let Ok(v) = parsed else {
        return err_response(&crate::err::binding_err_message("request is not valid JSON"));
    };
    let name = v.get("fn").and_then(Value::as_str).unwrap_or("");
    let empty = Vec::new();
    let args = v.get("a").and_then(Value::as_array).unwrap_or(&empty);
    match dispatch(name, args) {
        Ok(value) => json!({ "ok": value }).to_string(),
        Err(e) => err_response(&message_of(e)),
    }
}

fn err_response(message: &str) -> String {
    json!({ "err": message }).to_string()
}

/// Recover the message text from the carrier. Under `abi` the carrier *is* the text.
fn message_of(e: BErr) -> String {
    e.message().to_owned()
}

// -------------------------------------------------------------------------------------------
// handles
// -------------------------------------------------------------------------------------------

thread_local! {
    static ENGINES: RefCell<Vec<Option<SyncEngine>>> = const { RefCell::new(Vec::new()) };
    static CLOCKS: RefCell<Vec<Option<HlcClock>>> = const { RefCell::new(Vec::new()) };
}

/// Insert into the first free slot, so a long-lived instance that opens and closes many engines
/// does not grow the slab without bound.
fn insert<T>(slab: &RefCell<Vec<Option<T>>>, item: T) -> u32 {
    let mut s = slab.borrow_mut();
    match s.iter().position(Option::is_none) {
        Some(i) => {
            s[i] = Some(item);
            i as u32
        }
        None => {
            s.push(Some(item));
            (s.len() - 1) as u32
        }
    }
}

fn bad_handle(kind: &str) -> BErr {
    crate::err::binding_err(format!("no live {kind} for that handle"))
}

fn with_engine<R>(h: u32, f: impl FnOnce(&mut SyncEngine) -> R) -> Result<R, BErr> {
    ENGINES.with(|s| {
        let mut s = s.borrow_mut();
        match s.get_mut(h as usize).and_then(Option::as_mut) {
            Some(e) => Ok(f(e)),
            None => Err(bad_handle("engine")),
        }
    })
}

fn with_clock<R>(h: u32, f: impl FnOnce(&mut HlcClock) -> R) -> Result<R, BErr> {
    CLOCKS.with(|s| {
        let mut s = s.borrow_mut();
        match s.get_mut(h as usize).and_then(Option::as_mut) {
            Some(c) => Ok(f(c)),
            None => Err(bad_handle("clock")),
        }
    })
}

// -------------------------------------------------------------------------------------------
// argument readers
// -------------------------------------------------------------------------------------------

fn arg<'a>(args: &'a [Value], i: usize) -> Result<&'a Value, BErr> {
    args.get(i).ok_or_else(|| crate::err::binding_err(format!("missing argument {i}")))
}

fn s_arg(args: &[Value], i: usize) -> Result<String, BErr> {
    arg(args, i)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| crate::err::binding_err(format!("argument {i} is not a string")))
}

fn b_arg(args: &[Value], i: usize) -> Result<Vec<u8>, BErr> {
    crate::jsonval::unhex(&s_arg(args, i)?).map_err(crate::err::binding_err)
}

/// An `Option<Vec<u8>>` argument: hex, or `null` for absent.
fn ob_arg(args: &[Value], i: usize) -> Result<Option<Vec<u8>>, BErr> {
    match args.get(i) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => b_arg(args, i).map(Some),
    }
}

/// An `Option<String>` argument.
fn os_arg(args: &[Value], i: usize) -> Result<Option<String>, BErr> {
    match args.get(i) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => s_arg(args, i).map(Some),
    }
}

fn f_arg(args: &[Value], i: usize) -> Result<f64, BErr> {
    arg(args, i)?
        .as_f64()
        .ok_or_else(|| crate::err::binding_err(format!("argument {i} is not a number")))
}

fn h_arg(args: &[Value], i: usize) -> Result<u32, BErr> {
    let n = f_arg(args, i)?;
    if n < 0.0 || n.fract() != 0.0 {
        return Err(crate::err::binding_err(format!("argument {i} is not a handle")));
    }
    Ok(n as u32)
}

// --- result helpers ---

/// Byte results cross as hex, matching the argument spelling.
fn hexed(b: Vec<u8>) -> Value {
    Value::String(crate::jsonval::hex(&b))
}

/// String results are already JSON documents in most cases, but not all (`counter_total` is a
/// decimal, `lww_cell` may be the literal `null`). They cross as opaque strings and the Go side
/// parses them where it needs structure — the same thing the JS harness does with `JSON.parse`.
fn stringed(s: String) -> Value {
    Value::String(s)
}

// -------------------------------------------------------------------------------------------
// the table
// -------------------------------------------------------------------------------------------

/// Route one call to the `lib.rs` entry point of the same name.
///
/// Every arm is a straight delegation. If an arm ever grows logic of its own, that logic exists on
/// the Go surface and not the JS one, and the two have begun to diverge — put it in `lib.rs`
/// instead, where both surfaces get it.
fn dispatch(name: &str, a: &[Value]) -> Result<Value, BErr> {
    Ok(match name {
        // --- introspection ---
        "version" => stringed(crate::version()),
        "error_registry" => stringed(crate::error_registry()),
        "op_kinds" => stringed(crate::op_kinds()),

        // --- values and ops ---
        "encode_value" => hexed(crate::encode_value(&s_arg(a, 0)?)?),
        "decode_value" => stringed(crate::decode_value(&b_arg(a, 0)?)?),
        "is_ext_value" => Value::Bool(crate::is_ext_value(&s_arg(a, 0)?)?),
        "encode_op" => hexed(crate::encode_op(&s_arg(a, 0)?)?),
        "decode_op" => stringed(crate::decode_op(&b_arg(a, 0)?)?),
        "op_id" => hexed(crate::op_id(&b_arg(a, 0)?)),
        "validate_op" => {
            crate::validate_op(&b_arg(a, 0)?, f_arg(a, 1)?)?;
            Value::Null
        }

        // --- HLC ---
        "encode_hlc" => hexed(crate::encode_hlc(&s_arg(a, 0)?)?),
        "compare_hlc" => json!(crate::compare_hlc(&s_arg(a, 0)?, &s_arg(a, 1)?)?),
        "hlc.new" => {
            let author = b_arg(a, 0)?;
            json!(CLOCKS.with(|s| insert(s, HlcClock::new(&author))))
        }
        "hlc.close" => {
            let h = h_arg(a, 0)?;
            CLOCKS.with(|s| s.borrow_mut().get_mut(h as usize).map(Option::take));
            Value::Null
        }
        "hlc.tick" => {
            let ms = f_arg(a, 1)?;
            stringed(with_clock(h_arg(a, 0)?, |c| c.tick(ms))??)
        }
        "hlc.observe" => {
            let j = s_arg(a, 1)?;
            with_clock(h_arg(a, 0)?, |c| c.observe(&j))??;
            Value::Null
        }
        "hlc.current" => stringed(with_clock(h_arg(a, 0)?, |c| c.current())?),

        // --- COSE (detached signing; no key crosses this boundary) ---
        "op_signing_input" => stringed(crate::op_signing_input(&b_arg(a, 0)?)?),
        "op_attach_signature" => hexed(crate::op_attach_signature(&b_arg(a, 0)?, &b_arg(a, 1)?)?),
        "verify_signed_op" => hexed(crate::verify_signed_op(&b_arg(a, 0)?)?),
        "decode_signed_op" => stringed(crate::decode_signed_op(&b_arg(a, 0)?)?),

        // --- the engine ---
        "engine.new" => json!(ENGINES.with(|s| insert(s, SyncEngine::new()))),
        "engine.close" => {
            let h = h_arg(a, 0)?;
            ENGINES.with(|s| s.borrow_mut().get_mut(h as usize).map(Option::take));
            Value::Null
        }
        "engine.ingest_signed" => {
            let (b, ms) = (b_arg(a, 1)?, f_arg(a, 2)?);
            Value::Bool(with_engine(h_arg(a, 0)?, |e| e.ingest_signed(&b, ms))??)
        }
        "engine.ingest_ambient_authenticated" => {
            let (b, ms) = (b_arg(a, 1)?, f_arg(a, 2)?);
            Value::Bool(with_engine(h_arg(a, 0)?, |e| e.ingest_ambient_authenticated(&b, ms))??)
        }
        "engine.has_op" => {
            let id = b_arg(a, 1)?;
            Value::Bool(with_engine(h_arg(a, 0)?, |e| e.has_op(&id))?)
        }
        "engine.merge" => {
            // Cloned rather than borrowed twice: the slab is a single `RefCell`, and merge is
            // state-based, so folding in a copy is identical by construction.
            let src = h_arg(a, 1)?;
            let other = ENGINES
                .with(|s| {
                    s.borrow().get(src as usize).and_then(Option::as_ref).map(SyncEngine::snapshot_clone)
                })
                .ok_or_else(|| bad_handle("engine"))?;
            with_engine(h_arg(a, 0)?, |e| e.merge(&other))?;
            Value::Null
        }
        "engine.observable_state" => hexed(with_engine(h_arg(a, 0)?, |e| e.observable_state())?),
        "engine.observable_state_json" => {
            stringed(with_engine(h_arg(a, 0)?, |e| e.observable_state_json())??)
        }
        "engine.state_root" => hexed(with_engine(h_arg(a, 0)?, |e| e.state_root())?),
        "engine.verify_root" => {
            let c = b_arg(a, 1)?;
            with_engine(h_arg(a, 0)?, |e| e.verify_root(&c))??;
            Value::Null
        }
        "engine.version_vector" => stringed(with_engine(h_arg(a, 0)?, |e| e.version_vector())?),
        "engine.version_vector_cbor" => {
            hexed(with_engine(h_arg(a, 0)?, |e| e.version_vector_cbor())?)
        }
        "engine.lww_cell" => {
            let (t, f) = (s_arg(a, 1)?, s_arg(a, 2)?);
            stringed(with_engine(h_arg(a, 0)?, |e| e.lww_cell(&t, &f))??)
        }
        "engine.set_contains" => {
            let (t, v) = (s_arg(a, 1)?, s_arg(a, 2)?);
            Value::Bool(with_engine(h_arg(a, 0)?, |e| e.set_contains(&t, &v))??)
        }
        "engine.set_members" => stringed(with_engine(h_arg(a, 0)?, |e| e.set_members())??),
        "engine.set_surviving_tags" => {
            let (t, v) = (s_arg(a, 1)?, s_arg(a, 2)?);
            stringed(with_engine(h_arg(a, 0)?, |e| e.set_surviving_tags(&t, &v))??)
        }
        "engine.counter_total" => {
            let (t, f) = (s_arg(a, 1)?, s_arg(a, 2)?);
            stringed(with_engine(h_arg(a, 0)?, |e| e.counter_total(&t, &f))?)
        }
        "engine.counter_entries" => {
            let (t, f) = (s_arg(a, 1)?, s_arg(a, 2)?);
            stringed(with_engine(h_arg(a, 0)?, |e| e.counter_entries(&t, &f))?)
        }
        "engine.death_state" => {
            let o = s_arg(a, 1)?;
            stringed(with_engine(h_arg(a, 0)?, |e| e.death_state(&o))?)
        }
        "engine.sequence" => {
            let t = s_arg(a, 1)?;
            stringed(with_engine(h_arg(a, 0)?, |e| e.sequence(&t))??)
        }
        "engine.tree" => stringed(with_engine(h_arg(a, 0)?, |e| e.tree())?),
        "engine.prune_below" => {
            let c = s_arg(a, 1)?;
            json!(with_engine(h_arg(a, 0)?, |e| e.prune_below(&c))??)
        }

        // --- observable state and snapshots ---
        "observable_state_root" => hexed(crate::observable_state_root(&b_arg(a, 0)?)),
        "encode_observable_state" => hexed(crate::encode_observable_state(&s_arg(a, 0)?)?),
        "decode_observable_state" => stringed(crate::decode_observable_state(&b_arg(a, 0)?)?),
        "snapshot_decode" => stringed(crate::snapshot_decode(&b_arg(a, 0)?)?),
        "snapshot_verify" => {
            crate::snapshot_verify(&b_arg(a, 0)?)?;
            Value::Null
        }
        "snapshot_signing_input" => stringed(crate::snapshot_signing_input(&s_arg(a, 0)?)?),
        "snapshot_assemble" => hexed(crate::snapshot_assemble(&s_arg(a, 0)?, &b_arg(a, 1)?)?),

        // --- the §6.1.2 snapshot body (an op set, not a state document) ---
        "snapshot_body_decode" => stringed(crate::snapshot_body_decode(&b_arg(a, 0)?)?),
        "snapshot_body_encode" => hexed(crate::snapshot_body_encode(&s_arg(a, 0)?)?),
        "snapshot_body_fold" => {
            hexed(crate::snapshot_body_fold(&b_arg(a, 0)?, &s_arg(a, 1)?, f_arg(a, 2)?)?)
        }
        "snapshot_body_verify_root" => hexed(crate::snapshot_body_verify_root(
            &b_arg(a, 0)?,
            &b_arg(a, 1)?,
            &s_arg(a, 2)?,
            f_arg(a, 3)?,
        )?),

        // --- fast-join (§5.2.1) ---
        "fastjoin_decode" => stringed(crate::fastjoin_decode(&b_arg(a, 0)?)?),
        "fastjoin_encode" => hexed(crate::fastjoin_encode(&s_arg(a, 0)?)?),
        "caller_is_below_floor" => {
            Value::Bool(crate::caller_is_below_floor(&b_arg(a, 0)?, &s_arg(a, 1)?)?)
        }
        "fastjoin_state_address" => hexed(crate::fastjoin_state_address(&b_arg(a, 0)?)?),
        "fastjoin_adopt" => hexed(crate::fastjoin_adopt(
            &b_arg(a, 0)?,
            &s_arg(a, 1)?,
            &s_arg(a, 2)?,
            &s_arg(a, 3)?,
            f_arg(a, 4)?,
            ob_arg(a, 5)?,
        )?),
        "fastjoin_check_progress" => {
            crate::fastjoin_check_progress(&b_arg(a, 0)?, ob_arg(a, 1)?, os_arg(a, 2)?)?;
            Value::Null
        }
        "fastjoin_adopt_after" => hexed(crate::fastjoin_adopt_after(
            &b_arg(a, 0)?,
            ob_arg(a, 1)?,
            os_arg(a, 2)?,
            &s_arg(a, 3)?,
            &s_arg(a, 4)?,
            &s_arg(a, 5)?,
            f_arg(a, 6)?,
            ob_arg(a, 7)?,
        )?),
        "fastjoin_check_covers" => {
            crate::fastjoin_check_covers(&b_arg(a, 0)?, &s_arg(a, 1)?)?;
            Value::Null
        }
        "fastjoin_covers_carries_floor_author_mark" => {
            Value::Bool(crate::fastjoin_covers_carries_floor_author_mark(&b_arg(a, 0)?)?)
        }
        "fastjoin_naive_covers_lacks_floor_rejected" => {
            Value::Bool(crate::fastjoin_naive_covers_lacks_floor_rejected(&b_arg(a, 0)?)?)
        }

        // --- reconciliation (§5.3) ---
        "fingerprint" => stringed(crate::fingerprint(&s_arg(a, 0)?)?),
        "summarize" => stringed(crate::summarize(&s_arg(a, 0)?, &s_arg(a, 1)?, &s_arg(a, 2)?)?),
        "reconcile" => stringed(crate::reconcile(
            &s_arg(a, 0)?,
            &s_arg(a, 1)?,
            &s_arg(a, 2)?,
            &s_arg(a, 3)?,
        )?),

        // --- admission, namespaces, GC ---
        "check_admitted" => {
            crate::check_admitted(&b_arg(a, 0)?, &s_arg(a, 1)?)?;
            Value::Null
        }
        "check_counter_entry" => {
            crate::check_counter_entry(&b_arg(a, 0)?, &b_arg(a, 1)?)?;
            Value::Null
        }
        "check_ns_ref" => {
            crate::check_ns_ref(&s_arg(a, 0)?, &s_arg(a, 1)?)?;
            Value::Null
        }
        "scope_to_subscription" => {
            stringed(crate::scope_to_subscription(&s_arg(a, 0)?, &s_arg(a, 1)?)?)
        }
        "stability_cut" => stringed(crate::stability_cut(&s_arg(a, 0)?)?),

        other => {
            return Err(crate::err::binding_err(format!("no such entry point `{other}`")));
        }
    })
}

/// The dispatchable entry points, for the Go binding to assert against so a name added here
/// without a Go method (or vice versa) is caught at test time rather than at a call site.
#[no_mangle]
pub extern "C" fn dmtap_entry_points() -> u64 {
    handoff(json!(ENTRY_POINTS.to_vec()).to_string())
}

/// Kept beside [`dispatch`]; the test below asserts the two agree.
pub const ENTRY_POINTS: &[&str] = &[
    "version",
    "error_registry",
    "op_kinds",
    "encode_value",
    "decode_value",
    "is_ext_value",
    "encode_op",
    "decode_op",
    "op_id",
    "validate_op",
    "encode_hlc",
    "compare_hlc",
    "hlc.new",
    "hlc.close",
    "hlc.tick",
    "hlc.observe",
    "hlc.current",
    "op_signing_input",
    "op_attach_signature",
    "verify_signed_op",
    "decode_signed_op",
    "engine.new",
    "engine.close",
    "engine.ingest_signed",
    "engine.ingest_ambient_authenticated",
    "engine.has_op",
    "engine.merge",
    "engine.observable_state",
    "engine.observable_state_json",
    "engine.state_root",
    "engine.verify_root",
    "engine.version_vector",
    "engine.version_vector_cbor",
    "engine.lww_cell",
    "engine.set_contains",
    "engine.set_members",
    "engine.set_surviving_tags",
    "engine.counter_total",
    "engine.counter_entries",
    "engine.death_state",
    "engine.sequence",
    "engine.tree",
    "engine.prune_below",
    "observable_state_root",
    "encode_observable_state",
    "decode_observable_state",
    "snapshot_decode",
    "snapshot_verify",
    "snapshot_signing_input",
    "snapshot_assemble",
    "snapshot_body_decode",
    "snapshot_body_encode",
    "snapshot_body_fold",
    "snapshot_body_verify_root",
    "fastjoin_decode",
    "fastjoin_encode",
    "caller_is_below_floor",
    "fastjoin_state_address",
    "fastjoin_adopt",
    "fastjoin_check_progress",
    "fastjoin_adopt_after",
    "fastjoin_check_covers",
    "fastjoin_covers_carries_floor_author_mark",
    "fastjoin_naive_covers_lacks_floor_rejected",
    "fingerprint",
    "summarize",
    "reconcile",
    "check_admitted",
    "check_counter_entry",
    "check_ns_ref",
    "scope_to_subscription",
    "stability_cut",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn call(req: &str) -> Value {
        serde_json::from_str(&respond(req.as_bytes())).expect("response is JSON")
    }

    #[test]
    fn every_listed_entry_point_dispatches() {
        // A name in the list that `dispatch` does not know would otherwise only fail on the Go
        // side, at whichever call site happened to use it first.
        for name in ENTRY_POINTS {
            let r = dispatch(name, &[]);
            if let Err(e) = r {
                let m = message_of(e);
                assert!(
                    !m.contains("no such entry point"),
                    "`{name}` is listed but not dispatched"
                );
            }
        }
    }

    #[test]
    fn an_unknown_entry_point_is_a_binding_error_not_a_panic() {
        let v = call(r#"{"fn":"definitely_not_real","a":[]}"#);
        assert!(v["err"].as_str().unwrap().contains("no such entry point"));
    }

    #[test]
    fn a_substrate_refusal_crosses_with_its_registry_code() {
        // `check_ns_ref` across two namespaces is 0x0A0A — the Go side must be able to branch on
        // the code exactly as JS does, so the refusal has to survive the envelope intact.
        let v = call(r#"{"fn":"check_ns_ref","a":["a","b"]}"#);
        let m = v["err"].as_str().expect("a refusal");
        assert!(m.contains("0x0A0A"), "got {m}");
        assert!(m.contains(r#""error":"sync""#), "got {m}");
    }

    #[test]
    fn a_handle_round_trips_through_the_slab() {
        let h = call(r#"{"fn":"engine.new","a":[]}"#)["ok"].as_u64().expect("a handle");
        let root = call(&format!(r#"{{"fn":"engine.state_root","a":[{h}]}}"#))["ok"]
            .as_str()
            .expect("a root")
            .to_owned();
        assert_eq!(root.len(), 66, "0x1e-prefixed BLAKE3-256, hex");
        call(&format!(r#"{{"fn":"engine.close","a":[{h}]}}"#));
        let after = call(&format!(r#"{{"fn":"engine.state_root","a":[{h}]}}"#));
        assert!(
            after["err"].as_str().unwrap().contains("no live engine"),
            "a closed handle must not resolve"
        );
    }

    #[test]
    fn a_closed_slot_is_reused_rather_than_leaked() {
        let a = call(r#"{"fn":"engine.new","a":[]}"#)["ok"].as_u64().unwrap();
        call(&format!(r#"{{"fn":"engine.close","a":[{a}]}}"#));
        let b = call(r#"{"fn":"engine.new","a":[]}"#)["ok"].as_u64().unwrap();
        assert_eq!(a, b, "a long-lived instance must not grow the slab forever");
        call(&format!(r#"{{"fn":"engine.close","a":[{b}]}}"#));
    }

    #[test]
    fn there_is_no_dispatchable_entry_point_taking_key_material() {
        // The structural half of the no-raw-key rule, for the Go surface. `lib.rs` has the same
        // guard over its exports; this one covers the dispatch table, which is what the Go binding
        // can actually reach. Signing stays detached: preimage out, signature in.
        for name in ENTRY_POINTS {
            for banned in ["seed", "secret", "private", "_sk", "sign_op", "sign_snapshot"] {
                assert!(
                    !name.contains(banned),
                    "`{name}` looks like a raw-key entry point; signing is detached by design"
                );
            }
        }
    }

    #[test]
    fn a_malformed_request_does_not_panic() {
        // The message is carried as a JSON *string*, exactly as a JS caller reads it off
        // `e.message` — so it is escaped in the envelope and has to be parsed out, not
        // substring-matched. That nesting is deliberate: it keeps one refusal spelling for both
        // surfaces instead of a flat one here and a nested one there.
        let v: Value = serde_json::from_str(&respond(b"not json")).expect("still valid JSON");
        assert!(v["err"].as_str().unwrap().contains(r#""error":"binding""#));

        let v: Value = serde_json::from_str(&respond(b"{}")).expect("still valid JSON");
        assert!(v["err"].as_str().unwrap().contains("no such entry point"));
    }
}
