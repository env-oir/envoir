//! # dmtap-sync-wasm — the browser/JS binding for the shared sync engine
//!
//! A `wasm-bindgen` wrapper over [`dmtap_sync`], the reference implementation of DMTAP substrate
//! capability ③ (`dmtap/substrate/SYNC.md`). It exists so a JavaScript product can **replace its
//! hand-rolled CRDT engine with the same compiled algebra** every other surface runs, rather than
//! re-reading the spec in a fifth language and hoping its CBOR encoder agrees bit-for-bit.
//!
//! Per `substrate/BINDINGS.md` §2, **the binding lives here, not in the core**: `dmtap-sync` keeps
//! its `#![forbid(unsafe_code)]`, dependency-light posture, and this crate carries all the glue.
//!
//! ## The two rules this binding is built around
//!
//! **1. No private key ever crosses into WASM.** There is no "pass me your seed" entry point, and
//! adding one would be a security regression, not a convenience — see [`op_signing_input`] for the
//! full argument and the signing protocol that replaces it. Signing is *detached*: the binding
//! hands JS the exact RFC 9052 `Sig_structure` preimage, JS signs it with WebCrypto (or any key
//! custodian it likes, including a hardware token it cannot extract), and hands the signature back
//! to [`op_attach_signature`], which will not assemble an envelope whose signature does not verify.
//!
//! **2. Byte-identical or it is a bug.** Every output here is produced by `dmtap-sync` itself; this
//! crate marshals arguments and never re-implements a merge, a hash, or an encoding. The
//! `test/vectors.test.mjs` suite drives the frozen `sync_vectors.json` through *this* binding from
//! JS and diffs the results against a trace recorded from the native Rust runner — so the claim
//! "the browser computes what the server computes" is executable, not editorial
//! (`BINDINGS.md` §4).
//!
//! ## What this binding does NOT cover
//!
//! * **Transport.** No sockets, no HTTP, no peer discovery — §5.2's pull/push wire protocol is the
//!   host's job. This is the algebra and the envelope only.
//! * **Persistence.** [`SyncEngine`] is in-memory. A product supplies its own store and replays or
//!   fast-joins on load.
//! * **Identity and admission policy.** [`check_admitted`] evaluates an author list you supply; it
//!   does not resolve `DeviceCert` chains or namespace policy (§8/§9) — that is capability ①.
//! * **Snapshot minting from a raw key.** Rule 1 applies to snapshots too: see
//!   [`snapshot_signing_input`] / [`snapshot_assemble`].

#![deny(missing_docs)]

use dmtap_core::id::ContentId;
use dmtap_sync::detcbor::SVal;
use dmtap_sync::snapshot::{ObservableState, Snapshot};
use dmtap_sync::state::{SyncState, VersionVector};
use dmtap_sync::wire::{Hlc, SyncOp};
use dmtap_sync::{cose, FastJoin, OpEntry, ReconConfig, SyncError};
use serde_json::{json, Value};
#[cfg(feature = "js")]
use wasm_bindgen::prelude::*;

// The raw-ABI surface is mutually exclusive with the wasm-bindgen one: it unwraps the error
// carrier as a plain message, which only holds when `js` is off. Build it with
// `--no-default-features --features abi`.
#[cfg(all(feature = "abi", not(feature = "js")))]
mod abi;
#[cfg(all(target_arch = "wasm32", feature = "abi"))]
mod entropy;
pub mod err;
mod jsonval;

use err::{binding_err, BErr, IntoJs};
use jsonval::{addtag_to_json, hex, hlc_from_json, hlc_to_json, op_from_json, op_to_json,
    sval_from_json, sval_to_json, unhex};

/// The substrate version this binding speaks, and the crate it wraps.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn version() -> String {
    json!({
        "binding": env!("CARGO_PKG_VERSION"),
        "engine": "dmtap-sync",
        "substrate": "SYNC.md/v0",
        "suite": 1,
        "hlc_skew_ms": dmtap_sync::HLC_SKEW_MS,
    })
    .to_string()
}

// -------------------------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------------------------

fn parse(s: &str) -> Result<Value, BErr> {
    serde_json::from_str(s).map_err(|e| binding_err(format!("argument is not valid JSON: {e}")))
}

fn ops_from_json(v: &Value) -> Result<Vec<SyncOp>, BErr> {
    v.as_array()
        .ok_or_else(|| binding_err("expected a JSON array of ops"))?
        .iter()
        .map(|e| op_from_json(e).map_err(binding_err))
        .collect()
}

fn now(ms: f64) -> Result<u64, BErr> {
    if !ms.is_finite() || ms < 0.0 {
        return Err(binding_err("receiver_now_ms must be a non-negative finite number"));
    }
    Ok(ms as u64)
}

fn out(v: Value) -> String {
    v.to_string()
}

// -------------------------------------------------------------------------------------------
// values and ops
// -------------------------------------------------------------------------------------------

/// Encode a tagged JSON value (see the `jsonval` module docs) to deterministic CBOR (§18.1.1).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn encode_value(value_json: &str) -> Result<Vec<u8>, BErr> {
    Ok(sval_from_json(&parse(value_json)?).js()?.det_cbor())
}

/// Decode deterministic CBOR back to a tagged JSON value.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn decode_value(bytes: &[u8]) -> Result<String, BErr> {
    let v = dmtap_sync::detcbor::decode(bytes)
        .map_err(|e| binding_err(format!("not canonical CBOR: {e}")))?;
    Ok(out(sval_to_json(&v).js()?))
}

/// Whether a value is a legal §4.1 `cv` (the `ext-value` subset). A `SyncOp` carrying anything
/// else is refused at validation, so a product can check before it mints.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn is_ext_value(value_json: &str) -> Result<bool, BErr> {
    Ok(sval_from_json(&parse(value_json)?).js()?.is_ext_value())
}

/// Encode a `SyncOp` (JSON) to its canonical §4.1 deterministic-CBOR bytes.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn encode_op(op_json: &str) -> Result<Vec<u8>, BErr> {
    Ok(op_from_json(&parse(op_json)?).js()?.det_cbor())
}

/// Decode canonical `SyncOp` bytes to JSON. Non-canonical encodings are **refused**, never
/// silently re-canonicalized (§2.2).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn decode_op(bytes: &[u8]) -> Result<String, BErr> {
    let op = SyncOp::from_det_cbor(bytes).js()?;
    Ok(out(op_to_json(&op).js()?))
}

/// The §4.1 `op-id` content address of an encoded op (`0x1e ‖ BLAKE3-256(DS-tag ‖ 0x00 ‖ body)`).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn op_id(op_bytes: &[u8]) -> Vec<u8> {
    dmtap_sync::op_id_of(op_bytes).as_bytes().to_vec()
}

/// Run the state-free structural/causality/skew validators (§4) against an encoded op. Throws the
/// structured refusal on failure; this is the same check [`SyncEngine::ingest_signed`] performs.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn validate_op(op_bytes: &[u8], receiver_now_ms: f64) -> Result<(), BErr> {
    let op = SyncOp::from_det_cbor(op_bytes).js()?;
    dmtap_sync::validate_op(&op, now(receiver_now_ms)?).js()
}

// -------------------------------------------------------------------------------------------
// HLC
// -------------------------------------------------------------------------------------------

/// A Hybrid Logical Clock (§3) — the per-replica clock a product ticks to stamp its own ops and
/// advances when it observes a remote op.
///
/// The order is lexicographic by `(wall, counter, author)`, and because `author` is a public key
/// two distinct authors never tie, so the order is total across every replica.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub struct HlcClock {
    inner: Hlc,
}

#[cfg_attr(feature = "js", wasm_bindgen)]
impl HlcClock {
    /// A clock for `author` (a 32-byte Ed25519 public key), starting at zero.
    #[cfg_attr(feature = "js", wasm_bindgen(constructor))]
    pub fn new(author: &[u8]) -> HlcClock {
        HlcClock { inner: Hlc { wall: 0, counter: 0, author: author.to_vec() } }
    }

    /// Advance and return the next timestamp for a locally-minted op.
    pub fn tick(&mut self, now_ms: f64) -> Result<String, BErr> {
        Ok(out(hlc_to_json(&self.inner.tick(now(now_ms)?))))
    }

    /// Fold a remote timestamp in, so this clock never lags behind causality it has seen.
    pub fn observe(&mut self, hlc_json: &str) -> Result<(), BErr> {
        self.inner.observe(&hlc_from_json(&parse(hlc_json)?).js()?);
        Ok(())
    }

    /// The current timestamp without advancing.
    #[cfg_attr(feature = "js", wasm_bindgen(getter))]
    pub fn current(&self) -> String {
        out(hlc_to_json(&self.inner))
    }
}

/// The canonical CBOR encoding of an HLC — the bytes §2.2 tiebreaks and §6.1.1 sorts compare.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn encode_hlc(hlc_json: &str) -> Result<Vec<u8>, BErr> {
    Ok(hlc_from_json(&parse(hlc_json)?).js()?.det_cbor())
}

/// Compare two HLCs in the normative total order: `-1`, `0` or `1`.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn compare_hlc(a_json: &str, b_json: &str) -> Result<i32, BErr> {
    let a = hlc_from_json(&parse(a_json)?).js()?;
    let b = hlc_from_json(&parse(b_json)?).js()?;
    Ok(match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}

// -------------------------------------------------------------------------------------------
// COSE_Sign1 — detached signing, no private key crosses this boundary
// -------------------------------------------------------------------------------------------

/// The signing material for an op: everything a key custodian needs to produce the §4.1
/// `COSE_Sign1` signature, and nothing that would require it to surrender the key.
///
/// Returns `{author, protected, external_aad, sig_structure}` (all lowercase hex). **Sign
/// `sig_structure` with Ed25519 under the key named by `author`, then call
/// [`op_attach_signature`].** `author` is read out of `hlc.author`, so the key you sign with and
/// the key the op claims are the same by construction.
///
/// ## Why there is no `sign_op(seed)` here
///
/// It would be one line, and it would be wrong. WASM linear memory is an ordinary
/// `ArrayBuffer`: any script sharing the page — an analytics tag, a compromised dependency, a
/// devtools heap snapshot — can read every byte of it, and neither `mlock`, guard pages, nor
/// reliable zeroization exist in that address space. Handing a raw Ed25519 seed across this
/// boundary would therefore downgrade a `CryptoKey` the browser *guarantees* is non-extractable
/// into bytes sitting in a readable buffer for the lifetime of the tab. That is a real loss of a
/// real protection, bought for the price of one `crypto.subtle.sign` call.
///
/// The detached protocol costs one extra hop through JS and preserves the property that matters:
/// the signing key can live in WebCrypto with `extractable: false`, in a hardware token, or behind
/// a remote signing service, and this crate never learns it. Verification needs only public keys,
/// so the ingest path is unaffected.
///
/// The insecure path is not "discouraged" here — it is **absent**, because a documented-but-present
/// footgun is still a footgun. `dmtap_sync::cose::sign_op` remains available to native Rust
/// callers, who have a memory model in which holding a secret key is a defensible thing to do.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn op_signing_input(op_bytes: &[u8]) -> Result<String, BErr> {
    let op = SyncOp::from_det_cbor(op_bytes).js()?;
    let protected = cose::protected_header(&op.hlc.author);
    let aad = cose::op_external_aad();
    let payload = op.det_cbor();
    Ok(out(json!({
        "author": hex(&op.hlc.author),
        "protected": hex(&protected),
        "external_aad": hex(&aad),
        "sig_structure": hex(&cose::sig_structure(&protected, &aad, &payload)),
    })))
}

/// Assemble the wire `COSE_Sign1` from an op and a detached signature over
/// [`op_signing_input`]'s `sig_structure`.
///
/// The assembled envelope is **verified before it is returned**: a signature produced under the
/// wrong key, over the wrong preimage, or by a custodian that silently failed cannot leave this
/// function as a well-formed op. A binding that emitted unverifiable envelopes would just push the
/// failure onto some other replica's ingest path, hours later and with no context.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn op_attach_signature(op_bytes: &[u8], signature: &[u8]) -> Result<Vec<u8>, BErr> {
    let op = SyncOp::from_det_cbor(op_bytes).js()?;
    let envelope = cose::CoseSign1 {
        protected: cose::protected_header(&op.hlc.author),
        payload: op.det_cbor(),
        signature: signature.to_vec(),
    };
    cose::verify_op(&envelope).js()?;
    Ok(envelope.to_bytes())
}

/// Verify a `COSE_Sign1` op envelope and return the canonical op bytes it carries.
///
/// Fails closed (`0x0A02`) on a tampered payload, a substituted `kid`, a non-empty unprotected
/// header, a detached payload, or a signature minted under any other DS-tag.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn verify_signed_op(cose_bytes: &[u8]) -> Result<Vec<u8>, BErr> {
    Ok(cose::verify_op_bytes(cose_bytes).js()?.det_cbor())
}

/// The four wire parts of a `COSE_Sign1`, for inspection without trusting it:
/// `{protected, unprotected, payload, signature, alg, kid}`. Decoding and trusting are
/// deliberately separate steps — this does **not** verify.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn decode_signed_op(cose_bytes: &[u8]) -> Result<String, BErr> {
    let c = cose::CoseSign1::from_bytes(cose_bytes).js()?;
    let (alg, kid) = c.header().js()?;
    Ok(out(json!({
        "protected": hex(&c.protected),
        "unprotected": "a0",
        "payload": hex(&c.payload),
        "signature": hex(&c.signature),
        "alg": alg,
        "kid": hex(&kid),
    })))
}

// -------------------------------------------------------------------------------------------
// the engine
// -------------------------------------------------------------------------------------------

/// A replica's sync state: the six-kind CRDT algebra (§4.3–§4.8), the idempotent ingest path, the
/// §5.1 version vector, and the §6.1 observable-state projection.
///
/// In-memory only. Ops are deduplicated by `op-id`, so re-delivering one is a no-op, and every
/// merge is commutative/associative/idempotent — the arrival order of concurrent ops never changes
/// the outcome.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub struct SyncEngine {
    state: SyncState,
}

impl Default for SyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncEngine {
    /// A detached copy of this replica's state.
    ///
    /// Not exported to either surface — it exists because [`SyncEngine::merge`] takes two engines,
    /// and the raw-ABI surface reaches them through one handle slab it cannot borrow from twice at
    /// once — so it is `abi`-only, and gated rather than left to warn under the `js` build. Merging
    /// a copy is identical to merging the original by construction: the merge is state-based, so it
    /// reads the operand and never mutates it.
    #[cfg(feature = "abi")]
    pub(crate) fn snapshot_clone(&self) -> SyncEngine {
        SyncEngine { state: self.state.clone() }
    }
}

#[cfg_attr(feature = "js", wasm_bindgen)]
impl SyncEngine {
    /// An empty replica.
    #[cfg_attr(feature = "js", wasm_bindgen(constructor))]
    pub fn new() -> SyncEngine {
        SyncEngine { state: SyncState::new() }
    }

    /// **The network ingest path.** Verify a `COSE_Sign1` envelope, then validate and apply the op
    /// it carries. Returns `true` if the op was new, `false` if it was already held.
    ///
    /// Signature (`0x0A02`), structure/causality (`0x0A03`) and skew (`0x0A05`) are all checked
    /// **before** state is touched, so a refused op leaves the replica exactly as it was.
    pub fn ingest_signed(
        &mut self,
        cose_bytes: &[u8],
        receiver_now_ms: f64,
    ) -> Result<bool, BErr> {
        let op = cose::verify_op_bytes(cose_bytes).js()?;
        self.state.ingest(&op, now(receiver_now_ms)?).js()
    }

    /// Apply an op whose authenticity was **already established out of band** — the §5.6 profile,
    /// where ops ride unsigned inside an MLS group and authenticity is ambient group membership.
    ///
    /// The op is still fully validated (§4); only the signature check is skipped, because there is
    /// no signature to check. Use this **only** when the transport itself authenticates every
    /// writer. On a multi-author or untrusted path, [`SyncEngine::ingest_signed`] is the correct
    /// entry point and this one is a hole: it will accept any well-formed op claiming any author.
    pub fn ingest_ambient_authenticated(
        &mut self,
        op_bytes: &[u8],
        receiver_now_ms: f64,
    ) -> Result<bool, BErr> {
        let op = SyncOp::from_det_cbor(op_bytes).js()?;
        self.state.ingest(&op, now(receiver_now_ms)?).js()
    }

    /// Whether this replica already holds an op, by `op-id`.
    pub fn has_op(&self, op_id: &[u8]) -> bool {
        self.state.has_op(op_id)
    }

    /// Fold another replica's state in. State-based merge: idempotent and order-independent.
    pub fn merge(&mut self, other: &SyncEngine) {
        self.state.merge(&other.state);
    }

    // --- observable state ---

    /// The canonical six-section observable state (§6.1.1) as deterministic CBOR. **This is the
    /// artifact two replicas compare** — equal bytes mean equal observable state.
    pub fn observable_state(&self) -> Vec<u8> {
        ObservableState::of(&self.state).det_cbor()
    }

    /// The same projection as JSON, for a product that wants to render it rather than hash it.
    pub fn observable_state_json(&self) -> Result<String, BErr> {
        let o = ObservableState::of(&self.state);
        let orset = o
            .orset
            .iter()
            .map(|(t, v)| Ok(json!([t, sval_to_json(v)?])))
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        let lww = o
            .lww
            .iter()
            .map(|(t, f, v)| Ok(json!([t, f, sval_to_json(v)?])))
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        let rga = o
            .rga
            .iter()
            .map(|(t, atoms)| {
                Ok(json!([t, atoms.iter().map(sval_to_json).collect::<Result<Vec<_>, String>>()?]))
            })
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        Ok(out(json!({
            "orset": orset,
            "lww": lww,
            "pn": o.pn.iter().map(|(t, f, n)| json!([t, f, n.to_string()])).collect::<Vec<_>>(),
            "death": o.death.iter().map(|(t, c)| json!([t, c])).collect::<Vec<_>>(),
            "rga": rga,
            "tree": o.tree.iter().map(|(n, p, ord)| json!([n, p, ord])).collect::<Vec<_>>(),
        })))
    }

    /// The §6.1 observable-state root:
    /// `0x1e ‖ BLAKE3-256(DMTAP-SYNC-v0/snapshot-state ‖ 0x00 ‖ state)`.
    pub fn state_root(&self) -> Vec<u8> {
        dmtap_sync::state_root(&self.state).as_bytes().to_vec()
    }

    /// Recompute the root and compare it to a claimed one. A mismatch is `0x0A09` — evidence of
    /// divergence, whose §12 action is `HALT_ALERT`, not a retry.
    pub fn verify_root(&self, claimed: &[u8]) -> Result<(), BErr> {
        dmtap_sync::verify_root(&self.state, &ContentId(claimed.to_vec())).js()
    }

    /// The §5.1 version vector — the per-author max HLC this replica has applied.
    pub fn version_vector(&self) -> String {
        out(json!(self
            .state
            .vector
            .marks()
            .map(|(a, h)| json!({ "author": hex(a), "hlc": hlc_to_json(h) }))
            .collect::<Vec<_>>()))
    }

    /// The version vector's canonical CBOR (the `covers` member of a §6.1 snapshot).
    pub fn version_vector_cbor(&self) -> Vec<u8> {
        self.state.vector.to_sval().det_cbor()
    }

    // --- per-kind reads ---

    /// The winning LWW cell for `target`/`field`: `{hlc, value}`, or `null`.
    pub fn lww_cell(&self, target: &str, field: &str) -> Result<String, BErr> {
        Ok(match self.state.lww.cell(target, field) {
            Some((h, v)) => out(json!({ "hlc": hlc_to_json(h), "value": sval_to_json(v).js()? })),
            None => "null".into(),
        })
    }

    /// Whether an OR-Set element is present (add-wins, unless a death certificate dominates).
    pub fn set_contains(&self, target: &str, value_json: &str) -> Result<bool, BErr> {
        let v = sval_from_json(&parse(value_json)?).js()?;
        Ok(self.state.is_present(target, &v))
    }

    /// Every present `(target, element)` pair.
    pub fn set_members(&self) -> Result<String, BErr> {
        let members = self
            .state
            .present_members()
            .iter()
            .map(|(t, v)| Ok(json!([t, sval_to_json(v)?])))
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        Ok(out(json!(members)))
    }

    /// The add-tags of an element that no observed-remove has tombstoned — the causal evidence
    /// behind "present".
    pub fn set_surviving_tags(&self, target: &str, value_json: &str) -> Result<String, BErr> {
        let v = sval_from_json(&parse(value_json)?).js()?;
        Ok(out(json!(self
            .state
            .orset
            .surviving_tags(target, &v)
            .iter()
            .map(addtag_to_json)
            .collect::<Vec<_>>())))
    }

    /// A PN-counter's total, as a decimal string (the §4.6 sum is an `i128` and does not in
    /// general fit a JS number).
    pub fn counter_total(&self, target: &str, field: &str) -> String {
        self.state.counters.total(target, field).to_string()
    }

    /// The per-author `P`/`N` entries behind a counter — the union of op-id-keyed deltas (§4.6,
    /// correction C-01), which is what makes the merge associative.
    pub fn counter_entries(&self, target: &str, field: &str) -> String {
        out(json!(self
            .state
            .counters
            .entries(target, field)
            .iter()
            .map(|(author, (p, n))| json!({ "author": hex(author), "P": p, "N": n }))
            .collect::<Vec<_>>()))
    }

    /// The death dimension for an object: `{deleted, class}`.
    pub fn death_state(&self, object: &str) -> String {
        let s = self.state.deaths.state(object);
        out(json!({ "deleted": s.class().is_some(), "class": s.class().map(|c| c.token()) }))
    }

    /// An RGA sequence: `{values, atoms}`, where `atoms` carries every element id including
    /// tombstones (§4.7 keeps them until the §6.2 stability cut) and `values` is the visible
    /// sequence.
    pub fn sequence(&self, target: &str) -> Result<String, BErr> {
        let Some(seq) = self.state.sequences.get(target) else { return Ok("null".into()) };
        let atoms = seq
            .order()
            .iter()
            .map(|id| {
                Ok(json!({
                    "id": hlc_to_json(id),
                    "value": match seq.atom_value(id) {
                        Some(v) => sval_to_json(v)?,
                        None => Value::Null,
                    },
                    "tombstoned": seq.is_tombstoned(id),
                }))
            })
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        let values =
            seq.values().iter().map(sval_to_json).collect::<Result<Vec<_>, String>>().js()?;
        Ok(out(json!({ "values": values, "atoms": atoms })))
    }

    /// The movable tree after §4.8 cycle-safe replay: `{edges, applied, skipped}`. A move that
    /// would close a cycle is **skipped**, deterministically and identically on every replica —
    /// a skip is not an error.
    pub fn tree(&self) -> String {
        let r = self.state.tree.replay();
        out(json!({
            "edges": r.edges.iter().map(|(n, (p, o))| json!([n, p, o])).collect::<Vec<_>>(),
            "applied": r.applied.iter()
                .map(|(h, n)| json!({ "hlc": hlc_to_json(h), "node": n })).collect::<Vec<_>>(),
            "skipped": r.skipped.iter()
                .map(|(h, n)| json!({ "hlc": hlc_to_json(h), "node": n })).collect::<Vec<_>>(),
        }))
    }

    /// Reclaim collapsed add/tombstone pairs strictly below a §6.2 stability cut. Returns the
    /// number of entries dropped; **observable state is unchanged by construction** — GC below the
    /// cut can only remove causal evidence no replica can still cite.
    pub fn prune_below(&mut self, cut_hlc_json: &str) -> Result<usize, BErr> {
        let cut = hlc_from_json(&parse(cut_hlc_json)?).js()?;
        Ok(self.state.orset.prune_stable(&cut))
    }
}

// -------------------------------------------------------------------------------------------
// snapshots
// -------------------------------------------------------------------------------------------

/// The §6.1 root of an already-encoded observable state — for verifying a state body fetched by
/// address against a `Snapshot.root` before adopting it.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn observable_state_root(state_cbor: &[u8]) -> Vec<u8> {
    dmtap_sync::ds_hash(dmtap_sync::DS_SNAPSHOT_STATE, state_cbor).as_bytes().to_vec()
}

/// Encode a §6.1.1 observable state from its JSON projection (the shape
/// [`SyncEngine::observable_state_json`] emits) to canonical CBOR.
///
/// A replica adopting a fast-join checkpoint receives a **state body** rather than a history, so it
/// needs to move between the two representations without going through the op log: fetch the body,
/// re-encode it, hash it, and compare against `Snapshot.root` before trusting a byte of it.
/// Section entries are re-sorted canonically on the way out, so a body that arrives in any other
/// order still hashes to the same root — or, if it was tampered with, visibly does not.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn encode_observable_state(state_json: &str) -> Result<Vec<u8>, BErr> {
    Ok(observable_from_json(&parse(state_json)?).js()?.det_cbor())
}

/// Decode a canonical observable-state body to its JSON projection.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn decode_observable_state(bytes: &[u8]) -> Result<String, BErr> {
    let v = dmtap_sync::detcbor::decode(bytes)
        .map_err(|e| binding_err(format!("not canonical CBOR: {e}")))?;
    let sections = v.as_array().filter(|s| s.len() == 6).ok_or_else(|| {
        binding_err("an observable state is exactly six sections (§6.1.1) — never abbreviated")
    })?;
    let sec = |i: usize| sections[i].as_array().unwrap_or(&[]).to_vec();
    let tuples = |i: usize, arity: usize| -> Result<Vec<Vec<SVal>>, BErr> {
        sec(i)
            .iter()
            .map(|e| {
                e.as_array()
                    .filter(|t| t.len() == arity)
                    .map(<[SVal]>::to_vec)
                    .ok_or_else(|| binding_err("malformed observable-state entry"))
            })
            .collect()
    };
    let txt = |v: &SVal| v.as_text().unwrap_or_default().to_owned();
    let mut orset = Vec::new();
    for t in tuples(0, 2)? {
        orset.push(json!([txt(&t[0]), sval_to_json(&t[1]).js()?]));
    }
    let mut lww = Vec::new();
    for t in tuples(1, 3)? {
        lww.push(json!([txt(&t[0]), txt(&t[1]), sval_to_json(&t[2]).js()?]));
    }
    let mut pn = Vec::new();
    for t in tuples(2, 3)? {
        pn.push(json!([
            txt(&t[0]),
            txt(&t[1]),
            t[2].as_int().ok_or_else(|| binding_err("PN total is not an integer"))?.to_string()
        ]));
    }
    let mut death = Vec::new();
    for t in tuples(3, 2)? {
        death.push(json!([txt(&t[0]), txt(&t[1])]));
    }
    let mut rga = Vec::new();
    for t in tuples(4, 2)? {
        let atoms = t[1]
            .as_array()
            .ok_or_else(|| binding_err("RGA atoms is not an array"))?
            .iter()
            .map(sval_to_json)
            .collect::<Result<Vec<_>, String>>()
            .js()?;
        rga.push(json!([txt(&t[0]), atoms]));
    }
    let mut tree = Vec::new();
    for t in tuples(5, 3)? {
        tree.push(json!([txt(&t[0]), txt(&t[1]), txt(&t[2])]));
    }
    Ok(out(json!({
        "orset": orset, "lww": lww, "pn": pn, "death": death, "rga": rga, "tree": tree,
    })))
}

fn observable_from_json(v: &Value) -> Result<ObservableState, String> {
    let arr = |k: &str| -> Result<Vec<Value>, String> {
        Ok(v.get(k).and_then(Value::as_array).cloned().unwrap_or_default())
    };
    let txt = |e: &Value| -> Result<String, String> {
        e.as_str().map(str::to_owned).ok_or_else(|| "expected a string".to_owned())
    };
    let tup = |e: &Value, n: usize| -> Result<Vec<Value>, String> {
        e.as_array()
            .filter(|t| t.len() == n)
            .cloned()
            .ok_or_else(|| format!("expected a {n}-element entry"))
    };
    let mut st = ObservableState::default();
    for e in arr("orset")? {
        let t = tup(&e, 2)?;
        st.orset.push((txt(&t[0])?, sval_from_json(&t[1])?));
    }
    for e in arr("lww")? {
        let t = tup(&e, 3)?;
        st.lww.push((txt(&t[0])?, txt(&t[1])?, sval_from_json(&t[2])?));
    }
    for e in arr("pn")? {
        let t = tup(&e, 3)?;
        // Carried as a decimal STRING: the §4.6 total is an i128 and JS numbers are not.
        let total: i128 = match &t[2] {
            Value::String(s) => s.parse().map_err(|_| format!("PN total `{s}` is not an integer"))?,
            Value::Number(n) => n.as_i64().ok_or("PN total is not an integer")? as i128,
            _ => return Err("PN total must be a decimal string".into()),
        };
        st.pn.push((txt(&t[0])?, txt(&t[1])?, total));
    }
    for e in arr("death")? {
        let t = tup(&e, 2)?;
        st.death.push((txt(&t[0])?, txt(&t[1])?));
    }
    for e in arr("rga")? {
        let t = tup(&e, 2)?;
        let atoms = t[1]
            .as_array()
            .ok_or("RGA atoms is not an array")?
            .iter()
            .map(sval_from_json)
            .collect::<Result<Vec<_>, String>>()?;
        st.rga.push((txt(&t[0])?, atoms));
    }
    for e in arr("tree")? {
        let t = tup(&e, 3)?;
        st.tree.push((txt(&t[0])?, txt(&t[1])?, txt(&t[2])?));
    }
    Ok(st)
}

/// Decode a signed snapshot to JSON **without** trusting it. Call [`snapshot_verify`] before use.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn snapshot_decode(bytes: &[u8]) -> Result<String, BErr> {
    let s = Snapshot::from_det_cbor(bytes).js()?;
    Ok(out(snapshot_json(&s)))
}

fn snapshot_json(s: &Snapshot) -> Value {
    json!({
        "v": s.v,
        "suite": s.suite,
        "ns": s.ns,
        "covers": s.covers.marks()
            .map(|(a, h)| json!({ "author": hex(a), "hlc": hlc_to_json(h) })).collect::<Vec<_>>(),
        "root": hex(s.root.as_bytes()),
        "ts": s.ts,
        "signer": hex(&s.signer),
        "sig": hex(&s.sig),
    })
}

fn snapshot_from_json(v: &Value) -> Result<Snapshot, String> {
    let covers_entries = v.get("covers").and_then(Value::as_array).ok_or("missing `covers`")?;
    let mut covers = VersionVector::new();
    for e in covers_entries {
        covers.observe(&hlc_from_json(e.get("hlc").ok_or("covers entry without `hlc`")?)?);
    }
    let hexf = |k: &str| -> Result<Vec<u8>, String> {
        unhex(v.get(k).and_then(Value::as_str).ok_or(format!("missing `{k}`"))?)
    };
    Ok(Snapshot {
        v: u8::try_from(v.get("v").and_then(Value::as_u64).unwrap_or(0))
            .map_err(|_| "`v` exceeds u8")?,
        suite: u8::try_from(v.get("suite").and_then(Value::as_u64).unwrap_or(1))
            .map_err(|_| "`suite` exceeds u8")?,
        ns: v.get("ns").and_then(Value::as_str).unwrap_or_default().to_owned(),
        covers,
        root: ContentId(hexf("root")?),
        ts: v.get("ts").and_then(Value::as_u64).ok_or("missing `ts`")?,
        signer: hexf("signer")?,
        sig: match v.get("sig").and_then(Value::as_str) {
            Some(s) => unhex(s)?,
            None => Vec::new(),
        },
    })
}

/// Verify a snapshot's own signature under its declared `signer`. Fails closed (`0x0A02`).
///
/// This proves *who minted the checkpoint* — it does **not** prove the state is correct. A
/// fast-joining replica additionally hash-verifies the state body against `root` and decides
/// whether it trusts `signer` at all; §6.1's trust policy is the deployment's call, not this
/// crate's.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn snapshot_verify(bytes: &[u8]) -> Result<(), BErr> {
    Snapshot::from_det_cbor(bytes).js()?.verify_sig().js()
}

/// The detached signing preimage for a snapshot: `{preimage}` (hex), DS-tagged
/// `DMTAP-SYNC-v0/snapshot`. Same rule as ops — sign it externally, then [`snapshot_assemble`].
///
/// Takes the snapshot as JSON without `sig` (see [`snapshot_decode`] for the shape).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn snapshot_signing_input(snapshot_json_no_sig: &str) -> Result<String, BErr> {
    let s = snapshot_from_json(&parse(snapshot_json_no_sig)?).js()?;
    Ok(out(json!({ "preimage": hex(&s.signing_preimage()) })))
}

/// Assemble the signed snapshot wire bytes from its JSON and a detached signature. As with ops,
/// the signature is **verified before the bytes are returned**.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn snapshot_assemble(
    snapshot_json_no_sig: &str,
    signature: &[u8],
) -> Result<Vec<u8>, BErr> {
    let mut s = snapshot_from_json(&parse(snapshot_json_no_sig)?).js()?;
    s.sig = signature.to_vec();
    s.verify_sig().js()?;
    Ok(s.det_cbor())
}

// -------------------------------------------------------------------------------------------
// fast-join (§5.2.1)
// -------------------------------------------------------------------------------------------

/// Decode a `FastJoin` — the answer a `pull` returns to a caller below the responder's §6.2
/// truncation floor — **without** trusting it: `{snapshot, floor, state}`.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_decode(bytes: &[u8]) -> Result<String, BErr> {
    let fj = FastJoin::from_det_cbor(bytes).js()?;
    Ok(out(json!({
        "snapshot": snapshot_json(&fj.snapshot),
        "floor": hlc_to_json(&fj.floor),
        "state": fj.state.as_deref().map(hex),
    })))
}

/// Encode a `FastJoin` from `{snapshot, floor, state?}` (the shape [`fastjoin_decode`] emits).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_encode(fastjoin_json: &str) -> Result<Vec<u8>, BErr> {
    let v = parse(fastjoin_json)?;
    let state = match v.get("state").filter(|s| !s.is_null()) {
        Some(s) => Some(unhex(s.as_str().ok_or_else(|| binding_err("`state` is not hex"))?).js()?),
        None => None,
    };
    let fj = FastJoin {
        snapshot: snapshot_from_json(v.get("snapshot").ok_or_else(|| binding_err("missing `snapshot`"))?)
            .js()?,
        floor: hlc_from_json(v.get("floor").ok_or_else(|| binding_err("missing `floor`"))?).js()?,
        state,
    };
    Ok(fj.det_cbor())
}

/// **The §5.2.1 responder predicate**: is a caller holding `vector` below the floor this snapshot
/// stands in for — i.e. would the surviving suffix be an incomplete answer for it?
///
/// The test is domination of `covers`, not a comparison against the floor alone. A responder for
/// which this is true MUST answer fast-join; one for which it is false MUST answer with ops.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn caller_is_below_floor(snapshot_bytes: &[u8], vector_json: &str) -> Result<bool, BErr> {
    let snapshot = Snapshot::from_det_cbor(snapshot_bytes).js()?;
    Ok(dmtap_sync::caller_is_below_floor(&snapshot, &version_vector_from_json(&parse(vector_json)?).js()?))
}

/// The content address a fast-join's state body must be fetched from
/// (`GET /sync/state/<root>`) — what the host needs before it can call [`fastjoin_adopt`].
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_state_address(fastjoin_bytes: &[u8]) -> Result<Vec<u8>, BErr> {
    Ok(FastJoin::from_det_cbor(fastjoin_bytes).js()?.snapshot.root.as_bytes().to_vec())
}

/// The §5.2.1 caller-side sequence, steps 1–3: verify the snapshot, check it closes the gap, and
/// obtain and hash-verify the state body. Returns the **verified** observable-state bytes.
///
/// `fetched_body` is what the host retrieved from `GET /sync/state/<root>`, or `undefined` if it
/// could not retrieve anything. **The fetch itself is the host's job** — this binding does no I/O
/// (see the crate docs), and keeping the network out of it is also what keeps this call
/// synchronous. An inline `state` in the FastJoin is tried first and held to exactly the same hash
/// check, then discarded on mismatch: it is a cache hint, never a second source of truth.
///
/// Throws `0x0A02`/`0x0A01`/`0x0A0A` for an unverifiable or out-of-scope snapshot, `0x0A09` if it
/// does not close the caller's gap or the body does not hash to `root`, and `0x0A0C` if no body
/// could be obtained at all.
///
/// **On any failure the caller MUST keep its old vector and MUST NOT fall back to the responder's
/// surviving suffix.** That fallback is the silent lost-write this whole path exists to prevent,
/// which is why this function returns state rather than mutating an engine: adoption is a separate,
/// deliberate step the host takes only on success.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_adopt(
    fastjoin_bytes: &[u8],
    caller_vector_json: &str,
    subscribed_json: &str,
    admitted_hex_json: &str,
    fetched_body: Option<Vec<u8>>,
) -> Result<Vec<u8>, BErr> {
    let fj = FastJoin::from_det_cbor(fastjoin_bytes).js()?;
    let caller = version_vector_from_json(&parse(caller_vector_json)?).js()?;
    let subscribed: Vec<String> = parse(subscribed_json)?
        .as_array()
        .ok_or_else(|| binding_err("expected a JSON array of namespaces"))?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_owned())
        .collect();
    let admitted: Vec<Vec<u8>> = parse(admitted_hex_json)?
        .as_array()
        .ok_or_else(|| binding_err("expected a JSON array of hex signer keys"))?
        .iter()
        .map(|e| unhex(e.as_str().unwrap_or_default()).map_err(binding_err))
        .collect::<Result<_, _>>()?;
    let adopted = fj.adopt(&caller, &subscribed, &admitted, |_| fetched_body).js()?;
    Ok(adopted.det_cbor())
}

/// **The §5.2.1 step-5 progress MUST (§14 C-07).** A re-pull answered with another `fast-join`
/// carrying the *same* `Snapshot.root` **and** `covers` means the responder is looping — adopting
/// again cannot advance the caller. Throws `0x0A09`; returns nothing on progress.
///
/// Pass `previous_root`/`previous_covers_json` from the fast-join adopted on the preceding round of
/// the same join, or `undefined` on the first round. A host driving a pull loop MUST call this (or
/// [`fastjoin_adopt_after`]) rather than [`fastjoin_adopt`] alone: the loop it prevents is
/// unbounded, and nothing else in the protocol terminates it.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_check_progress(
    fastjoin_bytes: &[u8],
    previous_root: Option<Vec<u8>>,
    previous_covers_json: Option<String>,
) -> Result<(), BErr> {
    let fj = FastJoin::from_det_cbor(fastjoin_bytes).js()?;
    let prev = match (previous_root, previous_covers_json) {
        (Some(r), Some(c)) => {
            Some((ContentId(r), version_vector_from_json(&parse(&c)?).js()?))
        }
        _ => None,
    };
    fj.check_progress(prev.as_ref().map(|(r, c)| (r, c))).js()
}

/// [`fastjoin_adopt`] preceded by the [progress MUST](fastjoin_check_progress) — the call a real
/// pull loop should use.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_adopt_after(
    fastjoin_bytes: &[u8],
    previous_root: Option<Vec<u8>>,
    previous_covers_json: Option<String>,
    caller_vector_json: &str,
    subscribed_json: &str,
    admitted_hex_json: &str,
    fetched_body: Option<Vec<u8>>,
) -> Result<Vec<u8>, BErr> {
    fastjoin_check_progress(fastjoin_bytes, previous_root, previous_covers_json)?;
    fastjoin_adopt(
        fastjoin_bytes,
        caller_vector_json,
        subscribed_json,
        admitted_hex_json,
        fetched_body,
    )
}

/// **§5.2.1 step 2 in isolation** (§5.2.2): `covers` well-formed and non-empty (`0x0A03`), and the
/// caller genuinely below the floor (`0x0A09`). Throws the structured refusal; returns nothing when
/// the fast-join passes.
///
/// There is deliberately **no** floor-vs-`covers` comparison in here — see
/// [`fastjoin_naive_covers_lacks_floor_rejected`] for the predicate that was removed and why.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_check_covers(
    fastjoin_bytes: &[u8],
    caller_vector_json: &str,
) -> Result<(), BErr> {
    let fj = FastJoin::from_det_cbor(fastjoin_bytes).js()?;
    let caller = version_vector_from_json(&parse(caller_vector_json)?).js()?;
    dmtap_sync::check_covers_closes_gap(&fj.snapshot, &fj.floor, &caller).js()
}

/// **Advisory only (§5.2.2, MAY).** Does the fast-join's `covers` carry a mark for `floor.author`?
///
/// Exposed so a host can *log* the signal, and deliberately named so it cannot be mistaken for a
/// verdict. It is **not** a conformance test: an author whose only op sits *at* the floor is
/// retained rather than truncated, so `covers` need never name it. Treating `false` as a failure
/// rejects conformant peers — the defect §14 C-07 removed.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_covers_carries_floor_author_mark(fastjoin_bytes: &[u8]) -> Result<bool, BErr> {
    let fj = FastJoin::from_det_cbor(fastjoin_bytes).js()?;
    Ok(dmtap_sync::covers_carries_mark_for_floor_author(&fj.snapshot, &fj.floor))
}

/// The **rejected** naive predicate `covers.lacks(floor)`, exposed *only* so the cross-surface trace
/// can prove both surfaces agree it fires TRUE on a well-formed fast-join — and that neither acts
/// on it.
///
/// **Never gate adoption on this.** `floor` is a single `Hlc` and `covers` is a per-author
/// `VersionVector`; there is no ordering between them (§5.2.2). This is a counterexample witness,
/// not an API for deciding anything.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fastjoin_naive_covers_lacks_floor_rejected(fastjoin_bytes: &[u8]) -> Result<bool, BErr> {
    let fj = FastJoin::from_det_cbor(fastjoin_bytes).js()?;
    Ok(fj.snapshot.covers.lacks(&fj.floor))
}

fn version_vector_from_json(v: &Value) -> Result<VersionVector, String> {
    let mut vv = VersionVector::new();
    for e in v.as_array().ok_or("expected a JSON array of {author, hlc} marks")? {
        vv.observe(&hlc_from_json(e.get("hlc").ok_or("mark without `hlc`")?)?);
    }
    Ok(vv)
}

// -------------------------------------------------------------------------------------------
// reconciliation (§5.3)
// -------------------------------------------------------------------------------------------

fn entries_from_json(v: &Value) -> Result<Vec<OpEntry>, BErr> {
    v.as_array()
        .ok_or_else(|| binding_err("expected a JSON array of {hlc, id} entries"))?
        .iter()
        .map(|e| {
            let hlc = hlc_from_json(e.get("hlc").ok_or_else(|| binding_err("entry without `hlc`"))?)
                .map_err(binding_err)?;
            let id = e
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| binding_err("entry without `id`"))?;
            Ok(OpEntry { hlc, id: ContentId(unhex(id).map_err(binding_err)?) })
        })
        .collect()
}

/// The range-Merkle fingerprint of a set of `{hlc, id}` entries: `{fp, count}`.
///
/// `count` is carried alongside the hash on purpose — without it an empty range and a range whose
/// ops happen to fold to the same value would be indistinguishable (§5.3).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn fingerprint(entries_json: &str) -> Result<String, BErr> {
    let (fp, count) = dmtap_sync::fingerprint(&entries_from_json(&parse(entries_json)?)?);
    Ok(out(json!({ "fp": hex(fp.as_bytes()), "count": count })))
}

/// Fingerprint only the entries within `[lo, hi)`: `{lo, hi, fp, count}`.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn summarize(entries_json: &str, lo_json: &str, hi_json: &str) -> Result<String, BErr> {
    let entries = entries_from_json(&parse(entries_json)?)?;
    let lo = hlc_from_json(&parse(lo_json)?).js()?;
    let hi = hlc_from_json(&parse(hi_json)?).js()?;
    let r = dmtap_sync::summarize(&entries, &lo, &hi);
    Ok(out(json!({
        "lo": hlc_to_json(&r.lo),
        "hi": hlc_to_json(&r.hi),
        "fp": hex(r.fp.as_bytes()),
        "count": r.count,
    })))
}

/// Recursive range-Merkle diff between what this replica holds and what a peer holds:
/// `{missing_here, missing_there, ranges_compared}` (op-ids as hex).
///
/// Matching `(fp, count)` prunes a whole range with **nothing exchanged**, which is the entire
/// point: reconciliation cost tracks the size of the difference, not the size of the history.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn reconcile(
    here_json: &str,
    there_json: &str,
    lo_json: &str,
    hi_json: &str,
) -> Result<String, BErr> {
    let here = entries_from_json(&parse(here_json)?)?;
    let there = entries_from_json(&parse(there_json)?)?;
    let lo = hlc_from_json(&parse(lo_json)?).js()?;
    let hi = hlc_from_json(&parse(hi_json)?).js()?;
    let o = dmtap_sync::reconcile(&here, &there, &lo, &hi, ReconConfig::default());
    Ok(out(json!({
        "missing_here": o.missing_here.iter().map(|i| hex(i.as_bytes())).collect::<Vec<_>>(),
        "missing_there": o.missing_there.iter().map(|i| hex(i.as_bytes())).collect::<Vec<_>>(),
        "ranges_compared": o.ranges_compared,
    })))
}

// -------------------------------------------------------------------------------------------
// admission, namespaces, GC
// -------------------------------------------------------------------------------------------

/// Whether an author is in the admitted set (§8/§9). Throws `0x0A01` if not.
///
/// This is a **list membership check**, not a policy engine: resolving `DeviceCert` chains,
/// namespace policy objects and revocation is capability ① and lives outside this binding.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn check_admitted(author: &[u8], admitted_hex_json: &str) -> Result<(), BErr> {
    let list: Vec<Vec<u8>> = parse(admitted_hex_json)?
        .as_array()
        .ok_or_else(|| binding_err("expected a JSON array of hex author keys"))?
        .iter()
        .map(|e| unhex(e.as_str().unwrap_or_default()).map_err(binding_err))
        .collect::<Result<_, _>>()?;
    dmtap_sync::check_admitted(author, &list).js()
}

/// Whether a PN-counter op may touch an entry: an author may only mutate its **own** `P`/`N`
/// (§4.6). Throws `0x0A06` otherwise.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn check_counter_entry(op_author: &[u8], entry_author: &[u8]) -> Result<(), BErr> {
    dmtap_sync::check_counter_entry(op_author, entry_author).js()
}

/// Whether an op may reference a target: cross-namespace references are `0x0A0A` (§7).
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn check_ns_ref(op_ns: &str, referenced_target_ns: &str) -> Result<(), BErr> {
    dmtap_sync::check_ns_ref(op_ns, referenced_target_ns).js()
}

/// Filter ops down to a caller's subscribed namespaces (§7) — the responder-side sparse-sync
/// scope. Takes ops as JSON and returns their canonical bytes as hex, so nothing is re-encoded on
/// the way out.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn scope_to_subscription(ops_json: &str, subscribed_json: &str) -> Result<String, BErr> {
    let ops = ops_from_json(&parse(ops_json)?)?;
    let subs: Vec<String> = parse(subscribed_json)?
        .as_array()
        .ok_or_else(|| binding_err("expected a JSON array of namespace strings"))?
        .iter()
        .map(|e| e.as_str().unwrap_or_default().to_owned())
        .collect();
    Ok(out(json!(dmtap_sync::scope_to_subscription(&ops, &subs)
        .iter()
        .map(|op| hex(&op.det_cbor()))
        .collect::<Vec<_>>())))
}

/// The §6.2 stability cut: the minimum over **live** replicas' watermarks, below which history can
/// be truncated. Returns `null` when any live replica's watermark is unknown — an unknown
/// watermark must never be read as "caught up", so the fail-closed answer is "no cut yet".
///
/// Each element is either an HLC object or `null` for "watermark unknown". Excluding a stale
/// replica is the **caller's** liveness decision; including one drags the cut down forever.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn stability_cut(watermarks_json: &str) -> Result<String, BErr> {
    let marks: Vec<Option<Hlc>> = parse(watermarks_json)?
        .as_array()
        .ok_or_else(|| binding_err("expected a JSON array of HLCs or nulls"))?
        .iter()
        .map(|e| {
            if e.is_null() {
                Ok(None)
            } else {
                hlc_from_json(e).map(Some).map_err(binding_err)
            }
        })
        .collect::<Result<_, _>>()?;
    Ok(match dmtap_sync::stability_cut(&marks) {
        Some(h) => out(hlc_to_json(&h)),
        None => "null".into(),
    })
}

/// The `0x0A` error registry, for a product mapping refusals to its own UI:
/// `[{code, name, action}, …]`.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn error_registry() -> String {
    let all = [
        SyncError::AuthorUnauthorized,
        SyncError::OpSigInvalid,
        SyncError::OpInvalid,
        SyncError::UnsupportedVersion,
        SyncError::HlcSkew,
        SyncError::CounterForeign,
        SyncError::SeqOriginMissing,
        SyncError::FrameChainBroken,
        SyncError::SnapshotRootMismatch,
        SyncError::NsLeak,
        SyncError::AdmissionQuota,
    ];
    out(json!(all
        .iter()
        .map(|e| json!({ "code": e.code_hex(), "name": e.name(), "action": e.action_str() }))
        .collect::<Vec<_>>()))
}

/// The eight §4.2 op kinds by name, so a JS caller never hard-codes a magic number.
#[cfg_attr(feature = "js", wasm_bindgen)]
pub fn op_kinds() -> String {
    out(json!({
        "set_add": dmtap_sync::OP_SET_ADD,
        "set_remove": dmtap_sync::OP_SET_REMOVE,
        "lww_set": dmtap_sync::OP_LWW_SET,
        "death": dmtap_sync::OP_DEATH,
        "counter": dmtap_sync::OP_COUNTER,
        "seq_insert": dmtap_sync::OP_SEQ_INSERT,
        "seq_remove": dmtap_sync::OP_SEQ_REMOVE,
        "tree_move": dmtap_sync::OP_TREE_MOVE,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run on the NATIVE target and check the marshalling layer only. The algebra is
    // `dmtap-sync`'s own suite's job; the cross-surface byte equality is `test/vectors.test.mjs`'s.

    const OP_JSON: &str = r#"{"kind":3,"ns":"","target":"a","field":"x","value":{"tstr":"v"},
        "hlc":{"wall":1700000100000,"counter":0,
        "author":"ca57eed30e4a7274ef4c648f56f58f880b20d2ca25725d9e5c13c83c08c09aeb"}}"#;

    #[test]
    fn op_json_round_trips_through_canonical_cbor() {
        let bytes = encode_op(OP_JSON).expect("encode");
        assert_eq!(
            hex(&bytes),
            "a60103026003616104617805617606a3011b0000018bcfe6eea00200035820\
             ca57eed30e4a7274ef4c648f56f58f880b20d2ca25725d9e5c13c83c08c09aeb",
            "the binding must reproduce SYNC-OP-01's frozen bytes"
        );
        let back = decode_op(&bytes).expect("decode");
        assert_eq!(encode_op(&back).expect("re-encode"), bytes, "JSON round-trip changed bytes");
    }

    #[test]
    fn tagged_values_do_not_collapse_text_and_bytes() {
        let as_text = encode_value(r#"{"tstr":"ab"}"#).unwrap();
        let as_bytes = encode_value(r#"{"bstr":"6162"}"#).unwrap();
        assert_ne!(as_text, as_bytes, "a tstr and a bstr must never share an encoding");
    }

    #[test]
    fn negative_integers_survive_the_boundary() {
        let v = encode_value(r#"{"int":-3}"#).unwrap();
        assert_eq!(decode_value(&v).unwrap(), r#"{"int":-3}"#);
    }

    #[test]
    fn attach_signature_refuses_an_envelope_that_does_not_verify() {
        // Asserted at the `dmtap-sync` layer this function delegates to, because building a
        // `BErr` requires a JS host and cannot run on a native target. The wasm-side assertion
        // that `op_attach_signature` itself throws lives in `test/vectors.test.mjs`.
        let op = SyncOp::from_det_cbor(&encode_op(OP_JSON).unwrap()).unwrap();
        let envelope = cose::CoseSign1 {
            protected: cose::protected_header(&op.hlc.author),
            payload: op.det_cbor(),
            signature: vec![0u8; 64],
        };
        assert!(
            cose::verify_op(&envelope).is_err(),
            "a garbage signature must never assemble into a wire envelope"
        );
    }

    #[test]
    fn there_is_no_way_to_hand_this_crate_a_private_key() {
        // A guard against a future "convenience" regression: no EXPORTED signature may take a seed
        // or a secret key. If this fires, re-read `op_signing_input`'s rationale before deleting
        // it. Only exported signatures are scanned, so prose and test code do not trip it.
        //
        // Both surfaces are covered: an entry point is exported to JS by the `cfg_attr(…,
        // wasm_bindgen…)` marker, and to the Go binding by being dispatchable in `abi.rs` — which
        // can only reach functions declared here, so scanning this file covers that surface too.
        // `abi.rs` has its own, stricter guard over the dispatch table itself.
        let mut exported = false;
        for line in include_str!("lib.rs").lines() {
            let t = line.trim();
            if t.starts_with("#[cfg_attr(feature = \"js\", wasm_bindgen") {
                exported = true;
                continue;
            }
            if !t.starts_with("pub fn ") {
                continue;
            }
            if exported {
                for banned in ["seed", "secret", "private", "sk:"] {
                    assert!(
                        !t.contains(banned),
                        "an exported entry point taking key material was added: {t}"
                    );
                }
            }
            exported = false;
        }
    }
}
