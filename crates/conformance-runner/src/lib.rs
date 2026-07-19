//! The conformance-runner engine.
//!
//! This is the reusable, data-driven core behind the `conformance-runner` binary (`src/main.rs`).
//! It is deliberately a *library* as well as a binary so both the CLI and `cargo test` (see
//! `tests/`) exercise exactly the same logic.
//!
//! ## What this proves
//!
//! `dmtap-core/vectors.json` carries byte-exact known-answer vectors for DMTAP's deterministic,
//! security-critical operations (canonical CBOR, content addressing, Ed25519 signing preimages,
//! key-names, safety numbers, suite fail-closed, Merkle roots). This crate:
//!
//! 1. **Re-derives every vector from the reference crate** and asserts it reproduces the
//!    committed `expected` value (so the vectors are proven correct against the reference, not
//!    hand-typed).
//! 2. For every `cbor_*` vector, **decodes the committed bytes, then re-encodes**, and asserts
//!    the result is byte-identical — the executable definition of "canonical" (§18.1.1): a
//!    decoder that accepts the bytes and re-emits anything else has a canonicalization bug.
//! 3. Optionally layers a **typed semantic check** (does the object's own `verify()`/content-id
//!    invariant hold?) for vector types this crate recognizes; unrecognized types still get the
//!    generic canonical round-trip (charter item 1: *data-driven, auto-covers new vectors*).
//! 4. Cross-references the sibling **conformance-suite catalog** (`../dmtap/conformance/{suite.json}`)
//!    when present: for a `vectored` case, the outcome is exactly the corresponding vector check
//!    above; for a `self-contained` case, the literal bytes are fed to the low-level canonical-CBOR
//!    decoder and the actual accept/reject outcome is compared to the catalog's `expect`;
//!    `construction-todo` cases are reported as skipped (no byte-exact fixture exists yet).
//!
//! Everything here is read-only with respect to `dmtap-core`: it only calls the crate's public
//! API (`dmtap_core::cbor`, `dmtap_core::mote`, `dmtap_core::identity`, …).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

mod construction;
pub use construction::recognized_ids as construction_recognized_ids;

/// Executor for the Sync-substrate vectors (`sync_vectors.json`, `substrate/SYNC.md` §10).
pub mod sync;

/// Sync-substrate vectors whose committed `expected` value **contradicts the specification text**
/// they claim to mechanize. These are reported as a named, explained discrepancy instead of being
/// silently allowed to fail (or, worse, "fixed" by bending the implementation to the vector): this
/// repo is not the writer of the `dmtap` spec repo, and `SYNC.md` §13 is explicit that where the
/// document and an implementation disagree, **the document governs**.
///
/// Each entry is `(vector name, why it cannot pass as written)`.
///
/// **Currently empty.** Its one entry — `sync_pn_counter_convergence` (SYNC-PN-01, whose "replay"
/// op carried a different HLC and was therefore a distinct op, not a replay) — was fixed upstream
/// (`SYNC.md` §14 C-02) and removed here. The vector set is 20/20. The symmetric assertion in
/// `tests/sync_vectors.rs` is what surfaced the fix: it fails when an allowlisted vector starts
/// passing, so the allowlist cannot rot.
pub const SYNC_KNOWN_DISCREPANCIES: &[(&str, &str)] = &[];

use dmtap_core::capability::{CapabilityRevocation, CapabilityToken};
use dmtap_core::cbor::{self, Cv};
use dmtap_core::deniable::{DeniableFrame, DeniablePayload, DeniablePrekeyBundle};
use dmtap_core::directory::DomainDirectory;
use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, DeviceCert, Identity};
use dmtap_core::kt::{
    identity_leaf_hash, ConsistencyProof, InclusionProof, SignedTreeHead,
};
use dmtap_core::mixnet::{MixDirectory, MixNodeDescriptor};
use dmtap_core::mote::{Envelope, Manifest, Payload};
use dmtap_core::pubobj::{
    check_anti_rollback, check_supersede, pub_manifest_root, sealed_style_root, verify_feed_chain,
    FeedEntry, PubAnnounce, PubError, PubManifest, RollbackDecision,
};
use dmtap_core::sphinx::{RoutingCommand, SphinxCell, SphinxFragmentHeader, Surb};
use dmtap_core::suite::Suite;

// ============================================================================================
// vectors.json data model (mirrors dmtap-core's committed format exactly)
// ============================================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct VectorFile {
    pub format: String,
    pub suite: String,
    pub generated_by: String,
    pub methodology: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Vector {
    pub name: String,
    pub operation: String,
    pub input: Value,
    pub expected: Value,
    #[serde(default)]
    pub note: String,
}

/// Load and parse `vectors.json` from a path.
pub fn load_vectors(path: &std::path::Path) -> Result<VectorFile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))
}

// ============================================================================================
// suite.json data model (the ../dmtap conformance-suite catalog; optional cross-reference)
// ============================================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SuiteFile {
    pub format: String,
    pub cases: Vec<SuiteCase>,
}

/// A `vector` field in `suite.json` is either a single vector name or a short list of names
/// (e.g. `DMTAP-NAME-05` compares two vectors).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum VectorRef {
    One(String),
    Many(Vec<String>),
}

impl VectorRef {
    pub fn names(&self) -> Vec<&str> {
        match self {
            VectorRef::One(s) => vec![s.as_str()],
            VectorRef::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SuiteCase {
    pub id: String,
    pub level: String,
    pub category: String,
    pub req: String,
    #[serde(default)]
    pub clause: Vec<String>,
    pub checks: String,
    pub operation: String,
    #[serde(default)]
    pub vector: Option<VectorRef>,
    #[serde(default)]
    pub input: Option<Value>,
    pub expect: Value,
    pub status: String,
}

pub fn load_suite(path: &std::path::Path) -> Result<SuiteFile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))
}

// ============================================================================================
// hex helpers (no external crate; the vector JSON already uses lowercase hex throughout)
// ============================================================================================

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn as_hex_str<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing/non-string field `{field}`"))
}

fn as_bool(v: &Value, field: &str) -> Result<bool, String> {
    v.get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing/non-bool field `{field}`"))
}

// ============================================================================================
// Per-vector verdict
// ============================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// Passed the mandatory checks but a bonus typed-semantic check wasn't available for this
    /// vector's type (not a failure — see module docs item 3).
    PassGeneric,
    Fail(String),
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass | Verdict::PassGeneric)
    }
}

/// Run every check this crate knows how to perform for one vector, dispatching on
/// `vector.operation`. This function is the single source of truth reused by the binary, the
/// suite.json cross-reference below, and `tests/`.
pub fn check_vector(v: &Vector) -> Verdict {
    match check_vector_inner(v) {
        Ok(verdict) => verdict,
        Err(e) => Verdict::Fail(e),
    }
}

fn check_vector_inner(v: &Vector) -> Result<Verdict, String> {
    // The Sync substrate (`substrate/SYNC.md`) has its own vector file and its own reference
    // crate (`dmtap-sync`); dispatch there first so every `sync_*` operation EXECUTES rather than
    // falling through to the generic canonical round-trip.
    if sync::handles(&v.operation) {
        return sync::check(v);
    }
    match v.operation.as_str() {
        "content_address" => {
            let bytes = unhex(as_hex_str(&v.input, "bytes_hex")?)?;
            let id = ContentId::of(&bytes);
            let want = as_hex_str(&v.expected, "id_hex")?;
            if hex(id.as_bytes()) == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("content_address mismatch: got {}, want {want}", hex(id.as_bytes())))
            }
        }
        "content_address_verify" => {
            let ct = unhex(as_hex_str(&v.input, "ciphertext_hex")?)?;
            let id = ContentId(unhex(as_hex_str(&v.input, "id_hex")?)?);
            let want = as_bool(&v.expected, "valid")?;
            let got = id.verify(&ct);
            if got == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("content_address_verify mismatch: got {got}, want {want}"))
            }
        }
        "keyname_encode" => {
            let pk = unhex(as_hex_str(&v.input, "pubkey_hex")?)?;
            let name = dmtap_core::keyname::encode(&pk);
            let want_name = as_hex_str(&v.expected, "name")?;
            let want_verifies = as_bool(&v.expected, "checksum_verifies")?;
            if name != want_name {
                return Err(format!("keyname mismatch: got {name}, want {want_name}"));
            }
            let verifies = dmtap_core::keyname::verify(&name);
            if verifies != want_verifies {
                return Err(format!(
                    "keyname checksum_verifies mismatch: got {verifies}, want {want_verifies}"
                ));
            }
            Ok(Verdict::Pass)
        }
        "keyname_verify" => {
            let name = v
                .input
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing input.name")?;
            let want = as_bool(&v.expected, "checksum_verifies")?;
            let got = dmtap_core::keyname::verify(name);
            if got == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("keyname_verify mismatch: got {got}, want {want}"))
            }
        }
        "safety_number" => {
            let a = unhex(as_hex_str(&v.input, "ik_a_hex")?)?;
            let b = unhex(as_hex_str(&v.input, "ik_b_hex")?)?;
            let want_num = as_hex_str(&v.expected, "safety_number")?;
            let want_hex = as_hex_str(&v.expected, "fingerprint_hex")?;
            let got_num = dmtap_core::safety::safety_number(&a, &b);
            let got_hex = dmtap_core::safety::safety_number_hex(&a, &b);
            if got_num != want_num {
                return Err(format!("safety_number mismatch: got {got_num}, want {want_num}"));
            }
            if got_hex != want_hex {
                return Err(format!("safety fingerprint_hex mismatch: got {got_hex}, want {want_hex}"));
            }
            Ok(Verdict::Pass)
        }
        "ed25519_sign" => {
            let seed_bytes = unhex(as_hex_str(&v.input, "seed_hex")?)?;
            let seed: [u8; 32] = seed_bytes
                .try_into()
                .map_err(|_| "seed_hex is not 32 bytes".to_string())?;
            let domain = unhex(as_hex_str(&v.input, "domain_hex")?)?;
            let msg = unhex(as_hex_str(&v.input, "msg_hex")?)?;
            let sk = dmtap_core::identity::IdentityKey::from_seed(&seed);
            let sig = sk.sign_domain(&domain, &msg);
            let want_pk = as_hex_str(&v.expected, "pubkey_hex")?;
            let want_sig = as_hex_str(&v.expected, "sig_hex")?;
            if hex(&sk.public_array()) != want_pk {
                return Err(format!("pubkey mismatch: got {}, want {want_pk}", hex(&sk.public_array())));
            }
            if hex(&sig) != want_sig {
                return Err(format!("sig mismatch: got {}, want {want_sig}", hex(&sig)));
            }
            Ok(Verdict::Pass)
        }
        "ed25519_verify" => {
            let pk = unhex(as_hex_str(&v.input, "pubkey_hex")?)?;
            let domain = unhex(as_hex_str(&v.input, "domain_hex")?)?;
            let msg = unhex(as_hex_str(&v.input, "msg_hex")?)?;
            let sig = unhex(as_hex_str(&v.input, "sig_hex")?)?;
            let want = as_bool(&v.expected, "valid")?;
            let got = verify_domain(&pk, &domain, &msg, &sig).is_ok();
            if got == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("ed25519_verify mismatch: got {got}, want {want}"))
            }
        }
        "suite_decode" => {
            let bytes = unhex(as_hex_str(&v.input, "cbor_hex")?)?;
            let want = as_bool(&v.expected, "accepted")?;
            let r: Result<Suite, _> = ciborium::from_reader(&bytes[..]);
            let got = r.is_ok();
            if got == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("suite_decode mismatch: got accepted={got}, want {want}"))
            }
        }
        "manifest_root" => {
            let chunks: Vec<ContentId> = v
                .input
                .get("chunk_hashes_hex")
                .and_then(Value::as_array)
                .ok_or("missing input.chunk_hashes_hex")?
                .iter()
                .map(|h| {
                    let s = h.as_str().ok_or("chunk hash entry is not a string")?;
                    Ok::<_, String>(ContentId(unhex(s)?))
                })
                .collect::<Result<_, _>>()?;
            let m = Manifest { id: ContentId(Vec::new()), size: 0, chunk_sz: 0, chunks, suite: Suite::Classical };
            let want = as_hex_str(&v.expected, "id_hex")?;
            let got = hex(m.merkle_root().as_bytes());
            if got == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("manifest_root mismatch: got {got}, want {want}"))
            }
        }
        "kt_leaf_hash" => {
            let name = v.input.get("name").and_then(Value::as_str).ok_or("missing input.name")?;
            let ik = unhex(as_hex_str(&v.input, "ik_hex")?)?;
            let version = v.input.get("version").and_then(Value::as_u64).ok_or("missing input.version")?;
            let id = ContentId(unhex(as_hex_str(&v.input, "identity_id_hex")?)?);
            let leaf = identity_leaf_hash(name, &ik, version, &id);
            let want = as_hex_str(&v.expected, "leaf_hash_hex")?;
            if hex(leaf.as_bytes()) == want {
                Ok(Verdict::Pass)
            } else {
                Err(format!("kt_leaf_hash mismatch: got {}, want {want}", hex(leaf.as_bytes())))
            }
        }
        "sphinx_encode" => check_sphinx_encode_vector(v),
        "cbor_encode" => check_cbor_encode_vector(v),
        // ── DMTAP-PUB (§22) operations ──────────────────────────────────────────────────────
        "pub_manifest_root" => check_pub_manifest_root(v),
        "pub_manifest_type_mismatch" => check_pub_manifest_type_mismatch(v),
        "det_cbor_decode_pub_manifest" => check_pub_reject(v, |b| PubManifest::from_det_cbor(b).map(|_| ())),
        "det_cbor_decode_feed_entry" => check_pub_reject(v, |b| FeedEntry::from_det_cbor(b).map(|_| ())),
        "pub_supersede_check" => check_pub_supersede(v),
        "pub_feed_entry_root" => check_pub_feed_entry_root(v),
        "pub_feed_anti_rollback" => check_pub_anti_rollback(v),
        other => Err(format!("conformance-runner does not know operation `{other}` (extend check_vector_inner)")),
    }
}

// ── DMTAP-PUB (§22) vector handlers ─────────────────────────────────────────────────────────

/// Parse an ordered list of full `hash` (prefix ‖ digest) content addresses from a hex-string array.
fn cids_from(v: &Value, field: &str) -> Result<Vec<ContentId>, String> {
    v.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing/non-array `{field}`"))?
        .iter()
        .map(|h| Ok(ContentId(unhex(h.as_str().ok_or("hash entry is not a string")?)?)))
        .collect()
}

/// If the vector's `expected` carries an `error_code` (e.g. `"0x0902"`), assert it equals the
/// PUB error the reference actually raised (§22.10). A vector without `error_code` skips the check.
fn assert_pub_code(expected: &Value, got: &PubError) -> Result<(), String> {
    if let Some(code_str) = expected.get("error_code").and_then(Value::as_str) {
        let want = u16::from_str_radix(code_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("bad error_code `{code_str}`: {e}"))?;
        if got.code() != want {
            return Err(format!(
                "PUB error code mismatch: reference raised {} (0x{:04x}), vector expects {code_str}",
                got.name(),
                got.code()
            ));
        }
    }
    Ok(())
}

/// §22.2.2 — `PubManifest.id` = DS-tagged Merkle root over ordered plaintext chunk hashes. Accepts
/// either `plaintext_chunks_hex` (recompute `h_i` first, cross-checking `expected.chunk_hashes_hex`)
/// or a direct `chunk_hashes_hex` input.
fn check_pub_manifest_root(v: &Vector) -> Result<Verdict, String> {
    let chunks: Vec<ContentId> = if let Some(pts) = v.input.get("plaintext_chunks_hex").and_then(Value::as_array) {
        let computed: Vec<ContentId> = pts
            .iter()
            .map(|p| Ok::<_, String>(dmtap_core::pubobj::chunk_hash(&unhex(p.as_str().ok_or("plaintext entry not str")?)?)))
            .collect::<Result<_, _>>()?;
        if let Some(want) = v.expected.get("chunk_hashes_hex").and_then(Value::as_array) {
            for (c, w) in computed.iter().zip(want) {
                let ws = w.as_str().unwrap_or("");
                if hex(c.as_bytes()) != ws {
                    return Err(format!("chunk hash mismatch: got {}, want {ws}", hex(c.as_bytes())));
                }
            }
        }
        computed
    } else {
        cids_from(&v.input, "chunk_hashes_hex")?
    };
    let root = pub_manifest_root(&chunks);
    let want = as_hex_str(&v.expected, "id_hex")?;
    if hex(root.as_bytes()) == want {
        Ok(Verdict::Pass)
    } else {
        Err(format!("pub_manifest_root mismatch: got {}, want {want}", hex(root.as_bytes())))
    }
}

/// §22.2.3 — the same ordered chunk-hash list rooted under the public DS-tagged tree vs the §18.9.5
/// bare sealed tree MUST yield different values (type-incompatibility, `0x0903`).
fn check_pub_manifest_type_mismatch(v: &Vector) -> Result<Verdict, String> {
    let chunks = cids_from(&v.input, "chunk_hashes_hex")?;
    let pub_root = pub_manifest_root(&chunks);
    let sealed = sealed_style_root(&chunks);
    let want_pub = as_hex_str(&v.expected, "public_root_hex")?;
    let want_sealed = as_hex_str(&v.expected, "sealed_style_root_hex")?;
    if hex(pub_root.as_bytes()) != want_pub {
        return Err(format!("public_root mismatch: got {}, want {want_pub}", hex(pub_root.as_bytes())));
    }
    if hex(sealed.as_bytes()) != want_sealed {
        return Err(format!("sealed_style_root mismatch: got {}, want {want_sealed}", hex(sealed.as_bytes())));
    }
    if pub_root == sealed {
        return Err("public and sealed roots collided — DS-tag type-incompatibility broken".into());
    }
    if !v.expected.get("roots_differ").and_then(Value::as_bool).unwrap_or(true) {
        return Err("vector claims roots_differ=false, but §22.2.3 requires they differ".into());
    }
    Ok(Verdict::Pass)
}

/// A `reject`-outcome decode vector: the reference decoder MUST fail (fail-closed), and — when the
/// vector names an `error_code` — with exactly that §22.10 code.
fn check_pub_reject(v: &Vector, decode: impl Fn(&[u8]) -> Result<(), PubError>) -> Result<Verdict, String> {
    let bytes = unhex(as_hex_str(&v.input, "cbor_hex")?)?;
    let outcome = v.expected.get("outcome").and_then(Value::as_str).unwrap_or("");
    match (outcome, decode(&bytes)) {
        ("reject", Ok(())) => Err("expected reject but the reference decoder ACCEPTED the bytes".into()),
        ("reject", Err(e)) => {
            assert_pub_code(&v.expected, &e)?;
            Ok(Verdict::Pass)
        }
        ("accept", Ok(())) => Ok(Verdict::Pass),
        ("accept", Err(e)) => Err(format!("expected accept but decoder rejected: {e}")),
        (other, _) => Err(format!("unknown expect.outcome `{other}`")),
    }
}

/// §22.3.4 / §22.3.3 step 5 — a publisher may only supersede its own announcements. Decodes the
/// successor announce, cross-checks its `pub`/`supersedes` against the vector's declared fields, and
/// applies [`check_supersede`].
fn check_pub_supersede(v: &Vector) -> Result<Verdict, String> {
    let pred_pub = unhex(as_hex_str(&v.input, "predecessor_pub_hex")?)?;
    let succ_pub_declared = unhex(as_hex_str(&v.input, "successor_pub_hex")?)?;
    let succ_bytes = unhex(as_hex_str(&v.input, "successor_cbor_hex")?)?;
    let succ = PubAnnounce::from_det_cbor(&succ_bytes).map_err(|e| format!("successor decode: {e}"))?;
    // The decoded announce's own fields MUST agree with what the vector declares.
    if succ.publisher != succ_pub_declared {
        return Err("decoded successor.pub disagrees with successor_pub_hex".into());
    }
    if let Some(sup_hex) = v.input.get("successor_supersedes_hex").and_then(Value::as_str) {
        match &succ.supersedes {
            Some(s) if hex(s.as_bytes()) == sup_hex => {}
            _ => return Err("decoded successor.supersedes disagrees with successor_supersedes_hex".into()),
        }
    }
    let outcome = v.expected.get("outcome").and_then(Value::as_str).unwrap_or("");
    match (outcome.starts_with("accept"), check_supersede(&pred_pub, &succ.publisher)) {
        (true, Ok(())) => Ok(Verdict::Pass),
        (false, Err(e)) => {
            assert_pub_code(&v.expected, &e)?;
            Ok(Verdict::Pass)
        }
        (true, Err(e)) => Err(format!("expected accept but supersede check rejected: {e}")),
        (false, Ok(())) => Err("expected reject but supersede check accepted a cross-author link".into()),
    }
}

/// §22.4.1 — decode an ordered feed slice, recompute each `entry_id`, cross-check against
/// `expected.entry_ids_hex`, and validate the `prev`-chain (`expected` note: `prev_chain_valid`).
fn check_pub_feed_entry_root(v: &Vector) -> Result<Verdict, String> {
    let entries: Vec<FeedEntry> = v
        .input
        .get("entries_cbor_hex")
        .and_then(Value::as_array)
        .ok_or("missing entries_cbor_hex")?
        .iter()
        .map(|h| {
            let bytes = unhex(h.as_str().ok_or("entry entry not str")?)?;
            FeedEntry::from_det_cbor(&bytes).map_err(|e| format!("feed entry decode: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let want_ids = v
        .expected
        .get("entry_ids_hex")
        .and_then(Value::as_array)
        .ok_or("missing expected.entry_ids_hex")?;
    if entries.len() != want_ids.len() {
        return Err(format!("entry count mismatch: got {}, want {}", entries.len(), want_ids.len()));
    }
    for (e, w) in entries.iter().zip(want_ids) {
        let got = hex(e.entry_id().as_bytes());
        let ws = w.as_str().unwrap_or("");
        if got != ws {
            return Err(format!("entry_id mismatch: got {got}, want {ws}"));
        }
    }
    verify_feed_chain(&entries).map_err(|e| format!("prev-chain invalid: {e}"))?;
    Ok(Verdict::Pass)
}

/// §22.4.2 — the anti-rollback / equivocation decision on a freshly-fetched `FeedHead`.
fn check_pub_anti_rollback(v: &Vector) -> Result<Verdict, String> {
    let last_seq = v.input.get("last_accepted_seq").and_then(Value::as_u64).ok_or("missing last_accepted_seq")?;
    let pres_seq = v.input.get("presented_seq").and_then(Value::as_u64).ok_or("missing presented_seq")?;
    let pres_tip = ContentId(unhex(as_hex_str(&v.input, "presented_tip_hex")?)?);
    let last_tip = v
        .input
        .get("last_accepted_tip_hex")
        .and_then(Value::as_str)
        .map(|s| unhex(s).map(ContentId))
        .transpose()?;
    let outcome = v.expected.get("outcome").and_then(Value::as_str).unwrap_or("");
    match (outcome.starts_with("accept"), check_anti_rollback(last_seq, last_tip.as_ref(), pres_seq, &pres_tip)) {
        (true, Ok(RollbackDecision::AcceptNew)) | (true, Ok(RollbackDecision::AcceptIdempotent)) => Ok(Verdict::Pass),
        (false, Err(e)) => {
            assert_pub_code(&v.expected, &e)?;
            Ok(Verdict::Pass)
        }
        (true, Err(e)) => Err(format!("expected accept but anti-rollback rejected: {e}")),
        (false, Ok(d)) => Err(format!("expected reject but anti-rollback accepted ({d:?})")),
    }
}

/// Reconstruct a Sphinx byte-layout object (§18.5.4) from a `sphinx_encode` vector, re-encode it,
/// and assert the fixed on-wire bytes match — plus a `from_bytes`→`to_bytes` round-trip.
fn check_sphinx_encode_vector(v: &Vector) -> Result<Verdict, String> {
    fn arr<const N: usize>(v: &Value, field: &str) -> Result<[u8; N], String> {
        unhex(as_hex_str(v, field)?)?.try_into().map_err(|_| format!("`{field}` is not {N} bytes"))
    }
    let ty = v.input.get("type").and_then(Value::as_str).ok_or("missing sphinx input.type")?;
    let want = as_hex_str(&v.expected, "bytes_hex")?;
    let got = match ty {
        "RoutingCommand" => {
            let rc = RoutingCommand {
                cmd: v.input.get("cmd").and_then(Value::as_u64).ok_or("cmd")? as u8,
                flags: v.input.get("flags").and_then(Value::as_u64).ok_or("flags")? as u8,
                delay_ms: v.input.get("delay_ms").and_then(Value::as_u64).ok_or("delay_ms")? as u32,
                next_hop: arr(&v.input, "next_hop_hex")?,
            };
            let bytes = rc.to_bytes();
            if RoutingCommand::from_bytes(&bytes).map_err(|e| e.to_string())? != rc {
                return Err("RoutingCommand from_bytes round-trip mismatch".into());
            }
            bytes.to_vec()
        }
        "Surb" => {
            let s = Surb {
                first_hop: arr(&v.input, "first_hop_hex")?,
                header: unhex(as_hex_str(&v.input, "header_hex")?)?,
                key_seed: arr(&v.input, "key_seed_hex")?,
            };
            let bytes = s.to_bytes();
            if Surb::from_bytes(&bytes).map_err(|e| e.to_string())? != s {
                return Err("Surb from_bytes round-trip mismatch".into());
            }
            bytes
        }
        "SphinxFragmentHeader" => {
            let h = SphinxFragmentHeader {
                msg_id: arr(&v.input, "msg_id_hex")?,
                frag_index: v.input.get("frag_index").and_then(Value::as_u64).ok_or("frag_index")? as u16,
                frag_count: v.input.get("frag_count").and_then(Value::as_u64).ok_or("frag_count")? as u16,
                total_len: v.input.get("total_len").and_then(Value::as_u64).ok_or("total_len")? as u32,
            };
            let bytes = h.to_bytes();
            if SphinxFragmentHeader::from_bytes(&bytes).map_err(|e| e.to_string())? != h {
                return Err("SphinxFragmentHeader from_bytes round-trip mismatch".into());
            }
            bytes.to_vec()
        }
        "SphinxCell" => {
            let c = SphinxCell {
                alpha: arr(&v.input, "alpha_hex")?,
                beta: unhex(as_hex_str(&v.input, "beta_hex")?)?,
                gamma: arr(&v.input, "gamma_hex")?,
                delta: unhex(as_hex_str(&v.input, "delta_hex")?)?,
            };
            let bytes = c.to_bytes();
            if SphinxCell::from_bytes(&bytes).map_err(|e| e.to_string())? != c {
                return Err("SphinxCell from_bytes round-trip mismatch".into());
            }
            bytes
        }
        other => return Err(format!("unknown sphinx type `{other}`")),
    };
    if hex(&got) == want {
        Ok(Verdict::Pass)
    } else {
        Err(format!("sphinx_encode mismatch: got {}, want {want}", hex(&got)))
    }
}

/// The `cbor_*` charter check (task item 1): decode the committed bytes with the **generic**
/// canonical-CBOR primitive (`dmtap_core::cbor::decode`/`encode`) and assert the re-encoding is
/// byte-identical. This alone is fully data-driven — it needs no knowledge of the concrete Rust
/// type and therefore auto-covers any future `cbor_*` vector. Where this crate additionally
/// recognizes the `input.type` tag, it layers a typed semantic check (object self-verifies,
/// content-id / Merkle-root invariants hold) as a stronger bonus proof.
fn check_cbor_encode_vector(v: &Vector) -> Result<Verdict, String> {
    let cbor_hex = as_hex_str(&v.expected, "cbor_hex")?;
    let bytes = unhex(cbor_hex)?;

    // --- 1. Generic, type-agnostic canonical round trip (mandatory) ------------------------
    let cv: Cv = cbor::decode(&bytes).map_err(|e| format!("cbor::decode failed: {e}"))?;
    let re = cbor::encode(&cv);
    if hex(&re) != cbor_hex {
        return Err(format!(
            "canonical round-trip failed (non-canonical bytes accepted): decode(bytes) re-encodes to {}, expected {cbor_hex}",
            hex(&re)
        ));
    }

    // --- 2. Typed semantic check (bonus, only for recognized `input.type`) ------------------
    let ty = v.input.get("type").and_then(Value::as_str);
    match ty {
        Some("Identity") => {
            let obj = Identity::from_det_cbor(&bytes).map_err(|e| format!("Identity::from_det_cbor: {e}"))?;
            obj.verify(None).map_err(|e| format!("Identity::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("DeviceCert") => {
            let obj = DeviceCert::from_det_cbor(&bytes).map_err(|e| format!("DeviceCert::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("DeviceCert::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("Payload") => {
            let obj = Payload::from_det_cbor(&bytes).map_err(|e| format!("Payload::from_det_cbor: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("Envelope") => {
            let obj = Envelope::from_det_cbor(&bytes).map_err(|e| format!("Envelope::from_det_cbor: {e}"))?;
            if !obj.id.verify(&obj.ciphertext) {
                return Err("Envelope.id does not match content address of ciphertext".into());
            }
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("MixNodeDescriptor") => {
            let obj = MixNodeDescriptor::from_det_cbor(&bytes).map_err(|e| format!("MixNodeDescriptor::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("MixNodeDescriptor::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("MixDirectory") => {
            let obj = MixDirectory::from_det_cbor(&bytes).map_err(|e| format!("MixDirectory::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("MixDirectory::verify: {e}"))?;
            for m in &obj.mixes {
                m.verify().map_err(|e| format!("enclosed MixNodeDescriptor::verify: {e}"))?;
            }
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("DomainDirectory") => {
            let obj = DomainDirectory::from_det_cbor(&bytes).map_err(|e| format!("DomainDirectory::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("DomainDirectory::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("DeniablePrekeyBundle") => {
            let obj = DeniablePrekeyBundle::from_det_cbor(&bytes).map_err(|e| format!("DeniablePrekeyBundle::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("DeniablePrekeyBundle::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("DeniableFrame") => {
            let obj = DeniableFrame::from_det_cbor(&bytes).map_err(|e| format!("DeniableFrame::from_det_cbor: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("DeniablePayload") => {
            let obj = DeniablePayload::from_det_cbor(&bytes).map_err(|e| format!("DeniablePayload::from_det_cbor: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("Manifest") => {
            let obj = Manifest::from_det_cbor(&bytes).map_err(|e| format!("Manifest::from_det_cbor: {e}"))?;
            if obj.id != obj.merkle_root() {
                return Err("Manifest.id does not equal its own Merkle root".into());
            }
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("SignedTreeHead") => {
            let obj = SignedTreeHead::from_det_cbor(&bytes).map_err(|e| format!("SignedTreeHead::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("SignedTreeHead::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("InclusionProof") => {
            let obj = InclusionProof::from_det_cbor(&bytes).map_err(|e| format!("InclusionProof::from_det_cbor: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("ConsistencyProof") => {
            let obj = ConsistencyProof::from_det_cbor(&bytes).map_err(|e| format!("ConsistencyProof::from_det_cbor: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("CapabilityToken") => {
            let obj = CapabilityToken::from_det_cbor(&bytes).map_err(|e| format!("CapabilityToken::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("CapabilityToken::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some("CapabilityRevocation") => {
            let obj = CapabilityRevocation::from_det_cbor(&bytes).map_err(|e| format!("CapabilityRevocation::from_det_cbor: {e}"))?;
            obj.verify().map_err(|e| format!("CapabilityRevocation::verify: {e}"))?;
            re_encode_matches(&obj.det_cbor(), cbor_hex)?;
        }
        Some(other) => {
            // Recognized as a tag but no typed dispatch registered — still fine, the generic
            // check above already proved canonicality; just note it.
            return Ok(Verdict::Fail(format!(
                "no typed verifier registered for cbor_encode type `{other}` — extend check_cbor_encode_vector (generic round-trip alone passed)"
            )));
        }
        None => return Ok(Verdict::PassGeneric),
    }
    Ok(Verdict::Pass)
}

fn re_encode_matches(bytes: &[u8], want_hex: &str) -> Result<(), String> {
    if hex(bytes) == want_hex {
        Ok(())
    } else {
        Err(format!("typed re-encode mismatch: got {}, want {want_hex}", hex(bytes)))
    }
}

/// Run every vector, returning `(name, Verdict)` pairs in file order.
pub fn check_all_vectors(vf: &VectorFile) -> Vec<(String, Verdict)> {
    vf.vectors.iter().map(|v| (v.name.clone(), check_vector(v))).collect()
}

// ============================================================================================
// suite.json cross-reference
// ============================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseOutcome {
    Pass,
    Fail(String),
    /// `construction-todo`: no byte-exact fixture exists yet (skip-with-note, per the task).
    Skipped(String),
}

/// Evaluate one `suite.json` case against the already-computed vector verdicts (`results`, keyed
/// by vector name) and, for `self-contained` cases, the literal inline bytes.
pub fn run_suite_case(case: &SuiteCase, results: &BTreeMap<String, Verdict>) -> CaseOutcome {
    match case.status.as_str() {
        // Actually build the byte-exact input per the case's `construction` recipe (where a
        // dmtap-core API exists to exercise it) and execute it — see `construction.rs`. Cases with
        // no dmtap-core API surface yet come back as an explicit `Skipped(reason)`, never a silent
        // pass.
        "construction-todo" => construction::run_construction_case(case),
        "vectored" => run_vectored_case(case, results),
        "self-contained" => run_self_contained_case(case),
        // §22.7-style client-UX/process MUSTs with no wire bytes to recompute (the suite defines
        // this status as "verified by implementer/reviewer attestation, not by a byte-level
        // runner") — honestly skipped here, never counted as executed.
        "manual-attestation" => CaseOutcome::Skipped(
            "suite.json marks this case `manual-attestation`: a process/UX MUST verified by \
             implementer attestation, with no bytes for a runner to recompute"
                .into(),
        ),
        other => CaseOutcome::Fail(format!("unknown suite.json status `{other}`")),
    }
}

fn run_vectored_case(case: &SuiteCase, results: &BTreeMap<String, Verdict>) -> CaseOutcome {
    let Some(vref) = &case.vector else {
        return CaseOutcome::Fail("status=vectored but no `vector` field".into());
    };
    let names = vref.names();

    // One special multi-vector meta-check the catalog defines (DMTAP-NAME-05): two key-name
    // vectors' encoded names MUST differ. Every other vectored case is single-vector.
    if case.operation == "keyname_distinct" {
        return run_keyname_distinct(&names, results);
    }

    for name in &names {
        match results.get(*name) {
            None => {
                return CaseOutcome::Fail(format!(
                    "suite.json references vector `{name}` which is not present in vectors.json"
                ))
            }
            Some(Verdict::Fail(e)) => {
                return CaseOutcome::Fail(format!("vector `{name}` failed: {e}"))
            }
            Some(Verdict::Pass) | Some(Verdict::PassGeneric) => {}
        }
    }
    CaseOutcome::Pass
}

fn run_keyname_distinct(names: &[&str], results: &BTreeMap<String, Verdict>) -> CaseOutcome {
    if names.len() != 2 {
        return CaseOutcome::Fail(format!("keyname_distinct expects exactly 2 vectors, got {}", names.len()));
    }
    for n in names {
        if !matches!(results.get(*n), Some(v) if v.is_pass()) {
            return CaseOutcome::Fail(format!("prerequisite vector `{n}` did not pass"));
        }
    }
    // Names differing is asserted directly against the vectors.json `expected.name` fields by
    // the caller (see `run_all_suite_cases`), since this function only has pass/fail verdicts.
    CaseOutcome::Pass
}

/// A self-contained case gives inline bytes (`input.cbor_hex`) and an expected accept/reject
/// outcome for the low-level canonical-CBOR decoder (`operation: "det_cbor_decode"`). This is
/// the literal, reference-independent check described by `SUITE.md`.
fn run_self_contained_case(case: &SuiteCase) -> CaseOutcome {
    if case.operation != "det_cbor_decode" {
        return CaseOutcome::Fail(format!(
            "self-contained case with unhandled operation `{}` (extend run_self_contained_case)",
            case.operation
        ));
    }
    let Some(input) = &case.input else {
        return CaseOutcome::Fail("self-contained case has no `input`".into());
    };
    let Some(cbor_hex) = input.get("cbor_hex").and_then(Value::as_str) else {
        return CaseOutcome::Fail("self-contained case input has no cbor_hex".into());
    };
    let bytes = match unhex(cbor_hex) {
        Ok(b) => b,
        Err(e) => return CaseOutcome::Fail(format!("bad cbor_hex: {e}")),
    };
    let want_outcome = case
        .expect
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("");
    let decoded = cbor::decode(&bytes);
    match want_outcome {
        "reject" => match decoded {
            Err(_) => CaseOutcome::Pass,
            Ok(cv) => CaseOutcome::Fail(format!(
                "expected reject but cbor::decode ACCEPTED non-canonical bytes as {cv:?} \
                 (KNOWN REFERENCE GAP: dmtap-core's low-level cbor::decode does not yet enforce \
                 shortest-form integers / definite-length-only / ascending-key-order at decode \
                 time — see conformance-runner report)"
            )),
        },
        "accept" => match decoded {
            Ok(_) => CaseOutcome::Pass,
            Err(e) => CaseOutcome::Fail(format!("expected accept but cbor::decode rejected: {e}")),
        },
        other => CaseOutcome::Fail(format!("unknown expect.outcome `{other}`")),
    }
}

/// Run every case in a suite file, plus the `keyname_distinct` name-inequality assertion (which
/// needs the vector file's `expected.name` fields, not just pass/fail verdicts).
pub fn run_all_suite_cases(
    suite: &SuiteFile,
    vectors: &VectorFile,
    results: &BTreeMap<String, Verdict>,
) -> Vec<(String, CaseOutcome)> {
    let by_name: BTreeMap<&str, &Vector> = vectors.vectors.iter().map(|v| (v.name.as_str(), v)).collect();
    suite
        .cases
        .iter()
        .map(|c| {
            let mut outcome = run_suite_case(c, results);
            if c.operation == "keyname_distinct" && outcome == CaseOutcome::Pass {
                if let Some(vref) = &c.vector {
                    let names = vref.names();
                    if names.len() == 2 {
                        let a = by_name.get(names[0]).and_then(|v| v.expected.get("name")).and_then(Value::as_str);
                        let b = by_name.get(names[1]).and_then(|v| v.expected.get("name")).and_then(Value::as_str);
                        match (a, b) {
                            (Some(a), Some(b)) if a == b => {
                                outcome = CaseOutcome::Fail(format!(
                                    "keyname_distinct: {} and {} produced the SAME name `{a}`",
                                    names[0], names[1]
                                ));
                            }
                            (Some(_), Some(_)) => {}
                            _ => {
                                outcome = CaseOutcome::Fail("keyname_distinct: could not read both names".into());
                            }
                        }
                    }
                }
            }
            (c.id.clone(), outcome)
        })
        .collect()
}
