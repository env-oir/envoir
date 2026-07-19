package dmtapsync

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Call is the low-level escape hatch: dispatch an entry point by name and get its raw JSON result.
//
// The typed methods in this file are the intended surface and should be preferred — they exist so
// callers do not hand-build argument lists. Call is here for two cases the typed methods cannot
// serve: reaching an entry point this Go package has not yet grown a method for, and reading the
// engine's exact result bytes where re-marshaling through a Go struct would be a re-statement
// rather than a measurement (the conformance harness does this deliberately).
//
// Byte-string arguments are lowercase hex, absent Options are nil. See [Instance.EntryPoints] for
// the names.
func (in *Instance) Call(fn string, args ...any) (json.RawMessage, error) {
	return in.invoke(fn, args...)
}

// --- helpers ------------------------------------------------------------------------------------

// callHex dispatches an entry point whose result is a hex-spelled byte string.
func (in *Instance) callHex(fn string, args ...any) ([]byte, error) {
	raw, err := in.invoke(fn, args...)
	if err != nil {
		return nil, err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("dmtapsync: %s did not return hex: %w", fn, err)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: %s returned malformed hex: %w", fn, err)
	}
	return b, nil
}

// callStr dispatches an entry point whose result is an opaque string (often a JSON document).
func (in *Instance) callStr(fn string, args ...any) (string, error) {
	raw, err := in.invoke(fn, args...)
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("dmtapsync: %s did not return a string: %w", fn, err)
	}
	return s, nil
}

// callBool dispatches an entry point whose result is a boolean.
func (in *Instance) callBool(fn string, args ...any) (bool, error) {
	raw, err := in.invoke(fn, args...)
	if err != nil {
		return false, err
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, fmt.Errorf("dmtapsync: %s did not return a boolean: %w", fn, err)
	}
	return b, nil
}

// callUnit dispatches an entry point that returns nothing and either succeeds or refuses.
func (in *Instance) callUnit(fn string, args ...any) error {
	_, err := in.invoke(fn, args...)
	return err
}

// callInto dispatches an entry point whose result is a JSON document, into out.
func (in *Instance) callInto(out any, fn string, args ...any) error {
	s, err := in.callStr(fn, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return fmt.Errorf("dmtapsync: decoding the %s result: %w", fn, err)
	}
	return nil
}

// jsonArg marshals a value into the JSON-string form the engine's arguments take.
func jsonArg(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("dmtapsync: encoding an argument: %w", err)
	}
	return string(b), nil
}

func hexArg(b []byte) string { return hex.EncodeToString(b) }

// optHex renders an optional byte slice as the engine's hex-or-null argument.
func optHex(b []byte) any {
	if b == nil {
		return nil
	}
	return hex.EncodeToString(b)
}

// --- introspection --------------------------------------------------------------------------

// Version reports the binding version and the substrate revision it speaks.
func (in *Instance) Version() (Version, error) {
	var v Version
	return v, in.callInto(&v, "version")
}

// ErrorRegistry returns the 0x0A error registry (§12), for a product mapping refusals to its own UI.
func (in *Instance) ErrorRegistry() ([]RegistryEntry, error) {
	var out []RegistryEntry
	return out, in.callInto(&out, "error_registry")
}

// OpKinds returns the §4.2 op kinds by name.
func (in *Instance) OpKinds() (OpKinds, error) {
	var k OpKinds
	return k, in.callInto(&k, "op_kinds")
}

// --- values and ops ---------------------------------------------------------------------------

// EncodeValue encodes a tagged value to deterministic CBOR (§18.1.1).
func (in *Instance) EncodeValue(value json.RawMessage) ([]byte, error) {
	return in.callHex("encode_value", string(value))
}

// DecodeValue decodes deterministic CBOR back to a tagged value.
func (in *Instance) DecodeValue(b []byte) (json.RawMessage, error) {
	s, err := in.callStr("decode_value", hexArg(b))
	return json.RawMessage(s), err
}

// IsExtValue reports whether a value is a legal §4.1 operand. An op carrying anything else is
// refused at validation, so a product can check before it mints.
func (in *Instance) IsExtValue(value json.RawMessage) (bool, error) {
	return in.callBool("is_ext_value", string(value))
}

// EncodeOp encodes an op to its canonical §4.1 deterministic-CBOR bytes.
func (in *Instance) EncodeOp(op Op) ([]byte, error) {
	arg, err := jsonArg(op)
	if err != nil {
		return nil, err
	}
	return in.callHex("encode_op", arg)
}

// EncodeOpJSON encodes an op given directly as JSON, for callers holding a document rather than
// an [Op] — the conformance harness, and any product whose ops arrive over the wire as JSON.
func (in *Instance) EncodeOpJSON(opJSON string) ([]byte, error) {
	return in.callHex("encode_op", opJSON)
}

// DecodeOp decodes canonical op bytes.
//
// Non-canonical encodings are refused, never silently re-canonicalized (§2.2): an encoder that
// spells the same value two ways would break the content addressing everything else rests on.
func (in *Instance) DecodeOp(b []byte) (Op, error) {
	var op Op
	return op, in.callInto(&op, "decode_op", hexArg(b))
}

// DecodeOpJSON decodes canonical op bytes to the engine's exact JSON spelling.
func (in *Instance) DecodeOpJSON(b []byte) (string, error) {
	return in.callStr("decode_op", hexArg(b))
}

// OpID returns an encoded op's content address (§4.1).
func (in *Instance) OpID(opBytes []byte) ([]byte, error) {
	return in.callHex("op_id", hexArg(opBytes))
}

// ValidateOp runs the state-free structural, causality and skew validators (§4).
//
// This is the same check [Engine.IngestSigned] performs; it is exposed separately so a product can
// screen an op before deciding to store or forward it.
func (in *Instance) ValidateOp(opBytes []byte, receiverNowMS uint64) error {
	return in.callUnit("validate_op", hexArg(opBytes), float64(receiverNowMS))
}

// --- HLC ---------------------------------------------------------------------------------------

// EncodeHLC returns an HLC's canonical CBOR — the bytes §2.2 tiebreaks and §6.1.1 sorts compare.
func (in *Instance) EncodeHLC(h HLC) ([]byte, error) {
	arg, err := jsonArg(h)
	if err != nil {
		return nil, err
	}
	return in.callHex("encode_hlc", arg)
}

// CompareHLC compares two HLCs in the normative total order, returning -1, 0 or 1.
func (in *Instance) CompareHLC(a, b HLC) (int, error) {
	aj, err := jsonArg(a)
	if err != nil {
		return 0, err
	}
	bj, err := jsonArg(b)
	if err != nil {
		return 0, err
	}
	raw, err := in.invoke("compare_hlc", aj, bj)
	if err != nil {
		return 0, err
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("dmtapsync: compare_hlc did not return a number: %w", err)
	}
	return n, nil
}

// Clock is a per-replica Hybrid Logical Clock (§3).
//
// It belongs to the [Instance] that created it and must not be used with another. Close it when
// done so the instance can reuse the slot.
type Clock struct {
	in     *Instance
	handle uint32
	closed bool
}

// NewClock creates a clock for author, a 32-byte Ed25519 public key.
func (in *Instance) NewClock(author []byte) (*Clock, error) {
	raw, err := in.invoke("hlc.new", hexArg(author))
	if err != nil {
		return nil, err
	}
	var h uint32
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("dmtapsync: hlc.new did not return a handle: %w", err)
	}
	return &Clock{in: in, handle: h}, nil
}

// Close releases the clock.
func (c *Clock) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.in.callUnit("hlc.close", float64(c.handle))
}

// Tick advances the clock and returns the next timestamp for a locally-minted op.
func (c *Clock) Tick(nowMS uint64) (HLC, error) {
	var h HLC
	return h, c.in.callInto(&h, "hlc.tick", float64(c.handle), float64(nowMS))
}

// Observe folds a remote timestamp in, so this clock never lags behind causality it has seen.
func (c *Clock) Observe(h HLC) error {
	arg, err := jsonArg(h)
	if err != nil {
		return err
	}
	return c.in.callUnit("hlc.observe", float64(c.handle), arg)
}

// Current returns the clock's timestamp without advancing it.
func (c *Clock) Current() (HLC, error) {
	var h HLC
	return h, c.in.callInto(&h, "hlc.current", float64(c.handle))
}

// --- COSE: detached signing --------------------------------------------------------------------

// OpSigningInput returns the material a key custodian needs to sign an op.
//
// See [Signer] for why this is the only signing path: no entry point takes a private key.
func (in *Instance) OpSigningInput(opBytes []byte) (SigningInput, error) {
	var si SigningInput
	return si, in.callInto(&si, "op_signing_input", hexArg(opBytes))
}

// OpAttachSignature assembles the wire COSE_Sign1 from an op and a detached signature over
// [SigningInput.SigStructure].
//
// The envelope is verified before it is returned: a signature produced under the wrong key, over
// the wrong preimage, or by a custodian that silently failed cannot leave this function as a
// well-formed op. Emitting unverifiable envelopes would only push the failure onto some other
// replica's ingest path, hours later and with no context.
func (in *Instance) OpAttachSignature(opBytes, signature []byte) ([]byte, error) {
	return in.callHex("op_attach_signature", hexArg(opBytes), hexArg(signature))
}

// SignOp is the whole detached signing protocol in one call: obtain the preimage, have signer sign
// it, and assemble the verified envelope.
//
// This is the method most products want. The key stays with signer throughout — it is never passed
// into the engine, which is the property [Signer] exists to preserve.
func (in *Instance) SignOp(opBytes []byte, signer Signer) ([]byte, error) {
	si, err := in.OpSigningInput(opBytes)
	if err != nil {
		return nil, err
	}
	preimage, err := si.Bytes()
	if err != nil {
		return nil, err
	}
	// Checked here so the failure names the real problem. The engine would reject the envelope
	// anyway (the signature would not verify under the claimed author), but "signature invalid" is
	// a poor description of "you signed with the wrong key".
	if pub := signer.Public(); len(pub) > 0 && !bytes.Equal(pub, mustHex(si.Author)) {
		return nil, fmt.Errorf(
			"dmtapsync: signer's key %x does not match the op's author %s", pub, si.Author)
	}
	sig, err := signer.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: signer failed: %w", err)
	}
	return in.OpAttachSignature(opBytes, sig)
}

// mustHex decodes hex the engine produced. The engine never emits malformed hex; a nil return
// simply fails the comparison at the one call site, which then reports a key mismatch.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// VerifySignedOp verifies a COSE_Sign1 envelope and returns the canonical op bytes it carries.
//
// Fails closed (0x0A02) on a tampered payload, a substituted key id, a non-empty unprotected
// header, a detached payload, or a signature minted under any other domain-separation tag.
func (in *Instance) VerifySignedOp(coseBytes []byte) ([]byte, error) {
	return in.callHex("verify_signed_op", hexArg(coseBytes))
}

// DecodeSignedOp decodes a COSE_Sign1's four wire parts without verifying it.
func (in *Instance) DecodeSignedOp(coseBytes []byte) (CoseParts, error) {
	var c CoseParts
	return c, in.callInto(&c, "decode_signed_op", hexArg(coseBytes))
}

// --- the engine ----------------------------------------------------------------------------------

// Engine is a replica's sync state: the six-kind CRDT algebra (§4.3–§4.8), the idempotent ingest
// path, the §5.1 version vector, and the §6.1 observable-state projection.
//
// In-memory only — a product supplies its own store and replays or fast-joins on load. Ops are
// deduplicated by op-id, so re-delivering one is a no-op, and every merge is commutative,
// associative and idempotent: the arrival order of concurrent ops never changes the outcome.
//
// An Engine belongs to the [Instance] that created it and must not be used with another.
type Engine struct {
	in     *Instance
	handle uint32
	closed bool
}

// NewEngine creates an empty replica.
func (in *Instance) NewEngine() (*Engine, error) {
	raw, err := in.invoke("engine.new")
	if err != nil {
		return nil, err
	}
	var h uint32
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("dmtapsync: engine.new did not return a handle: %w", err)
	}
	return &Engine{in: in, handle: h}, nil
}

// Close releases the engine.
func (e *Engine) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.in.callUnit("engine.close", float64(e.handle))
}

func (e *Engine) h() float64 { return float64(e.handle) }

// IngestSigned is the network ingest path: verify a COSE_Sign1 envelope, then validate and apply
// the op it carries. It reports whether the op was new.
//
// Signature (0x0A02), structure and causality (0x0A03) and skew (0x0A05) are all checked before
// state is touched, so a refused op leaves the replica exactly as it was.
func (e *Engine) IngestSigned(coseBytes []byte, receiverNowMS uint64) (bool, error) {
	return e.in.callBool("engine.ingest_signed", e.h(), hexArg(coseBytes), float64(receiverNowMS))
}

// IngestAmbientAuthenticated applies an op whose authenticity was already established out of band
// — the §5.6 profile, where ops ride unsigned inside a group and authenticity is group membership.
//
// The op is still fully validated (§4); only the signature check is skipped, because there is no
// signature to check. Use this only when the transport itself authenticates every writer. On a
// multi-author or untrusted path it is a hole: it accepts any well-formed op claiming any author,
// and [Engine.IngestSigned] is the correct entry point.
func (e *Engine) IngestAmbientAuthenticated(opBytes []byte, receiverNowMS uint64) (bool, error) {
	return e.in.callBool(
		"engine.ingest_ambient_authenticated", e.h(), hexArg(opBytes), float64(receiverNowMS))
}

// HasOp reports whether this replica already holds an op, by op-id.
func (e *Engine) HasOp(opID []byte) (bool, error) {
	return e.in.callBool("engine.has_op", e.h(), hexArg(opID))
}

// Merge folds another replica's state in. State-based merge: idempotent and order-independent.
//
// Both engines must belong to the same [Instance].
func (e *Engine) Merge(other *Engine) error {
	if other == nil {
		return fmt.Errorf("dmtapsync: Merge needs an engine")
	}
	if other.in != e.in {
		return fmt.Errorf("dmtapsync: cannot merge engines from different instances")
	}
	return e.in.callUnit("engine.merge", e.h(), other.h())
}

// ObservableState returns the canonical six-section projection as deterministic CBOR (§6.1.1).
//
// This is the artifact two replicas compare: equal bytes mean equal observable state.
func (e *Engine) ObservableState() ([]byte, error) {
	return e.in.callHex("engine.observable_state", e.h())
}

// ObservableStateJSON returns the same projection as JSON, for rendering rather than hashing.
func (e *Engine) ObservableStateJSON() (ObservableState, error) {
	var s ObservableState
	return s, e.in.callInto(&s, "engine.observable_state_json", e.h())
}

// StateRoot returns the §6.1 observable-state root.
func (e *Engine) StateRoot() ([]byte, error) {
	return e.in.callHex("engine.state_root", e.h())
}

// VerifyRoot recomputes the root and compares it to a claimed one.
//
// A mismatch is 0x0A09 — evidence of divergence, whose §12 action is HALT_ALERT, not a retry.
func (e *Engine) VerifyRoot(claimed []byte) error {
	return e.in.callUnit("engine.verify_root", e.h(), hexArg(claimed))
}

// VersionVector returns the §5.1 per-author high-water marks this replica has applied.
func (e *Engine) VersionVector() ([]Mark, error) {
	var m []Mark
	return m, e.in.callInto(&m, "engine.version_vector", e.h())
}

// VersionVectorCBOR returns the version vector's canonical CBOR — a snapshot's covers member.
func (e *Engine) VersionVectorCBOR() ([]byte, error) {
	return e.in.callHex("engine.version_vector_cbor", e.h())
}

// LWWCell returns the winning last-write-wins cell, or nil if there is none.
func (e *Engine) LWWCell(target, field string) (*LWWCell, error) {
	s, err := e.in.callStr("engine.lww_cell", e.h(), target, field)
	if err != nil {
		return nil, err
	}
	if s == "null" {
		return nil, nil
	}
	var c LWWCell
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, fmt.Errorf("dmtapsync: decoding the lww_cell result: %w", err)
	}
	return &c, nil
}

// SetContains reports whether an OR-Set element is present — add-wins, unless a death certificate
// dominates.
func (e *Engine) SetContains(target string, value json.RawMessage) (bool, error) {
	return e.in.callBool("engine.set_contains", e.h(), target, string(value))
}

// SetMembers returns every present (target, element) pair.
func (e *Engine) SetMembers() ([][]json.RawMessage, error) {
	var m [][]json.RawMessage
	return m, e.in.callInto(&m, "engine.set_members", e.h())
}

// SetSurvivingTags returns the add-tags of an element that no observed-remove has tombstoned —
// the causal evidence behind "present".
func (e *Engine) SetSurvivingTags(target string, value json.RawMessage) ([]AddTag, error) {
	var t []AddTag
	return t, e.in.callInto(&t, "engine.set_surviving_tags", e.h(), target, string(value))
}

// CounterTotal returns a PN-counter's total as a decimal string.
//
// A string rather than an integer because the §4.6 sum is an i128 and does not in general fit any
// Go integer type — truncating it here would be a silent wrong answer.
func (e *Engine) CounterTotal(target, field string) (string, error) {
	return e.in.callStr("engine.counter_total", e.h(), target, field)
}

// CounterEntries returns the per-author entries behind a counter (§4.6).
func (e *Engine) CounterEntries(target, field string) ([]CounterEntry, error) {
	var c []CounterEntry
	return c, e.in.callInto(&c, "engine.counter_entries", e.h(), target, field)
}

// DeathState returns an object's death dimension.
func (e *Engine) DeathState(object string) (DeathState, error) {
	var d DeathState
	return d, e.in.callInto(&d, "engine.death_state", e.h(), object)
}

// Sequence returns an RGA sequence, or nil if the target holds none.
func (e *Engine) Sequence(target string) (*Sequence, error) {
	s, err := e.in.callStr("engine.sequence", e.h(), target)
	if err != nil {
		return nil, err
	}
	if s == "null" {
		return nil, nil
	}
	var seq Sequence
	if err := json.Unmarshal([]byte(s), &seq); err != nil {
		return nil, fmt.Errorf("dmtapsync: decoding the sequence result: %w", err)
	}
	return &seq, nil
}

// Tree returns the movable tree after §4.8 cycle-safe replay.
func (e *Engine) Tree() (Tree, error) {
	var t Tree
	return t, e.in.callInto(&t, "engine.tree", e.h())
}

// PruneBelow reclaims collapsed add/tombstone pairs strictly below a §6.2 stability cut, returning
// how many entries were dropped.
//
// Observable state is unchanged by construction: GC below the cut can only remove causal evidence
// no replica can still cite.
func (e *Engine) PruneBelow(cut HLC) (int, error) {
	arg, err := jsonArg(cut)
	if err != nil {
		return 0, err
	}
	raw, err := e.in.invoke("engine.prune_below", e.h(), arg)
	if err != nil {
		return 0, err
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("dmtapsync: prune_below did not return a count: %w", err)
	}
	return n, nil
}

// --- observable state and snapshots -------------------------------------------------------------

// ObservableStateRoot returns the §6.1 root of an already-encoded observable state — for verifying
// a state body fetched by address against a snapshot's root before adopting a byte of it.
func (in *Instance) ObservableStateRoot(stateCBOR []byte) ([]byte, error) {
	return in.callHex("observable_state_root", hexArg(stateCBOR))
}

// EncodeObservableState encodes a §6.1.1 observable state to canonical CBOR.
//
// Section entries are re-sorted canonically on the way out, so a body that arrives in any other
// order still hashes to the same root — or, if it was tampered with, visibly does not.
func (in *Instance) EncodeObservableState(s ObservableState) ([]byte, error) {
	arg, err := jsonArg(s)
	if err != nil {
		return nil, err
	}
	return in.callHex("encode_observable_state", arg)
}

// EncodeObservableStateJSON encodes an observable state given directly as JSON.
func (in *Instance) EncodeObservableStateJSON(stateJSON string) ([]byte, error) {
	return in.callHex("encode_observable_state", stateJSON)
}

// DecodeObservableState decodes a canonical observable-state body.
func (in *Instance) DecodeObservableState(b []byte) (ObservableState, error) {
	var s ObservableState
	return s, in.callInto(&s, "decode_observable_state", hexArg(b))
}

// SnapshotDecode decodes a signed snapshot without trusting it. Call [Instance.SnapshotVerify]
// before use.
func (in *Instance) SnapshotDecode(b []byte) (Snapshot, error) {
	var s Snapshot
	return s, in.callInto(&s, "snapshot_decode", hexArg(b))
}

// SnapshotVerify verifies a snapshot's own signature under its declared signer. Fails closed
// (0x0A02).
//
// This proves who minted the checkpoint — it does not prove the state is correct. A fast-joining
// replica additionally hash-verifies the state body against the root, and decides whether it
// trusts the signer at all; §6.1's trust policy is the deployment's call, not this binding's.
func (in *Instance) SnapshotVerify(b []byte) error {
	return in.callUnit("snapshot_verify", hexArg(b))
}

// SnapshotSigningInput returns the detached signing preimage for a snapshot, given the snapshot
// without its signature.
//
// The same rule as ops applies: sign it externally, then [Instance.SnapshotAssemble].
func (in *Instance) SnapshotSigningInput(s Snapshot) ([]byte, error) {
	arg, err := jsonArg(s)
	if err != nil {
		return nil, err
	}
	var out struct {
		Preimage string `json:"preimage"`
	}
	if err := in.callInto(&out, "snapshot_signing_input", arg); err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(out.Preimage)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: snapshot preimage is not hex: %w", err)
	}
	return b, nil
}

// SnapshotAssemble assembles signed snapshot wire bytes from a snapshot and a detached signature.
// As with ops, the signature is verified before the bytes are returned.
func (in *Instance) SnapshotAssemble(s Snapshot, signature []byte) ([]byte, error) {
	arg, err := jsonArg(s)
	if err != nil {
		return nil, err
	}
	return in.callHex("snapshot_assemble", arg, hexArg(signature))
}

// SignSnapshot is the snapshot equivalent of [Instance.SignOp]: preimage out, signature in,
// verified envelope back, key never entering the engine.
func (in *Instance) SignSnapshot(s Snapshot, signer Signer) ([]byte, error) {
	preimage, err := in.SnapshotSigningInput(s)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("dmtapsync: signer failed: %w", err)
	}
	return in.SnapshotAssemble(s, sig)
}

// --- fast-join (§5.2.1) ---------------------------------------------------------------------

// FastJoinDecode decodes a FastJoin without trusting it.
func (in *Instance) FastJoinDecode(b []byte) (FastJoin, error) {
	var fj FastJoin
	return fj, in.callInto(&fj, "fastjoin_decode", hexArg(b))
}

// --- §6.1.2 the snapshot BODY (an op set, not a state document) ---------------------------------

// SnapshotBodyDecode returns a snapshot body's members: the hex COSE_Sign1(SyncOp) envelopes it
// carries, in wire order.
//
// A host adopts a body by feeding each member to [Engine.IngestSigned] — the ordinary op path,
// which is the whole of §6.1.2: same signature check, same ext-value validation, same CRDT apply,
// same op-id dedup. There is deliberately no "load state" entry point on this binding, and §6.1.2
// is explicit that an implementation exposing none is not thereby incomplete.
func (in *Instance) SnapshotBodyDecode(bodyBytes []byte) ([]string, error) {
	var members []string
	if err := in.callInto(&members, "snapshot_body_decode", hexArg(bodyBytes)); err != nil {
		return nil, err
	}
	return members, nil
}

// SnapshotBodyEncode encodes a body from hex COSE_Sign1 envelopes — the responder side of
// GET /sync/state/<root>.
//
// Members are embedded as CBOR items, never bstr-wrapped (§5.2's op-framing rule, which §5.2.1
// says governs the ops inside a body too). A bstr-wrapped member is the C-06 non-conformant
// framing and is refused on decode rather than unwrapped.
func (in *Instance) SnapshotBodyEncode(membersHex []string) ([]byte, error) {
	arg, err := jsonArg(nonNilStrings(membersHex))
	if err != nil {
		return nil, err
	}
	return in.callHex("snapshot_body_encode", arg)
}

// SnapshotBodyFold ingests every member through the ordinary §4 op path and returns the resulting
// det_cbor(ObservableState).
//
// This is what a RESPONDER uses — it is building the body, so it has no root to check against yet;
// the root is defined as the hash of what this returns. A CALLER must use
// [Instance.SnapshotBodyVerifyRoot] instead: folding without checking the result against
// Snapshot.root is exactly the unverified adoption §5.2.1 step 3 forbids.
//
// Pass ns to reject a member from any other namespace with 0x0A0A, or "" to skip that scoping.
func (in *Instance) SnapshotBodyFold(bodyBytes []byte, ns string, receiverNowMS uint64) ([]byte, error) {
	return in.callHex("snapshot_body_fold", hexArg(bodyBytes), ns, float64(receiverNowMS))
}

// SnapshotBodyVerifyRoot is §6.1.2's fold-then-recompute: ingest every member of the body through
// the ordinary §4 op path into a PROVISIONAL state, derive ObservableState per §6.1.1, and require
// its hash to equal root. It returns the canonical observable-state bytes on success.
//
// Refuses with 0x0A09 if the ops do not reproduce root — and then returns nothing, because the body
// is discarded whole; the fold happened in a provisional state the host never saw.
//
// This is NOT hash(bodyBytes) == root. That would prove only that someone shipped the bytes they
// promised; this proves the ops PRODUCE the committed state, which is what makes a body safe to
// resume from and what bounds a malicious signer to omission rather than fabrication.
func (in *Instance) SnapshotBodyVerifyRoot(
	bodyBytes, root []byte, ns string, receiverNowMS uint64,
) ([]byte, error) {
	return in.callHex(
		"snapshot_body_verify_root", hexArg(bodyBytes), hexArg(root), ns, float64(receiverNowMS))
}

// FastJoinEncode encodes a FastJoin.
func (in *Instance) FastJoinEncode(fj FastJoin) ([]byte, error) {
	arg, err := jsonArg(fj)
	if err != nil {
		return nil, err
	}
	return in.callHex("fastjoin_encode", arg)
}

// CallerIsBelowFloor is the §5.2.1 responder predicate: is a caller holding vector below the floor
// this snapshot stands in for — that is, would the surviving suffix be an incomplete answer?
//
// The test is domination of covers, not a comparison against the floor alone. A responder for
// which this is true MUST answer fast-join; one for which it is false MUST answer with ops.
func (in *Instance) CallerIsBelowFloor(snapshotBytes []byte, vector []Mark) (bool, error) {
	arg, err := jsonArg(vector)
	if err != nil {
		return false, err
	}
	return in.callBool("caller_is_below_floor", hexArg(snapshotBytes), arg)
}

// FastJoinStateAddress returns the content address a fast-join's state body must be fetched from —
// what the host needs before it can call [Instance.FastJoinAdopt].
func (in *Instance) FastJoinStateAddress(fastjoinBytes []byte) ([]byte, error) {
	return in.callHex("fastjoin_state_address", hexArg(fastjoinBytes))
}

// FastJoinAdopt runs the §5.2.1 caller-side sequence, steps 1–3: verify the snapshot, check it
// closes the gap, and obtain and verify the body. It returns the verified observable-state bytes.
//
// The body is a SnapshotBody — a compacted set of signed ops, not a state document (§6.1.2). It is
// verified by fold-then-recompute: every member is ingested through the ordinary §4 op path into a
// provisional state, that state's §6.1.1 projection is hashed, and the hash must equal
// Snapshot.root. Hashing the received bytes would prove only that the sender shipped what it
// promised; this proves the ops produce the committed state.
//
// fetchedBody is what the host retrieved from the state address, or nil if it could not retrieve
// anything — the fetch itself is the host's job, because this binding does no I/O. An inline hint
// in the FastJoin is tried first and held to exactly the same fold-then-recompute, then discarded
// on failure: it is a cache hint, never a second source of truth.
//
// On any failure the caller MUST keep its old vector and MUST NOT fall back to the responder's
// surviving suffix. That fallback is the silent lost-write this whole path exists to prevent,
// which is why this returns state rather than mutating an engine: adoption is a separate,
// deliberate step the host takes only on success.
func (in *Instance) FastJoinAdopt(
	fastjoinBytes []byte, callerVector []Mark, subscribed []string, admittedHex []string,
	receiverNowMS uint64, fetchedBody []byte,
) ([]byte, error) {
	vec, err := jsonArg(callerVector)
	if err != nil {
		return nil, err
	}
	subs, err := jsonArg(nonNilStrings(subscribed))
	if err != nil {
		return nil, err
	}
	adm, err := jsonArg(nonNilStrings(admittedHex))
	if err != nil {
		return nil, err
	}
	return in.callHex(
		"fastjoin_adopt", hexArg(fastjoinBytes), vec, subs, adm, float64(receiverNowMS),
		optHex(fetchedBody))
}

// FastJoinCheckProgress is the §5.2.1 step-5 progress MUST (§14 C-07).
//
// A re-pull answered with another fast-join carrying the same snapshot root and covers means the
// responder is looping — adopting again cannot advance the caller. Refuses with 0x0A09; returns
// nil on progress.
//
// Pass previousRoot and previousCovers from the fast-join adopted on the preceding round of the
// same join, or nil on the first round. A host driving a pull loop MUST call this (or
// [Instance.FastJoinAdoptAfter]) rather than [Instance.FastJoinAdopt] alone: the loop it prevents
// is unbounded, and nothing else in the protocol terminates it.
func (in *Instance) FastJoinCheckProgress(
	fastjoinBytes, previousRoot []byte, previousCovers []Mark,
) error {
	var covers any
	if previousCovers != nil {
		s, err := jsonArg(previousCovers)
		if err != nil {
			return err
		}
		covers = s
	}
	return in.callUnit(
		"fastjoin_check_progress", hexArg(fastjoinBytes), optHex(previousRoot), covers)
}

// FastJoinAdoptAfter is [Instance.FastJoinAdopt] preceded by the progress MUST — the call a real
// pull loop should use.
func (in *Instance) FastJoinAdoptAfter(
	fastjoinBytes, previousRoot []byte, previousCovers []Mark,
	callerVector []Mark, subscribed []string, admittedHex []string,
	receiverNowMS uint64, fetchedBody []byte,
) ([]byte, error) {
	var covers any
	if previousCovers != nil {
		s, err := jsonArg(previousCovers)
		if err != nil {
			return nil, err
		}
		covers = s
	}
	vec, err := jsonArg(callerVector)
	if err != nil {
		return nil, err
	}
	subs, err := jsonArg(nonNilStrings(subscribed))
	if err != nil {
		return nil, err
	}
	adm, err := jsonArg(nonNilStrings(admittedHex))
	if err != nil {
		return nil, err
	}
	return in.callHex("fastjoin_adopt_after",
		hexArg(fastjoinBytes), optHex(previousRoot), covers, vec, subs, adm,
		float64(receiverNowMS), optHex(fetchedBody))
}

// FastJoinCheckCovers is §5.2.1 step 2 in isolation (§5.2.2): covers well-formed and non-empty
// (0x0A03), and the caller genuinely below the floor (0x0A09).
//
// There is deliberately no floor-versus-covers comparison in here — see
// [Instance.FastJoinNaiveCoversLacksFloorRejected] for the predicate that was removed and why.
func (in *Instance) FastJoinCheckCovers(fastjoinBytes []byte, callerVector []Mark) error {
	arg, err := jsonArg(callerVector)
	if err != nil {
		return err
	}
	return in.callUnit("fastjoin_check_covers", hexArg(fastjoinBytes), arg)
}

// FastJoinCoversCarriesFloorAuthorMark is advisory only (§5.2.2, MAY): does the fast-join's covers
// carry a mark for the floor's author?
//
// Exposed so a host can log the signal, and named so it cannot be mistaken for a verdict. It is
// not a conformance test: an author whose only op sits at the floor is retained rather than
// truncated, so covers need never name it. Treating false as a failure rejects conformant peers —
// the defect §14 C-07 removed.
func (in *Instance) FastJoinCoversCarriesFloorAuthorMark(fastjoinBytes []byte) (bool, error) {
	return in.callBool("fastjoin_covers_carries_floor_author_mark", hexArg(fastjoinBytes))
}

// FastJoinNaiveCoversLacksFloorRejected is the rejected naive predicate, exposed only so the
// cross-surface trace can prove all three surfaces agree it fires true on a well-formed fast-join
// — and that none of them acts on it.
//
// Never gate adoption on this. The floor is a single HLC and covers is a per-author version
// vector; there is no ordering between them (§5.2.2). This is a counterexample witness, not an API
// for deciding anything.
func (in *Instance) FastJoinNaiveCoversLacksFloorRejected(fastjoinBytes []byte) (bool, error) {
	return in.callBool("fastjoin_naive_covers_lacks_floor_rejected", hexArg(fastjoinBytes))
}

// --- reconciliation (§5.3) -------------------------------------------------------------------

// Fingerprint returns the range-Merkle fingerprint of a set of op entries.
func (in *Instance) Fingerprint(entries []OpEntry) (Fingerprint, error) {
	arg, err := jsonArg(nonNilEntries(entries))
	if err != nil {
		return Fingerprint{}, err
	}
	var f Fingerprint
	return f, in.callInto(&f, "fingerprint", arg)
}

// Summarize fingerprints only the entries within the half-open range [lo, hi).
func (in *Instance) Summarize(entries []OpEntry, lo, hi HLC) (Summary, error) {
	ea, err := jsonArg(nonNilEntries(entries))
	if err != nil {
		return Summary{}, err
	}
	la, err := jsonArg(lo)
	if err != nil {
		return Summary{}, err
	}
	ha, err := jsonArg(hi)
	if err != nil {
		return Summary{}, err
	}
	var s Summary
	return s, in.callInto(&s, "summarize", ea, la, ha)
}

// Reconcile performs a recursive range-Merkle diff between what this replica holds and what a peer
// holds.
func (in *Instance) Reconcile(here, there []OpEntry, lo, hi HLC) (Reconciliation, error) {
	ha, err := jsonArg(nonNilEntries(here))
	if err != nil {
		return Reconciliation{}, err
	}
	ta, err := jsonArg(nonNilEntries(there))
	if err != nil {
		return Reconciliation{}, err
	}
	la, err := jsonArg(lo)
	if err != nil {
		return Reconciliation{}, err
	}
	hia, err := jsonArg(hi)
	if err != nil {
		return Reconciliation{}, err
	}
	var r Reconciliation
	return r, in.callInto(&r, "reconcile", ha, ta, la, hia)
}

// --- admission, namespaces, GC ---------------------------------------------------------------

// CheckAdmitted reports whether an author is in the admitted set (§8/§9), refusing with 0x0A01 if
// not.
//
// This is a list membership check, not a policy engine: resolving device-certificate chains,
// namespace policy objects and revocation is capability ① and lives outside this binding.
func (in *Instance) CheckAdmitted(author []byte, admittedHex []string) error {
	arg, err := jsonArg(nonNilStrings(admittedHex))
	if err != nil {
		return err
	}
	return in.callUnit("check_admitted", hexArg(author), arg)
}

// CheckCounterEntry reports whether a PN-counter op may touch an entry: an author may only mutate
// its own P/N (§4.6). Refuses with 0x0A06 otherwise.
func (in *Instance) CheckCounterEntry(opAuthor, entryAuthor []byte) error {
	return in.callUnit("check_counter_entry", hexArg(opAuthor), hexArg(entryAuthor))
}

// CheckNsRef reports whether an op may reference a target: cross-namespace references are 0x0A0A
// (§7).
func (in *Instance) CheckNsRef(opNS, referencedTargetNS string) error {
	return in.callUnit("check_ns_ref", opNS, referencedTargetNS)
}

// ScopeToSubscription filters ops down to a caller's subscribed namespaces (§7) — the
// responder-side sparse-sync scope. It returns the ops' canonical bytes, so nothing is re-encoded
// on the way out.
func (in *Instance) ScopeToSubscription(opsJSON string, subscribed []string) ([][]byte, error) {
	subs, err := jsonArg(nonNilStrings(subscribed))
	if err != nil {
		return nil, err
	}
	var hexes []string
	if err := in.callInto(&hexes, "scope_to_subscription", opsJSON, subs); err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("dmtapsync: scope_to_subscription returned malformed hex: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}

// StabilityCut returns the §6.2 stability cut: the minimum over live replicas' watermarks, below
// which history can be truncated. It returns nil when any live replica's watermark is unknown.
//
// An unknown watermark must never be read as "caught up", so the fail-closed answer is "no cut
// yet". Each element is either a watermark or nil for "unknown". Excluding a stale replica is the
// caller's liveness decision; including one drags the cut down forever.
func (in *Instance) StabilityCut(watermarks []*HLC) (*HLC, error) {
	arg, err := jsonArg(nonNilWatermarks(watermarks))
	if err != nil {
		return nil, err
	}
	s, err := in.callStr("stability_cut", arg)
	if err != nil {
		return nil, err
	}
	if s == "null" {
		return nil, nil
	}
	var h HLC
	if err := json.Unmarshal([]byte(s), &h); err != nil {
		return nil, fmt.Errorf("dmtapsync: decoding the stability cut: %w", err)
	}
	return &h, nil
}

// --- nil-slice normalization -------------------------------------------------------------------
// A nil Go slice marshals to `null`, and the engine expects an array. These keep an empty argument
// from arriving as a type error rather than as "nothing".

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilEntries(e []OpEntry) []OpEntry {
	if e == nil {
		return []OpEntry{}
	}
	return e
}

func nonNilWatermarks(w []*HLC) []*HLC {
	if w == nil {
		return []*HLC{}
	}
	return w
}
