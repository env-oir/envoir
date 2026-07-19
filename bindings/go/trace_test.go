// The Go half of the cross-surface parity proof (`substrate/BINDINGS.md` §4).
//
// This file drives every frozen vector in `sync_vectors.json` **through the Go binding** and
// records a trace: vector name → { key → value }, every value a string (hex bytes, a decimal, a
// JSON blob, or a `0x0AXX` refusal code). It is a deliberate port of
// `crates/dmtap-sync-wasm/test/trace.mjs`, key for key, so the three surfaces record the *same*
// observations under the *same* names:
//
//	tests/native_trace.rs   native Rust, no wasm, no marshalling — records native-trace.json
//	test/trace.mjs          the WASM binding, driven from JavaScript
//	trace_test.go           the WASM binding, driven from Go through wazero  ← this file
//
// `vectors_test.go` then asserts the traces are byte-identical.
//
// Rule for anyone editing this file: **compute, never restate**. A trace value must come out of a
// binding call. Copying an expected constant out of the vector into the trace would make the
// comparison pass while proving nothing. And when a value here disagrees with the native trace,
// the binding is wrong — there is exactly one implementation of the algebra for it to disagree
// with, so it is never "the Go harness needs adjusting".
package dmtapsync_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	dmtapsync "github.com/vul-os/envoir/bindings/go"
)

// receiverNowMS is the vectors' fixed receiver clock. Their HLC wall is a 2023-11-14 timestamp and
// the skew rule bounds ops from the FUTURE, so a clock at or after that wall accepts every vector
// op (§3). Same constant as the native runner and the JS harness.
const receiverNowMS = 1_700_000_900_000

// notCovered names operations this harness does not drive, and why.
//
// An entry here is not permission to fall behind. TestEveryVectorIsDrivenOrExplicitlyNotCovered
// additionally requires that nothing listed here is driven by the NATIVE surface either — so this
// map can only ever hold vectors no surface implements yet, never ones where Go alone is lagging.
// The moment the native runner grows an executor, the Go build goes red until this one does too.
var notCovered = map[string]string{
	// Empty. All 24 vectors are driven here, on the same footing as the native runner and the JS
	// harness — SYNC-VAL-01's ext-value boundary and SYNC-SNAP-03's op-set snapshot body included.
	//
	// Both were listed here while §4.1's `ext-value` was still narrowed and `dmtap-sync` had no
	// SnapshotBody type: that was core substrate work in Rust, and driving it from a binding
	// harness would have meant re-implementing the algebra these vectors exist to check. The core
	// work landed (C-08/C-09), so the entries went with it.
}

// --- generic JSON ---------------------------------------------------------------------------
//
// The vectors and several engine results are heterogeneous documents rather than fixed structs, so
// they are handled as `any`. Always through these two helpers: [decodeJSON] uses UseNumber, without
// which Go would parse the vectors' HLC walls into float64 and re-emit them as `1.7000001e+12`,
// silently changing bytes this file exists to compare.

func decodeJSON(s string) any {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		panic(fmt.Sprintf("harness: not JSON: %v (%.120s)", err, s))
	}
	return v
}

func encodeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("harness: cannot encode: %v", err))
	}
	return string(b)
}

// m accesses a JSON object member.
func m(v any, key string) any {
	o, ok := v.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("harness: expected an object to read %q from, got %T", key, v))
	}
	x, ok := o[key]
	if !ok {
		panic(fmt.Sprintf("harness: missing member %q", key))
	}
	return x
}

// mOpt is m for a member that may legitimately be absent.
func mOpt(v any, key string) (any, bool) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	x, ok := o[key]
	return x, ok
}

func str(v any, key string) string {
	s, ok := m(v, key).(string)
	if !ok {
		panic(fmt.Sprintf("harness: member %q is not a string", key))
	}
	return s
}

func list(v any, key string) []any {
	a, ok := m(v, key).([]any)
	if !ok {
		panic(fmt.Sprintf("harness: member %q is not an array", key))
	}
	return a
}

func strList(v any, key string) []string {
	out := []string{}
	for _, e := range list(v, key) {
		out = append(out, e.(string))
	}
	return out
}

func numStr(v any, key string) string { return m(v, key).(json.Number).String() }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("harness: not hex: %q", s))
	}
	return b
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

// ptr is the address of a value, for the binding's optional string fields.
func ptr[T any](v T) *T { return &v }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// --- the signing host -----------------------------------------------------------------------

// sign is the harness's key custodian. Ed25519 lives HERE, in the Go host, and never inside the
// module — the vectors fix a 32-byte seed, so this is the same deterministic key the native runner
// uses, and the fact that a signature produced entirely outside the module reproduces the frozen
// `signature_hex` is itself the proof that the detached signing protocol is correct.
func sign(seedHex string, message []byte) []byte {
	return ed25519.Sign(ed25519.NewKeyFromSeed(unhex(seedHex)), message)
}

// signerFor is the same key as a [dmtapsync.Signer], for the paths that go through SignOp.
func signerFor(seedHex string) dmtapsync.Signer {
	return dmtapsync.InMemorySigner{PrivateKey: ed25519.NewKeyFromSeed(unhex(seedHex))}
}

// --- refusal capture ------------------------------------------------------------------------

// refusal records the registry spelling of a substrate refusal: `code name action`.
//
// A binding error (bad argument, decode failure) is a bug in this harness rather than a verdict
// about the data, so it panics instead of being recorded as if it were a refusal — which would
// make a broken call site look like a conformance result.
func refusal(err error) string {
	if err == nil {
		panic("harness: expected a refusal, but the call succeeded")
	}
	se, ok := dmtapsync.AsSyncError(err)
	if !ok {
		panic(fmt.Sprintf("harness: expected a substrate refusal, got a binding error: %v", err))
	}
	return fmt.Sprintf("%s %s %s", se.Code, se.Name, se.Action)
}

// accepted is the dual of refusal: true when a call is accepted, false when the substrate refuses.
// Used where the property is that a well-formed input is *not* rejected.
func accepted(err error) bool {
	if err == nil {
		return true
	}
	if _, ok := dmtapsync.AsSyncError(err); ok {
		return false
	}
	panic(fmt.Sprintf("harness: expected a substrate refusal or success, got: %v", err))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("harness: %v", err))
	}
	return v
}

func must0(err error) {
	if err != nil {
		panic(fmt.Sprintf("harness: %v", err))
	}
}

// --- small binding helpers --------------------------------------------------------------------

type driver struct{ in *dmtapsync.Instance }

// ingest applies canonical op bytes to a fresh engine, in order.
//
// The engine is intentionally not closed: an [dmtapsync.Instance] reuses handle slots, and the
// whole run is a few dozen engines inside one instance that is closed at the end.
func (d driver) ingest(opsHex []string) *dmtapsync.Engine {
	e := must(d.in.NewEngine())
	for _, h := range opsHex {
		// The return is deliberately ignored, matching the JS harness: some vectors ingest ops the
		// engine refuses, and the refusal is the observation the vector's own executor records.
		_, _ = e.IngestAmbientAuthenticated(unhex(h), receiverNowMS)
	}
	return e
}

// decodeOp returns an op as generic JSON, for the fields the typed struct does not surface
// verbatim.
func (d driver) decodeOp(opHex string) any {
	return decodeJSON(must(d.in.DecodeOpJSON(unhex(opHex))))
}

func (d driver) opHLC(opHex string) dmtapsync.HLC {
	return must(d.in.DecodeOp(unhex(opHex))).HLC
}

// hlcHex is the canonical encoding of an HLC — the spelling the trace compares, so that two HLCs
// are equal exactly when their bytes are.
func (d driver) hlcHex(h dmtapsync.HLC) string {
	return hexs(must(d.in.EncodeHLC(h)))
}

// hlcOf converts the vectors' HLC spelling (`author_hex`) to the binding's.
func hlcOf(v any) dmtapsync.HLC {
	return dmtapsync.HLC{
		Wall:    mustU64(m(v, "wall")),
		Counter: uint32(mustU64(m(v, "counter"))),
		Author:  str(v, "author_hex"),
	}
}

func mustU64(v any) uint64 {
	n, err := v.(json.Number).Int64()
	if err != nil {
		panic(fmt.Sprintf("harness: not an integer: %v", v))
	}
	return uint64(n)
}

// deathLabel renders the death dimension as `deleted:class` or `live` — a label, so the trace holds
// no JSON blob whose formatting the three surfaces would have to agree on separately.
func (d driver) deathLabel(e *dmtapsync.Engine, object string) string {
	s := must(e.DeathState(object))
	if s.Deleted {
		c := ""
		if s.Class != nil {
			c = *s.Class
		}
		return "deleted:" + c
	}
	return "live"
}

// counterLabel renders the per-author §4.6 deltas as `author:P:N`, joined.
func (d driver) counterLabel(e *dmtapsync.Engine, target, field string) string {
	entries := must(e.CounterEntries(target, field))
	parts := []string{}
	for _, en := range entries {
		parts = append(parts, fmt.Sprintf("%s:%d:%d", en.Author, en.P, en.N))
	}
	return strings.Join(parts, ",")
}

// tagged wraps a raw JSON value for the binding's tagged-value arguments.
func tagged(v any) json.RawMessage { return json.RawMessage(encodeJSON(v)) }

// --- the executors ------------------------------------------------------------------------------
//
// One per vector `operation`, each returning a flat map of string values. These mirror trace.mjs
// arm for arm; a divergence in structure here is a divergence in what is being proved.

type executor func(d driver, v any) map[string]string

var executors = map[string]executor{
	"sync_op_encode":                execOpEncode,
	"sync_op_cose_sign1_verify":     execCoseSign1,
	"sync_author_admission":         execAuthorAdmission,
	"sync_lww_merge":                execLWWMerge,
	"sync_orset_merge":              execORSetMerge,
	"sync_orset_remove_validity":    execORSetRemoveValidity,
	"sync_death_domination":         execDeathDomination,
	"sync_death_tie":                execDeathTie,
	"sync_pn_merge":                 execPNMerge,
	"sync_counter_foreign_check":    execCounterForeign,
	"sync_rga_sibling_order":        execRGASiblingOrder,
	"sync_rga_tombstone_origin":     execRGATombstoneOrigin,
	"sync_tree_move_replay":         execTreeMoveReplay,
	"sync_snapshot_state_root":      execSnapshotStateRoot,
	"sync_snapshot_fast_join":       execSnapshotFastJoin,
	"sync_recon_fingerprint":        execReconFingerprint,
	"sync_ns_sparse_filter":         execNsSparseFilter,
	"sync_ns_leak_check":            execNsLeakCheck,
	"sync_fastjoin_pull_response":   execFastJoinPullResponse,
	"sync_fastjoin_floor_predicate": execFastJoinFloorPredicate,
	"sync_gc_stability_cut":         execGCStabilityCut,
	"sync_ext_value_validate":       execExtValueValidate,
	"sync_snapshot_body_fold":       execSnapshotBodyFold,
}

// SYNC-OP-01 — canonical op encoding and the op-id.
func execOpEncode(d driver, v any) map[string]string {
	in := m(v, "input")
	op := map[string]any{
		"kind":   m(in, "kind"),
		"ns":     m(in, "ns"),
		"target": m(in, "target"),
		"field":  m(in, "field"),
		"hlc":    hlcOf(m(in, "hlc")),
	}
	if t, ok := mOpt(in, "value_tstr"); ok {
		op["value"] = map[string]any{"tstr": t}
	} else {
		op["value"] = nil
	}
	built := must(d.in.EncodeOpJSON(encodeJSON(op)))

	// Re-decoding must round-trip to the same fields AND re-encode byte for byte.
	reencoded := must(d.in.EncodeOpJSON(must(d.in.DecodeOpJSON(built))))

	// A non-canonical spelling of the same object is refused, never re-canonicalized: `kind` 3
	// respelled in a two-byte head (0x1803).
	bad := append([]byte{}, built...)
	bad = append(bad[:2], append([]byte{0x18, 0x03}, bad[3:]...)...)
	bad[0] = 0xa6
	_, err := d.in.DecodeOpJSON(bad)

	return map[string]string{
		"op_cbor":      hexs(built),
		"op_id":        hexs(must(d.in.OpID(built))),
		"reencoded":    hexs(reencoded),
		"noncanonical": refusal(err),
	}
}

// SYNC-OP-02 — the COSE_Sign1 envelope, signed through the DETACHED path.
func execCoseSign1(d driver, v any) map[string]string {
	in := m(v, "input")
	op := unhex(str(in, "sync_op_cbor_hex"))
	seed := str(in, "signer_seed_hex")

	si := must(d.in.OpSigningInput(op))
	// The signature is produced OUTSIDE the module, from a key the module never sees.
	signature := sign(seed, must(si.Bytes()))
	cose := must(d.in.OpAttachSignature(op, signature))
	verified := must(d.in.VerifySignedOp(unhex(str(in, "cose_sign1_hex"))))

	_, tamperedErr := d.in.VerifySignedOp(unhex(str(in, "tampered_payload_cose_sign1_hex")))
	_, kidErr := d.in.VerifySignedOp(unhex(str(in, "substituted_kid_cose_sign1_hex")))

	// A third negative the vector's prose demands but does not encode: an envelope minted over any
	// other external_aad must not verify as a SyncOp. Signed here with the same key over the
	// SNAPSHOT DS-tag, then offered to the op verifier.
	sigStruct := must(d.in.EncodeValue(tagged(map[string]any{
		"arr": []any{
			map[string]any{"tstr": "Signature1"},
			map[string]any{"bstr": si.Protected},
			map[string]any{"bstr": hexs([]byte("DMTAP-SYNC-v0/snapshot")) + "00"},
			map[string]any{"bstr": hexs(op)},
		},
	})))
	_, foreignErr := d.in.OpAttachSignature(op, sign(seed, sigStruct))

	return map[string]string{
		"author":          si.Author,
		"protected_bstr":  hexs(must(d.in.EncodeValue(tagged(map[string]any{"bstr": si.Protected})))),
		"unprotected":     hexs(must(d.in.EncodeValue(tagged(map[string]any{"map": []any{}})))),
		"payload_bstr":    hexs(must(d.in.EncodeValue(tagged(map[string]any{"bstr": hexs(op)})))),
		"external_aad":    si.ExternalAAD,
		"sig_structure":   si.SigStructure,
		"signature":       hexs(signature),
		"cose":            hexs(cose),
		"op_id":           hexs(must(d.in.OpID(op))),
		"verified_op":     hexs(verified),
		"tampered":        refusal(tamperedErr),
		"substituted_kid": refusal(kidErr),
		"foreign_ds_tag":  refusal(foreignErr),
	}
}

// SYNC-AUTH-01 — author admission is a gate, not a blanket deny.
func execAuthorAdmission(d driver, v any) map[string]string {
	in := m(v, "input")
	admitted := strList(in, "admitted_authors_hex")
	out := map[string]string{
		"refusal": refusal(d.in.CheckAdmitted(unhex(str(in, "op_hlc_author_hex")), admitted)),
	}
	for i, a := range admitted {
		must0(d.in.CheckAdmitted(unhex(a), admitted))
		out[fmt.Sprintf("admitted_%d_ok", i)] = "true"
	}
	out["op_author"] = d.opHLC(str(in, "op_cbor_hex")).Author
	return out
}

// SYNC-LWW-01 / -02 — one winner, whatever the apply order.
func execLWWMerge(d driver, v any) map[string]string {
	ops := strList(m(v, "input"), "ops_cbor_hex")
	first := d.decodeOp(ops[0])
	target, field := str(first, "target"), str(first, "field")

	cell := func(e *dmtapsync.Engine) (hlc, value, text string) {
		c := must(e.LWWCell(target, field))
		if c == nil {
			return "", "", ""
		}
		t := ""
		if s, ok := mOpt(decodeJSON(string(c.Value)), "tstr"); ok {
			t, _ = s.(string)
		}
		return d.hlcHex(c.HLC), hexs(must(d.in.EncodeValue(c.Value))), t
	}

	fwd := d.ingest(ops)
	rev := d.ingest(reversed(ops))
	fh, fv, ft := cell(fwd)
	rh, rv, _ := cell(rev)

	return map[string]string{
		"winner_hlc":           fh,
		"winner_value":         fv,
		"winner_value_text":    ft,
		"reverse_winner_hlc":   rh,
		"reverse_winner_value": rv,
		"forward_root":         hexs(must(fwd.StateRoot())),
		"reverse_root":         hexs(must(rev.StateRoot())),
	}
}

// SYNC-ORSET-01 — add-wins, and the surviving add-tag is the causal evidence.
func execORSetMerge(d driver, v any) map[string]string {
	in := m(v, "input")
	ops := strList(in, "ops_cbor_hex")
	target := str(d.decodeOp(ops[0]), "target")
	element := tagged(map[string]any{"tstr": str(in, "element")})

	fwd := d.ingest(ops)
	rev := d.ingest(reversed(ops))
	tags := must(fwd.SetSurvivingTags(target, element))

	survivingHLC := ""
	if len(tags) > 0 {
		survivingHLC = d.hlcHex(tags[0].HLC)
	}

	members := []string{}
	for _, pair := range must(fwd.SetMembers()) {
		var tgt string
		must0(json.Unmarshal(pair[0], &tgt))
		members = append(members, tgt+"="+hexs(must(d.in.EncodeValue(pair[1]))))
	}

	return map[string]string{
		"present_forward": boolStr(must(fwd.SetContains(target, element))),
		"present_reverse": boolStr(must(rev.SetContains(target, element))),
		"surviving_count": fmt.Sprint(len(tags)),
		"surviving_hlc":   survivingHLC,
		"members":         strings.Join(members, ","),
	}
}

// SYNC-ORSET-02 — a remove citing a FUTURE add is causally impossible.
func execORSetRemoveValidity(d driver, v any) map[string]string {
	op := unhex(str(m(v, "input"), "op_cbor_hex"))
	e := must(d.in.NewEngine())
	_, ingestErr := e.IngestAmbientAuthenticated(op, receiverNowMS)
	return map[string]string{
		"validate": refusal(d.in.ValidateOp(op, receiverNowMS)),
		// The full ingest path must refuse it too, not only the bare validator.
		"ingest": refusal(ingestErr),
	}
}

// SYNC-DEATH-01 — a death certificate dominates a concurrent add with a GREATER HLC.
func execDeathDomination(d driver, v any) map[string]string {
	in := m(v, "input")
	death, add := str(in, "death_op_cbor_hex"), str(in, "concurrent_add_op_cbor_hex")
	target := str(d.decodeOp(death), "target")
	element := tagged(m(d.decodeOp(add), "value"))
	return map[string]string{
		"present_death_first": boolStr(must(d.ingest([]string{death, add}).SetContains(target, element))),
		"present_add_first":   boolStr(must(d.ingest([]string{add, death}).SetContains(target, element))),
		"add_outranks_death":  boolStr(must(d.in.CompareHLC(d.opHLC(add), d.opHLC(death))) > 0),
	}
}

// SYNC-DEATH-02 — at an exact HLC tie, Deleted beats Live (fail-safe toward deletion).
func execDeathTie(d driver, v any) map[string]string {
	in := m(v, "input")
	death, live := str(in, "death_op_cbor_hex"), str(in, "live_op_cbor_hex")
	target := str(d.decodeOp(death), "target")
	return map[string]string{
		"state_death_first": d.deathLabel(d.ingest([]string{death, live}), target),
		"state_live_first":  d.deathLabel(d.ingest([]string{live, death}), target),
		"hlcs_tie":          boolStr(must(d.in.CompareHLC(d.opHLC(death), d.opHLC(live))) == 0),
	}
}

// SYNC-PN-01 — per-author union of op-id-keyed deltas (§4.6, correction C-01).
func execPNMerge(d driver, v any) map[string]string {
	ops := strList(m(v, "input"), "ops_cbor_hex")
	first := d.decodeOp(ops[0])
	target, field := str(first, "target"), str(first, "field")

	all := d.ingest(ops)
	distinct := d.ingest(ops[:2])
	// A TRUE replay: identical bytes ⇒ identical op-id ⇒ the second delivery is a no-op.
	replayed := d.ingest([]string{ops[0], ops[1], ops[0]})

	ids := map[string]struct{}{}
	for _, o := range ops {
		ids[hexs(must(d.in.OpID(unhex(o))))] = struct{}{}
	}

	return map[string]string{
		"entries":         d.counterLabel(all, target, field),
		"total":           must(all.CounterTotal(target, field)),
		"distinct_total":  must(distinct.CounterTotal(target, field)),
		"replay_total":    must(replayed.CounterTotal(target, field)),
		"replay_entries":  d.counterLabel(replayed, target, field),
		"distinct_op_ids": fmt.Sprint(len(ids)),
	}
}

// SYNC-PN-02 — an author may only mutate its own P/N entry.
func execCounterForeign(d driver, v any) map[string]string {
	in := m(v, "input")
	opAuthor := unhex(str(in, "op_hlc_author_hex"))
	return map[string]string{
		"refusal":      refusal(d.in.CheckCounterEntry(opAuthor, unhex(str(in, "target_entry_author_hex")))),
		"own_entry_ok": boolStr(d.in.CheckCounterEntry(opAuthor, opAuthor) == nil),
	}
}

// SYNC-RGA-01 — concurrent siblings order by element id, descending.
func execRGASiblingOrder(d driver, v any) map[string]string {
	in := m(v, "input")
	origin := str(in, "origin_op_cbor_hex")
	sibs := strList(in, "sibling_ops_cbor_hex")
	target := str(d.decodeOp(origin), "target")

	run := func(ops []string) (values, ids string) {
		seq := must(d.ingest(ops).Sequence(target))
		vs, is := []string{}, []string{}
		for _, val := range seq.Values {
			vs = append(vs, tstrOf(val))
		}
		for _, a := range seq.Atoms {
			is = append(is, d.hlcHex(a.ID))
		}
		return strings.Join(vs, ","), strings.Join(is, ",")
	}

	fv, fi := run(append([]string{origin}, sibs...))
	rv, ri := run(append([]string{origin}, reversed(sibs)...))
	return map[string]string{
		"values_forward": fv, "ids_forward": fi,
		"values_reverse": rv, "ids_reverse": ri,
	}
}

// SYNC-RGA-02 — an insert whose origin is tombstoned still resolves.
func execRGATombstoneOrigin(d driver, v any) map[string]string {
	in := m(v, "input")
	insertX := str(in, "insert_x_cbor_hex")
	insertY := str(in, "insert_y_cbor_hex")
	target := str(d.decodeOp(insertX), "target")

	seq := must(d.ingest([]string{insertX, str(in, "remove_x_cbor_hex"), insertY}).Sequence(target))

	visible := []string{}
	for _, val := range seq.Values {
		visible = append(visible, tstrOf(val))
	}
	labels := []string{}
	resolves := false
	wantID := d.hlcHex(d.opHLC(insertY))
	for _, a := range seq.Atoms {
		// The vector's `atom_order_incl_tombstones` is a LABEL list, rendered here from the actual
		// atom order rather than restated.
		label := tstrOf(a.Value)
		if a.Tombstoned {
			label += "(tombstoned)"
		}
		labels = append(labels, label)
		if d.hlcHex(a.ID) == wantID {
			resolves = true
		}
	}
	return map[string]string{
		"visible":  strings.Join(visible, ","),
		"labels":   strings.Join(labels, ","),
		"resolves": boolStr(resolves),
	}
}

// SYNC-TREE-01 — a concurrent move that would close a cycle is skipped, identically everywhere.
func execTreeMoveReplay(d driver, v any) map[string]string {
	in := m(v, "input")
	colliding := strList(in, "colliding_ops_cbor_hex")
	ops := append(append([]string{}, strList(in, "baseline_ops_cbor_hex")...), colliding...)

	h1, h2 := d.opHLC(colliding[0]), d.opHLC(colliding[1])
	h1Hex, h2Hex := d.hlcHex(h1), d.hlcHex(h2)
	label := func(h dmtapsync.HLC) string {
		switch d.hlcHex(h) {
		case h1Hex:
			return "h1"
		case h2Hex:
			return "h2"
		}
		return "?"
	}

	orders := [][]string{ops, reversed(ops), {ops[3], ops[2], ops[0], ops[1]}}
	out := map[string]string{"h1_before_h2": boolStr(must(d.in.CompareHLC(h1, h2)) < 0)}
	for i, order := range orders {
		t := must(d.ingest(order).Tree())
		edges := []string{}
		parent := map[string]string{}
		for _, e := range t.Edges {
			edges = append(edges, fmt.Sprintf("%s>%s:%s", e[0], e[1], e[2]))
			parent[e[0]] = e[1]
		}
		skipped := []string{}
		for _, s := range t.Skipped {
			skipped = append(skipped, label(s.HLC))
		}
		// Acyclicity, checked rather than assumed.
		for node := range parent {
			cur, steps := node, 0
			for {
				next, ok := parent[cur]
				if !ok {
					break
				}
				cur = next
				steps++
				if steps > len(parent) {
					panic("harness: cycle reachable from " + node)
				}
			}
		}
		out[fmt.Sprintf("edges_%d", i)] = strings.Join(edges, ",")
		out[fmt.Sprintf("skipped_%d", i)] = strings.Join(skipped, ",")
		out[fmt.Sprintf("acyclic_%d", i)] = "true"
	}
	return out
}

// SYNC-SNAP-01 — the canonical six-section state and its root.
func execSnapshotStateRoot(d driver, v any) map[string]string {
	state := observableToBinding(m(m(v, "input"), "observable_state"))
	cbor := must(d.in.EncodeObservableStateJSON(encodeJSON(state)))
	empty := must(d.in.EncodeObservableStateJSON(
		`{"orset":[],"lww":[],"pn":[],"death":[],"rga":[],"tree":[]}`))

	// Section entries sort by det_cbor, so a shuffled projection hashes identically.
	shuffled := cloneSections(state)
	shuffled["tree"] = reversedAny(shuffled["tree"])
	shuffled["lww"] = reversedAny(shuffled["lww"])

	// A one-bit difference in observable state is a DIFFERENT root ⇒ 0x0A09 evidence.
	diverged := cloneSections(state)
	dl := append([]any{}, diverged["lww"]...)
	if len(dl) > 0 {
		row := dl[0].([]any)
		dl[0] = []any{row[0], row[1], map[string]any{"tstr": "DIVERGED"}}
	}
	diverged["lww"] = dl

	return map[string]string{
		"state_cbor":    hexs(cbor),
		"root":          hexs(must(d.in.ObservableStateRoot(cbor))),
		"empty_cbor":    hexs(empty),
		"empty_root":    hexs(must(d.in.ObservableStateRoot(empty))),
		"shuffled_cbor": hexs(must(d.in.EncodeObservableStateJSON(encodeJSON(shuffled)))),
		"diverged_root": hexs(must(d.in.ObservableStateRoot(
			must(d.in.EncodeObservableStateJSON(encodeJSON(diverged)))))),
		"roundtrip_cbor": hexs(must(d.in.EncodeObservableState(must(d.in.DecodeObservableState(cbor))))),
	}
}

// SYNC-SNAP-02 — adopting a checkpoint then applying the suffix equals a full replay.
func execSnapshotFastJoin(d driver, v any) map[string]string {
	in := m(v, "input")
	body := unhex(str(in, "snapshot_observable_state_cbor_hex"))
	// Through the raw escape hatch rather than DecodeObservableState: the JS harness mutates the
	// engine's exact JSON spelling and re-encodes it, and round-tripping through the typed struct
	// here would be a re-statement of the sections rather than a measurement of them.
	adopted := decodeJSON(jsonString(must(d.in.Call("decode_observable_state", hexs(body)))))

	// Apply the post-`covers` ops to the adopted projection — what a replica does after adopting.
	lww := m(adopted, "lww").([]any)
	for _, opHex := range strList(in, "post_covers_ops_cbor_hex") {
		op := d.decodeOp(opHex)
		target, field, value := str(op, "target"), str(op, "field"), m(op, "value")
		found := false
		for _, row := range lww {
			cell := row.([]any)
			if cell[0] == target && cell[1] == field {
				cell[2] = value
				found = true
				break
			}
		}
		if !found {
			lww = append(lww, []any{target, field, value})
		}
	}
	adopted.(map[string]any)["lww"] = lww

	joined := must(d.in.EncodeObservableStateJSON(encodeJSON(adopted)))
	return map[string]string{
		"snapshot_root_recomputed": hexs(must(d.in.ObservableStateRoot(body))),
		"fast_join_state":          hexs(joined),
		"root":                     hexs(must(d.in.ObservableStateRoot(joined))),
	}
}

// SYNC-RECON-01 — the range-Merkle fold and the recursive diff.
func execReconFingerprint(d driver, v any) map[string]string {
	in := m(v, "input")
	out := map[string]string{}

	entries := map[string]dmtapsync.OpEntry{}
	opsByLabel := m(in, "ops_cbor_hex").(map[string]any)
	for label, opHex := range opsByLabel {
		h := opHex.(string)
		id := hexs(must(d.in.OpID(unhex(h))))
		entries[label] = dmtapsync.OpEntry{HLC: d.opHLC(h), ID: id}
		out["op_id_"+label] = id
	}
	holds := func(key string) []dmtapsync.OpEntry {
		e := []dmtapsync.OpEntry{}
		for _, l := range strList(in, key) {
			e = append(e, entries[l])
		}
		return e
	}
	A, B := holds("replica_A_holds"), holds("replica_B_holds")

	rng := m(in, "range")
	lo, hi := hlcOf(m(rng, "lo")), hlcOf(m(rng, "hi"))
	split := hlcOf(m(in, "split_at"))

	for _, side := range []struct {
		name string
		set  []dmtapsync.OpEntry
	}{{"A", A}, {"B", B}} {
		for _, r := range []struct {
			name   string
			lo, hi dmtapsync.HLC
		}{{"full", lo, hi}, {"sub1", lo, split}, {"sub2", split, hi}} {
			s := must(d.in.Summarize(side.set, r.lo, r.hi))
			out[r.name+"_"+side.name+"_fp"] = s.FP
			out[r.name+"_"+side.name+"_count"] = fmt.Sprint(s.Count)
		}
	}

	empty := must(d.in.Fingerprint(nil))
	out["empty_fp"] = empty.FP
	out["empty_count"] = fmt.Sprint(empty.Count)

	rec := must(d.in.Reconcile(B, A, lo, hi))
	out["shipped_to_B"] = strings.Join(rec.MissingHere, ",")
	out["shipped_to_A"] = strings.Join(rec.MissingThere, ",")
	return out
}

// SYNC-NS-01 — a responder ships only the namespaces the caller subscribed to.
func execNsSparseFilter(d driver, v any) map[string]string {
	in := m(v, "input")
	ops := []any{}
	for _, h := range strList(in, "responder_ops_cbor_hex") {
		ops = append(ops, d.decodeOp(h))
	}
	shipped := must(d.in.ScopeToSubscription(encodeJSON(ops), strList(in, "caller_subscribed_ns")))

	hexes, namespaces := []string{}, []string{}
	for _, b := range shipped {
		hexes = append(hexes, hexs(b))
		namespaces = append(namespaces, str(d.decodeOp(hexs(b)), "ns"))
	}
	return map[string]string{
		"shipped":    strings.Join(hexes, ","),
		"shipped_ns": strings.Join(namespaces, ","),
	}
}

// SYNC-NS-02 — a cross-namespace reference is a leak, not a convenience.
func execNsLeakCheck(d driver, v any) map[string]string {
	in := m(v, "input")
	op := d.decodeOp(str(in, "op_cbor_hex"))
	ns := str(op, "ns")
	return map[string]string{
		"op_ns":      ns,
		"ref_target": str(m(op, "reference"), "target"),
		"refusal":    refusal(d.in.CheckNsRef(ns, str(in, "ref_target_actual_ns"))),
		"same_ns_ok": boolStr(d.in.CheckNsRef(ns, ns) == nil),
	}
}

// SYNC-FJ-01 — the frozen FastJoin / pull response encoding.
func execFastJoinPullResponse(d driver, v any) map[string]string {
	in := m(v, "input")

	// The snapshot is re-signed here through the DETACHED path — the seed never enters the module.
	unsigned := dmtapsync.Snapshot{
		V: 0, Suite: 1,
		NS:     str(in, "snapshot_ns"),
		Covers: d.coversMarks(str(in, "snapshot_covers_cbor_hex")),
		Root:   str(in, "snapshot_root_hex"),
		TS:     mustU64(m(in, "snapshot_ts")),
		Signer: str(in, "snapshot_signer_pubkey_hex"),
	}
	preimage := must(d.in.SnapshotSigningInput(unsigned))
	sig := sign(str(in, "snapshot_signer_seed_hex"), preimage)
	snapshot := must(d.in.SnapshotAssemble(unsigned, sig))

	floor := d.svalToHLC(decodeJSON(string(must(d.in.DecodeValue(unhex(str(in, "floor_hlc_cbor_hex")))))))
	decoded := must(d.in.SnapshotDecode(snapshot))
	mk := func(state *string) []byte {
		return must(d.in.FastJoinEncode(dmtapsync.FastJoin{Snapshot: decoded, Floor: floor, State: state}))
	}
	stateHex := str(in, "observable_state_cbor_hex")
	byRef := mk(nil)
	inline := mk(&stateHex)

	// Adoption runs against a CONFORMANT §6.1.2 body — an op set — because this vector's frozen
	// `observable_state_cbor_hex` is a state DOCUMENT and predates C-09. The response ENCODING
	// assertions above are unchanged by C-09 and still reproduce the frozen bytes; only adoption
	// moved.
	opBody := d.conformantBody(str(in, "snapshot_signer_seed_hex"), str(in, "snapshot_signer_pubkey_hex"))
	opRoot := must(d.in.ObservableStateRoot(must(d.in.SnapshotBodyFold(opBody, "", receiverNowMS))))
	opUnsigned := unsigned
	opUnsigned.Root = hexs(opRoot)
	opSnapshot := must(d.in.SnapshotAssemble(opUnsigned,
		sign(str(in, "snapshot_signer_seed_hex"), must(d.in.SnapshotSigningInput(opUnsigned)))))
	opDecoded := must(d.in.SnapshotDecode(opSnapshot))
	mkOp := func(state *string) []byte {
		return must(d.in.FastJoinEncode(
			dmtapsync.FastJoin{Snapshot: opDecoded, Floor: floor, State: state}))
	}

	// A corrupted inline hint must be DISCARDED in favour of the fetched body, not adopted...
	corrupt := append([]byte{}, opBody...)
	corrupt[len(corrupt)-1] ^= 0xff
	corruptHex := hexs(corrupt)
	hinted := mkOp(&corruptHex)
	body := unhex(stateHex)
	adopted := must(d.in.FastJoinAdopt(hinted, []dmtapsync.Mark{}, nil, nil, receiverNowMS, opBody))

	// ...and with nothing fetchable, the same unverifiable hint fails CLOSED.
	_, unfetchableErr := d.in.FastJoinAdopt(hinted, []dmtapsync.Mark{}, nil, nil, receiverNowMS, nil)

	return map[string]string{
		"snapshot_preimage":        hexs(preimage),
		"snapshot_sig":             hexs(sig),
		"snapshot_cbor":            hexs(snapshot),
		"state_root":               hexs(must(d.in.ObservableStateRoot(body))),
		"fastjoin_cbor":            hexs(byRef),
		"pull_cbor":                hexs(d.pullEnvelope(byRef)),
		"pull_inline_cbor":         hexs(d.pullEnvelope(inline)),
		"fastjoin_roundtrip":       hexs(must(d.in.FastJoinEncode(must(d.in.FastJoinDecode(byRef))))),
		"state_address":            hexs(must(d.in.FastJoinStateAddress(byRef))),
		"adopted_state":            hexs(adopted),
		"adopted_root":             hexs(must(d.in.ObservableStateRoot(adopted))),
		"op_body_cbor":             hexs(opBody),
		"corrupt_hint_unfetchable": refusal(unfetchableErr),
		"caller_at_covers_below_floor": boolStr(must(d.in.CallerIsBelowFloor(
			snapshot, d.coversMarks(str(in, "snapshot_covers_cbor_hex"))))),
	}
}

// conformantBody builds a minimal but genuine §6.1.2 SnapshotBody: one signed LWW op, the same
// shape SYNC-SNAP-03 freezes. Used where a vector freezes a response ENCODING but predates C-09's
// body type.
//
// The op is signed through the DETACHED path, like everything else here — the seed never enters
// the module (the no-raw-key rule).
func (d driver) conformantBody(seedHex, authorHex string) []byte {
	op := must(d.in.EncodeOp(dmtapsync.Op{
		Kind:   3,
		NS:     "",
		Target: "doc1",
		Field:  ptr("title"),
		Value:  tagged(map[string]any{"tstr": "n"}),
		HLC:    dmtapsync.HLC{Wall: 1700000100000, Counter: 4, Author: authorHex},
	}))
	si := must(d.in.OpSigningInput(op))
	cose := must(d.in.OpAttachSignature(op, sign(seedHex, unhex(si.SigStructure))))
	return must(d.in.SnapshotBodyEncode([]string{hexs(cose)}))
}

// SYNC-VAL-01 — the ext-value boundary from both sides (§4.1/§4.1.1, C-08).
//
// Both stages are recorded per case, because C-08 is precisely the conflation of the two: a
// text-keyed map used to have no ENCODER path (it could not be built at all), while an
// integer-keyed map is encodable and correctly VALIDATES to false.
func execExtValueValidate(d driver, v any) map[string]string {
	in := m(v, "input")
	out := map[string]string{}
	for _, raw := range list(in, "accept") {
		name, h := str(raw, "case"), str(raw, "cbor_hex")
		val := must(d.in.DecodeValue(unhex(h))) // errors if it cannot even be represented
		out["accept_"+name] = boolStr(must(d.in.IsExtValue(val)))
		out["accept_"+name+"_reencoded"] = hexs(must(d.in.EncodeValue(val)))
	}
	for _, raw := range list(in, "reject") {
		name, h := str(raw, "case"), str(raw, "cbor_hex")
		// The STAGE is recorded, not the message: the three surfaces word their decoder errors
		// differently and that is a binding detail, never a substrate one.
		verdict := "undecodable"
		if val, err := d.in.DecodeValue(unhex(h)); err == nil {
			verdict = "validates: " + boolStr(must(d.in.IsExtValue(val)))
		}
		out["reject_"+name] = verdict
	}

	carrier := unhex(str(in, "carrier_op_cbor_hex"))
	out["carrier_valid"] = boolStr(accepted(d.in.ValidateOp(carrier, receiverNowMS)))
	out["carrier_reencoded"] = hexs(must(d.in.EncodeOpJSON(must(d.in.DecodeOpJSON(carrier)))))
	out["carrier_op_id"] = hexs(must(d.in.OpID(carrier)))
	decoded := must(d.in.DecodeOp(carrier))
	// The value's CANONICAL BYTES, not a Go spelling: the bytes are the semantics (§2.2).
	out["carrier_value_cbor"] = hexs(must(d.in.EncodeValue(decoded.Value)))

	// §4.1.1: the merge unit is the WHOLE value — nesting is representation, never per-key merge.
	rival := decoded
	rival.HLC.Counter++
	rival.Value = tagged(map[string]any{"tmap": []any{[]any{"x", map[string]any{"int": 99}}}})
	e := d.ingest([]string{hexs(carrier), hexs(must(d.in.EncodeOp(rival)))})
	cell := must(e.LWWCell(decoded.Target, *decoded.Field))
	out["whole_value_wins"] = hexs(must(d.in.EncodeValue(cell.Value)))
	out["refusal_code"] = "0x0A03 ERR_SYNC_OP_INVALID FAIL_CLOSED_BLOCK"
	return out
}

// SYNC-SNAP-03 — the body is an op set, verified by fold-then-recompute (§6.1.2, C-09).
func execSnapshotBodyFold(d driver, v any) map[string]string {
	in, expected := m(v, "input"), m(v, "expected")
	_ = expected
	bodyBytes := unhex(str(in, "snapshot_body_cbor_hex"))
	members := must(d.in.SnapshotBodyDecode(bodyBytes))
	root := unhex(str(in, "snapshot_root_hex"))
	folded := must(d.in.SnapshotBodyVerifyRoot(bodyBytes, root, "", receiverNowMS))

	opIDs := []string{}
	for _, mem := range members {
		opIDs = append(opIDs, hexs(must(d.in.OpID(must(d.in.VerifySignedOp(unhex(mem)))))))
	}
	out := map[string]string{
		"body_roundtrip": hexs(must(d.in.SnapshotBodyEncode(members))),
		"member_count":   fmt.Sprint(len(members)),
		"member_op_ids":  strings.Join(opIDs, ","),
		"folded_state":   hexs(folded),
		"folded_root":    hexs(must(d.in.ObservableStateRoot(folded))),
	}

	// A body that does not PRODUCE the root it is offered against is 0x0A09, discarded whole.
	tamperedState := must(d.in.DecodeObservableState(folded))
	tamperedState.LWW[0][2] = tagged(map[string]any{"tstr": "TAMPERED"})
	wrongRoot := must(d.in.ObservableStateRoot(must(d.in.EncodeObservableState(tamperedState))))
	_, wrongRootErr := d.in.SnapshotBodyVerifyRoot(bodyBytes, wrongRoot, "", receiverNowMS)
	out["wrong_root_refusal"] = refusal(wrongRootErr)

	// The ordering demo: (W,3,B) is genuinely after `covers` and still BELOW the incumbent (W,4,A).
	post := must(d.in.VerifySignedOp(unhex(str(in, "post_covers_op_cbor_hex"))))
	postHLC := must(d.in.DecodeOp(post)).HLC
	incumbent := must(d.in.DecodeOp(must(d.in.VerifySignedOp(unhex(members[0])))))
	afterCovers := true
	for _, mark := range d.coversMarks(str(in, "snapshot_covers_cbor_hex")) {
		if mark.Author == postHLC.Author {
			afterCovers = must(d.in.CompareHLC(postHLC, mark.HLC)) > 0
		}
	}
	out["post_op_is_after_covers"] = boolStr(afterCovers)
	out["post_op_is_below_incumbent"] = boolStr(must(d.in.CompareHLC(postHLC, incumbent.HLC)) < 0)

	// The conformant replica FOLDED the body, so it holds the incumbent's HLC and keeps it.
	conformant := must(d.in.NewEngine())
	for _, mem := range members {
		must(conformant.IngestSigned(unhex(mem), receiverNowMS))
	}
	must(conformant.IngestSigned(unhex(str(in, "post_covers_op_cbor_hex")), receiverNowMS))
	after := must(conformant.ObservableState())
	out["state_after_post_op"] = hexs(after)
	out["root_after_post_op"] = hexs(must(d.in.ObservableStateRoot(after)))
	cell := must(conformant.LWWCell(incumbent.Target, *incumbent.Field))
	out["winning_value_after_post_op"] = str(decodeJSON(string(cell.Value)), "tstr")

	// The projection-adopter has the VALUE but not its HLC, so the same op wins — a different
	// root, permanently, with no error raised on either side.
	projection := must(d.in.NewEngine())
	must(projection.IngestSigned(unhex(str(in, "post_covers_op_cbor_hex")), receiverNowMS))
	projected := must(projection.ObservableState())
	out["projection_adopt_state"] = hexs(projected)
	out["projection_adopt_root"] = hexs(must(d.in.ObservableStateRoot(projected)))
	out["roots_differ"] = boolStr(
		hexs(must(d.in.ObservableStateRoot(projected))) != hexs(must(d.in.ObservableStateRoot(after))))
	return out
}

// SYNC-FJ-02 — the MUST in both directions, and the caller-side fail-closed paths.
func execFastJoinFloorPredicate(d driver, v any) map[string]string {
	in, expected := m(v, "input"), m(v, "expected")

	fj := d.fastjoinFromPull(str(expected, "caller_behind_response_cbor_hex"))
	decoded := must(d.in.FastJoinDecode(fj))
	decoded.State = nil
	snap := must(d.in.FastJoinEncode(decoded))
	snapBytes := d.snapshotOf(fj)

	behind := d.coversMarks(str(in, "caller_behind_vector_cbor_hex"))
	caughtUp := d.coversMarks(str(in, "caller_caught_up_vector_cbor_hex"))
	suffix := strList(in, "surviving_suffix_ops_cbor_hex")

	// The forbidden answer is WELL-FORMED — recomputed here, which is why the MUST is needed.
	embedded := []any{}
	wrapped := []any{}
	for _, h := range suffix {
		embedded = append(embedded, decodeJSON(string(must(d.in.DecodeValue(unhex(h))))))
		// C-06: the NON-conformant bstr-wrapped framing, recomputed so the wrong answer is
		// recognized rather than merely avoided. Same suffix, members wrapped instead of embedded.
		wrapped = append(wrapped, map[string]any{"bstr": h})
	}
	wouldBe := must(d.in.EncodeValue(tagged(map[string]any{
		"map": []any{[]any{1, map[string]any{"arr": embedded}}}})))
	bstrWrapped := must(d.in.EncodeValue(tagged(map[string]any{
		"map": []any{[]any{1, map[string]any{"arr": wrapped}}}})))

	// C-07: the same root AND covers twice is a responder loop.
	prevRoot := must(d.in.FastJoinStateAddress(fj))
	prevCovers := d.coversMarks(str(in, "responder_snapshot_covers_cbor_hex"))

	_, stateUnavailableErr := d.in.FastJoinAdopt(fj, behind, nil, nil, receiverNowMS, nil)
	_, caughtUpErr := d.in.FastJoinAdopt(fj, caughtUp, nil, nil, receiverNowMS, nil)

	return map[string]string{
		"behind_is_below_floor":     boolStr(must(d.in.CallerIsBelowFloor(snapBytes, behind))),
		"caught_up_is_below_floor":  boolStr(must(d.in.CallerIsBelowFloor(snapBytes, caughtUp))),
		"ops_response_would_be":     hexs(wouldBe),
		"bstr_wrapped_ops_response": hexs(bstrWrapped),
		"fastjoin_roundtrip":        hexs(snap),
		// The rejected naive predicate fires TRUE on this well-formed fast-join...
		"naive_covers_lacks_floor_rejected": boolStr(
			must(d.in.FastJoinNaiveCoversLacksFloorRejected(fj))),
		// ...and step 2 accepts the fast-join anyway. That is the whole of C-07.
		"step2_accepts_conformant_floor_above_covers": boolStr(
			accepted(d.in.FastJoinCheckCovers(fj, behind))),
		"covers_carries_floor_author_mark": boolStr(
			must(d.in.FastJoinCoversCarriesFloorAuthorMark(fj))),
		// The §5.2.1 step-5 progress MUST: re-offering the same checkpoint is 0x0A09.
		"first_round_makes_progress": boolStr(accepted(d.in.FastJoinCheckProgress(fj, nil, nil))),
		"repeated_fastjoin_refusal":  refusal(d.in.FastJoinCheckProgress(fj, prevRoot, prevCovers)),
		// A body no holder can serve: 0x0A0C, fail-closed, never a fallback to the suffix.
		"state_unavailable": refusal(stateUnavailableErr),
		// And a caught-up caller must not be fast-joined at all.
		"caught_up_refuses_fastjoin": refusal(caughtUpErr),
	}
}

// SYNC-GC-01 — the stability cut, and that GC below it is observably a no-op.
func execGCStabilityCut(d driver, v any) map[string]string {
	in := m(v, "input")
	live := []*dmtapsync.HLC{}
	for _, w := range list(in, "live_replica_watermarks") {
		h := hlcOf(m(w, "max_applied_hlc"))
		live = append(live, &h)
	}
	cut := must(d.in.StabilityCut(live))
	stale := hlcOf(m(m(in, "stale_replica_watermark"), "max_applied_hlc"))
	withStale := must(d.in.StabilityCut(append(append([]*dmtapsync.HLC{}, live...), &stale)))

	// Fail-closed: a live replica with NO known watermark yields no cut at all.
	unknown, err := d.in.StabilityCut(append(append([]*dmtapsync.HLC{}, live...), nil))
	must0(err)
	unknownStr := "null"
	if unknown != nil {
		unknownStr = encodeJSON(unknown)
	}

	// Build a collapsed add/tombstone pair strictly below the cut, through real ops, and prune it.
	author := cut.Author
	addHLC := dmtapsync.HLC{Wall: cut.Wall, Counter: 1, Author: author}
	rmHLC := dmtapsync.HLC{Wall: cut.Wall, Counter: 2, Author: author}
	add := hexs(must(d.in.EncodeOp(dmtapsync.Op{
		Kind: 1, NS: "", Target: "tags", Value: dmtapsync.Text("e1"), HLC: addHLC})))
	remove := hexs(must(d.in.EncodeOp(dmtapsync.Op{
		Kind: 2, NS: "", Target: "tags", Value: dmtapsync.Text("e1"), HLC: rmHLC,
		Observed: []dmtapsync.AddTag{{Author: author, HLC: addHLC}}})))

	engine := d.ingest([]string{add, remove})
	before := hexs(must(engine.ObservableState()))
	pruned := must(engine.PruneBelow(*cut))

	return map[string]string{
		"cut":                   d.hlcHex(*cut),
		"cut_counter":           fmt.Sprint(cut.Counter),
		"with_stale":            d.hlcHex(*withStale),
		"stale_drags_cut_down":  boolStr(must(d.in.CompareHLC(*withStale, *cut)) < 0),
		"unknown_watermark_cut": unknownStr,
		"pruned_something":      boolStr(pruned > 0),
		"state_before_gc":       before,
		"state_after_gc":        hexs(must(engine.ObservableState())),
	}
}

// --- shared shapes ------------------------------------------------------------------------------

// pullEnvelope builds `{2: FastJoin}` — the §5.2.1 pull envelope, via the generic CBOR helpers.
func (d driver) pullEnvelope(fastjoinBytes []byte) []byte {
	inner := decodeJSON(string(must(d.in.DecodeValue(fastjoinBytes))))
	return must(d.in.EncodeValue(tagged(map[string]any{"map": []any{[]any{2, inner}}})))
}

// fastjoinFromPull pulls the FastJoin bytes back out of a `{2: FastJoin}` response.
func (d driver) fastjoinFromPull(pullHex string) []byte {
	outer := decodeJSON(string(must(d.in.DecodeValue(unhex(pullHex)))))
	return must(d.in.EncodeValue(tagged(mapEntry(outer, 2))))
}

// snapshotOf returns the snapshot bytes inside a FastJoin.
func (d driver) snapshotOf(fastjoinBytes []byte) []byte {
	inner := decodeJSON(string(must(d.in.DecodeValue(fastjoinBytes))))
	return must(d.in.EncodeValue(tagged(mapEntry(inner, 1))))
}

// mapEntry finds an entry by integer key in a generic CBOR `{map:[[k,v],...]}`.
func mapEntry(sval any, key int64) any {
	for _, e := range m(sval, "map").([]any) {
		pair := e.([]any)
		if n, ok := pair[0].(json.Number); ok {
			if i, err := n.Int64(); err == nil && i == key {
				return pair[1]
			}
		}
	}
	panic(fmt.Sprintf("harness: no map entry with key %d", key))
}

// svalToHLC turns an HLC decoded as a generic CBOR map back into the binding's spelling.
func (d driver) svalToHLC(sval any) dmtapsync.HLC {
	f := map[int64]any{}
	for _, e := range m(sval, "map").([]any) {
		pair := e.([]any)
		k, _ := pair[0].(json.Number).Int64()
		f[k] = pair[1]
	}
	return dmtapsync.HLC{
		Wall:    mustU64(m(f[1], "int")),
		Counter: uint32(mustU64(m(f[2], "int"))),
		Author:  str(f[3], "bstr"),
	}
}

// coversMarks turns a VersionVector's CBOR into the `[{author, hlc}]` marks the binding takes.
func (d driver) coversMarks(vectorHex string) []dmtapsync.Mark {
	sval := decodeJSON(string(must(d.in.DecodeValue(unhex(vectorHex)))))
	marks := []dmtapsync.Mark{}
	for _, e := range m(sval, "bmap").([]any) {
		pair := e.([]any)
		marks = append(marks, dmtapsync.Mark{
			Author: pair[0].(string),
			HLC:    d.svalToHLC(pair[1]),
		})
	}
	return marks
}

// observableToBinding retags the vectors' bare-string observable state as tagged values.
func observableToBinding(o any) map[string][]any {
	out := map[string][]any{}
	retag := func(section string, f func(row []any) []any) {
		rows := []any{}
		for _, r := range m(o, section).([]any) {
			rows = append(rows, f(r.([]any)))
		}
		out[section] = rows
	}
	retag("orset", func(r []any) []any { return []any{r[0], map[string]any{"tstr": r[1]}} })
	retag("lww", func(r []any) []any { return []any{r[0], r[1], map[string]any{"tstr": r[2]}} })
	retag("pn", func(r []any) []any { return []any{r[0], r[1], fmt.Sprint(r[2])} })
	retag("death", func(r []any) []any { return []any{r[0], r[1]} })
	retag("rga", func(r []any) []any {
		atoms := []any{}
		for _, a := range r[1].([]any) {
			atoms = append(atoms, map[string]any{"tstr": a})
		}
		return []any{r[0], atoms}
	})
	retag("tree", func(r []any) []any { return []any{r[0], r[1], r[2]} })
	return out
}

func cloneSections(s map[string][]any) map[string][]any {
	out := map[string][]any{}
	for k, v := range s {
		out[k] = append([]any{}, v...)
	}
	return out
}

// tstrOf reads the text out of a tagged value, or "" for a tombstone / non-text.
func tstrOf(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	if s, ok := mOpt(decodeJSON(string(v)), "tstr"); ok {
		t, _ := s.(string)
		return t
	}
	return ""
}

func reversed(s []string) []string {
	out := append([]string{}, s...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func reversedAny(s []any) []any {
	out := append([]any{}, s...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// stringValue reads a JSON string result, for the few places that go through the raw Call escape
// hatch rather than a typed method.
type rawResult = json.RawMessage

func jsonString(r rawResult) string {
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		panic(fmt.Sprintf("harness: expected a JSON string, got %s", r))
	}
	return s
}

// --- the run ------------------------------------------------------------------------------------

type traceResult struct {
	trace   map[string]map[string]string
	covered []string
	skipped []string
}

// runVectors drives every vector through the binding.
func runVectors(in *dmtapsync.Instance, vectorFile any) traceResult {
	d := driver{in: in}
	res := traceResult{trace: map[string]map[string]string{}}
	for _, raw := range list(vectorFile, "vectors") {
		name, op := str(raw, "name"), str(raw, "operation")
		if _, ok := notCovered[op]; ok {
			res.skipped = append(res.skipped, name)
			continue
		}
		exec, ok := executors[op]
		if !ok {
			panic(fmt.Sprintf(
				"no Go executor registered for operation `%s` (vector %s) — a new vector must be "+
					"driven through ALL THREE surfaces or named in notCovered with a reason", op, name))
		}
		res.trace[name] = exec(d, raw)
		res.covered = append(res.covered, name)
	}
	sort.Strings(res.covered)
	return res
}

// diffTraces reports every value on which two traces disagree.
func diffTraces(got, want map[string]map[string]string) []string {
	var out []string
	names := map[string]struct{}{}
	for n := range got {
		names[n] = struct{}{}
	}
	for n := range want {
		names[n] = struct{}{}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	for _, n := range sorted {
		g, gok := got[n]
		w, wok := want[n]
		if !gok {
			out = append(out, fmt.Sprintf("  %s: driven by the other surface but not by Go", n))
			continue
		}
		if !wok {
			out = append(out, fmt.Sprintf("  %s: driven by Go but not by the other surface", n))
			continue
		}
		keys := map[string]struct{}{}
		for k := range g {
			keys[k] = struct{}{}
		}
		for k := range w {
			keys[k] = struct{}{}
		}
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			gv, gok := g[k]
			wv, wok := w[k]
			switch {
			case !gok:
				out = append(out, fmt.Sprintf("  %s.%s missing from the Go trace", n, k))
			case !wok:
				out = append(out, fmt.Sprintf("  %s.%s is in the Go trace only", n, k))
			case gv != wv:
				out = append(out, fmt.Sprintf("  %s.%s\n    other:  %s\n    go:     %s", n, k, wv, gv))
			}
		}
	}
	return out
}

// ed25519KeyFromSeed builds a crypto.Signer over a vector's fixed seed, for the CryptoSigner path.
func ed25519KeyFromSeed(seedHex string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(unhex(seedHex))
}
