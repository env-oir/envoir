// THE PROOF (`substrate/BINDINGS.md` §4): the frozen Sync conformance vectors, driven through the
// Go binding, asserted byte-for-byte against (a) the vectors themselves and (b) the trace recorded
// from the native Rust runner — the same trace the JS/WASM surface is held to.
//
// Three surfaces, one set of frozen bytes, zero divergence. Without this the binding is a claim
// rather than a guarantee: nothing else stops a marshalling layer from quietly reordering a map,
// widening an integer, or normalising a string on its way in or out.
//
// Run, from the repo root:
//
//	crates/dmtap-sync-wasm/build-abi.sh                    # the module this embeds
//	cargo test -p dmtap-sync-wasm --test native_trace      # native Rust, records the trace
//	go test ./bindings/go/...                              # this file, diffed against it
//
// If this suite fails, the binding is wrong — there is only one implementation of the algebra for
// it to disagree with. A failure here is never "the Go harness needs adjusting".
package dmtapsync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dmtapsync "github.com/vul-os/envoir/bindings/go"
)

// The frozen vectors live in the sibling spec repo; the native trace lives beside the Rust harness
// that records it.
const (
	vectorsPath     = "../../../dmtap/conformance/vectors/sync_vectors.json"
	nativeTracePath = "../../crates/dmtap-sync-wasm/test/native-trace.json"
)

// --- fixture ------------------------------------------------------------------------------------

type fixture struct {
	rt     *dmtapsync.Runtime
	in     *dmtapsync.Instance
	file   any
	byName map[string]any
	result traceResult
	native map[string]map[string]string
}

func load(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()

	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		// Never skipped. This suite IS the conformance proof, and a proof that quietly does not run
		// when the spec repo is not checked out is worse than no proof, because it reports success.
		t.Fatalf("the frozen vectors are missing at %s: %v\n"+
			"This suite is the conformance proof; it must never be skipped because the sibling "+
			"spec repo is not checked out.", mustAbs(vectorsPath), err)
	}
	file := decodeJSON(string(raw))

	byName := map[string]any{}
	for _, v := range list(file, "vectors") {
		byName[str(v, "name")] = v
	}

	rt, err := dmtapsync.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in, err := rt.Instance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(ctx); rt.Close(ctx) })

	nraw, err := os.ReadFile(nativeTracePath)
	if err != nil {
		t.Fatalf("the native trace is missing at %s: %v\nRegenerate it with:\n"+
			"  UPDATE_SYNC_TRACE=1 cargo test -p dmtap-sync-wasm --test native_trace",
			mustAbs(nativeTracePath), err)
	}
	var native struct {
		ReceiverNowMS json.Number                  `json:"receiver_now_ms"`
		Trace         map[string]map[string]string `json:"trace"`
	}
	dec := json.NewDecoder(strings.NewReader(string(nraw)))
	dec.UseNumber()
	if err := dec.Decode(&native); err != nil {
		t.Fatal(err)
	}
	if native.ReceiverNowMS.String() != fmt.Sprint(receiverNowMS) {
		t.Fatalf("the native trace was recorded at receiver clock %s, this harness runs at %d — "+
			"the two are not comparable", native.ReceiverNowMS, receiverNowMS)
	}

	return &fixture{
		rt: rt, in: in, file: file, byName: byName,
		result: runVectors(in, file),
		native: native.Trace,
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

// v returns a vector by name.
func (f *fixture) v(name string) any { return f.byName[name] }

// got returns the traced values for a vector.
func (f *fixture) got(name string) map[string]string {
	tr, ok := f.result.trace[name]
	if !ok {
		panic("no trace for vector " + name)
	}
	return tr
}

// eq is the assertion these tests are built from. Values are strings by construction, so a
// mismatch prints both in full rather than a struct diff nobody can read.
func eq(t *testing.T, got, want, what string) {
	t.Helper()
	if got != want {
		t.Errorf("%s\n  got:  %s\n  want: %s", what, got, want)
	}
}

func matches(t *testing.T, got, pattern, what string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(got) {
		t.Errorf("%s\n  got:   %s\n  want ~ %s", what, got, pattern)
	}
}

// refusalOf renders a vector's declared refusal in the trace's spelling.
func refusalOf(expected any) string {
	return fmt.Sprintf("%s %s %s",
		str(expected, "error_code"), str(expected, "error_name"), str(expected, "action"))
}

// --- 0. the binding is wired at all -------------------------------------------------------------

func TestBindingReportsItsSubstrateVersion(t *testing.T) {
	f := load(t)
	v, err := f.in.Version()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, v.Engine, "dmtap-sync", "engine")
	eq(t, v.Substrate, "SYNC.md/v0", "substrate")
	eq(t, fmt.Sprint(v.HLCSkewMS), "120000", "hlc_skew_ms")
}

func TestEveryVectorIsDrivenOrExplicitlyNotCovered(t *testing.T) {
	f := load(t)
	total := len(list(f.file, "vectors"))
	if len(f.result.covered)+len(f.result.skipped) != total {
		t.Fatalf("a vector went missing between the file and the harness: %d driven + %d skipped != %d",
			len(f.result.covered), len(f.result.skipped), total)
	}
	for _, name := range f.result.skipped {
		op := str(f.v(name), "operation")
		if reason := notCovered[op]; len(reason) <= 40 {
			t.Errorf("vector %s is skipped without a real reason", name)
		}
		// The real guard: Go may only skip what NO surface drives. The native trace is the
		// contract — the moment the native runner grows an executor for one of these, this fails
		// until the Go harness grows one too, so this binding cannot quietly fall behind.
		if _, driven := f.native[name]; driven {
			t.Errorf("vector %s is driven natively but listed in notCovered — the Go binding is "+
				"lagging the other surfaces, which is exactly what this map must never permit", name)
		}
	}
	// Guard against silent erosion: if this drops, coverage was removed.
	if len(f.result.covered) < 24 {
		t.Errorf("only %d vectors driven through the binding", len(f.result.covered))
	}
	t.Logf("%d vectors driven, %d awaiting core substrate support on every surface",
		len(f.result.covered), len(f.result.skipped))
}

// --- 1. the traced values match the frozen vectors -----------------------------------------------

func TestSyncOp01CanonicalEncodingAndOpID(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_op_lww_canonical"), f.got("sync_op_lww_canonical")
	exp := m(v, "expected")
	eq(t, got["op_cbor"], str(exp, "cbor_hex"), "canonical op bytes")
	eq(t, got["reencoded"], str(exp, "cbor_hex"), "JSON round-trip changed the bytes")
	matches(t, got["noncanonical"], `0x0A03`, "a non-shortest-form op was not refused")
}

func TestSyncOp02CoseSign1EnvelopeSignedOutsideTheModule(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_op_cose_sign1_bind"), f.got("sync_op_cose_sign1_bind")
	in, exp := m(v, "input"), m(v, "expected")

	eq(t, got["author"], str(in, "signer_pubkey_hex"), "kid must be the op author")
	eq(t, got["external_aad"], str(in, "external_aad_hex"), "external_aad")
	eq(t, got["protected_bstr"], str(exp, "protected_hex"), "protected header")
	eq(t, got["unprotected"], str(exp, "unprotected_hex"), "unprotected header")
	eq(t, got["payload_bstr"], str(exp, "payload_hex"), "payload")
	eq(t, got["sig_structure"], str(exp, "sig_structure_hex"), "Sig_structure")
	eq(t, got["signature"], str(exp, "signature_hex"),
		"a detached signature produced by crypto/ed25519 must reproduce the frozen signature")
	eq(t, got["cose"], str(in, "cose_sign1_hex"), "assembled envelope")
	eq(t, got["op_id"], str(exp, "op_id_hex"), "op-id")
	eq(t, got["verified_op"], str(in, "sync_op_cbor_hex"), "verified op bytes")

	for _, c := range []struct{ key, expectedKey string }{
		{"tampered", "tampered_payload"},
		{"substituted_kid", "substituted_kid"},
	} {
		e := m(exp, c.expectedKey)
		if m(e, "verifies") != false {
			t.Errorf("%s: the vector expects a verification failure", c.key)
		}
		eq(t, got[c.key], refusalOf(e), c.key)
	}
	matches(t, got["foreign_ds_tag"], `0x0A02`,
		"an envelope minted under another DS-tag verified as a SyncOp — domain separation is broken")
}

func TestSyncAuth01UnadmittedAuthorRefused(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_author_unauthorized"), f.got("sync_author_unauthorized")
	in, exp := m(v, "input"), m(v, "expected")
	eq(t, got["refusal"], refusalOf(exp), "refusal")
	eq(t, got["op_author"], str(in, "op_hlc_author_hex"), "op author")
	for i := range strList(in, "admitted_authors_hex") {
		eq(t, got[fmt.Sprintf("admitted_%d_ok", i)], "true", "an admitted author was refused")
	}
}

func TestSyncLWW0102OneWinnerWhateverTheApplyOrder(t *testing.T) {
	f := load(t)
	for _, name := range []string{"sync_lww_hlc_winner", "sync_lww_exact_tie"} {
		v, got := f.v(name), f.got(name)
		exp := m(v, "expected")
		eq(t, got["winner_hlc"], got["reverse_winner_hlc"], name+": apply order changed the winner")
		eq(t, got["winner_value"], got["reverse_winner_value"], name+": apply order changed the value")
		eq(t, got["forward_root"], got["reverse_root"], name+": apply order changed the root")
		eq(t, got["winner_value_text"], str(exp, "winner_value"), name+": winner value")
		if h, ok := mOpt(exp, "winner_hlc_hex"); ok {
			eq(t, got["winner_hlc"], h.(string), name+": winner hlc")
		}
		if c, ok := mOpt(exp, "winner_value_cbor_hex"); ok {
			eq(t, got["winner_value"], c.(string), name+": winner value cbor")
		}
	}
}

func TestSyncORSet01AddWinsAndTheSurvivingTagIsTheEvidence(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_orset_add_wins"), f.got("sync_orset_add_wins")
	exp := m(v, "expected")
	present := boolStr(m(exp, "present").(bool))
	eq(t, got["present_forward"], present, "present, forward")
	eq(t, got["present_reverse"], present, "present, reverse")
	eq(t, got["surviving_count"], "1", "surviving add-tag count")
	eq(t, got["surviving_hlc"], str(exp, "surviving_add_tag_hlc_hex"), "surviving add-tag")
}

func TestSyncORSet02RemoveCitingAFutureAddRefusedByValidatorAndIngest(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_orset_future_add_remove_rejected"), f.got("sync_orset_future_add_remove_rejected")
	want := refusalOf(m(v, "expected"))
	eq(t, got["validate"], want, "validator")
	eq(t, got["ingest"], want, "ingest accepted an op the validator refused")
}

func TestSyncDeath01CertificateDominatesAHigherHLCConcurrentAdd(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_death_domination"), f.got("sync_death_domination")
	present := boolStr(m(m(v, "expected"), "present").(bool))
	eq(t, got["add_outranks_death"], "true", "vector premise broken")
	eq(t, got["present_death_first"], present, "death first")
	eq(t, got["present_add_first"], present, "add first")
}

func TestSyncDeath02AtAnExactTieDeletedBeatsLive(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_death_tie_failsafe"), f.got("sync_death_tie_failsafe")
	exp := m(v, "expected")
	eq(t, got["hlcs_tie"], "true", "vector premise broken: the two writes must share one HLC")
	want := "deleted:" + str(exp, "class")
	eq(t, got["state_death_first"], want, "death first")
	eq(t, got["state_live_first"], want, "live first")
	eq(t, str(exp, "winner"), "Deleted", "the vector's winner")
}

func TestSyncPN01PerAuthorDeltaUnionAndReplayIsANoOp(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_pn_counter_convergence"), f.got("sync_pn_counter_convergence")
	exp := m(v, "expected")

	entries := map[string][2]string{}
	for _, e := range strings.Split(got["entries"], ",") {
		if e == "" {
			continue
		}
		p := strings.Split(e, ":")
		entries[p[0]] = [2]string{p[1], p[2]}
	}
	for _, side := range []struct {
		key   string
		index int
	}{{"P", 0}, {"N", 1}} {
		for author, want := range m(exp, side.key).(map[string]any) {
			have := "0"
			if e, ok := entries[author]; ok {
				have = e[side.index]
			}
			eq(t, have, want.(json.Number).String(),
				fmt.Sprintf("%s[%s]", side.key, author[:8]))
		}
	}
	eq(t, got["total"], numStr(exp, "total"), "total")
	eq(t, got["distinct_op_ids"], numStr(exp, "distinct_op_ids"), "distinct op-ids")
	if m(exp, "replay_is_noop") == true {
		eq(t, got["replay_total"], got["distinct_total"], "a re-delivered op double-counted")
	}
}

func TestSyncPN02AnAuthorMayNotMutateAnotherAuthorsEntry(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_pn_counter_foreign_reject"), f.got("sync_pn_counter_foreign_reject")
	eq(t, got["refusal"], refusalOf(m(v, "expected")), "refusal")
	eq(t, got["own_entry_ok"], "true", "an author's own entry was refused")
}

func TestSyncRGA01ConcurrentSiblingsOrderByElementIDDescending(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_rga_concurrent_sibling_order"), f.got("sync_rga_concurrent_sibling_order")
	exp := m(v, "expected")
	eq(t, got["values_forward"], got["values_reverse"], "arrival order changed the sequence")
	eq(t, got["ids_forward"], got["ids_reverse"], "arrival order changed the element ids")
	// values[0] / ids[0] are the origin atom; the siblings follow, newer-first.
	eq(t, strings.Join(strings.Split(got["values_forward"], ",")[1:], ","),
		strings.Join(strList(exp, "order_values"), ","), "sibling values")
	eq(t, strings.Join(strings.Split(got["ids_forward"], ",")[1:], ","),
		strings.Join(strList(exp, "order_by_element_id_desc"), ","), "sibling element ids")
}

func TestSyncRGA02InsertAfterATombstonedOriginResolves(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_rga_insert_after_tombstone"), f.got("sync_rga_insert_after_tombstone")
	exp := m(v, "expected")
	eq(t, got["resolves"], boolStr(m(exp, "resolves").(bool)), "resolves")
	if m(exp, "reject") != false {
		t.Error("the vector expects the insert to be accepted")
	}
	eq(t, got["visible"], strings.Join(strList(exp, "visible_sequence"), ","), "visible sequence")
	eq(t, got["labels"], strings.Join(strList(exp, "atom_order_incl_tombstones"), ","), "atom order")
}

func TestSyncTree01SameAcyclicTreeFromEveryArrivalOrder(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_tree_concurrent_move_cycle"), f.got("sync_tree_concurrent_move_cycle")
	exp := m(v, "expected")
	eq(t, got["h1_before_h2"], "true", "vector premise broken: h1 must sort before h2")

	edges := []string{}
	for _, e := range list(exp, "final_edges") {
		edges = append(edges, fmt.Sprintf("%s>%s:%s", str(e, "node"), str(e, "parent"), str(e, "ord")))
	}
	wantEdges := strings.Join(edges, ",")
	wantSkipped := strings.Join(strList(exp, "skipped"), ",")
	for i := 0; i < 3; i++ {
		eq(t, got[fmt.Sprintf("edges_%d", i)], wantEdges,
			fmt.Sprintf("arrival order %d produced a different tree", i))
		eq(t, got[fmt.Sprintf("skipped_%d", i)], wantSkipped, fmt.Sprintf("skipped, order %d", i))
		eq(t, got[fmt.Sprintf("acyclic_%d", i)], "true", fmt.Sprintf("acyclic, order %d", i))
	}
	if m(exp, "skipped_is_error") != false {
		t.Error("a skipped move is a convergent outcome, never an error")
	}
}

func TestSyncSnap01SixSectionStateItsRootAndWhatChangesIt(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_snapshot_root_determinism"), f.got("sync_snapshot_root_determinism")
	exp := m(v, "expected")
	eq(t, got["state_cbor"], str(exp, "observable_state_cbor_hex"), "observable state")
	eq(t, got["root"], str(exp, "root_hex"), "root")
	eq(t, got["empty_cbor"], str(exp, "empty_state_cbor_hex"), "empty state")
	eq(t, got["empty_root"], str(exp, "empty_state_root_hex"), "empty root")
	eq(t, got["shuffled_cbor"], got["state_cbor"], "section order leaked into the encoding")
	eq(t, got["roundtrip_cbor"], got["state_cbor"], "decode/encode changed the state body")
	if got["diverged_root"] == got["root"] {
		t.Error("a diverged state produced the same root")
	}
	eq(t, str(exp, "mismatch_error_code"), "0x0A09", "mismatch code")
}

func TestSyncSnap02FastJoinThenSuffixEqualsAFullReplay(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_snapshot_fast_join_equals_replay"), f.got("sync_snapshot_fast_join_equals_replay")
	in, exp := m(v, "input"), m(v, "expected")
	eq(t, got["snapshot_root_recomputed"], str(in, "snapshot_root_hex"), "recomputed snapshot root")
	eq(t, got["fast_join_state"], str(exp, "fast_join_state_cbor_hex"), "fast-join state")
	eq(t, got["fast_join_state"], str(exp, "full_replay_state_cbor_hex"),
		"fast-join then suffix is not byte-identical to a full replay")
	eq(t, got["root"], str(exp, "root_hex"), "root")
	if m(exp, "states_byte_identical") != true || m(exp, "roots_equal") != true {
		t.Error("the vector's own premises do not hold")
	}
}

func TestSyncRecon01RangeFingerprintsAndAMinimalDiff(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_recon_range_merkle_diff"), f.got("sync_recon_range_merkle_diff")
	in, exp := m(v, "input"), m(v, "expected")

	for label, want := range m(in, "op_ids_hex").(map[string]any) {
		eq(t, got["op_id_"+label], want.(string), "op-id for "+label+" is not reproducible")
	}
	for _, r := range []struct{ key, expKey string }{
		{"full", "full_range"}, {"sub1", "subrange_1"}, {"sub2", "subrange_2"},
	} {
		e := m(exp, r.expKey)
		for _, side := range []string{"A", "B"} {
			s := m(e, side)
			eq(t, got[r.key+"_"+side+"_fp"], str(s, "fp_hex"), r.key+"."+side+".fp")
			eq(t, got[r.key+"_"+side+"_count"], numStr(s, "count"), r.key+"."+side+".count")
		}
		matched := got[r.key+"_A_fp"] == got[r.key+"_B_fp"] &&
			got[r.key+"_A_count"] == got[r.key+"_B_count"]
		if matched != m(e, "match").(bool) {
			t.Errorf("%s: match verdict disagrees with the fingerprints", r.key)
		}
	}
	// A matching subrange exchanges NOTHING — that is the whole economy of the protocol.
	if len(list(m(exp, "subrange_1"), "ops_exchanged")) != 0 {
		t.Error("a matching subrange must exchange nothing")
	}
	eq(t, got["empty_fp"], str(exp, "empty_range_fp_hex"), "empty-range fingerprint")
	eq(t, got["empty_count"], numStr(exp, "empty_range_count"), "empty-range count")
	eq(t, got["shipped_to_B"],
		strings.Join(strList(m(exp, "subrange_2"), "ops_shipped_to_B"), ","), "shipped to B")
	eq(t, got["shipped_to_A"], "", "nothing should ship to A")
	shipped := 0
	for _, s := range strings.Split(got["shipped_to_B"], ",") {
		if s != "" {
			shipped++
		}
	}
	eq(t, fmt.Sprint(shipped), numStr(exp, "ops_shipped_total"), "total ops shipped")
}

func TestSyncNS01ResponderShipsOnlySubscribedNamespaces(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_ns_sparse_scoping"), f.got("sync_ns_sparse_scoping")
	exp := m(v, "expected")
	eq(t, got["shipped"], strings.Join(strList(exp, "shipped_ops_cbor_hex"), ","), "shipped ops")
	eq(t, got["shipped_ns"], strings.Join(strList(exp, "shipped_ns"), ","), "shipped namespaces")
}

func TestSyncNS02CrossNamespaceReferenceRefused(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_ns_cross_namespace_ref_rejected"), f.got("sync_ns_cross_namespace_ref_rejected")
	in, exp := m(v, "input"), m(v, "expected")
	eq(t, got["op_ns"], str(in, "op_ns"), "op namespace")
	eq(t, got["ref_target"], str(in, "ref_target"), "referenced target")
	eq(t, got["refusal"], refusalOf(exp), "refusal")
	eq(t, got["same_ns_ok"], "true", "a same-namespace reference was refused")
}

func TestSyncGC01StabilityCutExcludesStaleReplicasAndFailsClosed(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_gc_stability_cut"), f.got("sync_gc_stability_cut")
	in, exp := m(v, "input"), m(v, "expected")
	eq(t, got["cut_counter"], numStr(exp, "stability_cut_counter"), "cut counter")
	if m(m(in, "stale_replica_watermark"), "seen_within_liveness_window") != false {
		t.Error("the vector's stale replica is not actually stale")
	}
	eq(t, got["stale_drags_cut_down"], "true", "vector premise broken")
	if m(exp, "stale_replica_excluded") != true {
		t.Error("the vector expects the stale replica to be excluded")
	}
	eq(t, got["unknown_watermark_cut"], "null", "a cut was computed with an unknown watermark")
	eq(t, got["pruned_something"], "true", "a collapsed pair below the cut was not reclaimed")
	eq(t, got["state_before_gc"], got["state_after_gc"], "GC below the cut changed observable state")
}

func TestSyncFJ01FrozenFastJoinAndPullResponse(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_fastjoin_response"), f.got("sync_fastjoin_response")
	in, exp := m(v, "input"), m(v, "expected")

	eq(t, got["snapshot_preimage"], str(exp, "snapshot_sig_preimage_hex"), "snapshot preimage")
	eq(t, got["snapshot_sig"], str(exp, "snapshot_sig_hex"),
		"a detached snapshot signature must reproduce the frozen one")
	eq(t, got["snapshot_cbor"], str(exp, "snapshot_cbor_hex"), "snapshot")
	eq(t, got["state_root"], str(in, "snapshot_root_hex"), "the root IS the address of the body")
	eq(t, got["fastjoin_cbor"], str(exp, "fastjoin_cbor_hex"), "fastjoin")
	eq(t, got["pull_cbor"], str(exp, "pull_response_cbor_hex"), "pull response")
	eq(t, got["pull_inline_cbor"], str(exp, "pull_response_with_inline_state_cbor_hex"),
		"pull response with inline state (C-11 regenerated: key 3 is now a real SnapshotBody)")
	eq(t, got["fastjoin_roundtrip"], got["fastjoin_cbor"], "decode/encode changed the FastJoin")
	eq(t, got["state_address"], str(exp, "state_fetch_address_hex"), "state fetch address")

	// --- C-11: adoption runs against the vector's OWN real §6.1.2 body (ten signed ops), which
	// folds to the UNCHANGED `snapshot_root_hex` — the materially stronger proof this correction
	// makes possible, in place of the encoding-only check it replaces.
	eq(t, got["op_body_cbor"], str(in, "snapshot_body_cbor_hex"),
		"the traced body must be the vector's own frozen SnapshotBody, not a synthetic stand-in")
	eq(t, got["adopted_root"], str(in, "snapshot_root_hex"),
		"THE FOLD: the real retention-set body must reproduce the UNCHANGED snapshot root")
	eq(t, got["adopted_root"],
		hexs(must(f.in.ObservableStateRoot(unhex(got["adopted_state"])))),
		"the adopted root must be the one the folded ops PRODUCE, not a hash of the transferred bytes")
	eq(t, got["adopted_state"], str(in, "observable_state_cbor_hex"),
		"the fold of the real body must reproduce the SAME observable state the snapshot commits to")
	// The inline copy is a cache hint: corrupted, it is discarded in favour of the fetched body —
	// and the fetch-fallback path reproduces the same (unchanged) root too.
	eq(t, got["adopted_via_fetch_root"], str(in, "snapshot_root_hex"),
		"a corrupted inline hint must fall back to a fetch of the SAME conformant body")
	if m(exp, "inline_body_is_cache_hint_verified_by_fold_then_recompute") != true {
		t.Error("the vector's own premise does not hold")
	}
	// ...and with nothing fetchable it fails CLOSED rather than trusting what it could not verify.
	matches(t, got["corrupt_hint_unfetchable"], `0x0A0C`, "unverifiable hint, nothing fetchable")

	// --- C-11's non-conformant artifact: the pre-C-09 `state` document, REJECTED not merely unused.
	if str(exp, "inline_state_document_would_be_nonconformant_cbor_hex") == "" {
		t.Error("the labelled non-conformant artifact must be present in the vector")
	}
	matches(t, got["pre_c09_state_document_rejected"], `^0x0A`,
		"det_cbor(ObservableState) must be REFUSED as a SnapshotBody, the exact C-09 defect")

	eq(t, got["caller_at_covers_below_floor"], "false",
		"a caller already at `covers` is not below the floor")
}

func TestSyncVAL01TheWholeRecursiveExtValue(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_ext_value_boundary"), f.got("sync_ext_value_boundary")
	in, exp := m(v, "input"), m(v, "expected")

	// Every accept case must DECODE and VALIDATE. Both stages matter: C-08 is the conflation of an
	// encoder-side refusal (a text-keyed map could not be built at all) with a validator-side one.
	for _, raw := range list(in, "accept") {
		name, h := str(raw, "case"), str(raw, "cbor_hex")
		eq(t, got["accept_"+name], "true", "accept case `"+name+"` validated to false")
		eq(t, got["accept_"+name+"_reencoded"], h, "accept case `"+name+"` re-encoding")
	}
	if m(exp, "accept_all") != true {
		t.Error("the vector's own premise does not hold")
	}
	// Every reject case is refused — at whichever stage. What is forbidden is accepting it.
	for _, raw := range list(in, "reject") {
		name := str(raw, "case")
		if got["reject_"+name] == "validates: true" {
			t.Errorf("reject case `%s` was ACCEPTED as an ext-value", name)
		}
	}
	if m(exp, "reject_all") != true {
		t.Error("the vector's own premise does not hold")
	}
	eq(t, str(exp, "reject_error_code"), "0x0A03", "reject error code")
	// The recursion is the point: an integer-keyed map nested at depth 2 is caught, not waved
	// through by a shallow check.
	eq(t, got["reject_nested_int_keyed_map"], "validates: false", "validation is not recursive")
	if m(exp, "validation_is_recursive") != true {
		t.Error("the vector's own premise does not hold")
	}
	// The carrier op — the intended end-to-end shape — is accepted and round-trips byte-exactly.
	eq(t, got["carrier_valid"], "true", "the carrier op was refused; that is the whole of C-08")
	eq(t, got["carrier_reencoded"], str(in, "carrier_op_cbor_hex"), "carrier op re-encoding")
	if m(exp, "carrier_op_accepted") != true {
		t.Error("the vector's own premise does not hold")
	}
	// §4.1.1: nesting is REPRESENTATION. The merge unit is the whole value, so a concurrent write
	// of a different nested map replaces it entire — there is no per-key merge at this boundary.
	rival := must(f.in.EncodeValue(json.RawMessage(`{"tmap":[["x",{"int":99}]]}`)))
	eq(t, got["whole_value_wins"], hexs(rival), "the whole value must win, never a per-key merge")

	// --- C-14: the empty map 0xa0 (key-type-ambiguous but vacuously so) and its non-empty
	// int-keyed sibling, still rejected. Already exercised generically by the accept/reject loops
	// above (`map_empty`/`array_empty` in accept, `int_keyed_map` in reject); this ties that pass
	// to the vector's own declarative statement.
	if m(exp, "empty_map_is_ext_value") != true {
		t.Error("the vector's own premise does not hold")
	}
	eq(t, str(exp, "empty_map_cbor_hex"), "a0", "empty map bytes")
	if m(exp, "empty_map_key_type_is_undeterminable") != true {
		t.Error("the vector's own premise does not hold")
	}
	if m(exp, "nonempty_int_keyed_map_still_rejected") != true {
		t.Error("the vector's own premise does not hold")
	}
	eq(t, got["accept_map_empty"], "true", "the empty map must be accepted as an ext-value")
	eq(t, got["accept_array_empty"], "true", "the empty array must be accepted as an ext-value")
	eq(t, got["reject_int_keyed_map"], "validates: false", "a non-empty int-keyed map is still rejected")

	// --- C-14: the depth ceiling is 64, a MUST, checked before recursing, for ALL sync decoding —
	// demonstrated here on a decode path OTHER than the bare `value` grammar (a SnapshotBody,
	// §6.1.2) so "all sync decoding" is not asserted only in the abstract.
	if numStr(exp, "max_nesting_depth") != "64" {
		t.Errorf("max_nesting_depth: got %s, want 64", numStr(exp, "max_nesting_depth"))
	}
	if m(exp, "max_nesting_depth_is_a_MUST") != true {
		t.Error("the vector's own premise does not hold")
	}
	overDeep := append([]byte{}, bytesOf(66, 0x81)...)
	overDeep = append(overDeep, 0x00)
	_, overDeepErr := f.in.SnapshotBodyDecode(overDeep)
	matches(t, refusal(overDeepErr), `0x0A03`,
		"a SnapshotBody nested past the ceiling must be refused BEFORE recursion completes")

	// --- C-13(b): the `sync-1/ext-value-2` sub-token — observational, never a gate ----------------
	eq(t, str(exp, "value_profile_subtoken"), "sync-1/ext-value-2", "the frozen sub-token spelling")
	if m(exp, "value_profile_subtoken_is_a_gate") != false {
		t.Error("the vector's own premise does not hold")
	}
}

// bytesOf returns n copies of b.
func bytesOf(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSyncSNAP03TheBodyIsAnOpSet(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_snapshot_body_is_op_set"), f.got("sync_snapshot_body_is_op_set")
	in, exp := m(v, "input"), m(v, "expected")

	// Fold-then-recompute: the ops PRODUCE the committed state, which is strictly stronger than
	// hashing the transfer bytes.
	eq(t, got["body_roundtrip"], str(in, "snapshot_body_cbor_hex"), "body round-trip")
	eq(t, got["folded_state"], str(exp, "folded_state_cbor_hex"), "folded state")
	eq(t, got["folded_root"], str(exp, "folded_root_hex"), "folded root")
	eq(t, got["folded_root"], str(in, "snapshot_root_hex"), "the body must fold to Snapshot.root")
	if m(exp, "body_folds_to_root") != true {
		t.Error("the vector's own premise does not hold")
	}
	// A body offered against a root it does not produce is 0x0A09 and discarded whole.
	matches(t, got["wrong_root_refusal"], `0x0A09`, "a body verified against a root it cannot produce")
	eq(t, str(exp, "body_mismatch_error_code"), "0x0A09", "body mismatch code")

	// The ordering premise the vector exists for: after `covers`, yet BELOW the incumbent.
	// `covers` bounds each author's own stream; the §3 HLC orders across authors.
	eq(t, got["post_op_is_after_covers"], "true", "vector premise broken")
	eq(t, got["post_op_is_below_incumbent"], "true", "vector premise broken")

	// A conformant replica folded the body, so it HAS the incumbent's HLC — and keeps it.
	eq(t, got["winning_value_after_post_op"], str(exp, "winning_value_after_post_op"), "winner")
	eq(t, got["state_after_post_op"], str(exp, "state_after_post_op_cbor_hex"), "state after")
	eq(t, got["root_after_post_op"], str(exp, "root_after_post_op_hex"), "root after")

	// A projection-adopter has the value but not its HLC, applies the write, and lands elsewhere.
	eq(t, got["projection_adopt_state"], str(exp, "projection_adopt_state_cbor_hex"), "projection")
	eq(t, got["projection_adopt_root"], str(exp, "projection_adopt_root_hex"), "projection root")
	if m(exp, "projection_adopt_is_nonconformant") != true || m(exp, "roots_differ") != true {
		t.Error("the vector's own premise does not hold")
	}
	eq(t, got["roots_differ"], "true", "the divergence was not reproduced")
}

func TestSyncFJ02TheMUSTInBothDirectionsAndNoSuffixFallback(t *testing.T) {
	f := load(t)
	v, got := f.v("sync_fastjoin_below_floor_suffix_forbidden"),
		f.got("sync_fastjoin_below_floor_suffix_forbidden")
	exp := m(v, "expected")

	eq(t, got["behind_is_below_floor"],
		boolStr(m(exp, "caller_behind_is_below_floor").(bool)), "caller behind")
	eq(t, got["caught_up_is_below_floor"],
		boolStr(m(exp, "caller_caught_up_is_below_floor").(bool)), "caller caught up")

	// The forbidden answer is well-formed — that is exactly why the MUST is needed.
	eq(t, got["ops_response_would_be"],
		str(exp, "caller_behind_ops_response_would_be_cbor_hex"), "the forbidden ops response")
	eq(t, got["ops_response_would_be"], str(exp, "caller_caught_up_response_cbor_hex"),
		"the same bytes are the CORRECT answer for a caught-up caller")

	// C-06: op framing is item-embedded, and the bstr-wrapped encoding is recognizably wrong.
	eq(t, str(exp, "ops_member_framing"), "item-embedded COSE_Sign1", "framing")
	if m(exp, "ops_member_bstr_wrapped_conformant") != false {
		t.Error("the bstr-wrapped framing is non-conformant")
	}
	eq(t, got["bstr_wrapped_ops_response"],
		str(exp, "ops_member_bstr_wrapped_NONCONFORMANT_cbor_hex"),
		"the NON-conformant framing must be reproducible, so it can be REJECTED rather than guessed at")
	if got["bstr_wrapped_ops_response"] == got["ops_response_would_be"] {
		t.Error("if the two framings encoded identically the C-06 rule would be unenforceable")
	}
	eq(t, str(exp, "ops_member_bstr_wrapped_error_code"), "0x0A03", "bstr-wrapped error code")

	// C-07: floor and covers are not comparable.
	if m(exp, "floor_vs_covers_is_orderable") != false {
		t.Error("floor and covers are not orderable")
	}
	eq(t, str(exp, "floor_vs_covers_naive_predicate_rejected"), "covers.lacks(floor)",
		"the rejected predicate")
	// The rejected predicate DOES fire on this data — keep the counterexample live...
	eq(t, got["naive_covers_lacks_floor_rejected"],
		boolStr(m(exp, "floor_vs_covers_naive_predicate_value_here").(bool)),
		"the counterexample stopped firing")
	// ...and the implementation must accept the fast-join regardless. This is the regression guard:
	// a `true` above with a `false` here is precisely the defect C-07 removed.
	eq(t, got["step2_accepts_conformant_floor_above_covers"], "true",
		"step 2 rejected a CONFORMANT fast-join whose floor sits above covers[A]")
	eq(t, got["covers_carries_floor_author_mark"],
		boolStr(m(exp, "covers_carries_mark_for_floor_author").(bool)), "advisory mark")
	if m(exp, "covers_mark_for_floor_author_is_MUST") != false {
		t.Error("the advisory mark must never be a MUST")
	}

	// The step-5 progress MUST: the same root AND covers twice is a responder loop.
	eq(t, got["first_round_makes_progress"], "true", "the first round must make progress")
	matches(t, got["repeated_fastjoin_refusal"],
		str(exp, "repeated_fastjoin_same_root_and_covers_error_code"), "responder loop")

	// Caller-side fail-closed.
	matches(t, got["state_unavailable"], str(exp, "state_body_unfetchable_error_code"),
		"unfetchable state body")
	for _, part := range []string{"state_body_unfetchable_error_name", "state_body_unfetchable_action"} {
		if !strings.Contains(got["state_unavailable"], str(exp, part)) {
			t.Errorf("the refusal is missing %s", part)
		}
	}
	if m(exp, "suffix_fallback_after_failed_fastjoin_forbidden") != true {
		t.Error("a suffix fallback after a failed fast-join is forbidden")
	}
	// And the other direction is refused from the caller's side too.
	matches(t, got["caught_up_refuses_fastjoin"], `0x0A09`, "a caught-up caller must not fast-join")
}

// --- 2. THE cross-surface assertion --------------------------------------------------------------

// TestGoAndNativeRustAreByteIdentical is the one that makes this a binding rather than a
// reimplementation.
//
// The native trace is recorded by tests/native_trace.rs calling dmtap-sync directly — no wasm, no
// marshalling. The JS surface is held to the same file by test/vectors.test.mjs. So a pass here
// means all three surfaces produced identical bytes for all 24 vectors, and any divergence is a
// CRITICAL finding about the binding, never a test to adjust.
func TestGoAndNativeRustAreByteIdentical(t *testing.T) {
	f := load(t)
	if divergences := diffTraces(f.result.trace, f.native); len(divergences) > 0 {
		t.Fatalf("the Go binding diverged from the native engine over %d value(s) — this is a "+
			"CRITICAL finding, not a test to adjust:\n%s",
			len(divergences), strings.Join(divergences, "\n"))
	}
	t.Logf("%d vectors, byte-identical to the native Rust trace", len(f.result.covered))
}

// TestTheThreeSurfacesDriveTheSameVectors catches the subtler failure: a surface that silently
// stops driving a vector still passes a value-by-value diff over what it did drive.
func TestTheThreeSurfacesDriveTheSameVectors(t *testing.T) {
	f := load(t)
	for name := range f.native {
		if _, ok := f.result.trace[name]; !ok {
			t.Errorf("vector %s is in the native trace but the Go binding does not drive it", name)
		}
	}
	for name := range f.result.trace {
		if _, ok := f.native[name]; !ok {
			t.Errorf("vector %s is driven by Go but absent from the native trace", name)
		}
	}
	// And every key within each vector, so a surface cannot quietly record less.
	for name, want := range f.native {
		got := f.result.trace[name]
		for k := range want {
			if _, ok := got[k]; !ok {
				t.Errorf("%s.%s is recorded natively but not by the Go binding", name, k)
			}
		}
	}
}

// --- 3. the key-handling contract ----------------------------------------------------------------

// TestNoEntryPointAcceptsKeyMaterial is the structural half of the no-raw-key rule.
//
// The Go API cannot offer a seed argument the module has no entry point for, so asserting over the
// module's own dispatch table covers the whole surface at once — including any method a future
// change adds. The property is checked on every run rather than maintained by remembering to be
// careful.
func TestNoEntryPointAcceptsKeyMaterial(t *testing.T) {
	f := load(t)
	names, err := f.in.EntryPoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 60 {
		t.Fatalf("only %d entry points — the table looks truncated, so this guard proves nothing",
			len(names))
	}
	for _, name := range names {
		for _, banned := range []string{
			"seed", "secret", "private", "keypair", "generate_key", "_sk", "sign_op", "sign_snapshot",
		} {
			if strings.Contains(strings.ToLower(name), banned) {
				t.Errorf("entry point %q looks like a raw-key path; signing is detached by design", name)
			}
		}
	}
}

// TestSigningIsDetachedEndToEnd walks the whole protocol with a key the module never sees, and
// confirms the frozen signature comes back out.
func TestSigningIsDetachedEndToEnd(t *testing.T) {
	f := load(t)
	v := f.v("sync_op_cose_sign1_bind")
	in, exp := m(v, "input"), m(v, "expected")
	op := unhex(str(in, "sync_op_cbor_hex"))

	// The high-level path: a Signer, never a seed.
	cose, err := f.in.SignOp(op, signerFor(str(in, "signer_seed_hex")))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, hexs(cose), str(in, "cose_sign1_hex"), "SignOp did not reproduce the frozen envelope")

	// A CryptoSigner (the HSM/KMS-shaped path) must produce identical bytes.
	viaCrypto, err := f.in.SignOp(op, dmtapsync.CryptoSigner{
		Key: ed25519KeyFromSeed(str(in, "signer_seed_hex"))})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, hexs(viaCrypto), hexs(cose), "CryptoSigner and InMemorySigner disagree")

	// And the preimage the custodian actually signs is the frozen Sig_structure.
	si, err := f.in.OpSigningInput(op)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, si.SigStructure, str(exp, "sig_structure_hex"), "signing preimage")
}

func TestAnEnvelopeWhoseSignatureDoesNotVerifyIsNeverAssembled(t *testing.T) {
	f := load(t)
	op, err := f.in.EncodeOpJSON(`{"kind":3,"ns":"","target":"a","field":"x",` +
		`"value":{"tstr":"v"},"hlc":{"wall":1700000100000,"counter":0,"author":"` +
		strings.Repeat("11", 32) + `"}}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.in.OpAttachSignature(op, make([]byte, 64))
	if !dmtapsync.IsRefusal(err, "0x0A02") {
		t.Fatalf("a garbage signature was assembled into a wire envelope: %v", err)
	}
}

func TestASignatureOverTheRightPreimageButTheWrongKeyIsRefused(t *testing.T) {
	f := load(t)
	op := unhex(str(m(f.v("sync_op_cose_sign1_bind"), "input"), "sync_op_cbor_hex"))
	si, err := f.in.OpSigningInput(op)
	if err != nil {
		t.Fatal(err)
	}
	wrong := sign(strings.Repeat("ab", 32), must(si.Bytes()))
	_, err = f.in.OpAttachSignature(op, wrong)
	if !dmtapsync.IsRefusal(err, "0x0A02") {
		t.Fatalf("a signature under the wrong key was accepted: %v", err)
	}

	// SignOp catches it earlier and more usefully: the key does not match the op's author, which is
	// a better description than "signature invalid".
	_, err = f.in.SignOp(op, signerFor(strings.Repeat("ab", 32)))
	if err == nil || !strings.Contains(err.Error(), "does not match the op's author") {
		t.Fatalf("SignOp accepted a signer whose key is not the op's author: %v", err)
	}
}

func TestTheStructuredRefusalCarriesTheRegistryCodeNotProse(t *testing.T) {
	f := load(t)
	registry, err := f.in.ErrorRegistry()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range registry {
		if e.Name == "ERR_SYNC_NS_LEAK" {
			found = true
			eq(t, e.Code, "0x0A0A", "code")
			eq(t, e.Action, "FAIL_CLOSED_BLOCK", "action")
		}
	}
	if !found {
		t.Fatal("ERR_SYNC_NS_LEAK is missing from the registry")
	}
}

func TestSignedAndAmbientIngestAgree(t *testing.T) {
	f := load(t)
	in := m(f.v("sync_op_cose_sign1_bind"), "input")
	cose := unhex(str(in, "cose_sign1_hex"))
	opBytes := unhex(str(in, "sync_op_cbor_hex"))

	signed := must(f.in.NewEngine())
	ambient := must(f.in.NewEngine())
	defer signed.Close()
	defer ambient.Close()

	if !must(signed.IngestSigned(cose, receiverNowMS)) {
		t.Fatal("the signed path did not accept the frozen envelope")
	}
	if !must(ambient.IngestAmbientAuthenticated(opBytes, receiverNowMS)) {
		t.Fatal("the ambient path did not accept the frozen op")
	}
	eq(t, hexs(must(signed.StateRoot())), hexs(must(ambient.StateRoot())),
		"the two ingest paths produced different state")

	// ...and re-delivering it is a no-op, not a double-apply.
	if must(signed.IngestSigned(cose, receiverNowMS)) {
		t.Fatal("a re-delivered op was reported as new")
	}
}
