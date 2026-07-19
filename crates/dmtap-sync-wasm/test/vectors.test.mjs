// THE PROOF (`substrate/BINDINGS.md` §4): the frozen Sync conformance vectors, driven through the
// WASM binding from JavaScript, asserted byte-for-byte against (a) the vectors themselves and
// (b) a trace recorded from the native Rust runner.
//
// Run: `node --test crates/dmtap-sync-wasm/test/` from the repo root, after
// `crates/dmtap-sync-wasm/build.sh`. See the crate README.
//
// If this suite fails, the binding is wrong — there is only one implementation of the algebra for
// it to disagree with. A failure here is never "the JS harness needs adjusting".

import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import * as sync from '../pkg-node/dmtap_sync.js';
import { runVectors, NOT_COVERED, hex, unhex, refusal } from './trace.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, '../../../../dmtap/conformance/vectors/sync_vectors.json');
const NATIVE_TRACE = join(here, 'native-trace.json');

// --- the signing host -----------------------------------------------------------------------
// Ed25519 lives HERE, in the JS host, never inside the wasm module. The vectors fix a 32-byte
// seed, so this is the same deterministic key the native runner uses — and the fact that a
// signature produced entirely outside the module reproduces the frozen `signature_hex` is itself
// the proof that the detached signing protocol is correct.
const PKCS8_ED25519_PREFIX = unhex('302e020100300506032b657004220420');

function sign(seedHex, message) {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, unhex(seedHex)]);
  const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return new Uint8Array(nodeSign(null, Buffer.from(message), key));
}

// --- load ---------------------------------------------------------------------------------------

assert.ok(
  existsSync(VECTORS),
  `the frozen vectors are missing at ${VECTORS}. This suite IS the conformance proof; it must ` +
    'never be skipped because the sibling spec repo is not checked out.',
);
const vectorFile = JSON.parse(readFileSync(VECTORS, 'utf8'));
const { trace, covered, skipped } = runVectors(vectorFile, { sign });

const byName = Object.fromEntries(vectorFile.vectors.map((v) => [v.name, v]));
const t = (name) => trace[name];

// --- 0. the binding is wired at all -------------------------------------------------------------

test('the binding reports the substrate version it implements', () => {
  const v = JSON.parse(sync.version());
  assert.equal(v.engine, 'dmtap-sync');
  assert.equal(v.substrate, 'SYNC.md/v0');
  assert.equal(v.hlc_skew_ms, 120000);
});

test('every vector is either driven or explicitly named as not covered', () => {
  assert.equal(
    covered.length + skipped.length,
    vectorFile.vectors.length,
    'a vector went missing between the file and the harness',
  );
  for (const name of skipped) {
    const reason = NOT_COVERED[byName[name].operation];
    assert.ok(reason && reason.length > 40, `vector ${name} is skipped without a real reason`);
  }
  // Guard against silent erosion: if this number drops, coverage was removed.
  assert.equal(skipped.length, 0, 'every vector is driven through the binding');
  assert.ok(covered.length >= 22, `only ${covered.length} vectors driven through the binding`);
});

// --- 1. the traced values match the frozen vectors -----------------------------------------------

test('SYNC-OP-01 — canonical op encoding and the op-id', () => {
  const v = byName.sync_op_lww_canonical;
  const got = t('sync_op_lww_canonical');
  assert.equal(got.op_cbor, v.expected.cbor_hex);
  assert.equal(got.reencoded, v.expected.cbor_hex, 'JSON round-trip changed the bytes');
  assert.match(got.noncanonical, /0x0A03/, 'a non-shortest-form op was not refused');
});

test('SYNC-OP-02 — the COSE_Sign1 envelope, signed outside the module', () => {
  const v = byName.sync_op_cose_sign1_bind;
  const got = t('sync_op_cose_sign1_bind');
  assert.equal(got.author, v.input.signer_pubkey_hex, 'kid must be the op author');
  assert.equal(got.external_aad, v.input.external_aad_hex);
  assert.equal(got.protected_bstr, v.expected.protected_hex);
  assert.equal(got.unprotected, v.expected.unprotected_hex);
  assert.equal(got.payload_bstr, v.expected.payload_hex);
  assert.equal(got.sig_structure, v.expected.sig_structure_hex);
  assert.equal(
    got.signature,
    v.expected.signature_hex,
    'a detached signature produced by node:crypto must reproduce the frozen signature',
  );
  assert.equal(got.cose, v.input.cose_sign1_hex);
  assert.equal(got.op_id, v.expected.op_id_hex);
  assert.equal(got.verified_op, v.input.sync_op_cbor_hex);
  assert.equal(v.expected.verifies, true);
  for (const [key, expectedKey] of [
    ['tampered', 'tampered_payload'],
    ['substituted_kid', 'substituted_kid'],
  ]) {
    const exp = v.expected[expectedKey];
    assert.equal(exp.verifies, false);
    assert.equal(got[key], `${exp.error_code} ${exp.error_name} ${exp.action}`);
  }
  assert.match(
    got.foreign_ds_tag,
    /0x0A02/,
    'an envelope minted under another DS-tag verified as a SyncOp — domain separation is broken',
  );
});

test('SYNC-AUTH-01 — an unadmitted author is refused, admitted ones are not', () => {
  const v = byName.sync_author_unauthorized;
  const got = t('sync_author_unauthorized');
  assert.equal(got.refusal, `${v.expected.error_code} ${v.expected.error_name} ${v.expected.action}`);
  assert.equal(got.op_author, v.input.op_hlc_author_hex);
  v.input.admitted_authors_hex.forEach((_, i) => assert.equal(got[`admitted_${i}_ok`], 'true'));
});

test('SYNC-LWW-01/02 — one winner, whatever the apply order', () => {
  for (const name of ['sync_lww_hlc_winner', 'sync_lww_exact_tie']) {
    const v = byName[name];
    const got = t(name);
    assert.equal(got.winner_hlc, got.reverse_winner_hlc, `${name}: apply order changed the winner`);
    assert.equal(got.winner_value, got.reverse_winner_value, `${name}: apply order changed the value`);
    assert.equal(got.forward_root, got.reverse_root, `${name}: apply order changed the root`);
    assert.equal(got.winner_value_text, v.expected.winner_value);
    if (v.expected.winner_hlc_hex) assert.equal(got.winner_hlc, v.expected.winner_hlc_hex);
    if (v.expected.winner_value_cbor_hex) {
      assert.equal(got.winner_value, v.expected.winner_value_cbor_hex);
    }
  }
});

test('SYNC-ORSET-01 — add-wins, and the surviving add-tag is the causal evidence', () => {
  const v = byName.sync_orset_add_wins;
  const got = t('sync_orset_add_wins');
  assert.equal(got.present_forward, String(v.expected.present));
  assert.equal(got.present_reverse, String(v.expected.present));
  assert.equal(got.surviving_count, '1');
  assert.equal(got.surviving_hlc, v.expected.surviving_add_tag_hlc_hex);
});

test('SYNC-ORSET-02 — a remove citing a future add is refused by validator AND ingest', () => {
  const v = byName.sync_orset_future_add_remove_rejected;
  const want = `${v.expected.error_code} ${v.expected.error_name} ${v.expected.action}`;
  const got = t('sync_orset_future_add_remove_rejected');
  assert.equal(got.validate, want);
  assert.equal(got.ingest, want, 'ingest accepted an op the validator refused');
});

test('SYNC-DEATH-01 — a death certificate dominates a higher-HLC concurrent add', () => {
  const v = byName.sync_death_domination;
  const got = t('sync_death_domination');
  assert.equal(got.add_outranks_death, 'true', 'vector premise broken');
  assert.equal(got.present_death_first, String(v.expected.present));
  assert.equal(got.present_add_first, String(v.expected.present));
});

test('SYNC-DEATH-02 — at an exact tie, Deleted beats Live', () => {
  const v = byName.sync_death_tie_failsafe;
  const got = t('sync_death_tie_failsafe');
  assert.equal(got.hlcs_tie, 'true', 'vector premise broken: the two writes must share one HLC');
  const want = `deleted:${v.expected.class}`;
  assert.equal(got.state_death_first, want);
  assert.equal(got.state_live_first, want);
  assert.equal(v.expected.winner, 'Deleted');
});

test('SYNC-PN-01 — per-author delta union; a true replay is a no-op', () => {
  const v = byName.sync_pn_counter_convergence;
  const got = t('sync_pn_counter_convergence');
  const entries = Object.fromEntries(
    got.entries.split(',').filter(Boolean).map((e) => {
      const [author, P, N] = e.split(':');
      return [author, { P: Number(P), N: Number(N) }];
    }),
  );
  for (const [author, want] of Object.entries(v.expected.P)) {
    assert.equal(entries[author]?.P ?? 0, want, `P[${author.slice(0, 8)}]`);
  }
  for (const [author, want] of Object.entries(v.expected.N)) {
    assert.equal(entries[author]?.N ?? 0, want, `N[${author.slice(0, 8)}]`);
  }
  assert.equal(got.total, String(v.expected.total));
  assert.equal(got.distinct_op_ids, String(v.expected.distinct_op_ids));
  if (v.expected.replay_is_noop) {
    assert.equal(got.replay_total, got.distinct_total, 'a re-delivered op double-counted');
  }
});

test('SYNC-PN-02 — an author may not mutate another author\'s counter entry', () => {
  const v = byName.sync_pn_counter_foreign_reject;
  const got = t('sync_pn_counter_foreign_reject');
  assert.equal(got.refusal, `${v.expected.error_code} ${v.expected.error_name} ${v.expected.action}`);
  assert.equal(got.own_entry_ok, 'true');
});

test('SYNC-RGA-01 — concurrent siblings order by element id, descending, either way round', () => {
  const v = byName.sync_rga_concurrent_sibling_order;
  const got = t('sync_rga_concurrent_sibling_order');
  assert.equal(got.values_forward, got.values_reverse, 'arrival order changed the sequence');
  assert.equal(got.ids_forward, got.ids_reverse);
  // values[0] / ids[0] are the origin atom; the siblings follow, newer-first.
  assert.equal(got.values_forward.split(',').slice(1).join(','), v.expected.order_values.join(','));
  assert.equal(
    got.ids_forward.split(',').slice(1).join(','),
    v.expected.order_by_element_id_desc.join(','),
  );
});

test('SYNC-RGA-02 — an insert after a tombstoned origin resolves', () => {
  const v = byName.sync_rga_insert_after_tombstone;
  const got = t('sync_rga_insert_after_tombstone');
  assert.equal(got.resolves, String(v.expected.resolves));
  assert.equal(v.expected.reject, false);
  assert.equal(got.visible, v.expected.visible_sequence.join(','));
  assert.equal(got.labels, v.expected.atom_order_incl_tombstones.join(','));
});

test('SYNC-TREE-01 — the same acyclic tree from every arrival order', () => {
  const v = byName.sync_tree_concurrent_move_cycle;
  const got = t('sync_tree_concurrent_move_cycle');
  assert.equal(got.h1_before_h2, 'true', 'vector premise broken: h1 must sort before h2');
  const wantEdges = v.expected.final_edges.map((e) => `${e.node}>${e.parent}:${e.ord}`).join(',');
  for (let i = 0; i < 3; i += 1) {
    assert.equal(got[`edges_${i}`], wantEdges, `arrival order ${i} produced a different tree`);
    assert.equal(got[`skipped_${i}`], v.expected.skipped.join(','));
    assert.equal(got[`acyclic_${i}`], 'true');
  }
  assert.equal(v.expected.skipped_is_error, false);
});

test('SYNC-SNAP-01 — the six-section state, its root, and what changes it', () => {
  const v = byName.sync_snapshot_root_determinism;
  const got = t('sync_snapshot_root_determinism');
  assert.equal(got.state_cbor, v.expected.observable_state_cbor_hex);
  assert.equal(got.root, v.expected.root_hex);
  assert.equal(got.empty_cbor, v.expected.empty_state_cbor_hex);
  assert.equal(got.empty_root, v.expected.empty_state_root_hex);
  assert.equal(got.shuffled_cbor, got.state_cbor, 'section order leaked into the encoding');
  assert.equal(got.roundtrip_cbor, got.state_cbor, 'decode/encode changed the state body');
  assert.notEqual(got.diverged_root, got.root, 'a diverged state produced the same root');
  assert.equal(v.expected.mismatch_error_code, '0x0A09');
});

test('SYNC-SNAP-02 — fast-join then suffix equals a full replay, byte for byte', () => {
  const v = byName.sync_snapshot_fast_join_equals_replay;
  const got = t('sync_snapshot_fast_join_equals_replay');
  assert.equal(got.snapshot_root_recomputed, v.input.snapshot_root_hex);
  assert.equal(got.fast_join_state, v.expected.fast_join_state_cbor_hex);
  assert.equal(got.fast_join_state, v.expected.full_replay_state_cbor_hex);
  assert.equal(got.root, v.expected.root_hex);
  assert.equal(v.expected.states_byte_identical, true);
  assert.equal(v.expected.roots_equal, true);
});

test('SYNC-RECON-01 — range fingerprints, and a diff that ships exactly the missing op', () => {
  const v = byName.sync_recon_range_merkle_diff;
  const got = t('sync_recon_range_merkle_diff');
  for (const [label, want] of Object.entries(v.input.op_ids_hex)) {
    assert.equal(got[`op_id_${label}`], want, `op-id for ${label} is not reproducible`);
  }
  const ranges = { full: v.expected.full_range, sub1: v.expected.subrange_1, sub2: v.expected.subrange_2 };
  for (const [range, exp] of Object.entries(ranges)) {
    for (const side of ['A', 'B']) {
      assert.equal(got[`${range}_${side}_fp`], exp[side].fp_hex, `${range}.${side}.fp`);
      assert.equal(got[`${range}_${side}_count`], String(exp[side].count), `${range}.${side}.count`);
    }
    const matched = got[`${range}_A_fp`] === got[`${range}_B_fp`] &&
      got[`${range}_A_count`] === got[`${range}_B_count`];
    assert.equal(matched, exp.match, `${range}: match verdict disagrees with the fingerprints`);
  }
  // A matching subrange exchanges NOTHING — that is the whole economy of the protocol.
  assert.equal(v.expected.subrange_1.ops_exchanged.length, 0);
  assert.equal(got.empty_fp, v.expected.empty_range_fp_hex);
  assert.equal(got.empty_count, String(v.expected.empty_range_count));
  assert.equal(got.shipped_to_B, v.expected.subrange_2.ops_shipped_to_B.join(','));
  assert.equal(got.shipped_to_A, '');
  assert.equal(got.shipped_to_B.split(',').filter(Boolean).length, v.expected.ops_shipped_total);
});

test('SYNC-NS-01 — a responder ships only the subscribed namespaces', () => {
  const v = byName.sync_ns_sparse_scoping;
  const got = t('sync_ns_sparse_scoping');
  assert.equal(got.shipped, v.expected.shipped_ops_cbor_hex.join(','));
  assert.equal(got.shipped_ns, v.expected.shipped_ns.join(','));
});

test('SYNC-NS-02 — a cross-namespace reference is refused; a same-namespace one is not', () => {
  const v = byName.sync_ns_cross_namespace_ref_rejected;
  const got = t('sync_ns_cross_namespace_ref_rejected');
  assert.equal(got.op_ns, v.input.op_ns);
  assert.equal(got.ref_target, v.input.ref_target);
  assert.equal(got.refusal, `${v.expected.error_code} ${v.expected.error_name} ${v.expected.action}`);
  assert.equal(got.same_ns_ok, 'true');
});

test('SYNC-GC-01 — the stability cut excludes stale replicas and fails closed on unknowns', () => {
  const v = byName.sync_gc_stability_cut;
  const got = t('sync_gc_stability_cut');
  assert.equal(got.cut_counter, String(v.expected.stability_cut_counter));
  assert.equal(v.input.stale_replica_watermark.seen_within_liveness_window, false);
  assert.equal(got.stale_drags_cut_down, 'true', 'vector premise broken');
  assert.equal(v.expected.stale_replica_excluded, true);
  assert.equal(got.unknown_watermark_cut, 'null', 'a cut was computed with an unknown watermark');
  assert.equal(got.pruned_something, 'true', 'a collapsed pair below the cut was not reclaimed');
  assert.equal(got.state_before_gc, got.state_after_gc, 'GC below the cut changed observable state');
});

test('SYNC-FJ-01 — the frozen FastJoin / pull response, snapshot signed outside the module', () => {
  const v = byName.sync_fastjoin_response;
  const got = t('sync_fastjoin_response');
  assert.equal(got.snapshot_preimage, v.expected.snapshot_sig_preimage_hex);
  assert.equal(
    got.snapshot_sig,
    v.expected.snapshot_sig_hex,
    'a detached snapshot signature must reproduce the frozen one',
  );
  assert.equal(got.snapshot_cbor, v.expected.snapshot_cbor_hex);
  assert.equal(got.state_root, v.input.snapshot_root_hex, 'the root IS the address of the body');
  assert.equal(got.fastjoin_cbor, v.expected.fastjoin_cbor_hex);
  assert.equal(got.pull_cbor, v.expected.pull_response_cbor_hex);
  assert.equal(got.pull_inline_cbor, v.expected.pull_response_with_inline_state_cbor_hex);
  assert.equal(got.fastjoin_roundtrip, got.fastjoin_cbor, 'decode/encode changed the FastJoin');
  assert.equal(got.state_address, v.expected.state_fetch_address_hex);
  assert.deepEqual(v.expected.pull_response_keys, [2], 'keys 1 and 2 are mutually exclusive');
  assert.equal(v.expected.ops_key_present, false);
  // The inline copy is a cache hint: corrupted, it is discarded in favour of the fetched body...
  assert.equal(
    got.adopted_state,
    v.input.observable_state_cbor_hex,
    'a corrupted inline hint must be discarded, not adopted',
  );
  assert.equal(v.expected.inline_state_is_cache_hint_verified_against_root, true);
  // ...and with nothing fetchable it fails CLOSED rather than trusting what it could not verify.
  assert.match(got.corrupt_hint_unfetchable, /0x0A0C/);
  assert.equal(
    got.caller_at_covers_below_floor,
    'false',
    'a caller already at `covers` is not below the floor',
  );
});

test('SYNC-FJ-02 — the MUST in both directions, and no fallback to the suffix', () => {
  const v = byName.sync_fastjoin_below_floor_suffix_forbidden;
  const got = t('sync_fastjoin_below_floor_suffix_forbidden');
  assert.equal(got.behind_is_below_floor, String(v.expected.caller_behind_is_below_floor));
  assert.equal(got.caught_up_is_below_floor, String(v.expected.caller_caught_up_is_below_floor));
  // The forbidden answer is well-formed — that is exactly why the MUST is needed.
  assert.equal(got.ops_response_would_be, v.expected.caller_behind_ops_response_would_be_cbor_hex);
  assert.equal(
    got.ops_response_would_be,
    v.expected.caller_caught_up_response_cbor_hex,
    'the same bytes are the CORRECT answer for a caught-up caller',
  );
  assert.equal(v.expected.caller_behind_ops_response_forbidden, true);
  assert.equal(v.expected.caller_caught_up_fastjoin_forbidden, true);
  // Caller-side fail-closed, both paths.
  assert.match(got.gap_not_closed, new RegExp(v.expected.snapshot_not_covering_gap_error_code));
  assert.ok(got.gap_not_closed.includes(v.expected.snapshot_not_covering_gap_error_name));
  assert.match(got.state_unavailable, new RegExp(v.expected.state_body_unfetchable_error_code));
  assert.ok(got.state_unavailable.includes(v.expected.state_body_unfetchable_error_name));
  assert.ok(got.state_unavailable.includes(v.expected.state_body_unfetchable_action));
  assert.equal(v.expected.suffix_fallback_after_failed_fastjoin_forbidden, true);
  // And the other direction is refused from the caller's side too.
  assert.match(got.caught_up_refuses_fastjoin, /0x0A09/);
});

// --- 2. THE cross-surface assertion --------------------------------------------------------------

test('native Rust and WASM produce byte-identical results for every vector', () => {
  assert.ok(
    existsSync(NATIVE_TRACE),
    `the native trace is missing. Regenerate it with:\n` +
      `  UPDATE_SYNC_TRACE=1 cargo test -p dmtap-sync-wasm --test native_trace`,
  );
  const native = JSON.parse(readFileSync(NATIVE_TRACE, 'utf8'));

  assert.deepEqual(
    Object.keys(trace).sort(),
    Object.keys(native.trace).sort(),
    'the two surfaces drove a different set of vectors',
  );

  const divergences = [];
  for (const [name, values] of Object.entries(trace)) {
    for (const [key, got] of Object.entries(values)) {
      const want = native.trace[name][key];
      if (want !== got) divergences.push(`  ${name}.${key}\n    native: ${want}\n    wasm:   ${got}`);
    }
    for (const key of Object.keys(native.trace[name])) {
      if (!(key in values)) divergences.push(`  ${name}.${key} missing from the WASM trace`);
    }
  }
  assert.equal(
    divergences.length,
    0,
    `the WASM binding diverged from the native engine — this is a CRITICAL finding, not a test ` +
      `to adjust:\n${divergences.join('\n')}`,
  );
});

// --- 3. the key-handling contract ----------------------------------------------------------------

test('the binding exports no way to hand it a private key', () => {
  const surface = Object.keys(sync).join(' ').toLowerCase();
  for (const banned of ['seed', 'secret', 'private', 'keypair', 'generate_key']) {
    assert.ok(!surface.includes(banned), `an export mentioning \`${banned}\` was added`);
  }
});

test('an envelope whose signature does not verify is never assembled', () => {
  const op = sync.encode_op(
    JSON.stringify({
      kind: 3,
      ns: '',
      target: 'a',
      field: 'x',
      value: { tstr: 'v' },
      hlc: { wall: 1700000100000, counter: 0, author: '11'.repeat(32) },
    }),
  );
  assert.match(
    refusal(() => sync.op_attach_signature(op, new Uint8Array(64))),
    /0x0A02/,
    'a garbage signature was assembled into a wire envelope',
  );
});

test('a signature over the right preimage but the wrong key is refused', () => {
  const op = unhex(byName.sync_op_cose_sign1_bind.input.sync_op_cbor_hex);
  const si = JSON.parse(sync.op_signing_input(op));
  const wrongKey = sign('ab'.repeat(32), unhex(si.sig_structure));
  assert.match(refusal(() => sync.op_attach_signature(op, wrongKey)), /0x0A02/);
});

test('the structured refusal carries the registry code, not prose', () => {
  const registry = JSON.parse(sync.error_registry());
  const nsLeak = registry.find((e) => e.name === 'ERR_SYNC_NS_LEAK');
  assert.deepEqual(nsLeak, {
    code: '0x0A0A',
    name: 'ERR_SYNC_NS_LEAK',
    action: 'FAIL_CLOSED_BLOCK',
  });
});

test('an op ingested through the signed path is the same as through the ambient path', () => {
  const v = byName.sync_op_cose_sign1_bind;
  const signed = new sync.SyncEngine();
  const ambient = new sync.SyncEngine();
  assert.equal(signed.ingest_signed(unhex(v.input.cose_sign1_hex), 1_700_000_900_000), true);
  assert.equal(
    ambient.ingest_ambient_authenticated(unhex(v.input.sync_op_cbor_hex), 1_700_000_900_000),
    true,
  );
  assert.equal(hex(signed.state_root()), hex(ambient.state_root()));
  // ...and re-delivering it is a no-op, not a double-apply.
  assert.equal(signed.ingest_signed(unhex(v.input.cose_sign1_hex), 1_700_000_900_000), false);
});
