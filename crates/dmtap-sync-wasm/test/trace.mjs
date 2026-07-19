// The JS half of the cross-surface parity proof (`substrate/BINDINGS.md` §4).
//
// This module drives every frozen vector in `sync_vectors.json` **through the WASM binding** and
// records a trace: an ordered map of `vector name → { key → value }`, where every value is a string
// (hex bytes, a decimal, a JSON blob, or a `0x0AXX` refusal code). `tests/native_trace.rs` records
// the *same* keys by calling `dmtap-sync` natively in Rust. `vectors.test.mjs` then asserts three
// things:
//
//   1. each traced value matches what the frozen vector declares (where it declares one),
//   2. the JS/WASM trace is byte-identical to the committed native Rust trace, and
//   3. no vector is silently skipped — anything this harness cannot drive is named in NOT_COVERED
//      with a reason.
//
// Rule for anyone editing this file: **compute, never restate**. A trace value must come out of a
// binding call. Copying an expected constant out of the vector into the trace would make the
// comparison pass while proving nothing.

import * as sync from '../pkg-node/dmtap_sync.js';

// The vectors' HLC wall is a fixed 2023-11-14 timestamp. The skew rule bounds ops from the FUTURE,
// so a receiver clock at or after that wall accepts every vector op (§3). Same constant as the
// native runner.
export const RECEIVER_NOW_MS = 1_700_000_900_000;

/**
 * Operations this harness deliberately does not drive, and why. Asserted to be exhaustive.
 *
 * Currently empty: the §5.2.1 fast-join objects looked like pure transport at first, but the
 * FastJoin encoding, the below-floor predicate and the caller-side verification sequence are all
 * algebra — only the fetch is transport, and the binding leaves that to the host. So a browser
 * replica can participate in fast-join, and both surfaces drive all 22 vectors.
 */
export const NOT_COVERED = {};

const enc = new TextEncoder();

export const hex = (u8) => Buffer.from(u8).toString('hex');
export const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

/** Recover the structured refusal a binding call throws (see the crate's `err` module). */
export function refusal(fn) {
  try {
    fn();
  } catch (e) {
    let parsed;
    try {
      parsed = JSON.parse(e.message);
    } catch {
      throw new Error(`binding threw a non-structured error: ${e.message}`);
    }
    if (parsed.error !== 'sync') {
      throw new Error(`expected a substrate refusal, got a binding error: ${e.message}`);
    }
    return `${parsed.code} ${parsed.name} ${parsed.action}`;
  }
  throw new Error('expected a refusal, but the call succeeded');
}

/** An HLC as the vectors spell it (`author_hex`) turned into the binding's spelling. */
const hlcJson = (h) => JSON.stringify({ wall: h.wall, counter: h.counter, author: h.author_hex });

/** Ingest ops (canonical bytes) into a fresh engine, in order. */
function ingest(opsHex) {
  const engine = new sync.SyncEngine();
  for (const h of opsHex) engine.ingest_ambient_authenticated(unhex(h), RECEIVER_NOW_MS);
  return engine;
}

/** `deleted:class` or `live` — a label, so the trace holds no JSON blob to format-match. */
const deathLabel = (engine, object) => {
  const s = JSON.parse(engine.death_state(object));
  return s.deleted ? `deleted:${s.class}` : 'live';
};

/** `author:P:N` per entry, joined — the per-author §4.6 deltas in a stable spelling. */
const counterLabel = (engine, target, field) =>
  JSON.parse(engine.counter_entries(target, field))
    .map((e) => `${e.author}:${e.P}:${e.N}`)
    .join(',');

const opHlc = (opHex) => JSON.parse(sync.decode_op(unhex(opHex))).hlc;
const opField = (opHex, k) => JSON.parse(sync.decode_op(unhex(opHex)))[k];

// --- the executors ------------------------------------------------------------------------------
// One per vector `operation`. Each returns a flat object of string values.

const executors = {
  // SYNC-OP-01 — canonical op encoding.
  sync_op_encode(v) {
    const built = sync.encode_op(
      JSON.stringify({
        kind: v.input.kind,
        ns: v.input.ns,
        target: v.input.target,
        field: v.input.field,
        value: v.input.value_tstr === undefined ? null : { tstr: v.input.value_tstr },
        hlc: JSON.parse(hlcJson(v.input.hlc)),
      }),
    );
    // Re-decoding must round-trip to the same fields AND re-encode byte-for-byte.
    const reencoded = sync.encode_op(sync.decode_op(built));
    // A non-canonical spelling of the same object is refused, never re-canonicalized: `kind` 3
    // respelled in a two-byte head (0x1803).
    const bad = Array.from(built);
    bad.splice(2, 1, 0x18, 0x03);
    bad[0] = 0xa6;
    return {
      op_cbor: hex(built),
      op_id: hex(sync.op_id(built)),
      reencoded: hex(reencoded),
      noncanonical: refusal(() => sync.decode_op(new Uint8Array(bad))),
    };
  },

  // SYNC-OP-02 — the COSE_Sign1 envelope, signed through the DETACHED path.
  sync_op_cose_sign1_verify(v, { sign }) {
    const op = unhex(v.input.sync_op_cbor_hex);
    const si = JSON.parse(sync.op_signing_input(op));
    // The signature is produced OUTSIDE the wasm module, from a key the module never sees.
    const signature = sign(v.input.signer_seed_hex, unhex(si.sig_structure));
    const cose = sync.op_attach_signature(op, signature);
    const verified = sync.verify_signed_op(unhex(v.input.cose_sign1_hex));
    // Both negative cases must fail closed.
    return {
      author: si.author,
      protected_bstr: hex(sync.encode_value(JSON.stringify({ bstr: si.protected }))),
      unprotected: hex(sync.encode_value(JSON.stringify({ map: [] }))),
      payload_bstr: hex(sync.encode_value(JSON.stringify({ bstr: hex(op) }))),
      external_aad: si.external_aad,
      sig_structure: si.sig_structure,
      signature: hex(signature),
      cose: hex(cose),
      op_id: hex(sync.op_id(op)),
      verified_op: hex(verified),
      tampered: refusal(() =>
        sync.verify_signed_op(unhex(v.input.tampered_payload_cose_sign1_hex)),
      ),
      substituted_kid: refusal(() =>
        sync.verify_signed_op(unhex(v.input.substituted_kid_cose_sign1_hex)),
      ),
      // A third negative the vector's prose demands but does not encode: an envelope minted over
      // any other external_aad must not verify as a SyncOp. Signed here with the same key over the
      // SNAPSHOT DS-tag, then offered to the op verifier.
      foreign_ds_tag: refusal(() => {
        const proto = unhex(si.protected);
        const sigStruct = sync.encode_value(
          JSON.stringify({
            arr: [
              { tstr: 'Signature1' },
              { bstr: hex(proto) },
              { bstr: hex(enc.encode('DMTAP-SYNC-v0/snapshot')) + '00' },
              { bstr: hex(op) },
            ],
          }),
        );
        const forged = sign(v.input.signer_seed_hex, sigStruct);
        sync.op_attach_signature(op, forged);
      }),
    };
  },

  // SYNC-AUTH-01 — author admission is a gate, not a blanket deny.
  sync_author_admission(v) {
    const admitted = JSON.stringify(v.input.admitted_authors_hex);
    const author = unhex(v.input.op_hlc_author_hex);
    const out = { refusal: refusal(() => sync.check_admitted(author, admitted)) };
    v.input.admitted_authors_hex.forEach((a, i) => {
      sync.check_admitted(unhex(a), admitted);
      out[`admitted_${i}_ok`] = 'true';
    });
    out.op_author = JSON.parse(sync.decode_op(unhex(v.input.op_cbor_hex))).hlc.author;
    return out;
  },

  // SYNC-LWW-01 / -02 — the winner is the same whichever order the ops arrive in.
  sync_lww_merge(v) {
    const ops = v.input.ops_cbor_hex;
    const target = opField(ops[0], 'target');
    const field = opField(ops[0], 'field');
    const fwd = ingest(ops);
    const rev = ingest([...ops].reverse());
    const cell = (e) => {
      const c = JSON.parse(e.lww_cell(target, field));
      return {
        hlc: hex(sync.encode_hlc(JSON.stringify(c.hlc))),
        value: hex(sync.encode_value(JSON.stringify(c.value))),
        text: c.value.tstr ?? '',
      };
    };
    const f = cell(fwd);
    const r = cell(rev);
    return {
      winner_hlc: f.hlc,
      winner_value: f.value,
      winner_value_text: f.text,
      reverse_winner_hlc: r.hlc,
      reverse_winner_value: r.value,
      forward_root: hex(fwd.state_root()),
      reverse_root: hex(rev.state_root()),
    };
  },

  // SYNC-ORSET-01 — add-wins, whatever the arrival order.
  sync_orset_merge(v) {
    const ops = v.input.ops_cbor_hex;
    const target = opField(ops[0], 'target');
    const element = JSON.stringify({ tstr: v.input.element });
    const fwd = ingest(ops);
    const rev = ingest([...ops].reverse());
    const tags = JSON.parse(fwd.set_surviving_tags(target, element));
    return {
      present_forward: String(fwd.set_contains(target, element)),
      present_reverse: String(rev.set_contains(target, element)),
      surviving_count: String(tags.length),
      surviving_hlc: tags.length ? hex(sync.encode_hlc(JSON.stringify(tags[0].hlc))) : '',
      members: JSON.parse(fwd.set_members())
        .map(([tgt, val]) => `${tgt}=${hex(sync.encode_value(JSON.stringify(val)))}`)
        .join(','),
    };
  },

  // SYNC-ORSET-02 — a remove citing a FUTURE add is causally impossible.
  sync_orset_remove_validity(v) {
    const op = unhex(v.input.op_cbor_hex);
    return {
      validate: refusal(() => sync.validate_op(op, RECEIVER_NOW_MS)),
      // The full ingest path must refuse it too, not only the bare validator.
      ingest: refusal(() =>
        new sync.SyncEngine().ingest_ambient_authenticated(op, RECEIVER_NOW_MS),
      ),
    };
  },

  // SYNC-DEATH-01 — a death certificate dominates a concurrent add with a GREATER HLC.
  sync_death_domination(v) {
    const death = v.input.death_op_cbor_hex;
    const add = v.input.concurrent_add_op_cbor_hex;
    const target = opField(death, 'target');
    const element = JSON.stringify(opField(add, 'value'));
    return {
      present_death_first: String(ingest([death, add]).set_contains(target, element)),
      present_add_first: String(ingest([add, death]).set_contains(target, element)),
      add_outranks_death: String(
        sync.compare_hlc(JSON.stringify(opHlc(add)), JSON.stringify(opHlc(death))) > 0,
      ),
    };
  },

  // SYNC-DEATH-02 — at an exact HLC tie, Deleted beats Live (fail-safe toward deletion).
  sync_death_tie(v) {
    const death = v.input.death_op_cbor_hex;
    const live = v.input.live_op_cbor_hex;
    const target = opField(death, 'target');
    return {
      state_death_first: deathLabel(ingest([death, live]), target),
      state_live_first: deathLabel(ingest([live, death]), target),
      hlcs_tie: String(
        sync.compare_hlc(JSON.stringify(opHlc(death)), JSON.stringify(opHlc(live))) === 0,
      ),
    };
  },

  // SYNC-PN-01 — per-author union of op-id-keyed deltas (§4.6, correction C-01).
  sync_pn_merge(v) {
    const ops = v.input.ops_cbor_hex;
    const target = opField(ops[0], 'target');
    const field = opField(ops[0], 'field');
    const all = ingest(ops);
    const distinct = ingest(ops.slice(0, 2));
    // A TRUE replay: identical bytes ⇒ identical op-id ⇒ the second delivery is a no-op.
    const replayed = ingest([ops[0], ops[1], ops[0]]);
    return {
      entries: counterLabel(all, target, field),
      total: all.counter_total(target, field),
      distinct_total: distinct.counter_total(target, field),
      replay_total: replayed.counter_total(target, field),
      replay_entries: counterLabel(replayed, target, field),
      distinct_op_ids: String(new Set(ops.map((o) => hex(sync.op_id(unhex(o))))).size),
    };
  },

  // SYNC-PN-02 — an author may only mutate its own P/N entry.
  sync_counter_foreign_check(v) {
    const opAuthor = unhex(v.input.op_hlc_author_hex);
    return {
      refusal: refusal(() =>
        sync.check_counter_entry(opAuthor, unhex(v.input.target_entry_author_hex)),
      ),
      own_entry_ok: String(sync.check_counter_entry(opAuthor, opAuthor) === undefined),
    };
  },

  // SYNC-RGA-01 — concurrent siblings order by element id, descending.
  sync_rga_sibling_order(v) {
    const origin = v.input.origin_op_cbor_hex;
    const sibs = v.input.sibling_ops_cbor_hex;
    const target = opField(origin, 'target');
    const run = (ops) => {
      const seq = JSON.parse(ingest(ops).sequence(target));
      return {
        values: seq.values.map((x) => x.tstr).join(','),
        ids: seq.atoms.map((a) => hex(sync.encode_hlc(JSON.stringify(a.id)))).join(','),
      };
    };
    const fwd = run([origin, ...sibs]);
    const rev = run([origin, ...[...sibs].reverse()]);
    return {
      values_forward: fwd.values,
      ids_forward: fwd.ids,
      values_reverse: rev.values,
      ids_reverse: rev.ids,
    };
  },

  // SYNC-RGA-02 — an insert whose origin is tombstoned still resolves.
  sync_rga_tombstone_origin(v) {
    const target = opField(v.input.insert_x_cbor_hex, 'target');
    const seq = JSON.parse(
      ingest([
        v.input.insert_x_cbor_hex,
        v.input.remove_x_cbor_hex,
        v.input.insert_y_cbor_hex,
      ]).sequence(target),
    );
    return {
      visible: seq.values.map((x) => x.tstr).join(','),
      // The vector's `atom_order_incl_tombstones` is a LABEL list, rendered here from the actual
      // atom order rather than restated.
      labels: seq.atoms
        .map((a) => `${a.value?.tstr ?? ''}${a.tombstoned ? '(tombstoned)' : ''}`)
        .join(','),
      resolves: String(
        seq.atoms.some(
          (a) =>
            hex(sync.encode_hlc(JSON.stringify(a.id))) ===
            hex(sync.encode_hlc(JSON.stringify(opHlc(v.input.insert_y_cbor_hex)))),
        ),
      ),
    };
  },

  // SYNC-TREE-01 — a concurrent move that would close a cycle is skipped, identically everywhere.
  sync_tree_move_replay(v) {
    const ops = [...v.input.baseline_ops_cbor_hex, ...v.input.colliding_ops_cbor_hex];
    const colliding = v.input.colliding_ops_cbor_hex;
    const h1 = JSON.stringify(opHlc(colliding[0]));
    const h2 = JSON.stringify(opHlc(colliding[1]));
    const label = (hlcJsonStr) => {
      const e = hex(sync.encode_hlc(hlcJsonStr));
      if (e === hex(sync.encode_hlc(h1))) return 'h1';
      if (e === hex(sync.encode_hlc(h2))) return 'h2';
      return '?';
    };
    const orders = [ops, [...ops].reverse(), [ops[3], ops[2], ops[0], ops[1]]];
    const out = { h1_before_h2: String(sync.compare_hlc(h1, h2) < 0) };
    orders.forEach((order, i) => {
      const t = JSON.parse(ingest(order).tree());
      out[`edges_${i}`] = t.edges.map(([n, p, ord]) => `${n}>${p}:${ord}`).join(',');
      out[`skipped_${i}`] = t.skipped.map((s) => label(JSON.stringify(s.hlc))).join(',');
      // Acyclicity, checked rather than assumed.
      const edges = new Map(t.edges.map(([n, p]) => [n, p]));
      for (const node of edges.keys()) {
        let cur = node;
        let steps = 0;
        while (edges.has(cur)) {
          cur = edges.get(cur);
          if (++steps > edges.size) throw new Error(`cycle reachable from ${node}`);
        }
      }
      out[`acyclic_${i}`] = 'true';
    });
    return out;
  },

  // SYNC-SNAP-01 — the canonical six-section state and its root.
  sync_snapshot_state_root(v) {
    const state = observableToBindingJson(v.input.observable_state);
    const cbor = sync.encode_observable_state(JSON.stringify(state));
    const empty = sync.encode_observable_state(
      JSON.stringify({ orset: [], lww: [], pn: [], death: [], rga: [], tree: [] }),
    );
    // Section entries sort by det_cbor, so a shuffled projection hashes identically.
    const shuffled = {
      ...state,
      tree: [...state.tree].reverse(),
      lww: [...state.lww].reverse(),
    };
    // A one-bit difference in observable state is a DIFFERENT root ⇒ 0x0A09 evidence.
    const diverged = {
      ...state,
      lww: state.lww.map((c, i) => (i === 0 ? [c[0], c[1], { tstr: 'DIVERGED' }] : c)),
    };
    return {
      state_cbor: hex(cbor),
      root: hex(sync.observable_state_root(cbor)),
      empty_cbor: hex(empty),
      empty_root: hex(sync.observable_state_root(empty)),
      shuffled_cbor: hex(sync.encode_observable_state(JSON.stringify(shuffled))),
      diverged_root: hex(
        sync.observable_state_root(sync.encode_observable_state(JSON.stringify(diverged))),
      ),
      roundtrip_cbor: hex(
        sync.encode_observable_state(sync.decode_observable_state(cbor)),
      ),
    };
  },

  // SYNC-SNAP-02 — adopting a checkpoint then applying the suffix equals a full replay.
  sync_snapshot_fast_join(v) {
    const body = unhex(v.input.snapshot_observable_state_cbor_hex);
    const adopted = JSON.parse(sync.decode_observable_state(body));
    // Apply the post-`covers` ops to the adopted projection — what a replica does after adopting.
    for (const opHex of v.input.post_covers_ops_cbor_hex) {
      const op = JSON.parse(sync.decode_op(unhex(opHex)));
      const cell = adopted.lww.find((c) => c[0] === op.target && c[1] === op.field);
      if (cell) cell[2] = op.value;
      else adopted.lww.push([op.target, op.field, op.value]);
    }
    const joined = sync.encode_observable_state(JSON.stringify(adopted));
    return {
      snapshot_root_recomputed: hex(sync.observable_state_root(body)),
      fast_join_state: hex(joined),
      root: hex(sync.observable_state_root(joined)),
    };
  },

  // SYNC-RECON-01 — the range-Merkle fold and the recursive diff.
  sync_recon_fingerprint(v) {
    const entries = {};
    const out = {};
    for (const [label, opHex] of Object.entries(v.input.ops_cbor_hex)) {
      const id = hex(sync.op_id(unhex(opHex)));
      entries[label] = { hlc: opHlc(opHex), id };
      out[`op_id_${label}`] = id;
    }
    const holds = (key) => JSON.stringify(v.input[key].map((l) => entries[l]));
    const A = holds('replica_A_holds');
    const B = holds('replica_B_holds');
    const lo = hlcJson(v.input.range.lo);
    const hi = hlcJson(v.input.range.hi);
    const split = hlcJson(v.input.split_at);
    for (const [name, set] of [
      ['A', A],
      ['B', B],
    ]) {
      for (const [range, l, h] of [
        ['full', lo, hi],
        ['sub1', lo, split],
        ['sub2', split, hi],
      ]) {
        const r = JSON.parse(sync.summarize(set, l, h));
        out[`${range}_${name}_fp`] = r.fp;
        out[`${range}_${name}_count`] = String(r.count);
      }
    }
    const empty = JSON.parse(sync.fingerprint('[]'));
    out.empty_fp = empty.fp;
    out.empty_count = String(empty.count);
    const rec = JSON.parse(sync.reconcile(B, A, lo, hi));
    out.shipped_to_B = rec.missing_here.join(',');
    out.shipped_to_A = rec.missing_there.join(',');
    return out;
  },

  // SYNC-NS-01 — a responder ships only the namespaces the caller subscribed to.
  sync_ns_sparse_filter(v) {
    const ops = v.input.responder_ops_cbor_hex.map((h) => JSON.parse(sync.decode_op(unhex(h))));
    const shipped = JSON.parse(
      sync.scope_to_subscription(
        JSON.stringify(ops),
        JSON.stringify(v.input.caller_subscribed_ns),
      ),
    );
    return {
      shipped: shipped.join(','),
      shipped_ns: shipped.map((h) => JSON.parse(sync.decode_op(unhex(h))).ns).join(','),
    };
  },

  // SYNC-NS-02 — a cross-namespace reference is a leak, not a convenience.
  sync_ns_leak_check(v) {
    const op = JSON.parse(sync.decode_op(unhex(v.input.op_cbor_hex)));
    return {
      op_ns: op.ns,
      ref_target: op.reference.target,
      refusal: refusal(() => sync.check_ns_ref(op.ns, v.input.ref_target_actual_ns)),
      same_ns_ok: String(sync.check_ns_ref(op.ns, op.ns) === undefined),
    };
  },

  // SYNC-FJ-01 — the frozen FastJoin / pull response encoding.
  sync_fastjoin_pull_response(v, { sign }) {
    const i = v.input;
    // The snapshot is re-signed here through the DETACHED path — the seed never enters the module.
    const unsigned = {
      v: 0,
      suite: 1,
      ns: i.snapshot_ns,
      covers: coversFromCbor(i.snapshot_covers_cbor_hex),
      root: i.snapshot_root_hex,
      ts: i.snapshot_ts,
      signer: i.snapshot_signer_pubkey_hex,
    };
    const { preimage } = JSON.parse(sync.snapshot_signing_input(JSON.stringify(unsigned)));
    const sig = sign(i.snapshot_signer_seed_hex, unhex(preimage));
    const snapshot = sync.snapshot_assemble(JSON.stringify(unsigned), sig);

    const floor = JSON.parse(sync.decode_value(unhex(i.floor_hlc_cbor_hex)));
    const floorHlc = svalToHlc(floor);
    const mk = (state) =>
      sync.fastjoin_encode(
        JSON.stringify({ snapshot: JSON.parse(sync.snapshot_decode(snapshot)), floor: floorHlc, state }),
      );
    const byRef = mk(null);
    const inline = mk(i.observable_state_cbor_hex);

    // A corrupted inline hint must be DISCARDED in favour of the fetched body, not adopted...
    const corrupt = Array.from(unhex(i.observable_state_cbor_hex));
    corrupt[3] ^= 0xff;
    const hinted = mk(hex(new Uint8Array(corrupt)));
    const body = unhex(i.observable_state_cbor_hex);
    const adopted = sync.fastjoin_adopt(hinted, '[]', '[]', '[]', body);

    return {
      snapshot_preimage: preimage,
      snapshot_sig: hex(sig),
      snapshot_cbor: hex(snapshot),
      state_root: hex(sync.observable_state_root(body)),
      fastjoin_cbor: hex(byRef),
      pull_cbor: hex(pullEnvelope(byRef)),
      pull_inline_cbor: hex(pullEnvelope(inline)),
      fastjoin_roundtrip: hex(sync.fastjoin_encode(sync.fastjoin_decode(byRef))),
      state_address: hex(sync.fastjoin_state_address(byRef)),
      adopted_state: hex(adopted),
      // ...and with nothing fetchable, the same unverifiable hint fails CLOSED.
      corrupt_hint_unfetchable: refusal(() =>
        sync.fastjoin_adopt(hinted, '[]', '[]', '[]', undefined),
      ),
      caller_at_covers_below_floor: String(
        sync.caller_is_below_floor(snapshot, JSON.stringify(coversMarks(i.snapshot_covers_cbor_hex))),
      ),
    };
  },

  // SYNC-FJ-02 — the MUST in both directions, and the caller-side fail-closed paths.
  sync_fastjoin_floor_predicate(v) {
    const i = v.input;
    const fj = fastjoinFromPull(v.expected.caller_behind_response_cbor_hex);
    const snap = sync.fastjoin_encode(
      JSON.stringify({ ...JSON.parse(sync.fastjoin_decode(fj)), state: null }),
    );
    const snapBytes = snapshotOf(fj);
    const behind = JSON.stringify(coversMarks(i.caller_behind_vector_cbor_hex));
    const caughtUp = JSON.stringify(coversMarks(i.caller_caught_up_vector_cbor_hex));

    // The forbidden answer is WELL-FORMED — recomputed here, which is why the MUST is needed.
    const wouldBe = sync.encode_value(
      JSON.stringify({
        map: [[1, { arr: i.surviving_suffix_ops_cbor_hex.map((h) => JSON.parse(sync.decode_value(unhex(h)))) }]],
      }),
    );

    const floor = svalToHlc(JSON.parse(sync.decode_value(unhex(i.responder_floor_hlc_cbor_hex))));
    const gapFj = sync.fastjoin_encode(
      JSON.stringify({
        snapshot: JSON.parse(sync.snapshot_decode(unhex(i.snapshot_not_covering_gap_cbor_hex))),
        floor,
        state: null,
      }),
    );

    return {
      behind_is_below_floor: String(sync.caller_is_below_floor(snapBytes, behind)),
      caught_up_is_below_floor: String(sync.caller_is_below_floor(snapBytes, caughtUp)),
      ops_response_would_be: hex(wouldBe),
      fastjoin_roundtrip: hex(snap),
      // A snapshot that does not close the gap it was sent to close.
      gap_not_closed: refusal(() => sync.fastjoin_adopt(gapFj, behind, '[]', '[]', new Uint8Array(0))),
      // A body no holder can serve: 0x0A0C, fail-closed, never a fallback to the suffix.
      state_unavailable: refusal(() => sync.fastjoin_adopt(fj, behind, '[]', '[]', undefined)),
      // And a caught-up caller must not be fast-joined at all.
      caught_up_refuses_fastjoin: refusal(() =>
        sync.fastjoin_adopt(fj, caughtUp, '[]', '[]', undefined),
      ),
    };
  },

  // SYNC-GC-01 — the stability cut, and that GC below it is observably a no-op.
  sync_gc_stability_cut(v) {
    const live = v.input.live_replica_watermarks.map((w) => JSON.parse(hlcJson(w.max_applied_hlc)));
    const cut = JSON.parse(sync.stability_cut(JSON.stringify(live)));
    const stale = JSON.parse(hlcJson(v.input.stale_replica_watermark.max_applied_hlc));
    const withStale = JSON.parse(sync.stability_cut(JSON.stringify([...live, stale])));

    // Build a collapsed add/tombstone pair strictly below the cut, through real ops, and prune it.
    const author = cut.author;
    const addHlc = { wall: cut.wall, counter: 1, author };
    const mk = (o) => hex(sync.encode_op(JSON.stringify(o)));
    const add = mk({
      kind: 1, ns: '', target: 'tags', value: { tstr: 'e1' }, hlc: addHlc,
    });
    const remove = mk({
      kind: 2, ns: '', target: 'tags', value: { tstr: 'e1' },
      hlc: { wall: cut.wall, counter: 2, author },
      observed: [{ author, hlc: addHlc }],
    });
    const engine = ingest([add, remove]);
    const before = hex(engine.observable_state());
    const pruned = engine.prune_below(JSON.stringify(cut));
    return {
      cut: hex(sync.encode_hlc(JSON.stringify(cut))),
      cut_counter: String(cut.counter),
      with_stale: hex(sync.encode_hlc(JSON.stringify(withStale))),
      stale_drags_cut_down: String(
        sync.compare_hlc(JSON.stringify(withStale), JSON.stringify(cut)) < 0,
      ),
      // Fail-closed: a live replica with NO known watermark yields no cut at all.
      unknown_watermark_cut: sync.stability_cut(JSON.stringify([...live, null])),
      pruned_something: String(pruned > 0),
      state_before_gc: before,
      state_after_gc: hex(engine.observable_state()),
    };
  },
};

/** `{2: FastJoin}` — the §5.2.1 pull envelope, built with the generic CBOR helpers. */
const pullEnvelope = (fastjoinBytes) =>
  sync.encode_value(
    JSON.stringify({ map: [[2, JSON.parse(sync.decode_value(fastjoinBytes))]] }),
  );

/** Pull the FastJoin bytes back out of a `{2: FastJoin}` response. */
function fastjoinFromPull(pullHex) {
  const outer = JSON.parse(sync.decode_value(unhex(pullHex)));
  const entry = outer.map.find(([k]) => k === 2);
  return sync.encode_value(JSON.stringify(entry[1]));
}

/** The snapshot bytes inside a FastJoin. */
const snapshotOf = (fastjoinBytes) => {
  const inner = JSON.parse(sync.decode_value(fastjoinBytes));
  return sync.encode_value(JSON.stringify(inner.map.find(([k]) => k === 1)[1]));
};

/** An HLC decoded as a generic CBOR map, turned back into the binding's HLC spelling. */
const svalToHlc = (sval) => {
  const f = Object.fromEntries(sval.map);
  return { wall: f[1].int, counter: f[2].int, author: f[3].bstr };
};

/** A VersionVector's CBOR turned into the `[{author, hlc}]` marks the binding takes. */
const coversMarks = (vectorHex) =>
  JSON.parse(sync.decode_value(unhex(vectorHex))).bmap.map(([author, hlc]) => ({
    author,
    hlc: svalToHlc(hlc),
  }));

/** The same, in the shape `snapshot_signing_input`/`snapshot_assemble` expect. */
const coversFromCbor = (vectorHex) => coversMarks(vectorHex);

/** The vectors spell observable state as bare strings; the binding wants tagged values. */
function observableToBindingJson(o) {
  return {
    orset: o.orset.map(([t, e]) => [t, { tstr: e }]),
    lww: o.lww.map(([t, f, val]) => [t, f, { tstr: val }]),
    pn: o.pn.map(([t, f, n]) => [t, f, String(n)]),
    death: o.death.map(([t, c]) => [t, c]),
    rga: o.rga.map(([t, atoms]) => [t, atoms.map((a) => ({ tstr: a }))]),
    tree: o.tree.map(([n, p, ord]) => [n, p, ord]),
  };
}

/**
 * Drive every vector through the binding.
 * @param {object} vectorFile parsed sync_vectors.json
 * @param {{sign: (seedHex: string, message: Uint8Array) => Uint8Array}} host
 * @returns {{trace: object, covered: string[], skipped: string[]}}
 */
export function runVectors(vectorFile, host) {
  const trace = {};
  const covered = [];
  const skipped = [];
  for (const v of vectorFile.vectors) {
    if (NOT_COVERED[v.operation]) {
      skipped.push(v.name);
      continue;
    }
    const exec = executors[v.operation];
    if (!exec) throw new Error(`no JS executor registered for operation \`${v.operation}\``);
    trace[v.name] = exec(v, host);
    covered.push(v.name);
  }
  return { trace, covered, skipped };
}

export { executors };
