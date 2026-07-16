// provenance.js — client-facing transport-path provenance (spec §7.8, §8.6, §18.8.1).
//
// The node assembles a per-message, RECIPIENT-ONLY `ProvenanceRecord` at reception: which
// transport TIER the message arrived on (an *observation*, never a sender claim), whether the
// message is PURE-MESH (no gateway attestation → never plaintext at any gateway) or
// GATEWAY-TOUCHED (≥1 verified, domain-anchored attestation → legacy-origin, plaintext at that
// gateway before the mesh), and — for the private tier only — a coarse profile-floor hop count
// (§4.4.10). This module renders that record as a small transport-path graph:
//
//     sender → tier (hops) → [gateway?] → you
//
// Two things this MUST NOT do (spec §6.8, §7.8.1(c), §18.8.1 privacy invariants), enforced here
// by simply never having the data to violate them:
//   1. Never invent or display a mix-node identity, address, or per-hop timing. `minHops` is a
//      guaranteed FLOOR the private-tier profile satisfies, not a measured path.
//   2. Never claim `private` tier is absolute anonymity — the UI always states the boundary
//      being shown (mixnet vs. gateway), never a node-by-node trace.
//
// Shape of a message's `provenance` (seed.js), mirroring `ProvenanceRecord` (§18.8.1):
//   {
//     tier: 'private' | 'fast',            // observed arrival tier
//     profile: 'standard' | 'high' | null, // mix profile floor (§4.4.10); null when tier='fast'
//     origin: 'pure-mesh' | 'gateway-touched',
//     minHops: number | null,              // guaranteed floor (3/5 private, 1 fast) — never exact
//     observedAt: number,                  // recipient node reception time (local; never synced out)
//     gateways: [{ domain, selector, recvAt, legacyFrom?, seq }],  // empty iff origin='pure-mesh'
//   }

import { icon, esc, fmtLong, fmtClock } from './ui.js';

export const isPureMesh = (prov) => !prov || prov.origin !== 'gateway-touched';

// ---- Compact glyph — decorative, used in the mail row + as the reading-pane message badge ----
// shield (violet)  = pure-mesh · private tier
// bolt   (indigo)  = pure-mesh · fast tier
// bridge (amber)   = gateway-touched (legacy-origin) — visually unmistakable from the other two
export function pathIconName(prov) {
  if (!prov) return null;
  if (prov.origin === 'gateway-touched') return 'bridge';
  return prov.tier === 'fast' ? 'bolt' : 'shield';
}
export function pathTone(prov) {
  if (!prov) return '';
  return prov.origin === 'gateway-touched' ? 'gw' : (prov.tier === 'fast' ? 'fast' : 'priv');
}
export function pathSummary(prov) {
  if (!prov) return '';
  if (prov.origin === 'gateway-touched') {
    const g = prov.gateways?.[0];
    return 'Gateway-touched' + (g ? ` — bridged via ${g.domain}` : '') + ' — legacy-origin, not E2E before the gateway';
  }
  if (prov.tier === 'private') return `Pure-mesh — private tier, ≥ ${prov.minHops || 3} mix hops (${prov.profile === 'high' ? 'high-security' : 'standard'} floor)`;
  return 'Pure-mesh — fast tier, direct — never plaintext at a gateway';
}

// Row-level decorative badge (mail list). Not interactive — full detail lives in the reading pane.
export function pathBadge(prov) {
  const name = pathIconName(prov);
  if (!name) return '';
  return `<i class="path-badge ${pathTone(prov)}" aria-hidden="true" title="${esc(pathSummary(prov))}">${icon(name)}</i>`;
}

// Which message in a thread carries the provenance shown at the row level — the newest received
// (non-authored-by-you) message, matching what the row preview already shows.
export function threadProvenance(t) {
  for (let i = t.msgs.length - 1; i >= 0; i--) {
    const m = t.msgs[i];
    if (m.from !== 'you' && m.provenance) return m.provenance;
  }
  return null;
}

// ---- The reading-pane toggle button + expandable transport-path graph ----------------------
export function pathToggleButton(prov, key) {
  if (!prov) return '';
  const name = pathIconName(prov);
  return `<button class="icon-btn sm path-btn ${pathTone(prov)}" data-pathbtn="${esc(key)}" aria-expanded="false" aria-controls="path-${esc(key)}" aria-label="Transport path — ${esc(pathSummary(prov))}" title="Transport path — ${isPureMesh(prov) ? 'pure-mesh' : 'gateway-touched'}">${icon(name)}</button>`;
}

// Every node/arrow gets a sequential --i custom property, so the whole graph can play a single
// left-to-right reveal + a looping "flow" pulse along the connectors (CSS, app.css) — the path
// literally animates in the direction the message travelled, tinted by its tone (violet/indigo
// for pure-mesh, amber the moment a gateway is involved) so the graph reads at a glance.
let seq = 0;
function node(iconName, label, sub, cls = '') {
  return `<div class="path-node ${cls}" style="--i:${seq++}">
    <div class="path-node-ic">${icon(iconName)}</div>
    <div class="path-node-txt"><b>${esc(label)}</b>${sub ? `<span class="mono">${esc(sub)}</span>` : ''}</div>
  </div>`;
}
function arrow(tone) { return `<div class="path-arrow ${tone}" style="--i:${seq++}">${icon('chevRight')}</div>`; }

export function pathGraphHtml(prov, senderPerson, key) {
  if (!prov) return '';
  const pureMesh = isPureMesh(prov);
  const tone = pathTone(prov);           // overall tone (gw wins once a gateway is touched)
  const tierTone = prov.tier === 'private' ? 'priv' : 'fast';   // tone of the tier hop itself
  const tierNode = prov.tier === 'private'
    ? node('shield', 'private tier', `mixnet · ≥ ${prov.minHops || 3} hops (${prov.profile === 'high' ? 'high-security' : 'standard'} floor)`, 'tier priv')
    : node('bolt', 'fast tier', prov.minHops ? `direct · ${prov.minHops} hop (observed)` : 'direct', 'tier fast');

  seq = 0;
  const graph = [
    node('at', senderPerson?.name || 'sender', senderPerson?.address, 'endpoint'),
    arrow(tierTone),
    tierNode,
    ...(pureMesh ? [] : (prov.gateways || []).flatMap(g => [arrow('gw'), node('bridge', 'gateway · ' + g.domain, fmtClock(g.recvAt), 'gateway')])),
    arrow(tone),
    node('mail', 'you', 'this device', 'endpoint'),
  ].join('');

  const gatewayDetail = pureMesh ? '' : (prov.gateways || []).map(g => `
    <div class="gw-attest">
      <div class="gw-attest-row"><span class="k">domain</span><span class="v mono">${esc(g.domain)}</span></div>
      <div class="gw-attest-row"><span class="k">received</span><span class="v mono">${esc(fmtLong(g.recvAt))}</span></div>
      ${g.legacyFrom ? `<div class="gw-attest-row"><span class="k">legacy sender</span><span class="v mono">${esc(g.legacyFrom)}</span></div>` : ''}
      <div class="gw-attest-row"><span class="k">attested by</span><span class="v mono">${esc(g.selector)}._dmtap-gw.${esc(g.domain)}</span></div>
    </div>`).join('');

  const note = pureMesh
    ? `<div class="path-note good">${icon('shield')} <b>Pure-mesh — never plaintext at a gateway.</b> This message carries no gateway attestation, and the protocol requires one for any legacy-origin mail — so its absence provably means the message was end-to-end encrypted the whole way.</div>
       ${prov.tier === 'private' ? `<div class="path-note dim">${icon('info')} <b>Private tier — this path is intentionally not traceable.</b> The hop count above is a guaranteed minimum the mix profile satisfies, never a measured route — no party, including your own node, can reconstruct which relays carried it. That is the anonymity guarantee, not a gap in what this view shows.</div>` : ''}`
    : `<div class="path-note warn">${icon('bridge')} <b>Gateway-touched — legacy-origin.</b> Plaintext at the gateway named below before it entered the mesh, authenticated by that domain's own signing key — not by you. A pure-mesh message would never carry an attestation like this.</div>`;

  return `<div class="path-detail" id="path-${esc(key)}">
    <div class="path-graph">${graph}</div>
    ${gatewayDetail}
    ${note}
  </div>`;
}
