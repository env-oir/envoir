// views/fleet.js — the fleet directory: a filterable list of every node / gateway / mix node /
// relay, with a detail pane showing health, version, region, operator, ATTESTATION status
// (domain-anchored §7.2a for nodes+gateways; operator-diversity §4.4.8 for mix nodes), reputation
// (§9.6 for gateways+mix), per-kind operational metrics, and enroll / decommission actions.

import { state, component, liveFleet, byKind, uid, persist, KIND, REGIONS, regionName, regionFlag, counts, SELF_OPERATOR } from '../store.js';
import { bus } from '../bus.js';
import {
  el, esc, icon, healthDot, healthPill, attestBadge, repBar, meter, sparkline, emptyState,
  openModal, closeModal, toast, timeAgo, fmtDate, fmtBytes, fmtNum, pct, copyBtn,
} from '../ui.js';

const KIND_ORDER = ['all', 'node', 'gateway', 'mix', 'relay'];

export function render(root) {
  root.className = 'view split-view' + (state.ui.mobileDetail ? ' detail' : '');
  const q = state.ui.search.trim().toLowerCase();
  const kind = state.ui.fleetKind || 'all';
  const base = liveFleet().filter(c => kind === 'all' || c.kind === kind);
  const list = base.filter(c => !q || (c.host + ' ' + c.region + ' ' + c.operator + ' ' + KIND[c.kind].label).toLowerCase().includes(q))
    .sort((a, b) => order(a.status) - order(b.status) || a.host.localeCompare(b.host));
  const sel = component(state.ui.selNode) && list.includes(component(state.ui.selNode)) ? component(state.ui.selNode) : (list[0] || null);
  state.ui.selNode = sel?.id || null;

  root.innerHTML = `
    <aside class="split-list">
      <div class="list-head">
        <h2>Fleet <span class="list-count">${base.length}</span></h2>
        <button class="btn primary sm" id="enroll">${icon('plus')} Enroll</button>
      </div>
      <div class="kind-filter" id="kind-filter" role="tablist" aria-label="Component kind">
        ${KIND_ORDER.map(k => {
          const on = k === kind;
          const n = k === 'all' ? liveFleet().length : byKind(k).filter(c => c.status !== 'decommissioned').length;
          return `<button class="chip ${on ? 'on' : ''}" data-kind="${k}" role="tab" aria-selected="${on}">${k === 'all' ? 'All' : esc(KIND[k].plural)} <i>${n}</i></button>`;
        }).join('')}
      </div>
      <div class="list-rows" id="rows"></div>
    </aside>
    <section class="split-detail" id="detail"></section>`;

  const rows = root.querySelector('#rows');
  if (!list.length) {
    rows.innerHTML = q ? emptyState('search', 'No matches', 'No components match your search.')
      : emptyState('fleet', 'No components', 'Enroll a node, gateway, mix node or relay to populate the fleet.');
  } else {
    list.forEach(c => {
      const on = c.id === sel?.id;
      const row = el(`<button class="list-row fleet-row ${on ? 'sel' : ''}" data-id="${c.id}"${on ? ' aria-current="true"' : ''}>
        <span class="fr-ic ${c.kind}">${icon(KIND[c.kind].icon)}</span>
        <div class="list-row-main">
          <span class="lr-name">${healthDot(c.status)} <span class="mono ellip">${esc(c.host)}</span></span>
          <span class="lr-sub">${esc(KIND[c.kind].label)} · ${regionFlag(c.region)} ${esc(regionName(c.region).replace(/^.*· /, ''))}</span>
        </div>
        ${c.rep != null ? `<span class="fr-rep ${c.rep >= 85 ? 'good' : c.rep >= 60 ? 'warn' : 'bad'} mono" title="Reputation (spec §9.6)">${c.rep}</span>` : ''}
      </button>`);
      row.onclick = () => { state.ui.selNode = c.id; state.ui.mobileDetail = true; bus.rerender(); };
      rows.appendChild(row);
    });
  }
  root.querySelector('#enroll').onclick = enrollModal;
  root.querySelectorAll('[data-kind]').forEach(b => b.onclick = () => { state.ui.fleetKind = b.dataset.kind; bus.rerender(); });
  drawDetail(root.querySelector('#detail'), sel);
}

const order = (s) => ({ down: 0, degraded: 1, up: 2 }[s] ?? 3);

function drawDetail(wrap, c) {
  if (!c) { wrap.innerHTML = emptyState('fleet', 'No component selected', 'Select a host to inspect its health, attestation and metrics.'); return; }
  const meta = KIND[c.kind];
  const metrics = kindMetrics(c);

  wrap.innerHTML = `
    <div class="detail-scroll">
      <button class="btn ghost sm mobile-back" id="back">${icon('minus')} Back to fleet</button>
      <div class="fleet-hero">
        <span class="fleet-hero-ic ${c.kind}">${icon(meta.icon)}</span>
        <div class="fleet-hero-main">
          <h1><span class="mono">${esc(c.host)}</span></h1>
          <div class="fleet-hero-tags">
            ${healthPill(c.status, false)}
            <span class="pill dim sm">${icon(meta.icon)} ${esc(meta.label)}</span>
            <span class="pill dim sm">${regionFlag(c.region)} ${esc(regionName(c.region))}</span>
            <span class="pill accent sm mono">v${esc(c.version)}</span>
            ${attestBadge(c.attest)}
          </div>
        </div>
        <button class="btn danger" id="decom">${icon('trash')} Decommission</button>
      </div>

      <p class="card-sub hero-desc">${esc(meta.desc)}</p>

      <div class="detail-cols">
        <div class="card">
          <div class="card-h"><h2>${icon('activity')} Health &amp; load</h2></div>
          <div class="load-block">
            <div class="load-figs">
              <div class="lf"><span class="lf-n">${pct(c.uptime)}</span><span class="lf-l">uptime (30d)</span></div>
              <div class="lf"><span class="lf-n ${c.cpu >= 90 ? 'bad' : c.cpu >= 75 ? 'warn' : ''}">${c.status === 'down' ? '—' : c.cpu + '%'}</span><span class="lf-l">CPU</span></div>
              <div class="lf"><span class="lf-n">${c.memGB} GB</span><span class="lf-l">memory</span></div>
            </div>
            <div class="load-spark">${sparkline(c.loadHistory, { cls: c.status === 'down' ? 'bad' : c.status === 'degraded' ? 'warn' : 'accent', w: 240, h: 44 })}<small>load, last 24h</small></div>
          </div>
          <div class="kv-list">
            <div class="kv"><span class="k">Load</span><span class="v load-inline">${meter(c.load)}<b class="mono">${Math.round(c.load * 100)}%</b></span></div>
            <div class="kv"><span class="k">Last seen</span><span class="v ${c.status === 'down' ? 'bad' : ''}">${c.status === 'down' ? 'no probe response · ' : ''}${esc(timeAgo(c.lastSeen))}</span></div>
            <div class="kv"><span class="k">Enrolled</span><span class="v">${esc(fmtDate(c.enrolledAt))}</span></div>
            <div class="kv"><span class="k">Operator</span><span class="v mono">${esc(c.operator)}</span></div>
          </div>
        </div>

        <div class="card attest-card ${c.attest.status}">
          <div class="card-h"><h2>${icon('shield')} Attestation</h2>${attestBadge(c.attest)}</div>
          <p class="card-sub">${attestCopy(c)}</p>
          ${c.attest.status === 'n/a' ? `<div class="sovereign-seal">${icon('info')} <span>Relays carry no message attestation — they forward opaque, sealed bytes and learn nothing about them.</span></div>` : `
          <div class="kv-list">
            <div class="kv"><span class="k">Status</span><span class="v">${attestBadge(c.attest)}</span></div>
            <div class="kv"><span class="k">Anchored key</span><span class="v mono ellip" id="attest-key">${esc(c.attest.key.slice(0, 28))}…</span></div>
            <div class="kv"><span class="k">Verified</span><span class="v">${esc(timeAgo(c.attest.verifiedAt))}</span></div>
            <div class="kv"><span class="k">Spec</span><span class="v mono">${c.kind === 'mix' ? '§4.4.8 operator diversity' : '§7.2a domain-anchored'}</span></div>
          </div>
          ${c.attest.status !== 'valid' ? `<button class="btn sm attest-reverify" id="reverify">${icon('refresh')} Re-verify attestation</button>` : ''}`}
        </div>
      </div>

      ${c.rep != null ? `
      <div class="card">
        <div class="card-h"><h2>${icon('gauge')} Operator reputation <span class="pill dim sm">spec §9.6</span></h2></div>
        <p class="card-sub">A behaviour score derived from delivery outcomes and abuse feedback — <b>never message content</b>. Low reputation throttles or de-prioritizes a ${esc(meta.label.toLowerCase())}; it never exposes what was sent.</p>
        <div class="rep-big">${repBar(c.rep)}<span class="rep-label">${c.rep >= 85 ? 'trusted' : c.rep >= 60 ? 'watch' : 'throttled'}</span></div>
      </div>` : ''}

      <div class="card">
        <div class="card-h"><h2>${icon(meta.icon)} ${esc(meta.label)} metrics <span class="pill dim sm">operations only</span></h2></div>
        <div class="metric-grid">${metrics}</div>
      </div>
    </div>`;

  wrap.querySelector('#back').onclick = () => { state.ui.mobileDetail = false; bus.rerender(); };
  wrap.querySelector('#decom').onclick = () => decommissionModal(c);
  wrap.querySelector('#reverify')?.addEventListener('click', () => {
    c.attest.status = 'valid'; c.attest.verifiedAt = Date.now(); persist();
    toast(`${icon('check')} Attestation re-verified for ${esc(c.host)}`); bus.rerender();
  });
  const keyEl = wrap.querySelector('#attest-key');
  if (keyEl && c.attest.key) keyEl.parentElement.appendChild(copyBtn(c.attest.key, 'Copy attestation key'));
}

function attestCopy(c) {
  if (c.kind === 'mix') return 'Mix nodes must present a valid operator-diversity attestation so the path builder can guarantee that consecutive hops belong to independent operators (spec §4.4.8). A stale/unattested mix is excluded from path selection.';
  if (c.kind === 'gateway') return 'A gateway signs each bridged MOTE with a <b>domain-anchored attestation key</b> published under <span class="mono">_dmtap-gw</span>; recipients verify it against the sender-domain’s own DNS (spec §7.2a). Unattested egress is rejected downstream.';
  return 'This node presents a domain-anchored attestation binding its identity to the operator domain (spec §7.2a). An unattested node is quarantined from serving hosted mailboxes.';
}

function kindMetrics(c) {
  const tile = (ic, label, value, sub = '') => `<div class="metric"><span class="metric-ic">${icon(ic)}</span><div><span class="metric-v">${esc(value)}</span><span class="metric-l">${esc(label)}${sub ? ` · ${esc(sub)}` : ''}</span></div></div>`;
  if (c.kind === 'node') return tile('users', 'Hosted mailboxes', fmtNum(c.mailboxes)) + tile('database', 'Stored', fmtBytes(c.storageBytes)) + tile('cpu', 'Memory', c.memGB + ' GB');
  // rate decimals via toLocaleString so the separator is locale-correct ("4,20 %" in de/fr)
  const rate = (v, d) => v.toLocaleString([], { minimumFractionDigits: d, maximumFractionDigits: d }) + '%';
  if (c.kind === 'gateway') return tile('gateway', 'Sends (24h)', fmtNum(c.sends24h)) + tile('up', 'Bounce rate', rate(c.bounceRate, 2), c.bounceRate > 4 ? 'high' : 'ok') + tile('flame', 'Complaint rate', rate(c.complaintRate, 3));
  if (c.kind === 'mix') return tile('mix', 'Layer', 'L' + c.layer + ' of 3') + tile('activity', 'Forwarded (24h)', fmtNum(c.forwarded24h)) + tile('clock', 'Mix latency', c.latencyMs + ' ms');
  if (c.kind === 'relay') return tile('relay', 'Bandwidth (24h)', fmtBytes(c.bandwidth24h)) + tile('wifi', 'Active tunnels', fmtNum(c.tunnels)) + tile('cpu', 'Memory', c.memGB + ' GB');
  return '';
}

// ---- enroll --------------------------------------------------------------------------------
function enrollModal() {
  let kind = 'node', region = 'eu-central';
  const card = openModal('<div></div>', { wide: true, label: 'Enroll a component' });
  const draw = () => {
    card.innerHTML = `
      <div class="modal-head"><h2>${icon('plus')} Enroll a component</h2><button class="icon-btn" id="ex" aria-label="Close">${icon('x')}</button></div>
      <div class="modal-body">
        <p class="modal-note">${icon('info')} Enrolling adds a component to the fleet registry and issues its enrollment credential. Attestation is verified out-of-band before it is allowed to serve.</p>
        <label class="cfield"><span>Kind</span></label>
        <div class="model-select">
          ${['node', 'gateway', 'mix', 'relay'].map(k => `<button class="model-opt ${kind === k ? 'sel' : ''}" data-k="${k}"><div class="model-opt-h">${icon(KIND[k].icon)} ${esc(KIND[k].label)}</div><p>${esc(KIND[k].desc)}</p></button>`).join('')}
        </div>
        <label class="cfield"><span>Hostname</span><input id="ehost" placeholder="mx4.eu-central.envoir.net" autofocus></label>
        <label class="cfield"><span>Region</span>
          <select id="ereg">${REGIONS.map(r => `<option value="${r.id}" ${region === r.id ? 'selected' : ''}>${r.flag} ${esc(r.name)}</option>`).join('')}</select>
        </label>
      </div>
      <div class="modal-foot">
        <button class="btn ghost" id="ecancel">Cancel</button>
        <div class="spacer"></div>
        <button class="btn primary" id="ecreate">${icon('plus')} Enroll ${esc(KIND[kind].label.toLowerCase())}</button>
      </div>`;
    card.querySelector('#ex').onclick = card.querySelector('#ecancel').onclick = closeModal;
    card.querySelectorAll('[data-k]').forEach(b => b.onclick = () => { kind = b.dataset.k; draw(); });
    card.querySelector('#ereg').onchange = (e) => { region = e.target.value; };
    card.querySelector('#ecreate').onclick = () => {
      const host = card.querySelector('#ehost').value.trim().toLowerCase();
      region = card.querySelector('#ereg').value;
      if (!host) return toast(`${icon('warn')} Enter a hostname`);
      if (state.fleet.some(x => x.host === host && x.status !== 'decommissioned')) return toast(`${icon('warn')} ${host} already enrolled`);
      const now = Date.now();
      const c = {
        id: uid(kind), kind, host, region, status: 'up', version: '0.4.2', uptime: 100, load: 0.05, cpu: 4, memGB: kind === 'node' ? 16 : 4,
        enrolledAt: now, lastSeen: now, operator: SELF_OPERATOR,
        attest: kind === 'relay' ? { status: 'n/a' } : { status: 'stale', key: 'pending-verification', verifiedAt: now },
        rep: kind === 'gateway' || kind === 'mix' ? 80 : null,
        loadHistory: Array.from({ length: 24 }, () => 4 + Math.random() * 6),
      };
      if (kind === 'node') { c.mailboxes = 0; c.storageBytes = 0; }
      if (kind === 'gateway') { c.sends24h = 0; c.bounceRate = 0; c.complaintRate = 0; }
      if (kind === 'mix') { c.layer = 1 + (state.fleet.filter(x => x.kind === 'mix').length % 3); c.forwarded24h = 0; c.latencyMs = 200; }
      if (kind === 'relay') { c.bandwidth24h = 0; c.tunnels = 0; }
      state.fleet.push(c); state.ui.selNode = c.id; state.ui.fleetKind = kind; persist();
      closeModal();
      toast(`${icon('check')} Enrolled ${esc(host)} · attestation pending`);
      bus.rerender();
    };
  };
  draw();
}

// ---- decommission --------------------------------------------------------------------------
function decommissionModal(c) {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('trash')} Decommission ${esc(c.host)}</h2><button class="icon-btn" id="dx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note warn">${icon('warn')} <span>This drains <span class="mono">${esc(c.host)}</span> and removes it from path selection / serving. ${c.kind === 'node' ? 'Hosted mailboxes must be migrated first — durability lives at the edges, but availability does not.' : c.kind === 'gateway' ? 'In-flight legacy egress fails over to peer gateways.' : c.kind === 'mix' ? 'The path builder excludes it on the next epoch.' : 'Active tunnels re-home to peer relays.'}</span></p>
      <div class="kv-list">
        <div class="kv"><span class="k">Kind</span><span class="v">${esc(KIND[c.kind].label)}</span></div>
        <div class="kv"><span class="k">Region</span><span class="v">${regionFlag(c.region)} ${esc(regionName(c.region))}</span></div>
        ${c.kind === 'node' ? `<div class="kv"><span class="k">Mailboxes</span><span class="v ${c.mailboxes ? 'warn' : ''}">${fmtNum(c.mailboxes)}${c.mailboxes ? ' · migrate first' : ''}</span></div>` : ''}
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn ghost" id="dcancel">Cancel</button>
      <div class="spacer"></div>
      <button class="btn danger" id="dconfirm">${icon('trash')} Decommission</button>
    </div>`, { wide: true, label: 'Decommission component' });
  card.querySelector('#dx').onclick = card.querySelector('#dcancel').onclick = closeModal;
  card.querySelector('#dconfirm').onclick = () => {
    c.status = 'decommissioned'; c.decommissionedAt = Date.now(); persist();
    state.ui.selNode = null;
    closeModal();
    toast(`${icon('check')} ${esc(c.host)} decommissioned`);
    bus.rerender();
  };
}
