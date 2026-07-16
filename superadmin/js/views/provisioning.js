// views/provisioning.js — the capacity / warm-pool view (conceptual) plus the incident feed.
// Mirrors the generic-box warm-pool/claim/attach model: each region keeps a warm pool of ready
// instances; a claim attaches one to a tenant; the autoscaler refills toward a target. Capacity
// pressure and provider mix are shown per region. Incidents are managed here (acknowledge /
// resolve). Simulated — a production superadmin reads the operator's scaler + provider registry.

import { state, REGIONS, regionName, regionFlag, liveFleet, persist } from '../store.js';
import { bus } from '../bus.js';
import { esc, icon, emptyState, timeAgo, meter, toast, openModal, closeModal } from '../ui.js';

const SEV = { critical: 'bad', major: 'bad', minor: 'warn', info: 'accent' };

export function render(root) {
  root.className = 'view scroll-view';
  const pool = state.pool;
  const totalWarm = pool.reduce((n, p) => n + p.warm, 0);
  const totalActive = pool.reduce((n, p) => n + p.active, 0);
  const tightest = pool.slice().sort((a, b) => b.capacity - a.capacity)[0];
  const incidents = state.incidents;
  const open = incidents.filter(i => i.status !== 'resolved');

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Provisioning</h1>
        <p class="page-sub">Warm-pool &amp; capacity per region and the incident feed. Warm instances are claimed on demand and the autoscaler refills toward target.</p>
      </div>
    </header>

    <section class="prov-stats">
      ${statTile('box', totalActive, 'active instances', 'accent')}
      ${statTile('provision', totalWarm, 'warm & ready', totalWarm ? 'good' : 'warn')}
      ${statTile('gauge', Math.round((tightest?.capacity || 0) * 100) + '%', 'tightest region', (tightest?.capacity || 0) > 0.85 ? 'bad' : (tightest?.capacity || 0) > 0.7 ? 'warn' : 'good')}
      ${statTile('bell', open.length, 'open incidents', open.length ? 'warn' : 'good')}
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('globe')} Regional capacity &amp; warm pool</h2></div>
      <p class="card-sub">Per-region utilization, the ready warm pool, the autoscaler target, and the compute provider. A drained pool (warm 0) means every claim cold-starts until the scaler refills.</p>
      <div class="prov-regions">
        ${pool.map(p => provRegion(p)).join('')}
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('bell')} Incident &amp; alert feed <span class="pill ${open.length ? 'warn' : 'good'} sm">${open.length} open</span></h2></div>
      <div class="incident-feed" id="incident-feed"></div>
    </section>
  </div>`;

  const feed = root.querySelector('#incident-feed');
  if (!incidents.length) {
    feed.innerHTML = emptyState('check', 'No incidents', 'Nothing has tripped an alert.');
  } else {
    feed.innerHTML = incidents.map(i => `
      <div class="incident-row ${i.status}">
        <span class="incident-sev ${SEV[i.sev] || 'dim'}">${icon(i.status === 'resolved' ? 'check' : 'warn')}</span>
        <div class="incident-main">
          <div class="incident-top"><b>${esc(i.title)}</b><span class="pill ${i.status === 'resolved' ? 'good' : SEV[i.sev]} sm">${esc(i.status)}</span><span class="pill dim sm">${esc(i.sev)}</span></div>
          <p>${esc(i.body)}</p>
          <small class="incident-meta">${i.components.map(c => `<span class="chiplet">${esc(c)}</span>`).join('')} · updated ${esc(timeAgo(i.updated))} · opened ${esc(timeAgo(i.started))}</small>
        </div>
        <div class="incident-actions">
          ${i.status !== 'resolved' ? `<button class="btn sm" data-resolve="${i.id}">${icon('check')} Resolve</button>` : `<span class="pill good sm">${icon('check')} resolved</span>`}
        </div>
      </div>`).join('');
  }

  root.querySelectorAll('[data-resolve]').forEach(b => b.onclick = () => {
    const i = state.incidents.find(x => x.id === b.dataset.resolve);
    if (!i) return;
    i.status = 'resolved'; i.updated = Date.now(); persist();
    toast(`${icon('check')} Incident resolved`);
    bus.rerender();
  });
}

function provRegion(p) {
  const capCls = p.capacity > 0.85 ? 'bad' : p.capacity > 0.7 ? 'warn' : 'good';
  const warmCls = p.warm === 0 ? 'bad' : p.warm < 2 ? 'warn' : 'good';
  return `
    <div class="prov-region ${p.capacity > 0.85 ? 'tight' : ''}">
      <div class="pr-head">
        <span class="pr-flag" aria-hidden="true">${regionFlag(p.region)}</span>
        <div class="pr-title"><b>${esc(regionName(p.region))}</b><small class="mono">${esc(p.provider)}</small></div>
        <span class="pill ${capCls} sm">${Math.round(p.capacity * 100)}% used</span>
      </div>
      <div class="pr-cap">${meter(p.capacity)}</div>
      <div class="pr-figs">
        <div class="pr-fig"><span class="pf-n">${p.active}</span><span class="pf-l">active</span></div>
        <div class="pr-fig"><span class="pf-n ${warmCls}">${p.warm}</span><span class="pf-l">warm pool</span></div>
        <div class="pr-fig"><span class="pf-n">${p.target}</span><span class="pf-l">target</span></div>
        <div class="pr-fig"><span class="pf-n">${p.claimed24h}</span><span class="pf-l">claims 24h</span></div>
      </div>
      ${p.warm === 0 ? `<div class="pr-warnrow">${icon('warn')} Pool drained — claims cold-start until refill</div>` : ''}
    </div>`;
}

function statTile(ic, n, label, cls) {
  return `<div class="card stat-tile"><span class="st-ic ${cls}">${icon(ic)}</span><span class="st-n ${cls}">${esc(String(n))}</span><span class="st-l">${esc(label)}</span></div>`;
}
