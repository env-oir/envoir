// views/overview.js — the superadmin home: fleet health at a glance. Counts by component kind
// (nodes · gateways · mix nodes · relays), up/down, per-region rollup, the open incident feed, and
// the standing content-blind guarantee made legible up front. Everything a superadmin needs to
// answer "is the fleet healthy, and where does it hurt?" in one screen.

import {
  state, counts, byKind, liveFleet, KIND, REGIONS, regionName, regionFlag, meterTotals, openIncidents,
  ktWitnessFresh, ktWitnessSplit, ktStaleCount, ktSplitCount, ktReverify,
} from '../store.js';
import { bus } from '../bus.js';
import { esc, icon, healthDot, emptyState, timeAgo, fmtBytes, fmtNum, toast } from '../ui.js';

const SEV = { critical: 'bad', major: 'bad', minor: 'warn', info: 'accent' };

export function render(root) {
  root.className = 'view scroll-view';
  const total = counts();
  const kinds = ['node', 'gateway', 'mix', 'relay'];
  const mt = meterTotals();
  const incidents = openIncidents();
  const allIncidents = state.incidents;
  const kt = state.kt;
  const ktStale = kt ? ktStaleCount() > 0 : false;
  const ktSplit = kt ? ktSplitCount() > 0 : false;

  // region rollup
  const regions = REGIONS.map(r => {
    const list = liveFleet().filter(c => c.region === r.id);
    return { ...r, total: list.length, up: list.filter(c => c.status === 'up').length, down: list.filter(c => c.status === 'down').length, degraded: list.filter(c => c.status === 'degraded').length };
  }).filter(r => r.total);

  const banner = total.down
    ? `<div class="banner bad">${icon('warn')} <span><b>${total.down} component${total.down > 1 ? 's' : ''} down</b>${total.degraded ? ` and ${total.degraded} degraded` : ''}. ${incidents.length} open incident${incidents.length !== 1 ? 's' : ''} — see the feed below.</span></div>`
    : total.degraded
      ? `<div class="banner warn">${icon('warn')} <span><b>${total.degraded} component${total.degraded > 1 ? 's' : ''} degraded.</b> No hard outages. Fleet serving normally.</span></div>`
      : `<div class="banner good">${icon('check')} <span><b>All ${total.total} components operational.</b> No open incidents affecting service.</span></div>`;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Overview</h1>
        <p class="page-sub">Fleet health for the <span class="mono">envoir-cloud</span> control plane — nodes, gateways, mix nodes and relays across ${regions.length} regions. Operations only; never content.</p>
      </div>
      <div class="page-head-aside">
        <span class="content-blind" title="The inviolable rule (spec §12.3)">${icon('lock')} content-blind</span>
      </div>
    </header>

    ${banner}

    <section class="kind-grid">
      ${kinds.map(k => {
        const c = counts(k);
        const meta = KIND[k];
        return `<button class="card kind-card clickable" data-kind="${k}">
          <div class="kind-top"><span class="kind-ic">${icon(meta.icon)}</span><span class="kind-name">${esc(meta.plural)}</span></div>
          <div class="kind-n">${c.total}</div>
          <div class="kind-health">
            <span class="kh ${c.up ? 'good' : 'off'}">${healthDot('up')}${c.up} up</span>
            ${c.degraded ? `<span class="kh warn">${healthDot('degraded')}${c.degraded}</span>` : ''}
            ${c.down ? `<span class="kh bad">${healthDot('down')}${c.down} down</span>` : '<span class="kh off">0 down</span>'}
          </div>
        </button>`;
      }).join('')}
    </section>

    <section class="ov-grid-2">
      <div class="card region-card">
        <div class="card-h"><h2>${icon('globe')} Regions</h2><span class="list-count">${regions.length}</span></div>
        <p class="card-sub">Fleet distribution and health by region. EU is the primary cell; JHB carries the Africa relay path.</p>
        <div class="region-list">
          ${regions.map(r => `
            <div class="region-row ${r.down ? 'has-down' : ''}">
              <span class="region-flag" aria-hidden="true">${r.flag}</span>
              <div class="region-main"><b>${esc(r.name)}</b><small>${r.total} component${r.total > 1 ? 's' : ''}${r.primary ? ' · primary cell' : ''}</small></div>
              <div class="region-bars" title="${r.up} up · ${r.degraded} degraded · ${r.down} down">
                ${bars(r)}
              </div>
              <span class="region-count mono ${r.down ? 'bad' : r.degraded ? 'warn' : 'good'}">${r.up}/${r.total}</span>
            </div>`).join('')}
        </div>
      </div>

      <div class="card meters-card">
        <div class="card-h"><h2>${icon('activity')} Metered operations <span class="pill dim sm">last period</span></h2></div>
        <p class="card-sub">Aggregate <span class="mono">dmtap-seam</span> usage across all accounts — the genuine cost centers. Deliberately small; deliberately not content.</p>
        <div class="meter-tiles">
          ${meterTile('database', 'Hosted storage', fmtBytes(mt.storage_bytes))}
          ${meterTile('gateway', 'Gateway sends', fmtNum(mt.gateway_sends))}
          ${meterTile('mail', 'Inbound legacy', fmtNum(mt.inbound_legacy))}
          ${meterTile('relay', 'Relayed bytes', fmtBytes(mt.relay_bytes))}
          ${meterTile('tag', 'Managed domains', fmtNum(mt.domains))}
          ${meterTile('zap', 'Native messages', fmtNum(mt.messages_sent))}
        </div>
        <button class="btn ghost sm meters-more" data-go="billing">Open billing metrics →</button>
      </div>
    </section>

    ${kt ? `
    <section class="card kt-card">
      <div class="card-h">
        <h2>${icon('kt')} Key Transparency log health <span class="pill dim sm">spec §3.5</span></h2>
        <span class="pill ${ktSplit ? 'bad' : ktStale ? 'warn' : 'good'} sm">${ktSplit ? icon('warn') + ' split-view' : ktStale ? icon('warn') + ' stale witness' : icon('check') + ' consistent'}</span>
      </div>
      <p class="card-sub">Independent witnesses gossip the published root so a covert re-key or split-view is detectable, not just trusted (spec §3.5). Content-blind: this is metadata about the <b>log</b>, never about what any binding resolves to for whom.</p>
      <div class="kt-figs">
        <div class="kt-fig"><span class="kf-n mono">${fmtNum(kt.treeSize)}</span><span class="kf-l">tree size</span></div>
        <div class="kt-fig"><span class="kf-n mono ellip">${esc(kt.rootHash.slice(0, 16))}…</span><span class="kf-l">published root</span></div>
        <div class="kt-fig"><span class="kf-n ${(Date.now() - kt.publishedAt) > kt.freshnessSla ? 'warn' : ''}">${esc(timeAgo(kt.publishedAt))}</span><span class="kf-l">last published</span></div>
      </div>
      <div class="kt-witness-list">
        ${kt.witnesses.map(w => {
          const split = ktWitnessSplit(w), fresh = ktWitnessFresh(w);
          const cls = split ? 'bad' : fresh ? 'good' : 'warn';
          return `<div class="kt-witness ${cls}">
            <span class="hdot ${split ? 'down' : fresh ? 'up' : 'degraded'}"></span>
            <div class="kt-witness-main"><b class="mono">${esc(w.name)}</b><small>${regionFlag(w.region)} ${esc(regionName(w.region))}</small></div>
            <span class="pill ${cls} sm">${split ? 'SPLIT' : fresh ? 'consistent' : 'stale'}</span>
            <span class="kt-witness-t">${esc(timeAgo(w.lastGossip))}</span>
          </div>`;
        }).join('')}
      </div>
      ${ktSplit ? `<div class="banner bad">${icon('warn')} <span><b>Split-view detected.</b> ${ktSplitCount()} witness(es) report a root hash that disagrees with the published checkpoint. Treat as a critical incident until cross-witness quorum re-confirms a single canonical root.</span></div>`
        : ktStale ? `<div class="banner warn">${icon('warn')} <span><b>${ktStaleCount()}</b> witness(es) haven't gossiped within the ${Math.round(kt.freshnessSla / 60000)}m freshness SLA. Not a split-view on its own, but re-verify to confirm they still agree.</span></div>` : ''}
      <div class="card-foot"><span class="sim-tag">${icon('info')} witness gossip is simulated</span><div class="spacer"></div><button class="btn sm" id="ktreverify">${icon('refresh')} Force gossip round</button></div>
    </section>` : ''}

    <section class="card">
      <div class="card-h">
        <h2>${icon('bell')} Incident &amp; alert feed</h2>
        <span class="pill ${incidents.length ? 'warn' : 'good'} sm">${incidents.length} open</span>
      </div>
      <div class="incident-feed" id="incident-feed"></div>
    </section>
  </div>`;

  const feed = root.querySelector('#incident-feed');
  if (!allIncidents.length) {
    feed.innerHTML = emptyState('check', 'No incidents', 'Nothing has tripped an alert. The fleet is quiet.');
  } else {
    feed.innerHTML = allIncidents.slice(0, 6).map(i => `
      <div class="incident-row ${i.status}">
        <span class="incident-sev ${SEV[i.sev] || 'dim'}" title="${esc(i.sev)}">${icon(i.status === 'resolved' ? 'check' : 'warn')}</span>
        <div class="incident-main">
          <div class="incident-top"><b>${esc(i.title)}</b><span class="pill ${i.status === 'resolved' ? 'good' : SEV[i.sev]} sm">${esc(i.status)}</span><span class="pill dim sm">${esc(i.sev)}</span></div>
          <p>${esc(i.body)}</p>
          <small class="incident-meta">${i.components.map(c => `<span class="chiplet">${esc(c)}</span>`).join('')} · updated ${esc(timeAgo(i.updated))} · opened ${esc(timeAgo(i.started))}</small>
        </div>
      </div>`).join('');
  }

  root.querySelectorAll('[data-kind]').forEach(b => b.onclick = () => { state.ui.fleetKind = b.dataset.kind; bus.setView('fleet'); });
  root.querySelectorAll('[data-go]').forEach(b => b.onclick = () => bus.setView(b.dataset.go));
  root.querySelector('#ktreverify')?.addEventListener('click', () => {
    ktReverify();
    toast(`${icon('check')} Gossip round forced — ${kt.witnesses.length} witnesses re-confirmed`);
    bus.rerender();
  });
}

function bars(r) {
  const seg = (n, cls) => Array.from({ length: n }, () => `<i class="rb ${cls}"></i>`).join('');
  return `<div class="rbars">${seg(r.up, 'good')}${seg(r.degraded, 'warn')}${seg(r.down, 'bad')}</div>`;
}
function meterTile(ic, label, value) {
  return `<div class="meter-tile"><span class="mt-ic">${icon(ic)}</span><div class="mt-body"><span class="mt-v">${esc(value)}</span><span class="mt-l">${esc(label)}</span></div></div>`;
}
