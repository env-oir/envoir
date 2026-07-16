// views/public.js — the unauthenticated public status page. A polished, statuspage.io-class view
// on Aurora Indigo: a big overall banner (operational / degraded / outage), per-component health
// with 90-day uptime bars + 90-day uptime %, the active-incident section (with an empty state when
// quiet), and a past-incident history. Legible at a glance, honest about scope.

import { state, componentMeta } from '../store.js';
import { esc, icon, healthDot, healthPill, uptimeBars, emptyState, timeAgo, fmtLong, pct, OVERALL, COMP } from '../ui.js';

const IMPACT = { none: 'dim', minor: 'warn', major: 'bad', critical: 'bad' };
const UPD = { investigating: 'bad', identified: 'warn', monitoring: 'accent', resolved: 'good', maintenance: 'accent' };

export function renderPublic(root, actions) {
  const ov = OVERALL[state.overall] || OVERALL.operational;
  const active = state.incidents.filter(i => i.status !== 'resolved');
  const past = state.incidents.filter(i => i.status === 'resolved');
  const overallUptime = state.components.reduce((a, c) => a + c.uptime, 0) / state.components.length;

  root.innerHTML = `
  <div class="status-page">
    <section class="status-banner ${ov.cls}" role="status">
      <span class="sb-ic">${icon(ov.icon)}</span>
      <div class="sb-main">
        <h1>${esc(ov.label)}</h1>
        <p>${bannerSub()}</p>
      </div>
      <div class="sb-side">
        <span class="sb-uptime"><b>${pct(overallUptime)}</b><small>90-day uptime</small></span>
        <button class="icon-btn" id="refresh" title="Refresh" aria-label="Refresh status">${icon('refresh')}</button>
      </div>
    </section>

    ${active.length ? `
    <section class="active-incidents">
      ${active.map(i => incidentCard(i, true)).join('')}
    </section>` : `
    <div class="all-clear">${icon('check')} <span>No active incidents. All monitored services are responding normally.</span></div>`}

    <section class="components card">
      <div class="comp-head">
        <h2>Components</h2>
        <span class="comp-legend">
          <span class="cl"><span class="ub up"></span> Operational</span>
          <span class="cl"><span class="ub degraded"></span> Degraded</span>
          <span class="cl"><span class="ub down"></span> Outage</span>
        </span>
      </div>
      <div class="comp-list">
        ${state.components.map(c => componentRow(c)).join('')}
      </div>
      <div class="comp-foot"><span>90 days ago</span><span>Today</span></div>
    </section>

    <section class="history">
      <h2 class="history-h">${icon('clock')} Incident history</h2>
      <div id="history-list"></div>
    </section>
  </div>`;

  const hist = root.querySelector('#history-list');
  if (!past.length) hist.innerHTML = emptyState('check', 'No past incidents', 'Nothing in the recent history window. When incidents resolve, they are archived here.');
  else hist.innerHTML = `<div class="incident-history">${past.map(i => incidentCard(i, false)).join('')}</div>`;

  root.querySelector('#refresh').onclick = () => actions.refresh ? actions.refresh() : location.reload();
}

function bannerSub() {
  const active = state.incidents.filter(i => i.status !== 'resolved');
  if (state.overall === 'operational') return 'Native mail, key transparency, directory and reachability are all responding normally.';
  const names = [...new Set(active.flatMap(i => i.components))].map(c => componentMeta(c)?.name || c);
  if (state.overall === 'outage') return `A partial outage is affecting ${list(names)}. Native mail remains durable — messages are held and retried at the edges until delivery.`;
  return `Degraded performance on ${list(names)}. Native DMTAP mail is unaffected; the impact is on the named surfaces only.`;
}
function list(a) { return a.length <= 1 ? (a[0] || 'a service') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1]; }

function componentRow(c) {
  return `
    <div class="comp-row">
      <div class="comp-id">
        <span class="comp-ic ${c.status}">${icon(c.icon)}</span>
        <div class="comp-name"><b>${esc(c.name)}</b><small>${esc(c.desc)}</small></div>
        <span class="comp-status ${COMP[c.status].cls}">${healthDot(c.status)} ${esc(COMP[c.status].label)}</span>
      </div>
      <div class="comp-uptime">
        ${uptimeBars(c.history)}
        <div class="comp-uptime-foot"><span class="mono">${pct(c.uptime)} uptime</span></div>
      </div>
    </div>`;
}

function incidentCard(i, active) {
  return `
    <article class="incident-card ${active ? 'active' : 'past'} impact-${i.impact}">
      <div class="incident-card-h">
        <span class="incident-impact ${IMPACT[i.impact]}">${icon(active ? 'warn' : 'check')}</span>
        <div class="incident-card-title">
          <h3>${esc(i.title)}</h3>
          <div class="incident-card-tags">
            <span class="pill ${i.status === 'resolved' ? 'good' : UPD[i.status] || 'dim'} sm">${esc(i.status)}</span>
            <span class="pill ${IMPACT[i.impact]} sm">${esc(i.impact)} impact</span>
            ${i.components.map(c => `<span class="comp-chip">${esc(componentMeta(c)?.name || c)}</span>`).join('')}
          </div>
        </div>
        <span class="incident-when" title="${esc(fmtLong(i.started))}">${esc(timeAgo(i.started))}</span>
      </div>
      <ol class="incident-updates">
        ${i.updates.map(u => `
          <li class="incident-update">
            <span class="iu-dot ${UPD[u.status] || 'dim'}"></span>
            <div class="iu-body">
              <div class="iu-top"><b class="${UPD[u.status] || ''}">${esc(cap(u.status))}</b><span class="iu-t">${esc(fmtLong(u.ts))}</span></div>
              <p>${esc(u.body)}</p>
            </div>
          </li>`).join('')}
      </ol>
    </article>`;
}
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
