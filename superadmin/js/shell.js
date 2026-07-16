// shell.js — the superadmin shell: left rail (Overview · Fleet · Billing · Abuse ops ·
// Provisioning), a topbar with the operator identity, fleet-health summary + search, and view
// dispatch. Fills the bus so views trigger re-renders without importing the shell (no cycle).

import { state, persist, wipe, counts, seed, openIncidents } from './store.js';
import { esc, icon, brandMark, openModal, closeModal, toast, healthDot } from './ui.js';
import { bus } from './bus.js';

import { render as renderOverview } from './views/overview.js';
import { render as renderFleet } from './views/fleet.js';
import { render as renderBilling } from './views/billing.js';
import { render as renderAbuse } from './views/abuse.js';
import { render as renderProvisioning } from './views/provisioning.js';

const VIEWS = [
  { id: 'overview', name: 'Overview', icon: 'home', render: renderOverview },
  { id: 'fleet', name: 'Fleet', icon: 'fleet', render: renderFleet, search: 'Search hosts, regions, operators' },
  { id: 'billing', name: 'Billing', icon: 'billing', render: renderBilling, search: 'Search accounts' },
  { id: 'abuse', name: 'Abuse ops', icon: 'abuse', render: renderAbuse, search: 'Search signals' },
  { id: 'provisioning', name: 'Provisioning', icon: 'provision', render: renderProvisioning },
];

export function mountShell() {
  const app = document.getElementById('app');
  app.classList.remove('hidden');
  app.innerHTML = `
    <nav class="rail" aria-label="Primary">
      <div class="rail-brand" title="Envoir Superadmin" aria-hidden="true">${brandMark(30)}</div>
      <div class="rail-nav" id="rail-nav">
        ${VIEWS.map(v => `<button class="rail-btn" data-view="${v.id}" title="${v.name}" aria-label="${v.name}">${icon(v.icon)}<span>${v.name}</span><i class="rail-badge" data-badge="${v.id}" aria-hidden="true"></i></button>`).join('')}
      </div>
      <div class="rail-spacer"></div>
      <button class="rail-id" id="rail-id" title="Operator control plane" aria-label="Operator — open overview">OP</button>
    </nav>
    <div class="workspace">
      <header class="topbar">
        <div class="op-chip" id="op-chip" title="Operator control plane">${icon('globe')}<b class="mono">envoir-cloud</b><span class="op-scope mono" title="Fleet scope">fleet</span></div>
        <div class="fleet-glance" id="fleet-glance"></div>
        <div class="topbar-search hidden" id="topbar-search" role="search">
          ${icon('search')}
          <input id="globalsearch" placeholder="Search…" aria-label="Search the current view" autocomplete="off" spellcheck="false">
        </div>
        <div class="spacer"></div>
        <div class="topbar-right">
          <span class="net-pill" title="This superadmin's registry, seam and alert bus are simulated in your browser">${icon('info')} simulated seam</span>
          <button class="icon-btn" id="theme-toggle" title="Toggle theme" aria-label="Toggle light or dark theme">${icon(state.ui.theme === 'dark' ? 'sun' : 'moon')}</button>
          <button class="icon-btn" id="acct" title="Session" aria-label="Session menu">${icon('more')}</button>
        </div>
      </header>
      <main id="view" class="view" role="main" aria-live="polite"></main>
    </div>`;

  app.querySelectorAll('.rail-btn').forEach(b => b.onclick = () => setView(b.dataset.view));
  app.querySelector('#rail-id').onclick = () => setView('overview');
  app.querySelector('#op-chip').onclick = () => setView('overview');
  const gs = app.querySelector('#globalsearch');
  gs.oninput = () => { state.ui.search = gs.value; rerender(); };
  app.querySelector('#theme-toggle').onclick = toggleTheme;
  app.querySelector('#acct').onclick = sessionMenu;

  bus.setView = setView;
  bus.rerender = rerender;
  bus.refreshChrome = refreshChrome;

  setView(state.view);
  refreshChrome();
}

function setView(v) {
  state.view = v;
  state.ui.search = '';
  state.ui.mobileDetail = false;
  const app = document.getElementById('app');
  const def = VIEWS.find(x => x.id === v) || VIEWS[0];
  const gs = app.querySelector('#globalsearch');
  if (gs) { gs.value = ''; gs.placeholder = (def.search || 'Search') + '…'; }
  app.querySelector('#topbar-search')?.classList.toggle('hidden', !def.search);
  app.querySelectorAll('.rail-btn').forEach(b => {
    const on = b.dataset.view === v;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  rerender();
}

function rerender() {
  const root = document.getElementById('view');
  const def = VIEWS.find(x => x.id === state.view) || VIEWS[0];
  def.render(root);
  refreshChrome();
}

function refreshChrome() {
  const app = document.getElementById('app');
  if (!app) return;
  const c = counts();
  const inc = openIncidents().length;
  const setBadge = (id, n, cls) => { const e = app.querySelector(`[data-badge="${id}"]`); if (e) { e.textContent = n || ''; e.classList.toggle('on', !!n); e.classList.toggle('alert', cls === 'alert'); } };
  setBadge('fleet', c.down + c.degraded ? c.down + c.degraded : '', c.down ? 'alert' : '');
  setBadge('abuse', inc || '', inc ? 'alert' : '');
  const glance = app.querySelector('#fleet-glance');
  if (glance) glance.innerHTML = `
    <span class="glance-item" title="${c.up} operational">${healthDot('up')}${c.up}</span>
    <span class="glance-item ${c.degraded ? '' : 'off'}" title="${c.degraded} degraded">${healthDot('degraded')}${c.degraded}</span>
    <span class="glance-item ${c.down ? '' : 'off'}" title="${c.down} down">${healthDot('down')}${c.down}</span>
    ${inc ? `<span class="glance-item alert" title="${inc} open incident(s)">${icon('bell')}${inc}</span>` : ''}`;
  const t = app.querySelector('#theme-toggle'); if (t) t.innerHTML = icon(state.ui.theme === 'dark' ? 'sun' : 'moon');
}

function toggleTheme() {
  state.ui.theme = state.ui.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.ui.theme);
  persist(); refreshChrome();
}

function sessionMenu() {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('shield')} Operator session</h2><button class="icon-btn" id="sx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} You are signed in as a <b>platform superadmin</b> for the <span class="mono">envoir-cloud</span> fleet. This console's enrollment registry, <span class="mono">dmtap-seam</span> metering/provisioning endpoints and alert bus are <b>simulated</b> and held in your browser.</p>
      <p class="modal-note warn">${icon('lock')} <span><b>Content-blind by construction.</b> Nothing in this console can read a mailbox, a message, a recipient set, or a user's keys. It meters <b>operations</b> and aggregates <b>anti-abuse signals</b> only — the inviolable rule (spec §12.3, dmtap-seam CONTRACT).</span></p>
      <div class="sess-row"><div><b>Reseed demo fleet</b><small>Regenerate the simulated fleet, billing and incidents from a fresh snapshot.</small></div><button class="btn danger" id="reset">${icon('refresh')} Reseed</button></div>
    </div>`, { label: 'Operator session' });
  card.querySelector('#sx').onclick = closeModal;
  card.querySelector('#reset').onclick = () => {
    wipe(); closeModal();
    toast(`${icon('check')} Reseeding — reloading`);
    setTimeout(() => location.reload(), 500);
  };
}
