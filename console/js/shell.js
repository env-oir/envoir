// shell.js — the console shell: left rail (Overview · Members · Directory · Groups · Roles ·
// Audit), a topbar with the domain identity + directory version + search, and view dispatch.
// Fills the bus so views trigger re-renders without importing the shell (no cycle).

import { state, persist, wipe } from './store.js';
import { wipeSession } from './session.js';
import { esc, icon, brandMark, initials, openModal, closeModal, toast } from './ui.js';
import { bus } from './bus.js';

import { render as renderOverview } from './views/overview.js';
import { render as renderMembers } from './views/members.js';
import { render as renderDirectory } from './views/directory.js';
import { render as renderGroups } from './views/groups.js';
import { render as renderRoles } from './views/roles.js';
import { render as renderAudit } from './views/audit.js';

const VIEWS = [
  { id: 'overview', name: 'Overview', icon: 'home', render: renderOverview },
  { id: 'members', name: 'Members', icon: 'members', render: renderMembers, search: 'Search members' },
  { id: 'directory', name: 'Directory', icon: 'directory', render: renderDirectory, search: 'Search directory' },
  { id: 'groups', name: 'Groups', icon: 'groups', render: renderGroups, search: 'Search groups' },
  { id: 'roles', name: 'Admin roles', icon: 'roles', render: renderRoles, search: 'Search capabilities' },
  { id: 'audit', name: 'Audit log', icon: 'audit', render: renderAudit, search: 'Search events' },
];

export function mountShell() {
  const app = document.getElementById('app');
  app.classList.remove('hidden');
  const d = state.domain;
  app.innerHTML = `
    <nav class="rail" aria-label="Primary">
      <div class="rail-brand" title="Envoir Console" aria-hidden="true">${brandMark(30)}</div>
      <div class="rail-nav" id="rail-nav">
        ${VIEWS.map(v => `<button class="rail-btn" data-view="${v.id}" title="${v.name}" aria-label="${v.name}">${icon(v.icon)}<span>${v.name}</span><i class="rail-badge" data-badge="${v.id}" aria-hidden="true"></i></button>`).join('')}
      </div>
      <div class="rail-spacer"></div>
      <button class="rail-id" id="rail-id" title="Domain @${esc(d.name)}" aria-label="Domain ${esc(d.name)} — open overview">${esc(initials(d.name))}</button>
    </nav>
    <div class="workspace">
      <header class="topbar">
        <div class="domain-chip" id="domain-chip" title="Administered domain">${icon('domain')}<b class="mono">@${esc(d.name)}</b><span class="dir-ver mono" title="Published DomainDirectory version">dir v<span data-dirver>${d.dirVersion}</span></span></div>
        <div class="topbar-search hidden" id="topbar-search" role="search">
          ${icon('search')}
          <input id="globalsearch" placeholder="Search…" aria-label="Search the current view" autocomplete="off" spellcheck="false">
        </div>
        <div class="spacer"></div>
        <div class="topbar-right">
          <span class="net-pill" title="This console's node, DNS zone and KT log are simulated">${icon('dns')} simulated node</span>
          <button class="icon-btn" id="theme-toggle" title="Toggle theme" aria-label="Toggle light or dark theme">${icon(state.ui.theme === 'dark' ? 'sun' : 'moon')}</button>
          <button class="icon-btn" id="acct" title="Session" aria-label="Session menu">${icon('more')}</button>
        </div>
      </header>
      <main id="view" class="view" role="main" aria-live="polite"></main>
    </div>`;

  app.querySelectorAll('.rail-btn').forEach(b => b.onclick = () => setView(b.dataset.view));
  app.querySelector('#rail-id').onclick = () => setView('overview');
  app.querySelector('#domain-chip').onclick = () => setView('overview');
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
  const setBadge = (id, n) => { const e = app.querySelector(`[data-badge="${id}"]`); if (e) { e.textContent = n || ''; e.classList.toggle('on', !!n); } };
  setBadge('members', state.members.filter(m => m.status === 'active').length);
  setBadge('groups', state.groups.length);
  const dv = app.querySelector('[data-dirver]'); if (dv) dv.textContent = state.domain.dirVersion;
  const t = app.querySelector('#theme-toggle'); if (t) t.innerHTML = icon(state.ui.theme === 'dark' ? 'sun' : 'moon');
}

function toggleTheme() {
  state.ui.theme = state.ui.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.ui.theme);
  persist(); refreshChrome();
}

function sessionMenu() {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('shield')} Admin session</h2><button class="icon-btn" id="sx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} You are signed in as the <b>domain authority</b> for <span class="mono">@${esc(state.domain.name)}</span>. This console's node, DNS zone and key-transparency log are simulated and held in your browser.</p>
      <div class="sess-row"><div><b>Reset demo organization</b><small>Wipe the local org, authority key and escrow, and start setup again.</small></div><button class="btn danger" id="reset">${icon('trash')} Reset</button></div>
    </div>`, { label: 'Admin session' });
  card.querySelector('#sx').onclick = closeModal;
  card.querySelector('#reset').onclick = () => {
    wipe(); wipeSession(); closeModal();
    toast(`${icon('check')} Reset — reloading`);
    setTimeout(() => location.reload(), 600);
  };
}
