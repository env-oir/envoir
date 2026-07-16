// shell.js — the unified app shell: left rail, global search, command palette (⌘/Ctrl-K),
// Gmail-parity keyboard shortcuts, a shortcuts help overlay (?), and view dispatch. Fills in
// the bus so view modules can trigger re-renders without importing the shell (no cycle).

import { state, initStore, saveSettings } from './store.js';
import { currentIdentity, displayAddress, displayName } from './identity.js';
import { PEOPLE } from './seed.js';
import { esc, icon, brandMark, openModal, closeModal, initials, hideInspector, applyStagger } from './ui.js';
import { bus } from './bus.js';
import { openCompose } from './compose.js';

import { render as renderMail, mailKeys } from './views/mail.js';
import { render as renderChat } from './views/chat.js';
import { render as renderCalendar } from './views/calendar.js';
import { render as renderContacts } from './views/contacts.js';
import { render as renderFiles } from './views/files.js';
import { render as renderIdentity } from './views/identity.js';
import { render as renderGroups } from './views/groups.js';
import { render as renderSettings } from './views/settings.js';

const VIEWS = [
  { id: 'mail', name: 'Mail', icon: 'mail', render: renderMail, search: 'Search mail' },
  { id: 'chat', name: 'Chat', icon: 'chat', render: renderChat, search: 'Search conversations' },
  { id: 'calendar', name: 'Calendar', icon: 'calendar', render: renderCalendar },
  { id: 'contacts', name: 'Contacts', icon: 'contacts', render: renderContacts, search: 'Search contacts' },
  { id: 'files', name: 'Files', icon: 'files', render: renderFiles, search: 'Search files' },
  { id: 'identity', name: 'Identity', icon: 'key', render: renderIdentity },
  { id: 'groups', name: 'Groups', icon: 'groups', render: renderGroups, search: 'Search groups' },
  { id: 'settings', name: 'Settings', icon: 'settings', render: renderSettings },
];

export const SHORTCUTS = [
  ['⌘K / Ctrl K', 'Command palette'],
  ['/', 'Search'],
  ['c', 'Compose'],
  ['g then m/c/a/p/f/i/r', 'Go to Mail / Chat / cAlendar / People / Files / Identity / gRoups'],
  ['1 – 8', 'Jump to view'],
  ['j / k', 'Next / previous conversation'],
  ['Enter', 'Open conversation'],
  ['e', 'Archive'],
  ['#', 'Delete'],
  ['r', 'Reply'],
  ['s', 'Star'],
  ['u', 'Mark unread'],
  ['x', 'Select conversation'],
  ['b / h', 'Snooze… (command menu)'],
  ['l', 'Label… (command menu)'],
  ['?', 'This help'],
  ['Esc', 'Close overlay'],
];

export function mountShell() {
  initStore();
  const app = document.getElementById('app');
  app.classList.remove('hidden');
  const id = currentIdentity();
  app.innerHTML = `
    <nav class="rail" aria-label="Primary">
      <div class="rail-brand" title="Envoir" aria-hidden="true">${brandMark(30)}</div>
      <div class="rail-nav" id="rail-nav">
        ${VIEWS.filter(v => v.id !== 'settings').map(v => `<button class="rail-btn" data-view="${v.id}" title="${v.name}" aria-label="${v.name}">${icon(v.icon)}<span>${v.name}</span><i class="rail-badge" data-badge="${v.id}" aria-hidden="true"></i></button>`).join('')}
      </div>
      <div class="rail-spacer"></div>
      <button class="rail-btn" data-view="settings" title="Settings" aria-label="Settings">${icon('settings')}<span>Settings</span></button>
      <button class="rail-id" id="rail-id" title="${esc(displayAddress(id))}" aria-label="Open settings — signed in as ${esc(displayAddress(id))}">${esc(initials(displayName(id)))}</button>
    </nav>
    <div class="workspace">
      <header class="topbar">
        <div class="topbar-search" id="topbar-search" role="search">
          ${icon('search')}
          <input id="globalsearch" placeholder="Search…" aria-label="Search the current view" autocomplete="off" spellcheck="false">
        </div>
        <button class="cmd-open" id="cmdk" aria-label="Open command palette"><kbd>⌘K</kbd> commands</button>
        <div class="topbar-right">
          <span class="net-pill" title="This client's network is simulated">${icon('network')} simulated network</span>
          <button class="icon-btn" id="theme-toggle" title="Toggle theme" aria-label="Toggle light or dark theme">${icon(state.settings.theme === 'dark' ? 'sun' : 'moon')}</button>
          <button class="btn primary sm" id="quick-compose">${icon('edit')} Compose</button>
        </div>
      </header>
      <main id="view" class="view" role="main" aria-live="polite"></main>
    </div>`;

  app.querySelectorAll('.rail-btn').forEach(b => b.onclick = () => setView(b.dataset.view));
  app.querySelector('#rail-id').onclick = () => setView('settings');
  app.querySelector('#cmdk').onclick = openPalette;
  const gs = app.querySelector('#globalsearch');
  gs.oninput = () => { state.ui.search = gs.value; rerenderKeepSearch(); };
  app.querySelector('#quick-compose').onclick = () => openCompose();
  app.querySelector('#theme-toggle').onclick = toggleTheme;

  // wire the bus
  bus.setView = setView;
  bus.rerender = rerender;
  bus.openCompose = openCompose;
  bus.refreshChrome = refreshChrome;

  installKeys();
  setView(state.view);
  refreshChrome();
}

function setView(v) {
  state.view = v;
  state.ui.search = '';
  state.ui.mobileDetail = false;   // land on the list pane when arriving at a view (mobile)
  hideInspector();                 // the MOTE inspector is mail-scoped; don't leak it across views
  const nav = document.getElementById('app');
  const def = VIEWS.find(x => x.id === v);
  const gs = nav.querySelector('#globalsearch'); if (gs) { gs.value = ''; gs.placeholder = (def?.search || 'Search') + '…'; }
  // Search only filters list-style views; on Calendar/Settings it would be a dead field, so hide it.
  const searchBox = nav.querySelector('#topbar-search'); if (searchBox) searchBox.classList.toggle('hidden', !def?.search);
  nav.querySelectorAll('.rail-btn').forEach(b => {
    const on = b.dataset.view === v;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  rerender();
}
const rerenderKeepSearch = () => rerender();

let _lastStaggerView = null;
function rerender() {
  const root = document.getElementById('view');
  const def = VIEWS.find(x => x.id === state.view) || VIEWS[0];
  def.render(root);
  // Play the entrance stagger only when the *view* changed — never on in-place re-renders
  // (star/read/select), which would otherwise re-flicker the whole workspace mid-interaction.
  const entered = _lastStaggerView !== state.view;
  _lastStaggerView = state.view;
  applyStagger(root, entered);
}

function refreshChrome() {
  const app = document.getElementById('app');
  const unread = state.mail.filter(t => t.folder === 'inbox' && !t.read).length;
  const chatUnread = state.chats.reduce((n, c) => n + (c.unread || 0), 0);
  const setBadge = (id, n) => { const e = app.querySelector(`[data-badge="${id}"]`); if (e) { e.textContent = n || ''; e.classList.toggle('on', !!n); } };
  setBadge('mail', unread); setBadge('chat', chatUnread);
  const t = app.querySelector('#theme-toggle'); if (t) t.innerHTML = icon(state.settings.theme === 'dark' ? 'sun' : 'moon');
}

function toggleTheme() {
  state.settings.theme = state.settings.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', state.settings.theme);
  saveSettings(); refreshChrome();
}

// ---- Command palette ----------------------------------------------------------------------
function commands() {
  const base = [
    ...VIEWS.map(v => ({ icon: v.icon, label: 'Go to ' + v.name, hint: 'view', run: () => setView(v.id) })),
    { icon: 'edit', label: 'Compose new message', hint: 'action', run: () => openCompose() },
    { icon: 'calendar', label: 'New event', hint: 'action', run: () => { setView('calendar'); } },
    { icon: state.settings.theme === 'dark' ? 'sun' : 'moon', label: 'Toggle theme', hint: 'action', run: toggleTheme },
    { icon: 'settings', label: 'Settings', hint: 'view', run: () => setView('settings') },
  ];
  const people = PEOPLE.map(p => ({ icon: 'contacts', label: p.name, hint: p.address, run: () => { setView('contacts'); } }));
  return base.concat(people);
}

function openPalette() {
  const card = openModal(`
    <div class="palette">
      <div class="pal-input">${icon('search')}<input id="palq" role="combobox" aria-expanded="true" aria-controls="pallist" aria-activedescendant="pal-0" aria-label="Search commands, views and people" placeholder="Search commands, views, people…" autocomplete="off"></div>
      <div class="pal-list" id="pallist" role="listbox" aria-label="Commands"></div>
      <div class="pal-foot"><kbd>↑↓</kbd> navigate <kbd>↵</kbd> run <kbd>esc</kbd> close</div>
    </div>`, { sticky: false, label: 'Command palette' });
  const all = commands();
  let cur = 0, filtered = all;
  const listEl = card.querySelector('#pallist');
  const input = card.querySelector('#palq');
  const draw = () => {
    listEl.innerHTML = filtered.map((c, i) => `<button id="pal-${i}" role="option" aria-selected="${i === cur}" class="pal-item ${i === cur ? 'on' : ''}" data-i="${i}">${icon(c.icon)}<span class="pal-label">${esc(c.label)}</span><span class="pal-hint mono">${esc(c.hint)}</span></button>`).join('') || '<div class="pal-empty">No matches</div>';
    listEl.querySelectorAll('[data-i]').forEach(b => b.onclick = () => run(Number(b.dataset.i)));
    input.setAttribute('aria-activedescendant', filtered.length ? `pal-${cur}` : '');
    const on = listEl.querySelector('.on'); on?.scrollIntoView({ block: 'nearest' });
  };
  const run = (i) => { const c = filtered[i]; if (c) { closeModal(); c.run(); } };
  input.oninput = () => {
    const q = input.value.trim().toLowerCase();
    filtered = q ? all.filter(c => (c.label + ' ' + c.hint).toLowerCase().includes(q)) : all;
    cur = 0; draw();
  };
  input.onkeydown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); cur = Math.min(filtered.length - 1, cur + 1); draw(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); cur = Math.max(0, cur - 1); draw(); }
    else if (e.key === 'Enter') { e.preventDefault(); run(cur); }
  };
  draw();
  setTimeout(() => input.focus(), 40);
}

function openShortcuts() {
  const card = openModal(`<div class="shortcuts-modal">
    <div class="ev-detail-head"><h2>${icon('command')} Keyboard shortcuts</h2><button class="icon-btn" id="sx">${icon('x')}</button></div>
    <div class="kbd-grid big">${SHORTCUTS.map(([k, d]) => `<div class="kbd-row"><kbd>${esc(k)}</kbd><span>${esc(d)}</span></div>`).join('')}</div>
  </div>`, { wide: true });
  card.querySelector('#sx').onclick = closeModal;
}

// ---- Keyboard shortcuts -------------------------------------------------------------------
let gPending = false;
function installKeys() {
  document.addEventListener('keydown', (e) => {
    const typing = /input|textarea|select/i.test(document.activeElement?.tagName || '') || document.activeElement?.isContentEditable;
    const meta = e.metaKey || e.ctrlKey;

    if (meta && e.key.toLowerCase() === 'k') { e.preventDefault(); if (!document.getElementById('modal').classList.contains('hidden')) return; openPalette(); return; }
    if (e.key === 'Escape') {
      if (!document.getElementById('modal').classList.contains('hidden')) closeModal();
      if (document.getElementById('inspector').classList.contains('show')) document.getElementById('inspector').querySelector('#insp-close')?.click();
      gPending = false; return;
    }
    if (typing || meta) return;

    // go-to prefix
    if (gPending) {
      gPending = false;
      const map = { m: 'mail', c: 'chat', a: 'calendar', p: 'contacts', f: 'files', i: 'identity', r: 'groups', s: 'settings' };
      if (map[e.key]) { e.preventDefault(); setView(map[e.key]); return; }
    }
    if (e.key === 'g') { gPending = true; setTimeout(() => gPending = false, 900); return; }

    const num = Number(e.key);
    if (num >= 1 && num <= VIEWS.length) { setView(VIEWS[num - 1].id); return; }
    if (e.key === '/') { e.preventDefault(); openPalette(); return; }
    if (e.key === '?') { e.preventDefault(); openShortcuts(); return; }
    if (e.key === 'c') { e.preventDefault(); openCompose(); return; }

    // mail-context keys
    if (state.view === 'mail') {
      const k = e.key;
      if (k === 'j') { e.preventDefault(); mailKeys.move(1); }
      else if (k === 'k') { e.preventDefault(); mailKeys.move(-1); }
      else if (k === 'e') { mailKeys.archive(); }
      else if (k === '#') { mailKeys.trash(); }
      else if (k === 'r') { e.preventDefault(); mailKeys.reply(); }
      else if (k === 's') { mailKeys.star(); }
      else if (k === 'u') { mailKeys.unread(); }
      else if (k === 'x') { mailKeys.select(); }
      else if (k === 'b' || k === 'h') { e.preventDefault(); mailKeys.snooze(); }
      else if (k === 'l') { e.preventDefault(); mailKeys.label(); }
    }
  });
}
