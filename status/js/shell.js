// shell.js — the Envoir Status shell: a top header (brand + wordmark, System-status / My-status
// tabs, a demo scenario switcher, theme toggle, sign-in) over a centered content column. It owns
// the loading / error orchestration: a short simulated fetch shows a shimmer, an offline hash
// shows the error state with retry, otherwise the active view renders.

import { state, rebuild, persist, setTheme, setScenario, signIn, signOut } from './store.js';
import { esc, icon, brandMark, shimmerRows, errorState, openModal, closeModal, toast } from './ui.js';
import { renderPublic } from './views/public.js';
import { renderUser } from './views/user.js';

const SCENARIOS = [
  { id: 'operational', label: 'Operational' },
  { id: 'degraded', label: 'Degraded' },
  { id: 'outage', label: 'Outage' },
];

function authLabel() {
  return state.signedIn
    ? icon('user') + '<span class="auth-label mono"> you@abc.com</span>'
    : icon('lock') + '<span class="auth-label"> Sign in</span>';
}

export function mountShell() {
  const app = document.getElementById('app');
  app.classList.remove('hidden');
  app.innerHTML = `
    <header class="site-head">
      <div class="head-inner">
        <a class="head-brand" id="brand" href="#" aria-label="Envoir Status — home">
          ${brandMark(30)}
          <span class="head-word">Envoir <b>Status</b></span>
        </a>
        <nav class="head-tabs" role="tablist" aria-label="Status views">
          <button class="head-tab" data-view="public" role="tab">${icon('globe')}<span>System status</span></button>
          <button class="head-tab" data-view="user" role="tab">${icon('user')}<span>My status</span></button>
        </nav>
        <div class="head-right">
          <div class="scenario-switch" id="scenario" title="Demo: simulate a system state" aria-label="Demo scenario">
            ${icon('activity')}
            <div class="seg" role="group" aria-label="Simulate state">
              ${SCENARIOS.map(s => `<button data-sc="${s.id}" aria-pressed="${state.scenario === s.id}">${esc(s.label)}</button>`).join('')}
            </div>
          </div>
          <button class="icon-btn" id="theme" aria-label="Toggle light or dark theme">${icon(state.theme === 'dark' ? 'sun' : 'moon')}</button>
          <button class="btn sm" id="auth">${authLabel()}</button>
        </div>
      </div>
    </header>
    <main id="view" class="status-main" role="main" aria-live="polite"></main>
    <footer class="site-foot">
      <div class="foot-inner">
        <span>${icon('shield')} Envoir / DMTAP — sovereign mail &amp; identity</span>
        <span class="foot-sim">${icon('info')} This status feed is <b>simulated</b> in your browser. Use the demo switch to preview each state.</span>
      </div>
    </footer>`;

  app.querySelector('#brand').onclick = (e) => { e.preventDefault(); setView('public'); };
  app.querySelectorAll('.head-tab').forEach(b => b.onclick = () => setView(b.dataset.view));
  app.querySelectorAll('[data-sc]').forEach(b => b.onclick = () => {
    setScenario(b.dataset.sc);
    app.querySelectorAll('[data-sc]').forEach(x => x.setAttribute('aria-pressed', x.dataset.sc === state.scenario));
    load();
  });
  app.querySelector('#theme').onclick = () => {
    setTheme(state.theme === 'dark' ? 'light' : 'dark');
    app.querySelector('#theme').innerHTML = icon(state.theme === 'dark' ? 'sun' : 'moon');
  };
  app.querySelector('#auth').onclick = () => state.signedIn ? accountMenu() : signInModal();

  window.addEventListener('hashchange', () => load());

  setView(state.view, true);
}

function setView(v, initial = false) {
  if (v === 'user' && !state.signedIn) { state.view = 'public'; if (!initial) signInModal('user'); load(); return; }
  state.view = v;
  const app = document.getElementById('app');
  app.querySelectorAll('.head-tab').forEach(b => {
    const on = b.dataset.view === v;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on);
  });
  load();
}

// Simulated fetch: brief loading → error (if #error) → view.
let _t = null;
function load() {
  const root = document.getElementById('view');
  const app = document.getElementById('app');
  // keep tab highlight in sync
  app.querySelectorAll('.head-tab').forEach(b => { const on = b.dataset.view === state.view; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); });
  const authBtn = app.querySelector('#auth');
  if (authBtn) authBtn.innerHTML = authLabel();

  if (location.hash === '#error') { renderError(root); return; }

  root.innerHTML = `<div class="status-page">${shimmerRows(5)}</div>`;
  clearTimeout(_t);
  _t = setTimeout(() => {
    try {
      rebuild();
      if (state.view === 'user' && state.signedIn) renderUser(root, { setView, refresh: load });
      else renderPublic(root, { setView, signIn: () => signInModal('user') });
    } catch (e) {
      renderError(root, e?.message);
    }
  }, 420);
}

function renderError(root, msg) {
  root.innerHTML = `<div class="status-page">${errorState('Could not reach the status service', msg || 'The status feed is temporarily unavailable. Your mail is unaffected — DMTAP delivery is durable at the edges.', 'retry')}</div>`;
  root.querySelector('#retry').onclick = () => { if (location.hash === '#error') history.replaceState(null, '', location.pathname); load(); };
}

// ---- sign-in (demo) -----------------------------------------------------------------------
function signInModal(then) {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('lock')} Sign in to My status</h2><button class="icon-btn" id="sx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} <span><b>Demo sign-in.</b> The authenticated view shows <i>your</i> service health — your mailbox, your node's reachability, and your recent delivery outcomes. No real credentials are used or stored.</span></p>
      <label class="cfield"><span>Envoir address</span><input id="addr" value="you@abc.com" autocomplete="off" spellcheck="false"></label>
    </div>
    <div class="modal-foot">
      <button class="btn ghost" id="scancel">Cancel</button>
      <div class="spacer"></div>
      <button class="btn primary" id="sgo">${icon('user')} View my status</button>
    </div>`, { label: 'Sign in' });
  card.querySelector('#sx').onclick = card.querySelector('#scancel').onclick = closeModal;
  card.querySelector('#sgo').onclick = () => {
    signIn(); closeModal();
    toast(`${icon('check')} Signed in`);
    setView('user');
  };
}

function accountMenu() {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('user')} <span class="mono">you@abc.com</span></h2><button class="icon-btn" id="ax" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} You are viewing the authenticated <b>My status</b> surface for <span class="mono">you@abc.com</span>. This is a demo session held in your browser.</p>
      <div class="sess-row"><div><b>Sign out</b><small>Return to the public system-status page.</small></div><button class="btn danger" id="out">${icon('lock')} Sign out</button></div>
    </div>`, { label: 'Account' });
  card.querySelector('#ax').onclick = closeModal;
  card.querySelector('#out').onclick = () => { signOut(); closeModal(); toast(`${icon('check')} Signed out`); setView('public'); };
}
