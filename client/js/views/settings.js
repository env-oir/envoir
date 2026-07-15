// views/settings.js — identity + safety number, aliases, signatures, vacation/auto-responder,
// filters, default privacy, appearance (theme), keyboard reference, sign-out, and the sign-in
// demo. Settings persist to localStorage (a real client syncs them as MOTEs, spec §8.5).

import { state, saveSettings } from '../store.js';
import { currentIdentity, displayAddress, displayName, logout, addAlias, removeAlias, makePrimary, fromB64u } from '../identity.js';
import { verifySafety } from '../safety.js';
import { claimHandle } from '../mesh-sim.js';
import { el, esc, icon, toast, safetyWords, safetyGrid, safetyNumeric } from '../ui.js';
import { renderSignin } from '../signin.js';
import { bus } from '../bus.js';
import { SHORTCUTS } from '../shell.js';

export function render(root) {
  const id = currentIdentity();
  const s = state.settings;
  root.className = 'view settings-view';
  root.innerHTML = `<div class="set-scroll"><div class="set-inner">
    <header class="set-header"><h1>Settings</h1><p>Your identity and defaults. Privacy is never a paid feature.</p></header>

    <section class="set-card">
      <h2>${icon('key')} Identity &amp; safety number</h2>
      <p class="set-hint">Your <b>key</b> is your identity. Your address is a pointer to it. To prove a contact is really them (not a look-alike key), compare this <b>safety number</b> out-of-band — read the words, scan the grid, or compare the digits.</p>
      <div class="id-grid">
        <div class="id-facts">
          <div class="kvr"><span>Display name</span><b>${esc(displayName(id))}</b></div>
          <div class="kvr"><span>Primary address</span><b class="mono">${esc(displayAddress(id))}</b></div>
          <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(id.fingerprint)}</b></div>
          <div class="kvr"><span>Algorithm</span><b class="mono">${esc(id.alg)}</b></div>
        </div>
        <div class="id-safety">
          ${safetyGrid(id.safety)}
        </div>
      </div>
      <div class="safety-full">${safetyWords(id.safety)}${safetyNumeric(id.safety)}</div>
      <div class="set-row">
        <button class="btn" id="verifysafety">${icon('repeat')} Recompute &amp; verify</button>
        <span class="set-hint inline">re-derives the number from your public key, right now — proves it's deterministic, not stored or looked up.</span>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('mail')} Addresses &amp; aliases</h2>
      <p class="set-hint">One identity, many addresses — all resolving to the same key (spec §3.9.4). Keep a legacy address, add a work alias, or claim an @handle. Plus-addressing (you+tag@…) routes to the same key automatically.</p>
      <div class="alias-list" id="aliases"></div>
      <div class="alias-add">
        <input id="newalias" placeholder="add name@domain, a kept legacy address, or @handle">
        <button class="btn" id="addalias">${icon('plus')} Add</button>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('edit')} Signatures</h2>
      <div class="sig-list" id="sigs"></div>
      <button class="btn" id="addsig">${icon('plus')} New signature</button>
    </section>

    <section class="set-card">
      <h2>${icon('bell')} Vacation / auto-responder</h2>
      <div class="set-row between">
        <div><b>Auto-reply when away</b><small>replies once per sender with your message</small></div>
        <label class="switch"><input type="checkbox" id="vacon" ${s.vacation.enabled ? 'checked' : ''}><i></i></label>
      </div>
      <div id="vacbody" class="${s.vacation.enabled ? '' : 'hidden'}">
        <label class="cfield"><span>Subject</span><input id="vacsubj" value="${esc(s.vacation.subject)}"></label>
        <label class="cfield"><span>Message</span><textarea id="vacmsg" rows="3">${esc(s.vacation.message)}</textarea></label>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('label')} Filters &amp; rules</h2>
      <div class="filter-list" id="filters"></div>
      <button class="btn" id="addfilter">${icon('plus')} New rule</button>
    </section>

    <section class="set-card">
      <h2>${icon('shield')} Privacy &amp; network</h2>
      <div class="set-row between"><div><b>Default privacy tier</b><small>private = mixnet (metadata-private); fast = direct (lower latency)</small></div>
        <div class="seg" id="tierseg"><button data-t="private" class="${s.tierDefault === 'private' ? 'on' : ''}">${icon('shield')} Private</button><button data-t="fast" class="${s.tierDefault === 'fast' ? 'on' : ''}">Fast</button></div></div>
      <div class="set-row between"><div><b>Presence &amp; typing</b><small>metadata-sensitive — reveals when you're online</small></div>
        <label class="switch"><input type="checkbox" id="presence" ${s.presence ? 'checked' : ''}><i></i></label></div>
      <div class="set-row between"><div><b>Legacy gateway</b><small>bridge to/from the Gmail world (fades as the network grows)</small></div>
        <label class="switch"><input type="checkbox" id="gateway" ${s.gateway ? 'checked' : ''}><i></i></label></div>
    </section>

    <section class="set-card">
      <h2>${icon('sun')} Appearance</h2>
      <div class="set-row between"><div><b>Theme</b><small>dark is primary</small></div>
        <div class="seg" id="themeseg"><button data-th="dark" class="${s.theme === 'dark' ? 'on' : ''}">${icon('moon')} Dark</button><button data-th="light" class="${s.theme === 'light' ? 'on' : ''}">${icon('sun')} Light</button></div></div>
    </section>

    <section class="set-card">
      <h2>${icon('command')} Keyboard shortcuts</h2>
      <div class="kbd-grid">${SHORTCUTS.map(([k, d]) => `<div class="kbd-row"><kbd>${esc(k)}</kbd><span>${esc(d)}</span></div>`).join('')}</div>
    </section>

    <section class="set-card">
      <h2>${icon('key')} Sign in with Envoir — demo (spec §13)</h2>
      <div id="signinbox"></div>
    </section>

    <section class="set-card danger-card">
      <div class="set-row between"><div><b>Recovery phrase</b><small>restore your identity on a new device</small></div><button class="btn" id="showphrase">Show</button></div>
      <div class="set-row between"><div><b>Sign out</b><small>clears this identity from this browser</small></div><button class="btn danger" id="signout">Sign out</button></div>
    </section>
  </div></div>`;

  // Identity
  root.querySelector('#verifysafety').onclick = async () => {
    const { match, recomputed } = await verifySafety(fromB64u(id.ik), id.safety.full);
    toast(match ? `${icon('check')} recomputed identical: ${esc(recomputed)}` : '✗ mismatch: ' + esc(recomputed), { ms: 5000 });
  };

  drawAliases(root, id);
  drawSigs(root);
  drawFilters(root);

  // Vacation
  root.querySelector('#vacon').onchange = (e) => { s.vacation.enabled = e.target.checked; root.querySelector('#vacbody').classList.toggle('hidden', !e.target.checked); saveSettings(); };
  root.querySelector('#vacsubj').oninput = (e) => { s.vacation.subject = e.target.value; saveSettings(); };
  root.querySelector('#vacmsg').oninput = (e) => { s.vacation.message = e.target.value; saveSettings(); };

  // Privacy/network
  root.querySelectorAll('#tierseg [data-t]').forEach(b => b.onclick = () => { s.tierDefault = b.dataset.t; saveSettings(); bus.rerender(); });
  root.querySelector('#presence').onchange = (e) => { s.presence = e.target.checked; saveSettings(); };
  root.querySelector('#gateway').onchange = (e) => { s.gateway = e.target.checked; saveSettings(); };

  // Appearance
  root.querySelectorAll('#themeseg [data-th]').forEach(b => b.onclick = () => { s.theme = b.dataset.th; document.documentElement.setAttribute('data-theme', s.theme); saveSettings(); bus.rerender(); bus.refreshChrome(); });

  // Danger
  root.querySelector('#showphrase').onclick = () => toast(id.phrase.join(' '), { ms: 6000 });
  root.querySelector('#signout').onclick = () => { if (confirm('Sign out and clear this identity from this browser?')) { logout(); location.reload(); } };

  renderSignin(root.querySelector('#signinbox'));
}

function drawAliases(root, id) {
  const wrap = root.querySelector('#aliases');
  wrap.innerHTML = id.addresses.map(a => {
    const label = { primary: 'primary', alias: 'alias', legacy: 'kept legacy', handle: 'handle' }[a.kind];
    return `<div class="alias-row">
      <span class="mono alias-addr">${esc(a.address)}</span>
      <span class="pill ${a.kind === 'primary' ? 'accent' : a.kind === 'legacy' ? 'legacy' : 'dim'} sm">${label}</span>
      ${a.kind === 'legacy' ? `<span class="set-hint inline">inbound marked legacy-origin</span>` : ''}
      <div class="spacer"></div>
      ${a.kind !== 'primary' && a.kind !== 'handle' ? `<button class="btn ghost sm" data-primary="${esc(a.address)}">Make primary</button>` : ''}
      ${a.kind !== 'primary' ? `<button class="icon-btn sm" data-del="${esc(a.address)}" title="Remove">${icon('trash')}</button>` : ''}
    </div>`;
  }).join('');
  wrap.querySelectorAll('[data-primary]').forEach(b => b.onclick = () => { makePrimary(b.dataset.primary); bus.rerender(); bus.refreshChrome(); toast(`${icon('check')} Primary address is now ${b.dataset.primary}`); });
  wrap.querySelectorAll('[data-del]').forEach(b => b.onclick = () => { removeAlias(b.dataset.del); bus.rerender(); });

  root.querySelector('#addalias').onclick = async () => {
    const v = root.querySelector('#newalias').value.trim();
    if (v.startsWith('@')) {
      const r = await claimHandle(v);
      if (!r.ok) return toast(r.reason);
      addAlias('@' + r.handle, 'handle');
      toast(`${icon('check')} @${r.handle} claimed · ${r.kt} (simulated key-transparency entry)`, { ms: 4500 });
    } else {
      const kind = /@(gmail|outlook|yahoo|proton|oldprovider)\./.test(v) ? 'legacy' : 'alias';
      const r = addAlias(v, kind);
      if (!r.ok) return toast(r.reason);
      toast(`${icon('check')} ${v} added — resolves to your key`);
    }
    bus.rerender();
  };
}

function drawSigs(root) {
  const wrap = root.querySelector('#sigs');
  wrap.innerHTML = state.settings.signatures.map(sig => `<div class="sig-item">
    <div class="sig-item-head"><b>${esc(sig.name)}</b>${sig.default ? `<span class="pill accent sm">default</span>` : `<button class="btn ghost sm" data-def="${sig.id}">Set default</button>`}</div>
    <div class="sig-body mono">${esc(sig.body)}</div>
  </div>`).join('');
  wrap.querySelectorAll('[data-def]').forEach(b => b.onclick = () => { state.settings.signatures.forEach(x => x.default = x.id === b.dataset.def); saveSettings(); bus.rerender(); });
  root.querySelector('#addsig').onclick = () => {
    const name = prompt('Signature name?'); if (!name) return;
    const body = prompt('Signature text?') || '';
    state.settings.signatures.push({ id: 'sig' + Date.now(), name, body, default: false }); saveSettings(); bus.rerender();
  };
}

function drawFilters(root) {
  const wrap = root.querySelector('#filters');
  wrap.innerHTML = state.settings.filters.map(f => `<div class="filter-item">
    <span class="mono">${f.from ? 'from:' + esc(f.from) : ''}${f.subject ? ' subject:' + esc(f.subject) : ''}</span>
    <span class="arrow-lil">→</span>
    <span class="pill ${f.action === 'legacy-flag' ? 'legacy' : 'accent'} sm">${f.action === 'label' ? 'label ' + esc(f.label) : esc(f.action)}</span>
    <label class="switch sm"><input type="checkbox" data-flt="${f.id}" ${f.enabled ? 'checked' : ''}><i></i></label>
  </div>`).join('');
  wrap.querySelectorAll('[data-flt]').forEach(c => c.onchange = () => { const f = state.settings.filters.find(x => x.id === c.dataset.flt); f.enabled = c.checked; saveSettings(); });
  root.querySelector('#addfilter').onclick = () => toast('Simulated — a rule builder applies label/archive/forward actions to incoming MOTEs client-side.', { ms: 4200 });
}
