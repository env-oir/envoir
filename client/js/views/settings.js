// views/settings.js — identity + safety number, aliases, signatures, vacation/auto-responder,
// filters, default privacy, appearance (theme), keyboard reference, sign-out, and the sign-in
// demo. Settings persist to localStorage (a real client syncs them as MOTEs, spec §8.5).

import { state, saveSettings, applyFilters, uid, unblockSender, allowSender, blockSender } from '../store.js';
import { LABELS } from '../seed.js';
import { currentIdentity, displayAddress, displayName, logout, addAlias, removeAlias, makePrimary } from '../identity.js';
import { claimHandle } from '../mesh-sim.js';
import { el, esc, icon, avatar, toast, openModal, closeModal } from '../ui.js';
import { renderSignin } from '../signin.js';
import { bus } from '../bus.js';
import { SHORTCUTS } from '../shell.js';
import { openEditProfile } from '../profileModal.js';
import {
  canInstall, promptInstall, isStandalone,
  notifSupported, notificationPermission, requestNotificationPermission,
  pushSupported, getPushSubscription, subscribePush, unsubscribePush, sendTestWakePing,
} from '../pwa.js';

export function render(root) {
  const id = currentIdentity();
  const s = state.settings;
  root.className = 'view settings-view';
  root.innerHTML = `<div class="set-scroll"><div class="set-inner">
    <header class="set-header"><h1 class="display">Settings</h1><p>Your identity and defaults. Privacy is never a paid feature.</p></header>

    <section class="set-card">
      <h2>${icon('key')} Identity</h2>
      <p class="set-hint">Your <b>key</b> is your identity; your address is just a pointer to it — your <b>name and photo below are self-asserted profile fields</b>, pointers too. Your <b>safety number</b>, device cluster, recovery anchors, key rotation and signed-in apps all live on the dedicated <b>Identity</b> page.</p>
      <div class="id-grid">
        <div class="pf-summary">
          ${avatar({ name: displayName(id), hue: id.hue ?? 250, trust: 'verified', avatarUrl: id.avatarUrl || null, _avatarSrc: id._avatarSrc }, 56, { ring: true })}
          <div class="id-facts">
            <div class="kvr"><span>Display name</span><b>${esc(displayName(id))}</b></div>
            <div class="kvr"><span>Primary address</span><b class="mono">${esc(displayAddress(id))}</b></div>
            <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(id.fingerprint)}</b></div>
            <div class="kvr"><span>Algorithm</span><b class="mono">${esc(id.alg)}</b></div>
          </div>
        </div>
        <div class="set-id-cta">
          <button class="btn" id="editprofile">${icon('edit')} Edit profile</button>
          <button class="btn primary" id="openidentity">${icon('fingerprint')} Open Identity</button>
        </div>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('mail')} Addresses &amp; aliases</h2>
      <p class="set-hint">One identity, many addresses — all resolving to the same key (spec §3.9.4). Keep a legacy address, add a work alias, claim an @handle, or link an on-chain <span class="mono">.eth</span>/<span class="mono">.sol</span> name. Plus-addressing (you+tag@…) routes to the same key automatically.</p>
      <div class="alias-list" id="aliases"></div>
      <div class="alias-add">
        <input id="newalias" placeholder="add name@domain, alice.eth / alice.sol, a kept legacy address, or @handle">
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
      <p class="set-hint">Rules run on your own always-on node (spec §17#3) — they apply even while this client is closed, but no third party ever sees your plaintext. Matching incoming mail is labelled, starred, archived, or filed as spam automatically.</p>
      <div class="filter-list" id="filters"></div>
      <div class="set-row"><button class="btn" id="addfilter">${icon('plus')} New rule</button><button class="btn ghost" id="runfilters">${icon('repeat')} Run rules on mailbox now</button></div>
    </section>

    <section class="set-card">
      <h2>${icon('shield')} Spam · block &amp; allow lists</h2>
      <p class="set-hint">Recipient-local policy (spec §9.2): blocked senders are filed straight to Spam; allowed senders always reach your inbox. In a real node this is enforced <b>before decryption</b> for cold senders — cost-to-reach replaces central content scanning (§17#20).</p>
      <div class="bl-cols">
        <div class="bl-col">
          <div class="bl-h">${icon('trash')} Blocked <i class="list-count">${state.settings.blocked.length}</i></div>
          <div class="bl-list" id="blocked"></div>
          <div class="alias-add"><input id="newblock" placeholder="block name@domain"><button class="btn sm" id="addblock">Block</button></div>
        </div>
        <div class="bl-col">
          <div class="bl-h">${icon('check')} Allowed <i class="list-count">${state.settings.allowed.length}</i></div>
          <div class="bl-list" id="allowed"></div>
          <div class="alias-add"><input id="newallow" placeholder="allow name@domain"><button class="btn sm" id="addallow">Allow</button></div>
        </div>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('shield')} Privacy &amp; network</h2>
      <div class="set-row between"><div><b>Default privacy tier</b><small>private = mixnet (metadata-private); fast = direct (lower latency)</small></div>
        <div class="seg" id="tierseg" role="group" aria-label="Default privacy tier"><button data-t="private" aria-pressed="${s.tierDefault === 'private'}" class="${s.tierDefault === 'private' ? 'on' : ''}">${icon('shield')} Private</button><button data-t="fast" aria-pressed="${s.tierDefault === 'fast'}" class="${s.tierDefault === 'fast' ? 'on' : ''}">Fast</button></div></div>
      <div class="set-row between"><div><b>Presence &amp; typing</b><small>metadata-sensitive — reveals when you're online</small></div>
        <label class="switch"><input type="checkbox" id="presence" ${s.presence ? 'checked' : ''}><i></i></label></div>
      <div class="set-row between"><div><b>Legacy gateway</b><small>bridge to/from the Gmail world (fades as the network grows)</small></div>
        <label class="switch"><input type="checkbox" id="gateway" ${s.gateway ? 'checked' : ''}><i></i></label></div>
    </section>

    <section class="set-card">
      <h2>${icon('sun')} Appearance</h2>
      <div class="set-row between"><div><b>Theme</b><small>dark is primary</small></div>
        <div class="seg" id="themeseg" role="group" aria-label="Theme"><button data-th="dark" aria-pressed="${s.theme === 'dark'}" class="${s.theme === 'dark' ? 'on' : ''}">${icon('moon')} Dark</button><button data-th="light" aria-pressed="${s.theme === 'light'}" class="${s.theme === 'light' ? 'on' : ''}">${icon('sun')} Light</button></div></div>
    </section>

    <section class="set-card">
      <h2>${icon('download')} App</h2>
      <p class="set-hint">Envoir works as an installable app — its own window, an offline-ready app shell, and (with notifications on) the ability to wake in the background to sync.</p>
      <div class="set-row between">
        <div><b>Install app</b><small>${isStandalone() ? 'Already running as an installed app on this device' : 'Add Envoir to your home screen / apps'}</small></div>
        <button class="btn ${canInstall() ? 'primary' : ''}" id="installapp" ${isStandalone() || !canInstall() ? 'disabled' : ''}>${icon('download')} Install</button>
      </div>
    </section>

    <section class="set-card">
      <h2>${icon('bell')} Notifications</h2>
      <p class="set-hint">Pings are <b>content-free and sender-blind</b>: a push only ever means "your node has something new — open to sync." <b>Your own node originates it</b>, never a company reading your mail to decide when to notify you — the real message travels later, end-to-end, over the mesh. On iOS the OS push gateway sees timing only, never content.</p>
      <div class="set-row between">
        <div><b>Browser permission</b><small id="notifpermtxt">checking…</small></div>
        <button class="btn sm" id="notifperm">Enable</button>
      </div>
      <div class="set-row between">
        <div><b>Push subscription</b><small id="pushsubtxt">checking…</small></div>
        <button class="btn sm" id="pushsub" disabled>Subscribe</button>
      </div>
      <div class="set-row between">
        <div><b>Send test wake-ping</b><small>Local simulation of what your own node would send — posts straight to this browser's service worker and exercises the real push → sync → notification path, no server involved.</small></div>
        <button class="btn ghost sm" id="testping">${icon('bell')} Send test wake-ping</button>
      </div>
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

  // Identity — the full surface (safety number, devices, recovery, rotation) lives in its own view.
  root.querySelector('#openidentity').onclick = () => bus.setView('identity');
  root.querySelector('#editprofile').onclick = () => openEditProfile();

  drawAliases(root, id);
  drawSigs(root);
  drawFilters(root);
  drawBlockLists(root);

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

  // App: install affordance
  root.querySelector('#installapp').onclick = async () => {
    const r = await promptInstall();
    if (r.outcome === 'unavailable') toast('Your browser hasn’t offered an install prompt yet — try its menu → "Install Envoir" / "Add to Home Screen" instead.', { ms: 5000 });
    else if (r.outcome === 'accepted') toast(`${icon('check')} Installing Envoir…`);
    bus.rerender();
  };

  // Notifications: permission, push subscription, and the local test wake-ping
  wireNotifications(root);

  // Danger
  root.querySelector('#showphrase').onclick = () => toast(id.phrase.join(' '), { ms: 6000 });
  root.querySelector('#signout').onclick = () => { if (confirm('Sign out and clear this identity from this browser?')) { logout(); location.reload(); } };

  renderSignin(root.querySelector('#signinbox'));
}

// ---- Notifications: browser permission + Web Push subscription + local test wake-ping -------
function wireNotifications(root) {
  const permBtn = root.querySelector('#notifperm');
  const permTxt = root.querySelector('#notifpermtxt');
  const subBtn = root.querySelector('#pushsub');
  const subTxt = root.querySelector('#pushsubtxt');

  const syncPerm = () => {
    const p = notificationPermission();
    if (!notifSupported) { permTxt.textContent = 'Not supported in this browser'; permBtn.disabled = true; return; }
    permTxt.textContent = p === 'granted' ? 'Granted — this browser can show notifications' : p === 'denied' ? 'Denied — allow notifications for this site in your browser settings' : 'Not requested yet';
    permBtn.textContent = p === 'granted' ? `${icon('check')} Enabled` : 'Enable';
    permBtn.disabled = p === 'granted';
  };
  permBtn.onclick = async () => { await requestNotificationPermission(); syncPerm(); };
  syncPerm();

  const syncSub = async () => {
    if (!pushSupported) { subTxt.textContent = 'Not supported in this browser'; subBtn.disabled = true; return; }
    subBtn.disabled = false;
    const sub = await getPushSubscription();
    subTxt.textContent = sub ? 'Subscribed — this device can receive wake pings' : 'Not subscribed';
    subBtn.textContent = sub ? 'Unsubscribe' : 'Subscribe';
    subBtn.onclick = sub
      ? async () => { await unsubscribePush(); toast('Unsubscribed from push'); syncSub(); }
      : async () => {
          try { await subscribePush(); toast(`${icon('check')} Subscribed — your node can now send a wake ping to this device`); }
          catch (err) { toast('Could not subscribe: ' + (err?.message || err)); }
          syncSub();
        };
  };
  syncSub();

  root.querySelector('#testping').onclick = async () => {
    try {
      if (notifSupported && notificationPermission() !== 'granted') {
        const p = await requestNotificationPermission();
        syncPerm();
        if (p !== 'granted') { toast('Grant notification permission first to see the test ping appear'); return; }
      }
      await sendTestWakePing();
      toast(`${icon('bell')} Test wake-ping sent to the service worker — a generic, content-free notification should appear now`, { ms: 4400 });
    } catch (err) { toast('Test wake-ping failed: ' + (err?.message || err), { ms: 4400 }); }
  };
}

function drawAliases(root, id) {
  const wrap = root.querySelector('#aliases');
  wrap.innerHTML = id.addresses.map(a => {
    const label = { primary: 'primary', alias: 'alias', legacy: 'kept legacy', handle: 'handle', namechain: 'on-chain' }[a.kind] || a.kind;
    return `<div class="alias-row">
      <span class="mono alias-addr">${esc(a.address)}</span>
      <span class="pill ${a.kind === 'primary' ? 'accent' : a.kind === 'legacy' ? 'legacy' : a.kind === 'namechain' ? 'chain' : 'dim'} sm">${label}</span>
      ${a.kind === 'legacy' ? `<span class="set-hint inline">inbound marked legacy-origin</span>` : ''}
      ${a.kind === 'namechain' ? `<span class="set-hint inline">${icon('link')} bidirectional binding — key claims name + chain record points back, KT-audited</span>` : ''}
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
    } else if (!v.includes('@') && /\.(eth|sol)$/i.test(v)) {
      const r = addAlias(v, 'namechain');
      if (!r.ok) return toast(r.reason);
      toast(`${icon('link')} ${v} linked — bidirectional binding required: your key claims the name, and the chain record must point back to your key (spec §3.12.5b)`, { ms: 5000 });
    } else {
      const kind = /@(gmail|outlook|yahoo|proton|oldprovider)\./.test(v) ? 'legacy' : 'alias';
      const r = addAlias(v, kind);
      if (!r.ok) return toast(r.reason);
      toast(`${icon('check')} ${v} added — resolves to your key`);
    }
    root.querySelector('#newalias').value = '';
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

const ACTION_LABEL = { label: 'apply label', star: 'star it', archive: 'skip inbox (archive)', spam: 'mark as spam', read: 'mark read', 'legacy-flag': 'flag legacy-origin' };
function actionText(f) { return f.action === 'label' ? 'label “' + esc(LABELS.find(l => l.id === f.label)?.name || f.label) + '”' : (ACTION_LABEL[f.action] || esc(f.action)); }

function drawFilters(root) {
  const wrap = root.querySelector('#filters');
  if (!state.settings.filters.length) { wrap.innerHTML = `<div class="set-hint inline">No rules yet.</div>`; }
  else wrap.innerHTML = state.settings.filters.map(f => `<div class="filter-item">
    <span class="mono">${f.from ? 'from:' + esc(f.from) : ''}${f.subject ? (f.from ? ' ' : '') + 'subject:' + esc(f.subject) : ''}${!f.from && !f.subject ? '(empty)' : ''}</span>
    <span class="arrow-lil">→</span>
    <span class="pill ${f.action === 'legacy-flag' ? 'legacy' : f.action === 'spam' ? 'warn' : 'accent'} sm">${actionText(f)}</span>
    <div class="spacer"></div>
    <button class="icon-btn sm" data-edit="${f.id}" title="Edit rule">${icon('edit')}</button>
    <button class="icon-btn sm" data-del="${f.id}" title="Delete rule">${icon('trash')}</button>
    <label class="switch sm"><input type="checkbox" data-flt="${f.id}" ${f.enabled ? 'checked' : ''}><i></i></label>
  </div>`).join('');
  wrap.querySelectorAll('[data-flt]').forEach(c => c.onchange = () => { const f = state.settings.filters.find(x => x.id === c.dataset.flt); f.enabled = c.checked; saveSettings(); });
  wrap.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => ruleBuilder(root, state.settings.filters.find(x => x.id === b.dataset.edit)));
  wrap.querySelectorAll('[data-del]').forEach(b => b.onclick = () => { state.settings.filters = state.settings.filters.filter(x => x.id !== b.dataset.del); saveSettings(); bus.rerender(); });
  root.querySelector('#addfilter').onclick = () => ruleBuilder(root, null);
  root.querySelector('#runfilters').onclick = () => { const n = applyFilters(); saveSettings(); bus.rerender(); bus.refreshChrome(); toast(n ? `${icon('check')} Rules applied — ${n} conversation(s) updated` : 'No conversations matched your rules right now'); };
}

// A real client-side rule builder: condition (from / subject) → action. Persists to settings
// and applies to the current mailbox immediately.
function ruleBuilder(root, existing) {
  const f = existing || { id: uid('flt'), from: '', subject: '', action: 'label', label: LABELS[0].id, enabled: true };
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>${existing ? 'Edit rule' : 'New rule'}</h2><button class="icon-btn" id="rx">${icon('x')}</button></div>
      <p class="modal-note">${icon('info')} If a message matches <b>all</b> the conditions you set, the action runs automatically. Leave a condition blank to ignore it. <span class="mono">from</span> accepts <span class="mono">*</span> wildcards (e.g. <span class="mono">*@envoir.org</span>).</p>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>From contains / matches</span><input id="rfrom" value="${esc(f.from)}" placeholder="*@envoir.org"></label>
        <label class="cfield"><span>Subject contains</span><input id="rsubj" value="${esc(f.subject)}" placeholder="receipt"></label>
      </div>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Then</span><select id="raction">
          ${['label', 'star', 'archive', 'spam', 'read'].map(a => `<option value="${a}" ${f.action === a ? 'selected' : ''}>${ACTION_LABEL[a]}</option>`).join('')}
        </select></label>
        <label class="cfield" id="rlabelwrap"><span>Label</span><select id="rlabel">${LABELS.map(l => `<option value="${l.id}" ${f.label === l.id ? 'selected' : ''}>${esc(l.name)}</option>`).join('')}</select></label>
      </div>
      <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} runs on your node · client-side, no third party</span><div class="spacer"></div><button class="btn primary" id="rsave">${existing ? 'Save rule' : 'Create rule'}</button></div>
    </div>`, { wide: true });
  const syncLabel = () => card.querySelector('#rlabelwrap').style.display = card.querySelector('#raction').value === 'label' ? '' : 'none';
  card.querySelector('#raction').onchange = syncLabel; syncLabel();
  card.querySelector('#rx').onclick = closeModal;
  card.querySelector('#rsave').onclick = () => {
    f.from = card.querySelector('#rfrom').value.trim();
    f.subject = card.querySelector('#rsubj').value.trim();
    f.action = card.querySelector('#raction').value;
    f.label = card.querySelector('#rlabel').value;
    if (!f.from && !f.subject) { toast('Add at least one condition'); return; }
    if (!existing) state.settings.filters.push(f);
    saveSettings();
    const n = applyFilters();
    closeModal(); bus.rerender(); bus.refreshChrome();
    toast(`${icon('check')} Rule saved${n ? ` · applied to ${n} conversation(s)` : ''}`);
  };
}

function drawBlockLists(root) {
  const rowHtml = (a, kind) => `<div class="bl-row"><span class="mono">${esc(a)}</span><button class="icon-btn sm" data-${kind}="${esc(a)}" title="Remove">${icon('x')}</button></div>`;
  const bwrap = root.querySelector('#blocked'), awrap = root.querySelector('#allowed');
  bwrap.innerHTML = state.settings.blocked.length ? state.settings.blocked.map(a => rowHtml(a, 'unblock')).join('') : `<div class="set-hint inline">Nothing blocked.</div>`;
  awrap.innerHTML = state.settings.allowed.length ? state.settings.allowed.map(a => rowHtml(a, 'unallow')).join('') : `<div class="set-hint inline">No allow-listed senders.</div>`;
  bwrap.querySelectorAll('[data-unblock]').forEach(b => b.onclick = () => { unblockSender(b.dataset.unblock); bus.rerender(); });
  awrap.querySelectorAll('[data-unallow]').forEach(b => b.onclick = () => { state.settings.allowed = state.settings.allowed.filter(x => x !== b.dataset.unallow); saveSettings(); bus.rerender(); });
  root.querySelector('#addblock').onclick = () => { const v = root.querySelector('#newblock').value.trim(); if (v) { blockSender(v); bus.rerender(); toast(`${icon('shield')} ${v} blocked`); } };
  root.querySelector('#addallow').onclick = () => { const v = root.querySelector('#newallow').value.trim(); if (v) { allowSender(v); bus.rerender(); toast(`${icon('check')} ${v} allow-listed`); } };
}
