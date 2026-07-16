// views/mail.js — the flagship three-pane mail experience.
// Folders + labels rail · conversation-threaded list with multi-select + bulk actions ·
// reading pane with per-message verified badges, legacy-origin marking, and the MOTE inspector.

import { state, threadsIn, thread, unreadCount, lastTime, parseSearch, matchThread, searchIsGlobal, blockSender, allowSender, threadSender, uid, saveSettings } from '../store.js';
import { FOLDERS, LABELS, person } from '../seed.js';
import { el, esc, icon, avatar, timeAgo, fmtLong, trustPill, emptyState, verifiedGlyph, showInspector, litHop, toast, renderBody, commandMenu } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { planDelivery, animatePath } from '../mesh-sim.js';
import { bus } from '../bus.js';
import { openCompose } from '../compose.js';

export function render(root) {
  const ui = state.ui;
  root.className = 'view mail-view' + (state.settings.mailDensity === 'compact' ? ' compact' : '');
  root.innerHTML = `
    <aside class="mail-rail">
      <button class="btn primary block" id="m-compose">${icon('edit')} Compose</button>
      <nav class="folders" id="folders"></nav>
      <div class="rail-label-h">Labels</div>
      <nav class="labels" id="labels"></nav>
    </aside>
    <section class="mail-list" id="mail-list"></section>
    <section class="mail-read" id="mail-read"></section>`;

  root.querySelector('#m-compose').onclick = () => openCompose();
  drawFolders(root);
  drawLabels(root);
  drawList(root);
  drawRead(root);
  // mobile master/detail: reveal the reading pane only when a visible thread is chosen
  root.classList.toggle('detail', state.ui.mobileDetail && currentList().some(x => x.id === state.ui.selThread));
}

function drawFolders(root) {
  const nav = root.querySelector('#folders');
  nav.innerHTML = FOLDERS.map(f => {
    const n = f.id === 'inbox' ? unreadCount('inbox') : (f.id === 'drafts' ? state.mail.filter(t => t.folder === 'drafts').length : 0);
    const active = !state.ui.mailLabel && state.ui.mailFolder === f.id;
    return `<button class="folder ${active ? 'on' : ''}" data-f="${f.id}">${icon(f.icon)}<span>${f.name}</span>${n ? `<i class="count">${n}</i>` : ''}</button>`;
  }).join('');
  nav.querySelectorAll('[data-f]').forEach(b => b.onclick = () => {
    state.ui.mailFolder = b.dataset.f; state.ui.mailLabel = null; state.ui.selected.clear();
    state.ui.selThread = threadsIn(b.dataset.f)[0]?.id || null;
    bus.rerender();
  });
}

function drawLabels(root) {
  const nav = root.querySelector('#labels');
  nav.innerHTML = LABELS.map(l => `<button class="label-item ${state.ui.mailLabel === l.id ? 'on' : ''}" data-l="${l.id}"><i class="dot" style="--h:${l.hue}"></i>${esc(l.name)}</button>`).join('');
  nav.querySelectorAll('[data-l]').forEach(b => b.onclick = () => {
    state.ui.mailLabel = b.dataset.l; state.ui.selected.clear();
    state.ui.selThread = threadsIn(null, b.dataset.l)[0]?.id || null;
    bus.rerender();
  });
}

export function currentList() {
  const q = state.ui.search.trim();
  const parsed = parseSearch(q);
  // Operator-driven searches (label:/in:) go global across the mailbox; otherwise search stays
  // scoped to the folder/label the sidebar has selected — predictable, Gmail-ish behavior.
  if (q && searchIsGlobal(parsed)) {
    return state.mail.filter(t => t.folder !== 'trash' && matchThread(t, parsed)).sort((a, b) => lastTime(b) - lastTime(a));
  }
  const base = threadsIn(state.ui.mailFolder, state.ui.mailLabel);
  return q ? base.filter(t => matchThread(t, parsed)) : base;
}

let _listKey = null;
function drawList(root) {
  const wrap = root.querySelector('#mail-list');
  const list = currentList();
  const sel = state.ui.selected;
  const title = state.ui.mailLabel ? (LABELS.find(l => l.id === state.ui.mailLabel)?.name + ' label') : (FOLDERS.find(f => f.id === state.ui.mailFolder)?.name);
  // Only play the row entrance stagger when the *set* of rows changes (folder/label/search),
  // not on in-place mutations like star/read/archive — otherwise the whole list re-flickers.
  const key = state.ui.mailFolder + '|' + state.ui.mailLabel + '|' + state.ui.search;
  const fresh = key !== _listKey; _listKey = key;
  const dense = state.settings.mailDensity === 'compact';

  wrap.innerHTML = `
    <div class="list-head">
      ${sel.size ? `<div class="bulk-bar">
        <span class="bulk-n">${sel.size} selected</span>
        <div class="spacer"></div>
        <button class="icon-btn" data-bulk="archive" title="Archive (e)">${icon('archive')}</button>
        <button class="icon-btn" data-bulk="read" title="Mark read">${icon('check')}</button>
        <button class="icon-btn" data-bulk="spam" title="Spam">${icon('shield')}</button>
        <button class="icon-btn" data-bulk="trash" title="Delete (#)">${icon('trash')}</button>
        <button class="icon-btn" data-bulk="clear" title="Clear">${icon('x')}</button>
      </div>` : `<h2>${esc(state.ui.search ? 'Search' : title)}</h2><span class="list-count">${list.length}</span>${searchChips()}
        <button class="icon-btn sm density-toggle" id="densebtn" title="Density: ${dense ? 'compact' : 'comfortable'} — click for ${dense ? 'comfortable' : 'compact'}" aria-label="Toggle list density" aria-pressed="${dense}">${icon(dense ? 'rows2' : 'density')}</button>`}
    </div>
    <div class="thread-list ${fresh ? '' : 'static'}" id="threads"></div>`;

  if (sel.size) wrap.querySelectorAll('[data-bulk]').forEach(b => b.onclick = () => bulk(b.dataset.bulk));
  wrap.querySelector('#densebtn')?.addEventListener('click', () => {
    state.settings.mailDensity = dense ? 'comfortable' : 'compact'; saveSettings(); bus.rerender();
  });

  const tl = wrap.querySelector('#threads');
  if (!list.length) { tl.innerHTML = emptyState('inbox', 'Nothing here', state.ui.search ? 'No messages match. Try operators: from: to: subject: label: in: is:unread has:attachment' : 'You are all caught up.'); return; }

  list.forEach((t, i) => {
    const last = t.msgs[t.msgs.length - 1];
    const p = person(t.msgs[0].from === 'you' ? (t.msgs[0].to?.[0] || 'you') : t.msgs[0].from);
    const names = [...new Set(t.msgs.map(m => m.from === 'you' ? 'You' : person(m.from).name.split(' ')[0]))].join(', ');
    const row = el(`<div class="trow ${state.ui.selThread === t.id ? 'sel' : ''} ${t.read ? '' : 'unread'} ${t.legacy ? 'legacy' : ''}" data-id="${t.id}" role="button" tabindex="0" aria-label="${esc(t.subject)} — from ${esc(names)}${t.read ? '' : ', unread'}" style="animation-delay:${Math.min(i * 20, 300)}ms">
      <button class="tcheck ${sel.has(t.id) ? 'on' : ''}" data-check="${t.id}" aria-label="Select">${sel.has(t.id) ? icon('check') : ''}</button>
      ${avatar(p, dense ? 28 : 36, { ring: true })}
      <div class="tmain">
        <div class="trow-top">
          <span class="tfrom">${esc(names)}${t.verified ? verifiedGlyph() : ''}${t.msgs.length > 1 ? `<i class="tcount">${t.msgs.length}</i>` : ''}</span>
          <span class="ttime">${t.scheduledAt ? icon('clock') : ''}${timeAgo(lastTime(t))}</span>
        </div>
        <div class="tsubj">${esc(t.subject)}</div>
        <div class="tprev">${esc(last.body.split('\n')[0])}</div>
        <div class="tchips">${t.labels.map(id => { const l = LABELS.find(x => x.id === id); return l ? `<i class="chip-lbl" style="--h:${l.hue}">${esc(l.name)}</i>` : ''; }).join('')}${t.snoozeUntil ? `<i class="chip-lbl snoozed">${icon('snooze')} snoozed</i>` : ''}${t.legacy ? `<i class="chip-lbl legacy">legacy-origin</i>` : ''}</div>
      </div>
      <button class="tstar ${t.starred ? 'on' : ''}" data-star="${t.id}" aria-label="Star">${icon('star')}</button>
    </div>`);
    row.querySelector('[data-check]').onclick = (e) => { e.stopPropagation(); toggleSel(t.id); };
    row.querySelector('[data-star]').onclick = (e) => { e.stopPropagation(); t.starred = !t.starred; bus.rerender(); };
    const open = () => { state.ui.selThread = t.id; t.read = true; state.ui.mobileDetail = true; bus.rerender(); };
    row.onclick = open;
    row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } };
    tl.appendChild(row);
  });
  // Keep the selected conversation visible when moving through the list with j/k.
  tl.querySelector('.trow.sel')?.scrollIntoView({ block: 'nearest' });
}

// Show which search operators were recognized — makes on-device operator search discoverable.
function searchChips() {
  const q = state.ui.search.trim(); if (!q) return '';
  const p = parseSearch(q);
  const chips = [];
  if (p.from) chips.push('from:' + p.from);
  if (p.to) chips.push('to:' + p.to);
  if (p.subject) chips.push('subject:' + p.subject);
  if (p.label) chips.push('label:' + p.label);
  if (p.in) chips.push('in:' + p.in);
  if (p.flags.unread) chips.push('is:unread');
  if (p.flags.read) chips.push('is:read');
  if (p.flags.starred) chips.push('is:starred');
  if (p.flags.attachment) chips.push('has:attachment');
  if (!chips.length) return '';
  return `<div class="search-ops">${chips.map(c => `<i class="op-chip mono">${esc(c)}</i>`).join('')}</div>`;
}

function toggleSel(id) { const s = state.ui.selected; s.has(id) ? s.delete(id) : s.add(id); bus.rerender(); }
function bulk(action) {
  const ids = [...state.ui.selected];
  ids.forEach(id => { const t = thread(id); if (!t) return;
    if (action === 'archive') t.folder = 'archive';
    else if (action === 'trash') t.folder = 'trash';
    else if (action === 'spam') t.folder = 'spam';
    else if (action === 'read') t.read = true;
  });
  state.ui.selected.clear();
  bus.rerender(); bus.refreshChrome();
}

function drawRead(root) {
  const wrap = root.querySelector('#mail-read');
  const t = thread(state.ui.selThread);
  if (!t || !currentList().some(x => x.id === t.id)) {
    wrap.innerHTML = emptyState('mail', 'Select a conversation', 'Your mailbox is end-to-end encrypted and metadata-private.');
    return;
  }
  wrap.innerHTML = `
    <header class="read-head">
      <button class="icon-btn mobile-back" id="m-back" aria-label="Back to conversation list" title="Back">${icon('reply')}</button>
      <div class="read-title">
        <h1 class="display">${esc(t.subject)}</h1>
        <div class="read-tags">
          ${t.labels.map(id => { const l = LABELS.find(x => x.id === id); return l ? `<i class="chip-lbl" style="--h:${l.hue}">${esc(l.name)}</i>` : ''; }).join('')}
          ${t.tier === 'private' ? `<span class="pill priv">${icon('shield')} metadata-private</span>` : ''}
          ${t.legacy ? `<span class="pill legacy">legacy-origin</span>` : ''}
        </div>
      </div>
      <div class="read-actions">
        ${t.folder === 'spam'
          ? `<button class="icon-btn" id="a-notspam" title="Not spam — move to inbox">${icon('check')}</button>`
          : `<button class="icon-btn" id="a-archive" title="Archive (e)">${icon('archive')}</button>`}
        <button class="icon-btn" id="a-snooze" title="Snooze">${icon('snooze')}</button>
        <button class="icon-btn" id="a-label" title="Label">${icon('label')}</button>
        <button class="icon-btn" id="a-star" title="Star" >${icon('star')}</button>
        <button class="icon-btn" id="a-unread" title="Mark unread (u)">${icon('mail')}</button>
        <button class="icon-btn" id="a-more" title="More actions">${icon('more')}</button>
        <button class="icon-btn" id="a-trash" title="Delete (#)">${icon('trash')}</button>
      </div>
    </header>
    <div class="read-scroll" id="read-scroll"></div>
    <footer class="read-foot">
      ${t.folder === 'drafts'
        ? `<button class="btn primary" id="a-edit">${icon('edit')} ${t.scheduledAt ? 'Edit scheduled' : 'Continue editing'}</button>
           <button class="btn danger" id="a-discard">${icon('trash')} Discard draft</button>`
        : `<button class="btn primary" id="a-reply">${icon('reply')} Reply</button>
           <button class="btn" id="a-forward">${icon('forward')} Forward</button>`}
    </footer>`;

  const scroll = wrap.querySelector('#read-scroll');
  t.msgs.forEach((m, i) => {
    const p = m.from === 'you' ? { name: 'You', hue: 220, address: 'you', trust: 'verified' } : person(m.from);
    const last = i === t.msgs.length - 1;
    const legacyMsg = m.tier === 'legacy';
    const card = el(`<article class="msg ${last ? 'open' : ''} ${legacyMsg ? 'legacy' : ''}">
      <div class="msg-head">
        ${avatar(p, 40, { ring: true, badge: true })}
        <div class="msg-who">
          <div class="msg-name">${esc(p.name)} ${p.trust === 'verified' && m.from !== 'you' ? trustPill('verified') : (p.trust === 'tofu' ? trustPill('tofu') : (legacyMsg ? trustPill('legacy') : ''))}</div>
          <div class="msg-addr mono">${esc(p.address)}${m.plusTag ? ` <i class="plus">+${esc(m.plusTag)} → same key</i>` : ''} · to ${esc((m.to || []).join(', '))}</div>
        </div>
        <div class="msg-side">
          <span class="msg-time">${fmtLong(m.time)}</span>
          <button class="icon-btn sm" data-insp="${i}" title="Why is this private?">${icon('info')}</button>
        </div>
      </div>
      ${legacyMsg ? `<div class="legacy-note">${icon('shield')} Arrived from the legacy world via the gateway — authenticated (DKIM) but not end-to-end encrypted before the gateway (spec §7.2).</div>` : ''}
      <div class="msg-body">${renderBody(m)}</div>
      ${(m.attach || []).length ? `<div class="msg-attach">${m.attach.map(a => `<span class="att">${icon('files')} ${esc(a.name)} · ${fmt(a.size)}</span>`).join('')}</div>` : ''}
    </article>`);
    card.querySelector('[data-insp]').onclick = () => inspectMessage(t, m);
    if (!last) card.querySelector('.msg-head').onclick = (e) => { if (e.target.closest('[data-insp]')) return; card.classList.toggle('open'); };
    scroll.appendChild(card);
  });

  const A = wrap;
  A.querySelector('#m-back').onclick = () => { state.ui.mobileDetail = false; bus.rerender(); };
  A.querySelector('#a-archive')?.addEventListener('click', () => moveWithUndo(t, 'archive', 'Archived'));
  A.querySelector('#a-notspam')?.addEventListener('click', () => { allowSender(threadSender(t)); moveWithUndo(t, 'inbox', 'Moved to Inbox · sender allow-listed'); });
  A.querySelector('#a-trash').onclick = () => moveWithUndo(t, 'trash', 'Deleted');
  A.querySelector('#a-star').onclick = () => { t.starred = !t.starred; bus.rerender(); };
  A.querySelector('#a-unread').onclick = () => { t.read = false; nextAfterAction(); };
  A.querySelector('#a-snooze').onclick = () => snoozeMenu(A.querySelector('#a-snooze'), t);
  A.querySelector('#a-label').onclick = () => labelMenu(A.querySelector('#a-label'), t);
  A.querySelector('#a-more').onclick = () => moreMenu(A.querySelector('#a-more'), t);
  A.querySelector('#a-reply')?.addEventListener('click', () => replyTo(t));
  A.querySelector('#a-forward')?.addEventListener('click', () => openCompose({ subject: 'Fwd: ' + t.subject, body: (t.msgs[t.msgs.length - 1].html ? '<br><br>--- Forwarded ---<br>' : '\n\n--- Forwarded ---\n') + t.msgs[t.msgs.length - 1].body, html: !!t.msgs[t.msgs.length - 1].html }));
  A.querySelector('#a-edit')?.addEventListener('click', () => {
    const m = t.msgs[0];
    openCompose({ threadId: t.id, to: (m.to || []).join(', '), subject: t.subject === '(no subject)' ? '' : t.subject, body: m.body, html: !!m.html, tier: t.tier, attach: m.attach || [], scheduleAt: t.scheduledAt || null });
  });
  A.querySelector('#a-discard')?.addEventListener('click', () => { state.mail = state.mail.filter(x => x.id !== t.id); toast(`${icon('trash')} Draft discarded`); nextAfterAction(); });
}

// Destructive/move actions get a Gmail-style Undo toast (spec §17#19 archive, §17#20 spam).
function moveWithUndo(t, dest, label) {
  const prev = t.folder;
  t.folder = dest;
  nextAfterAction();
  toast(`${icon(dest === 'archive' ? 'archive' : dest === 'spam' ? 'shield' : dest === 'trash' ? 'trash' : 'inbox')} ${label}`, {
    ms: 5000, action: 'Undo', onAction: () => { t.folder = prev; state.ui.selThread = t.id; bus.rerender(); bus.refreshChrome(); },
  });
}

function moreMenu(anchor, t) {
  const items = [];
  if (t.folder !== 'spam') items.push({ label: 'Report spam', run: () => moveWithUndo(t, 'spam', 'Reported as spam') });
  items.push({ label: 'Block sender', run: () => { blockSender(threadSender(t)); moveWithUndo(t, 'spam', 'Sender blocked'); } });
  if (t.folder !== 'inbox') items.push({ label: 'Move to Inbox', run: () => moveWithUndo(t, 'inbox', 'Moved to Inbox') });
  items.push({ label: t.read ? 'Mark unread' : 'Mark read', run: () => { t.read = !t.read; bus.rerender(); bus.refreshChrome(); } });
  popover(anchor, items);
}

async function inspectMessage(t, m) {
  const p = m.from === 'you' ? { address: 'you' } : person(m.from);
  const mote = await buildMote({ to: (m.to || [])[0] || p.address, kind: KIND.mail, subject: t.subject, body: m.body, tier: m.tier });
  const plan = planDelivery(mote, m.from === 'you' ? (m.to || [])[0] : m.from);
  showInspector(mote, plan);
  animatePath(plan, (i) => litHop(i));
}

function replyTo(t) {
  const first = t.msgs[0];
  const to = first.from === 'you' ? (first.to?.[0] || '') : person(first.from).address;
  openCompose({ to, subject: t.subject.startsWith('Re:') ? t.subject : 'Re: ' + t.subject, replyThread: t.id, body: '\n\n' });
}

function nextAfterAction() {
  const list = currentList();
  const idx = list.findIndex(x => x.id === state.ui.selThread);
  state.ui.selThread = (list[idx + 1] || list[idx - 1] || {}).id || null;
  bus.rerender(); bus.refreshChrome();
}

// Keyboard-driven snooze picker — a command menu (type-to-nothing here, but ↑↓ + ↵ + Esc),
// anchored to the reading-pane control or the selected row.
function snoozeMenu(anchor, t) {
  const wknd = (() => { const d = new Date(); d.setDate(d.getDate() + ((6 - d.getDay() + 7) % 7 || 7)); d.setHours(9, 0, 0, 0); return d.getTime() - Date.now(); })();
  const opts = [
    ['Later today', 6 * 3600e3, '+6h', 'clock'],
    ['Tomorrow', 24 * 3600e3, tomorrowLabel(), 'clock'],
    ['This weekend', wknd, 'Sat 9am', 'clock'],
    ['Next week', 7 * 24 * 3600e3, 'Mon', 'clock'],
  ];
  commandMenu(anchor, {
    title: 'Snooze until', icon: 'snooze', align: 'right', filterable: false,
    items: opts.map(([label, ms, sub, ic]) => ({ label, sub, icon: ic, run: () => {
      t.snoozeUntil = Date.now() + ms; t.folder = 'inbox';
      toast(`${icon('snooze')} Snoozed — resurfaces ${sub === '+6h' ? 'later today' : label.toLowerCase()}`);
      nextAfterAction();
    } })),
  });
}
function tomorrowLabel() { const d = new Date(); d.setDate(d.getDate() + 1); return d.toLocaleDateString([], { weekday: 'short' }); }

// Keyboard-driven label picker — type-to-filter, ↵ toggles, Esc closes.
function labelMenu(anchor, t) {
  commandMenu(anchor, {
    title: 'Apply label', icon: 'label', align: 'right', filterable: true, placeholder: 'Filter labels…',
    items: LABELS.map(l => ({ label: l.name, hue: l.hue, checked: t.labels.includes(l.id), run: () => {
      t.labels.includes(l.id) ? (t.labels = t.labels.filter(x => x !== l.id)) : t.labels.push(l.id);
      toast(`${icon('label')} ${t.labels.includes(l.id) ? 'Labelled' : 'Removed'} ${esc(l.name)}`);
      bus.rerender();
    } })),
  });
}
function popover(anchor, items) {
  document.querySelector('.popover')?.remove();
  const r = anchor.getBoundingClientRect();
  const pop = el(`<div class="popover" style="top:${r.bottom + 6}px;left:${Math.min(r.left, innerWidth - 210)}px">${items.map((it, i) => `<button data-i="${i}"><i class="dot" style="--h:${it.hue ?? 220}"></i>${esc(it.label)}</button>`).join('')}</div>`);
  document.body.appendChild(pop);
  items.forEach((it, i) => pop.querySelector(`[data-i="${i}"]`).onclick = () => { pop.remove(); it.run(); });
  setTimeout(() => document.addEventListener('click', function h(e) { if (!pop.contains(e.target)) { pop.remove(); document.removeEventListener('click', h); } }), 0);
}

function fmt(n) { const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; }

// --- Keyboard action surface (called by shell) ---
export const mailKeys = {
  move(delta) {
    const list = currentList(); if (!list.length) return;
    let idx = list.findIndex(x => x.id === state.ui.selThread);
    idx = Math.max(0, Math.min(list.length - 1, (idx < 0 ? 0 : idx + delta)));
    const t = list[idx]; state.ui.selThread = t.id; t.read = true; bus.rerender();
  },
  archive() { const t = thread(state.ui.selThread); if (t) { t.folder = 'archive'; nextAfterAction(); } },
  trash() { const t = thread(state.ui.selThread); if (t) { t.folder = 'trash'; nextAfterAction(); } },
  star() { const t = thread(state.ui.selThread); if (t) { t.starred = !t.starred; bus.rerender(); } },
  unread() { const t = thread(state.ui.selThread); if (t) { t.read = false; bus.rerender(); bus.refreshChrome(); } },
  reply() { const t = thread(state.ui.selThread); if (t) replyTo(t); },
  select() { if (state.ui.selThread) toggleSel(state.ui.selThread); },
  snooze() { const t = thread(state.ui.selThread); if (!t) return; const a = document.querySelector('#a-snooze') || document.querySelector('.trow.sel'); if (a) snoozeMenu(a, t); },
  label() { const t = thread(state.ui.selThread); if (!t) return; const a = document.querySelector('#a-label') || document.querySelector('.trow.sel'); if (a) labelMenu(a, t); },
};
