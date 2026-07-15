// views/mail.js — the flagship three-pane mail experience.
// Folders + labels rail · conversation-threaded list with multi-select + bulk actions ·
// reading pane with per-message verified badges, legacy-origin marking, and the MOTE inspector.

import { state, threadsIn, thread, unreadCount, lastTime } from '../store.js';
import { FOLDERS, LABELS, person } from '../seed.js';
import { el, esc, icon, avatar, timeAgo, fmtLong, trustPill, emptyState, verifiedGlyph, showInspector, litHop } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { planDelivery, animatePath } from '../mesh-sim.js';
import { bus } from '../bus.js';
import { openCompose } from '../compose.js';

export function render(root) {
  const ui = state.ui;
  root.className = 'view mail-view';
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

function matchesSearch(t) {
  const q = state.ui.search.trim().toLowerCase();
  if (!q) return true;
  const hay = (t.subject + ' ' + t.msgs.map(m => (person(m.from).name || '') + ' ' + m.body).join(' ')).toLowerCase();
  return hay.includes(q);
}

export function currentList() {
  return threadsIn(state.ui.mailFolder, state.ui.mailLabel).filter(matchesSearch);
}

function drawList(root) {
  const wrap = root.querySelector('#mail-list');
  const list = currentList();
  const sel = state.ui.selected;
  const title = state.ui.mailLabel ? (LABELS.find(l => l.id === state.ui.mailLabel)?.name + ' label') : (FOLDERS.find(f => f.id === state.ui.mailFolder)?.name);

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
      </div>` : `<h2>${esc(title)}</h2><span class="list-count">${list.length}</span>`}
    </div>
    <div class="thread-list" id="threads"></div>`;

  if (sel.size) wrap.querySelectorAll('[data-bulk]').forEach(b => b.onclick = () => bulk(b.dataset.bulk));

  const tl = wrap.querySelector('#threads');
  if (!list.length) { tl.innerHTML = emptyState('inbox', 'Nothing here', state.ui.search ? 'No messages match your search.' : 'You are all caught up.'); return; }

  list.forEach((t, i) => {
    const last = t.msgs[t.msgs.length - 1];
    const p = person(t.msgs[0].from === 'you' ? (t.msgs[0].to?.[0] || 'you') : t.msgs[0].from);
    const names = [...new Set(t.msgs.map(m => m.from === 'you' ? 'You' : person(m.from).name.split(' ')[0]))].join(', ');
    const row = el(`<div class="trow ${state.ui.selThread === t.id ? 'sel' : ''} ${t.read ? '' : 'unread'} ${t.legacy ? 'legacy' : ''}" data-id="${t.id}" style="animation-delay:${Math.min(i * 20, 300)}ms">
      <button class="tcheck ${sel.has(t.id) ? 'on' : ''}" data-check="${t.id}" aria-label="Select">${sel.has(t.id) ? icon('check') : ''}</button>
      ${avatar(p, 36, { ring: true })}
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
    row.onclick = () => { state.ui.selThread = t.id; t.read = true; bus.rerender(); };
    tl.appendChild(row);
  });
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
      <div class="read-title">
        <h1>${esc(t.subject)}</h1>
        <div class="read-tags">
          ${t.labels.map(id => { const l = LABELS.find(x => x.id === id); return l ? `<i class="chip-lbl" style="--h:${l.hue}">${esc(l.name)}</i>` : ''; }).join('')}
          ${t.tier === 'private' ? `<span class="pill priv">${icon('shield')} metadata-private</span>` : ''}
          ${t.legacy ? `<span class="pill legacy">legacy-origin</span>` : ''}
        </div>
      </div>
      <div class="read-actions">
        <button class="icon-btn" id="a-archive" title="Archive (e)">${icon('archive')}</button>
        <button class="icon-btn" id="a-snooze" title="Snooze">${icon('snooze')}</button>
        <button class="icon-btn" id="a-label" title="Label">${icon('label')}</button>
        <button class="icon-btn" id="a-star" title="Star" >${icon('star')}</button>
        <button class="icon-btn" id="a-trash" title="Delete (#)">${icon('trash')}</button>
      </div>
    </header>
    <div class="read-scroll" id="read-scroll"></div>
    <footer class="read-foot">
      <button class="btn primary" id="a-reply">${icon('reply')} Reply</button>
      <button class="btn" id="a-forward">${icon('forward')} Forward</button>
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
      <div class="msg-body">${esc(m.body)}</div>
      ${(m.attach || []).length ? `<div class="msg-attach">${m.attach.map(a => `<span class="att">${icon('files')} ${esc(a.name)} · ${fmt(a.size)}</span>`).join('')}</div>` : ''}
    </article>`);
    card.querySelector('[data-insp]').onclick = () => inspectMessage(t, m);
    if (!last) card.querySelector('.msg-head').onclick = (e) => { if (e.target.closest('[data-insp]')) return; card.classList.toggle('open'); };
    scroll.appendChild(card);
  });

  const A = wrap;
  A.querySelector('#a-archive').onclick = () => { t.folder = 'archive'; nextAfterAction(); };
  A.querySelector('#a-trash').onclick = () => { t.folder = 'trash'; nextAfterAction(); };
  A.querySelector('#a-star').onclick = () => { t.starred = !t.starred; bus.rerender(); };
  A.querySelector('#a-snooze').onclick = () => snoozeMenu(A.querySelector('#a-snooze'), t);
  A.querySelector('#a-label').onclick = () => labelMenu(A.querySelector('#a-label'), t);
  A.querySelector('#a-reply').onclick = () => replyTo(t);
  A.querySelector('#a-forward').onclick = () => openCompose({ subject: 'Fwd: ' + t.subject, body: '\n\n---\n' + t.msgs[t.msgs.length - 1].body });
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

function snoozeMenu(anchor, t) {
  popover(anchor, [
    ['Later today', 6 * 3600e3], ['Tomorrow', 24 * 3600e3], ['This weekend', 3 * 24 * 3600e3], ['Next week', 7 * 24 * 3600e3],
  ].map(([label, ms]) => ({ label, run: () => { t.snoozeUntil = Date.now() + ms; t.folder = 'inbox'; nextAfterAction(); } })));
}
function labelMenu(anchor, t) {
  popover(anchor, LABELS.map(l => ({
    label: (t.labels.includes(l.id) ? '✓ ' : '') + l.name, hue: l.hue,
    run: () => { t.labels.includes(l.id) ? (t.labels = t.labels.filter(x => x !== l.id)) : t.labels.push(l.id); bus.rerender(); },
  })));
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
};
