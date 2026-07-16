// views/chat.js — real-time chat over the SAME MOTE substrate (kind=chat, fast tier).
// DMs + channels (channels are GROUPS with addresses, spec §5.8). Slack-grade surface:
// threaded replies in a side panel, hover message actions, reactions/emoji, @mentions,
// pinned messages, day dividers, typing/presence (opt-in, labelled metadata-sensitive).

import { state } from '../store.js';
import { person, PEOPLE } from '../seed.js';
import { el, esc, icon, avatar, timeAgo, fmtClock, fmtDay, emptyState, trustPill, toast, openModal, closeModal, emojiPanel } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { bus } from '../bus.js';

const REPLIES = ['makes sense 👍', 'on it', 'love that', 'let\'s ship it', 'agreed', 'looking now ✨'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

// In-conversation search state (kind=chat local search — the mailbox is never server-indexed).
let chatSearch = { q: '', idx: 0, open: false };
function resetSearch() { chatSearch = { q: '', idx: 0, open: false }; }

// Ordered pinned messages: a stable reorderable list distinct from message order.
function getPins(c) {
  const pinned = c.msgs.filter(m => m.pinned);
  if (!c._pinOrder) c._pinOrder = [];
  c._pinOrder = c._pinOrder.filter(m => pinned.includes(m));
  pinned.forEach(m => { if (!c._pinOrder.includes(m)) c._pinOrder.push(m); });
  return c._pinOrder;
}

export function render(root) {
  root.className = 'view chat-view';
  root.innerHTML = `
    <aside class="chat-list">
      <div class="list-head"><h2>Chat</h2><span class="pill accent">${icon('shield')} fast tier</span></div>
      <div class="conv-list" id="convs"></div>
    </aside>
    <section class="chat-main" id="chat-main"></section>`;
  drawConvs(root);
  drawMain(root);
  root.classList.toggle('detail', state.ui.mobileDetail && !!state.chats.find(x => x.id === state.ui.selChat));
  root.classList.toggle('thread-open', !!state.ui.chatThread);
}

function convTitle(c) { return c.type === 'channel' ? (state.groups.find(g => g.id === c.group)?.name || c.group) : person(c.with).name; }

function matchesSearch(c) {
  const q = state.ui.search.trim().toLowerCase();
  if (!q) return true;
  const hay = (convTitle(c) + ' ' + c.msgs.map(m => m.body).join(' ')).toLowerCase();
  return hay.includes(q);
}

function drawConvs(root) {
  const wrap = root.querySelector('#convs');
  wrap.innerHTML = '';
  const list = state.chats.filter(matchesSearch);
  if (!list.length) { wrap.innerHTML = emptyState('search', 'No conversations', 'No chats match your search.'); return; }
  const dms = list.filter(c => c.type === 'dm');
  const channels = list.filter(c => c.type === 'channel');
  const section = (label, items) => {
    if (!items.length) return;
    wrap.appendChild(el(`<div class="conv-section-h">${esc(label)}</div>`));
    items.forEach(c => wrap.appendChild(convRow(c)));
  };
  section('Channels', channels);
  section('Direct messages', dms);
}

function convRow(c) {
  const last = c.msgs[c.msgs.length - 1];
  const isCh = c.type === 'channel';
  const p = isCh ? { name: convTitle(c), hue: 250, trust: 'verified' } : person(c.with);
  const sel = state.ui.selChat === c.id;
  const row = el(`<button class="conv ${sel ? 'sel' : ''}" data-id="${c.id}"${sel ? ' aria-current="true"' : ''} aria-label="${esc(convTitle(c))}${c.unread ? `, ${c.unread} unread` : ''}">
    ${isCh ? `<span class="av chgroup" style="--h:250">${icon('hash')}</span>` : avatar(p, 40, { presence: state.settings.presence ? c.presence : null })}
    <div class="conv-main">
      <div class="conv-top"><span class="conv-name">${esc(convTitle(c))}</span><span class="conv-time">${timeAgo(last.t)}</span></div>
      <div class="conv-prev">${c.typing ? '<i class="typing"><i></i><i></i><i></i></i> typing…' : esc((last.me ? 'You: ' : (isCh ? person(last.from).name.split(' ')[0] + ': ' : '')) + last.body)}</div>
    </div>
    ${c.unread ? `<i class="conv-unread">${c.unread}</i>` : ''}
  </button>`);
  row.onclick = () => { state.ui.selChat = c.id; state.ui.chatThread = null; c.unread = 0; state.ui.mobileDetail = true; resetSearch(); bus.rerender(); bus.refreshChrome(); };
  return row;
}

// Highlight @mentions. Escape first, then wrap tokens. @you / @here / @channel read as "to me".
function mentionize(raw) {
  const selfish = new Set(['you', 'here', 'channel', 'everyone']);
  return esc(raw).replace(/(^|[\s(])@([\w.-]+)/g, (m, pre, name) =>
    `${pre}<span class="mention${selfish.has(name.toLowerCase()) ? ' me' : ''}">@${esc(name)}</span>`);
}

function drawMain(root) {
  const wrap = root.querySelector('#chat-main');
  const c = state.chats.find(x => x.id === state.ui.selChat);
  if (!c) { wrap.innerHTML = emptyState('chat', 'Select a conversation', 'Chat and mail are one object — kind=chat instead of kind=mail.'); return; }
  const isCh = c.type === 'channel';
  const g = isCh ? state.groups.find(x => x.id === c.group) : null;
  const p = isCh ? null : person(c.with);
  const pins = getPins(c);
  const members = isCh && g ? g.members.filter(m => !m.hidden).map(m => person(m.address)) : [];

  wrap.innerHTML = `
    <header class="chat-head">
      <button class="icon-btn mobile-back" id="chat-back" aria-label="Back to conversation list" title="Back">${icon('reply')}</button>
      ${isCh ? `<span class="av chgroup" style="--h:250;width:38px;height:38px">${icon('hash')}</span>` : avatar(p, 38, { presence: state.settings.presence ? c.presence : null, ring: true })}
      <div class="chat-head-main">
        <div class="chat-head-name">${esc(convTitle(c))} ${isCh ? '' : (p.trust === 'verified' ? trustPill('verified') : trustPill('tofu'))}</div>
        <div class="chat-head-sub mono">${isCh ? esc(g.address) + ' · ' + g.members.length + ' members · ' + g.mode : (state.settings.presence ? (c.presence === 'online' ? '<span class="pres-inline online"></span> online' : c.presence) : 'presence off') }</div>
      </div>
      <button class="pill ${isCh ? 'accent' : 'priv'} proto-pill" id="protopill" title="How this conversation is authenticated — click for details">${icon(isCh ? 'groups' : 'lock')} <span class="pp-label">${isCh ? 'MLS group · signed' : 'Deniable 1:1'}</span></button>
      <button class="icon-btn ${chatSearch.open ? 'on' : ''}" id="chatsearchbtn" title="Search this conversation" aria-label="Search this conversation" aria-pressed="${chatSearch.open}">${icon('search')}</button>
      ${members.length ? `<div class="chat-members">${members.slice(0, 4).map(m => avatar(m, 26, { ring: false })).join('')}${g.members.length > members.length ? `<span class="chat-more-m">+${g.members.length - members.length}</span>` : ''}</div>` : ''}
    </header>
    ${chatSearch.open ? `<div class="chat-search">${icon('search')}<input id="csearch" placeholder="Search in this conversation…" value="${esc(chatSearch.q)}" autocomplete="off" spellcheck="false" aria-label="Search in this conversation"><span class="chat-search-count" id="cscount"></span><div class="chat-search-nav"><button class="icon-btn sm" id="csprev" title="Previous match (Shift+Enter)" aria-label="Previous match">${icon('chevUp')}</button><button class="icon-btn sm" id="csnext" title="Next match (Enter)" aria-label="Next match">${icon('chevDown')}</button></div><button class="icon-btn sm" id="csclose" title="Close search" aria-label="Close search">${icon('x')}</button></div>` : ''}
    ${pins.length ? `<div class="pin-bar" id="pinbar">${icon('pin')} <b>${pins.length}</b> pinned · <span class="pin-prev">${esc(pins[0].body.slice(0, 60))}</span></div>` : ''}
    <div class="bubbles" id="bubbles"></div>
    ${c.typing ? `<div class="typing-row">${avatar(p || { name: '?', hue: 200 }, 22)}<span class="typing"><i></i><i></i><i></i></span></div>` : ''}
    <div class="chat-input">
      <button class="icon-btn ci-emoji" id="ciemoji" title="Emoji" aria-label="Insert emoji">${icon('smile')}</button>
      <input id="ci" placeholder="Message ${isCh ? '#' + esc(g.handle?.replace('@', '') || convTitle(c)) : esc(convTitle(c))} — sealed, kind=chat" autocomplete="off">
      <button class="btn primary" id="cs" aria-label="Send">${icon('send')}</button>
    </div>`;

  const b = wrap.querySelector('#bubbles');
  let lastDay = null;
  c.msgs.forEach((m, i) => {
    const dayKey = new Date(m.t).toDateString();
    if (dayKey !== lastDay) { b.appendChild(el(`<div class="day-div"><span>${esc(dayDivLabel(m.t))}</span></div>`)); lastDay = dayKey; }
    b.appendChild(bubble(c, m, i));
  });
  const inp = wrap.querySelector('#ci');
  const send = async () => {
    const v = inp.value.trim(); if (!v) return;
    c.msgs.push({ from: 'you', me: true, t: Date.now(), body: v, reactions: {} });
    await buildMote({ to: isCh ? g.address : person(c.with).address, kind: KIND.chat, body: v, tier: 'fast', group: g || null });
    inp.value = ''; bus.rerender();
    if (!isCh && Math.random() > 0.4) setTimeout(() => { c.typing = true; if (state.ui.selChat === c.id) bus.rerender();
      setTimeout(() => { c.typing = false; c.msgs.push({ from: c.with, me: false, t: Date.now(), body: pick(REPLIES), reactions: {} }); if (state.ui.selChat === c.id) bus.rerender(); }, 1400); }, 700);
  };
  wrap.querySelector('#chat-back').onclick = () => { state.ui.mobileDetail = false; bus.rerender(); };
  wrap.querySelector('#protopill').onclick = () => protocolModal(c, isCh, g);
  wrap.querySelector('#cs').onclick = send;
  inp.onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
  wrap.querySelector('#ciemoji').onclick = (e) => { e.stopPropagation(); emojiPanel(wrap.querySelector('#ciemoji'), (emo) => { inp.value += emo; inp.focus(); }); };
  wrap.querySelector('#pinbar')?.addEventListener('click', () => pinnedModal(c));

  // ---- in-conversation search: highlight matches in-place, ↵/⇧↵ to walk them ----
  const runSearch = () => {
    // clear prior marks, then re-highlight
    b.querySelectorAll('mark.hl').forEach(m => m.replaceWith(document.createTextNode(m.textContent)));
    b.querySelectorAll('.bubble').forEach(x => x.normalize());
    const q = chatSearch.q.trim().toLowerCase();
    const countEl = wrap.querySelector('#cscount');
    if (!q) { if (countEl) countEl.textContent = ''; return; }
    const marks = [];
    b.querySelectorAll('.bubble').forEach(bub => {
      const nodes = []; const w = document.createTreeWalker(bub, NodeFilter.SHOW_TEXT);
      let n; while ((n = w.nextNode())) nodes.push(n);
      nodes.forEach(node => {
        const text = node.nodeValue, lower = text.toLowerCase();
        if (!lower.includes(q)) return;
        const frag = document.createDocumentFragment(); let i = 0, pos;
        while ((pos = lower.indexOf(q, i)) !== -1) {
          if (pos > i) frag.appendChild(document.createTextNode(text.slice(i, pos)));
          const mk = document.createElement('mark'); mk.className = 'hl'; mk.textContent = text.slice(pos, pos + q.length);
          frag.appendChild(mk); marks.push(mk); i = pos + q.length;
        }
        if (i < text.length) frag.appendChild(document.createTextNode(text.slice(i)));
        node.replaceWith(frag);
      });
    });
    if (!marks.length) { if (countEl) countEl.textContent = 'no matches'; return; }
    const cur = ((chatSearch.idx % marks.length) + marks.length) % marks.length;
    chatSearch.idx = cur;
    marks[cur].classList.add('cur');
    marks[cur].scrollIntoView({ block: 'center', behavior: 'auto' });
    if (countEl) countEl.textContent = `${cur + 1} / ${marks.length}`;
  };
  wrap.querySelector('#chatsearchbtn').onclick = () => { chatSearch.open = !chatSearch.open; if (!chatSearch.open) chatSearch.q = ''; bus.rerender(); };
  const searchInput = wrap.querySelector('#csearch');
  if (searchInput) {
    searchInput.oninput = () => { chatSearch.q = searchInput.value; chatSearch.idx = 0; runSearch(); };
    searchInput.onkeydown = (e) => {
      if (e.key === 'Enter') { e.preventDefault(); chatSearch.idx += e.shiftKey ? -1 : 1; runSearch(); }
      else if (e.key === 'Escape') { e.preventDefault(); chatSearch.open = false; chatSearch.q = ''; bus.rerender(); }
    };
    wrap.querySelector('#csnext').onclick = () => { chatSearch.idx += 1; runSearch(); searchInput.focus(); };
    wrap.querySelector('#csprev').onclick = () => { chatSearch.idx -= 1; runSearch(); searchInput.focus(); };
    wrap.querySelector('#csclose').onclick = () => { chatSearch.open = false; chatSearch.q = ''; bus.rerender(); };
  }

  // thread side panel
  if (state.ui.chatThread && state.ui.chatThread.cid === c.id) drawThread(wrap, c, state.ui.chatThread.idx);
  else wrap.querySelector('.chat-thread')?.remove();

  // On a search, keep the current match centered; otherwise rest at the newest message.
  if (chatSearch.open && chatSearch.q.trim()) runSearch();
  else b.scrollTop = b.scrollHeight;
  setTimeout(() => wrap.querySelector(chatSearch.open ? '#csearch' : '#ci')?.focus(), 30);
}

function dayDivLabel(t) {
  const d = new Date(t), today = new Date();
  const diff = Math.round((today.setHours(0,0,0,0) - new Date(t).setHours(0,0,0,0)) / 86400e3);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return fmtDay(t);
}

function bubble(c, m, i) {
  const p = m.me ? { name: 'You', hue: 220 } : person(m.from);
  const reacts = Object.entries(m.reactions || {}).filter(([, n]) => n > 0);
  const node = el(`<div class="brow ${m.me ? 'me' : 'them'}" data-idx="${i}">
    ${!m.me ? avatar(p, 26) : ''}
    <div class="bwrap">
      ${!m.me && c.type === 'channel' ? `<div class="bname">${esc(p.name)}</div>` : ''}
      <div class="bubble">${m.pinned ? `<i class="bpin" title="Pinned">${icon('pin')}</i>` : ''}${mentionize(m.body)}
        <div class="bactions">
          <button class="ba" data-act="react" title="React">${icon('smile')}</button>
          <button class="ba" data-act="thread" title="Reply in thread">${icon('reply')}</button>
          <button class="ba" data-act="pin" title="${m.pinned ? 'Unpin' : 'Pin'}">${icon('pin')}</button>
        </div>
      </div>
      ${m.thread?.length ? `<button class="bthread" data-act="open-thread">${icon('reply')} ${m.thread.length} ${m.thread.length === 1 ? 'reply' : 'replies'} · ${[...new Set(m.thread.map(r => esc(person(r.from).name.split(' ')[0])))].join(', ')}</button>` : ''}
      ${reacts.length ? `<div class="reacts">${reacts.map(([e, n]) => `<button class="rct" data-emo="${e}">${e} ${n}</button>`).join('')}<button class="rct add" data-act="react">${icon('smile')}</button></div>` : ''}
      <div class="btime">${fmtClock(m.t)}${m.edited ? ' · edited' : ''}</div>
    </div>
  </div>`);
  node.querySelectorAll('[data-act]').forEach(btn => btn.onclick = (ev) => {
    ev.stopPropagation();
    const act = btn.dataset.act;
    if (act === 'react') reactPicker(btn, m);
    else if (act === 'thread' || act === 'open-thread') { state.ui.chatThread = { cid: c.id, idx: i }; if (!m.thread) m.thread = []; bus.rerender(); }
    else if (act === 'pin') { m.pinned = !m.pinned; toast(m.pinned ? `${icon('pin')} Pinned to conversation` : 'Unpinned'); bus.rerender(); }
  });
  node.querySelectorAll('.rct[data-emo]').forEach(chip => chip.onclick = (ev) => { ev.stopPropagation(); const e = chip.dataset.emo; m.reactions[e] = (m.reactions[e] || 0) + 1; bus.rerender(); });
  return node;
}

function drawThread(wrap, c, idx) {
  const m = c.msgs[idx]; if (!m) { state.ui.chatThread = null; return; }
  const p = m.me ? { name: 'You', hue: 220 } : person(m.from);
  wrap.querySelector('.chat-thread')?.remove();
  const panel = el(`<aside class="chat-thread">
    <header class="thread-head"><b>${icon('reply')} Thread</b><button class="icon-btn sm" id="thclose" aria-label="Close thread">${icon('x')}</button></header>
    <div class="thread-scroll" id="thscroll">
      <div class="thread-parent">
        <div class="brow them"><div class="bwrap"><div class="bname">${esc(p.name)}</div><div class="bubble">${mentionize(m.body)}</div><div class="btime">${fmtClock(m.t)}</div></div></div>
      </div>
      <div class="thread-count">${(m.thread || []).length} ${(m.thread || []).length === 1 ? 'reply' : 'replies'}</div>
      <div class="thread-replies" id="threplies"></div>
    </div>
    <div class="chat-input thread-input">
      <input id="thi" placeholder="Reply in thread…" autocomplete="off">
      <button class="btn primary" id="ths" aria-label="Send reply">${icon('send')}</button>
    </div>
  </aside>`);
  const rep = panel.querySelector('#threplies');
  (m.thread || []).forEach(r => {
    const rp = r.me ? { name: 'You', hue: 220 } : person(r.from);
    rep.appendChild(el(`<div class="brow them"><div class="bwrap"><div class="bname">${esc(rp.name)}</div><div class="bubble">${mentionize(r.body)}</div><div class="btime">${fmtClock(r.t)}</div></div></div>`));
  });
  wrap.appendChild(panel);
  panel.querySelector('#thclose').onclick = () => { state.ui.chatThread = null; bus.rerender(); };
  const thi = panel.querySelector('#thi');
  const sendReply = () => {
    const v = thi.value.trim(); if (!v) return;
    m.thread = m.thread || []; m.thread.push({ from: 'you', me: true, t: Date.now(), body: v });
    bus.rerender();
  };
  panel.querySelector('#ths').onclick = sendReply;
  thi.onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendReply(); } };
  panel.querySelector('#thscroll').scrollTop = 9999;
  setTimeout(() => thi.focus(), 30);
}

function reactPicker(anchor, m) { emojiPanel(anchor, (e) => { m.reactions = m.reactions || {}; m.reactions[e] = (m.reactions[e] || 0) + 1; bus.rerender(); }); }

// ---- Deniable 1:1 vs MLS group — which cryptographic mode this conversation uses ----------
// Two DISTINCT pairwise substrates, never mixed (spec §5.2.1 vs §5.3/§5.8): a DM is a separate
// Double-Ratchet channel authenticated by a shared-key MAC (deniable — either party could have
// produced any message); a channel is an MLS group where every message carries the sender's
// signature (efficient at group scale, but the signature is non-repudiable). The badge in the
// chat header always tells you honestly which one you're in.
function protocolModal(c, isCh, g) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon(isCh ? 'groups' : 'lock')} ${isCh ? 'MLS group messaging' : 'Deniable 1:1 messaging'}</h2><button class="icon-btn" id="pmx">${icon('x')}</button></div>
    ${isCh ? `
    <p class="modal-note">${icon('info')} <b>${esc(g?.name || convTitle(c))}</b> is a group conversation: every member's client holds the shared MLS group state (spec §5.3, §5.8), and every message is <b>signed</b> by its sender's key. That signature is what lets a group scale efficiently with a provable, ordered history — but it also means a member could prove authorship to someone outside the group. Efficiency and group-scale forward secrecy, traded for deniability.</p>
    <div class="gw-attest">
      <div class="gw-attest-row"><span class="k">authentication</span><span class="v">Ed25519 signature per message</span></div>
      <div class="gw-attest-row"><span class="k">deniability</span><span class="v">none — signatures are non-repudiable</span></div>
      <div class="gw-attest-row"><span class="k">scales to</span><span class="v">any group size (tree-based key schedule)</span></div>
    </div>` : `
    <p class="modal-note">${icon('info')} This DM runs on a separate pairwise channel (spec §5.2.1) — X3DH key agreement into a Double Ratchet, the same design Signal popularized. Every message is authenticated only by a <b>shared-key MAC</b>, never a signature: either of you holds the key material to have produced any message, so neither can prove to a third party who sent what. Forward secrecy <i>and</i> deniability — traded for group scale; this mode is pairwise-only and is never used for groups.</p>
    <div class="gw-attest">
      <div class="gw-attest-row"><span class="k">authentication</span><span class="v">shared-key MAC (Double Ratchet)</span></div>
      <div class="gw-attest-row"><span class="k">deniability</span><span class="v teal">offline-deniable — no signature ties a message to you</span></div>
      <div class="gw-attest-row"><span class="k">scales to</span><span class="v">pairwise (1:1) only</span></div>
    </div>`}
    <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} real design, structural in this browser demo — the actual ratchet/MLS session runs in the Rust core (dmtap-deniable / dmtap-mls crates)</span></div>
  </div>`, { wide: true });
  card.querySelector('#pmx').onclick = closeModal;
}

// Pinned messages — reorderable (drag the grip, or the ↑/↓ controls). The top pin shows in the bar.
function pinnedModal(c) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('pin')} Pinned messages</h2><button class="icon-btn" id="px">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} Drag the grip or use the arrows to reorder — the top pin is the one shown in the conversation's pinned bar.</p>
    <div class="pin-list" id="pinlist"></div>
  </div>`, { wide: true });
  card.querySelector('#px').onclick = closeModal;
  const listEl = card.querySelector('#pinlist');
  const draw = () => {
    const pins = getPins(c);
    if (!pins.length) { listEl.innerHTML = '<div class="id-empty-inline">Nothing pinned. Hover a message and pin it.</div>'; return; }
    listEl.innerHTML = pins.map((m, i) => `<div class="pin-item" draggable="true" data-i="${i}">
      <div class="pin-grip" title="Drag to reorder">${icon('grip')}</div>
      <div class="pin-item-main"><div class="pin-who">${esc(m.me ? 'You' : person(m.from).name)} · ${fmtClock(m.t)}</div><div class="pin-body">${mentionize(m.body)}</div></div>
      <div class="pin-reorder">
        <button class="icon-btn sm" data-up="${i}" title="Move up" aria-label="Move up" ${i === 0 ? 'disabled' : ''}>${icon('chevUp')}</button>
        <button class="icon-btn sm" data-down="${i}" title="Move down" aria-label="Move down" ${i === pins.length - 1 ? 'disabled' : ''}>${icon('chevDown')}</button>
      </div>
      <button class="icon-btn sm pin-unpin" data-unpin="${i}" title="Unpin" aria-label="Unpin">${icon('x')}</button>
    </div>`).join('');
    const arr = c._pinOrder;
    const move = (from, to) => { if (to < 0 || to >= arr.length) return; const [x] = arr.splice(from, 1); arr.splice(to, 0, x); draw(); bus.rerender(); };
    listEl.querySelectorAll('[data-up]').forEach(b => b.onclick = () => move(+b.dataset.up, +b.dataset.up - 1));
    listEl.querySelectorAll('[data-down]').forEach(b => b.onclick = () => move(+b.dataset.down, +b.dataset.down + 1));
    listEl.querySelectorAll('[data-unpin]').forEach(b => b.onclick = () => { arr[+b.dataset.unpin].pinned = false; draw(); bus.rerender(); });
    // HTML5 drag-to-reorder
    let dragI = null;
    listEl.querySelectorAll('.pin-item').forEach(item => {
      item.addEventListener('dragstart', () => { dragI = +item.dataset.i; item.classList.add('dragging'); });
      item.addEventListener('dragend', () => { dragI = null; item.classList.remove('dragging'); listEl.querySelectorAll('.drop-target').forEach(x => x.classList.remove('drop-target')); });
      item.addEventListener('dragover', (e) => { e.preventDefault(); if (dragI === null) return; listEl.querySelectorAll('.drop-target').forEach(x => x.classList.remove('drop-target')); item.classList.add('drop-target'); });
      item.addEventListener('drop', (e) => { e.preventDefault(); const to = +item.dataset.i; if (dragI === null || dragI === to) return; move(dragI, to); });
    });
  };
  draw();
}
