// views/chat.js — real-time chat over the SAME MOTE substrate (kind=chat, fast tier).
// DMs + channels (channels are GROUPS with addresses, spec §5.8). Slack-grade surface:
// threaded replies in a side panel, hover message actions, reactions/emoji, @mentions,
// pinned messages, day dividers, typing/presence (opt-in, labelled metadata-sensitive).

import { state } from '../store.js';
import { person, PEOPLE } from '../seed.js';
import { el, esc, icon, avatar, timeAgo, fmtClock, fmtDay, emptyState, trustPill, toast, openModal, closeModal } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { bus } from '../bus.js';

const REACTIONS = ['👍', '🔥', '💯', '✨', '👀', '🙏', '❤️', '😂', '🎉', '👏'];
const REPLIES = ['makes sense 👍', 'on it', 'love that', 'let\'s ship it', 'agreed', 'looking now ✨'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

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
  row.onclick = () => { state.ui.selChat = c.id; state.ui.chatThread = null; c.unread = 0; state.ui.mobileDetail = true; bus.rerender(); bus.refreshChrome(); };
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
  const pinned = c.msgs.filter(m => m.pinned);
  const members = isCh && g ? g.members.filter(m => !m.hidden).map(m => person(m.address)) : [];

  wrap.innerHTML = `
    <header class="chat-head">
      <button class="icon-btn mobile-back" id="chat-back" aria-label="Back to conversation list" title="Back">${icon('reply')}</button>
      ${isCh ? `<span class="av chgroup" style="--h:250;width:38px;height:38px">${icon('hash')}</span>` : avatar(p, 38, { presence: state.settings.presence ? c.presence : null, ring: true })}
      <div class="chat-head-main">
        <div class="chat-head-name">${esc(convTitle(c))} ${isCh ? '' : (p.trust === 'verified' ? trustPill('verified') : trustPill('tofu'))}</div>
        <div class="chat-head-sub mono">${isCh ? esc(g.address) + ' · ' + g.members.length + ' members · ' + g.mode : (state.settings.presence ? (c.presence === 'online' ? '<span class="pres-inline online"></span> online' : c.presence) : 'presence off') }</div>
      </div>
      ${members.length ? `<div class="chat-members">${members.slice(0, 4).map(m => avatar(m, 26, { ring: false })).join('')}${g.members.length > members.length ? `<span class="chat-more-m">+${g.members.length - members.length}</span>` : ''}</div>` : ''}
    </header>
    ${pinned.length ? `<div class="pin-bar" id="pinbar">${icon('pin')} <b>${pinned.length}</b> pinned · <span class="pin-prev">${esc(pinned[pinned.length - 1].body.slice(0, 60))}</span></div>` : ''}
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
  b.scrollTop = b.scrollHeight;

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
  wrap.querySelector('#cs').onclick = send;
  inp.onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
  wrap.querySelector('#ciemoji').onclick = (e) => { e.stopPropagation(); emojiPicker(wrap.querySelector('#ciemoji'), (emo) => { inp.value += emo; inp.focus(); }); };
  wrap.querySelector('#pinbar')?.addEventListener('click', () => pinnedModal(c));

  // thread side panel
  if (state.ui.chatThread && state.ui.chatThread.cid === c.id) drawThread(wrap, c, state.ui.chatThread.idx);
  else wrap.querySelector('.chat-thread')?.remove();

  setTimeout(() => wrap.querySelector('#ci')?.focus(), 30);
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

function reactPicker(anchor, m) { emojiPicker(anchor, (e) => { m.reactions = m.reactions || {}; m.reactions[e] = (m.reactions[e] || 0) + 1; bus.rerender(); }); }

function emojiPicker(anchor, onPick) {
  document.querySelector('.react-pop')?.remove();
  const r = anchor.getBoundingClientRect();
  const top = Math.max(8, r.top - 52);
  const pop = el(`<div class="react-pop" style="top:${top}px;left:${Math.min(r.left, innerWidth - 320)}px">${REACTIONS.map(e => `<button data-e="${e}">${e}</button>`).join('')}</div>`);
  document.body.appendChild(pop);
  REACTIONS.forEach(e => pop.querySelector(`[data-e="${e}"]`).onclick = () => { pop.remove(); onPick(e); });
  setTimeout(() => document.addEventListener('click', function h(ev) { if (!pop.contains(ev.target)) { pop.remove(); document.removeEventListener('click', h); } }), 0);
}

function pinnedModal(c) {
  const pinned = c.msgs.filter(m => m.pinned);
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('pin')} Pinned messages</h2><button class="icon-btn" id="px">${icon('x')}</button></div>
    <div class="pin-list">${pinned.map(m => `<div class="pin-item"><div class="pin-who">${esc((m.me ? 'You' : person(m.from).name))} · ${fmtClock(m.t)}</div><div class="pin-body">${mentionize(m.body)}</div></div>`).join('') || '<div class="id-empty-inline">Nothing pinned.</div>'}</div>
  </div>`, { wide: true });
  card.querySelector('#px').onclick = closeModal;
}
