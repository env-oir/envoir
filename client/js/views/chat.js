// views/chat.js — real-time chat over the SAME MOTE substrate (kind=chat, fast tier).
// DMs + channels (channels are GROUPS with addresses, spec §5.8), reactions, threaded replies,
// and opt-in typing/presence — labeled metadata-sensitive because presence leaks who's online.

import { state } from '../store.js';
import { person } from '../seed.js';
import { el, esc, icon, avatar, timeAgo, fmtClock, emptyState, trustPill } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { bus } from '../bus.js';

const REACTIONS = ['👍', '🔥', '💯', '✨', '👀', '🙏'];

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
  list.forEach(c => {
    const last = c.msgs[c.msgs.length - 1];
    const isCh = c.type === 'channel';
    const p = isCh ? { name: convTitle(c), hue: 250, trust: 'verified' } : person(c.with);
    const sel = state.ui.selChat === c.id;
    const row = el(`<button class="conv ${sel ? 'sel' : ''}" data-id="${c.id}"${sel ? ' aria-current="true"' : ''} aria-label="${esc(convTitle(c))}${c.unread ? `, ${c.unread} unread` : ''}">
      ${isCh ? `<span class="av chgroup" style="--h:250">${icon('groups')}</span>` : avatar(p, 40, { presence: state.settings.presence ? c.presence : null })}
      <div class="conv-main">
        <div class="conv-top"><span class="conv-name">${esc(convTitle(c))}</span><span class="conv-time">${timeAgo(last.t)}</span></div>
        <div class="conv-prev">${c.typing ? '<i class="typing"><i></i><i></i><i></i></i> typing…' : esc((last.me ? 'You: ' : '') + last.body)}</div>
      </div>
      ${c.unread ? `<i class="conv-unread">${c.unread}</i>` : ''}
    </button>`);
    row.onclick = () => { state.ui.selChat = c.id; c.unread = 0; state.ui.mobileDetail = true; bus.rerender(); bus.refreshChrome(); };
    wrap.appendChild(row);
  });
}

function drawMain(root) {
  const wrap = root.querySelector('#chat-main');
  const c = state.chats.find(x => x.id === state.ui.selChat);
  if (!c) { wrap.innerHTML = emptyState('chat', 'Select a conversation', 'Chat and mail are one object — kind=chat instead of kind=mail.'); return; }
  const isCh = c.type === 'channel';
  const g = isCh ? state.groups.find(x => x.id === c.group) : null;
  const p = isCh ? null : person(c.with);

  wrap.innerHTML = `
    <header class="chat-head">
      <button class="icon-btn mobile-back" id="chat-back" aria-label="Back to conversation list" title="Back">${icon('reply')}</button>
      ${isCh ? `<span class="av chgroup" style="--h:250;width:38px;height:38px">${icon('groups')}</span>` : avatar(p, 38, { presence: state.settings.presence ? c.presence : null, ring: true })}
      <div class="chat-head-main">
        <div class="chat-head-name">${esc(convTitle(c))} ${isCh ? '' : (p.trust === 'verified' ? trustPill('verified') : trustPill('tofu'))}</div>
        <div class="chat-head-sub mono">${isCh ? esc(g.address) + ' · ' + g.members.length + ' members · ' + g.mode : (state.settings.presence ? (c.presence === 'online' ? '● online' : c.presence) : 'presence off') }</div>
      </div>
      ${isCh ? `<span class="pill accent">${icon('groups')} channel</span>` : ''}
    </header>
    <div class="bubbles" id="bubbles"></div>
    ${c.typing ? `<div class="typing-row">${avatar(p || { name: '?', hue: 200 }, 22)}<span class="typing"><i></i><i></i><i></i></span></div>` : ''}
    <div class="chat-input">
      <input id="ci" placeholder="Message ${esc(convTitle(c))} — sealed, kind=chat" autocomplete="off">
      <button class="btn primary" id="cs">${icon('send')}</button>
    </div>`;

  const b = wrap.querySelector('#bubbles');
  c.msgs.forEach((m, i) => b.appendChild(bubble(c, m, i)));
  b.scrollTop = b.scrollHeight;

  const send = async () => {
    const inp = wrap.querySelector('#ci'); const v = inp.value.trim(); if (!v) return;
    c.msgs.push({ from: 'you', me: true, t: Date.now(), body: v, reactions: {} });
    const mote = await buildMote({ to: isCh ? g.address : person(c.with).address, kind: KIND.chat, body: v, tier: 'fast', group: g || null });
    inp.value = ''; bus.rerender();
    // simulate a reply on DMs
    if (!isCh && Math.random() > 0.4) setTimeout(() => { c.typing = true; bus.rerender();
      setTimeout(() => { c.typing = false; c.msgs.push({ from: c.with, me: false, t: Date.now(), body: pick(REPLIES), reactions: {} }); if (state.ui.selChat === c.id) bus.rerender(); }, 1400); }, 700);
  };
  wrap.querySelector('#chat-back').onclick = () => { state.ui.mobileDetail = false; bus.rerender(); };
  wrap.querySelector('#cs').onclick = send;
  wrap.querySelector('#ci').onkeydown = e => { if (e.key === 'Enter') send(); };
  setTimeout(() => wrap.querySelector('#ci')?.focus(), 30);
}

const REPLIES = ['makes sense 👍', 'on it', 'love that', 'let\'s ship it', 'agreed', 'looking now ✨'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

function bubble(c, m, i) {
  const p = m.me ? { name: 'You', hue: 220 } : person(m.from);
  const reacts = Object.entries(m.reactions || {}).filter(([, n]) => n > 0);
  const node = el(`<div class="brow ${m.me ? 'me' : 'them'}">
    ${!m.me ? avatar(p, 26) : ''}
    <div class="bwrap">
      ${!m.me && c.type === 'channel' ? `<div class="bname">${esc(p.name)}</div>` : ''}
      <div class="bubble">${esc(m.body)}
        <button class="react-btn" title="React">🙂</button>
      </div>
      ${m.thread?.length ? `<div class="bthread">${icon('reply')} ${m.thread.length} replies · ${m.thread.map(r => esc(person(r.from).name.split(' ')[0])).join(', ')}</div>` : ''}
      ${reacts.length ? `<div class="reacts">${reacts.map(([e, n]) => `<span class="rct">${e} ${n}</span>`).join('')}</div>` : ''}
      <div class="btime">${fmtClock(m.t)}</div>
    </div>
  </div>`);
  node.querySelector('.react-btn').onclick = (ev) => { ev.stopPropagation(); reactPicker(node.querySelector('.react-btn'), m); };
  return node;
}

function reactPicker(anchor, m) {
  document.querySelector('.react-pop')?.remove();
  const r = anchor.getBoundingClientRect();
  const pop = el(`<div class="react-pop" style="top:${r.top - 44}px;left:${Math.min(r.left, innerWidth - 200)}px">${REACTIONS.map(e => `<button data-e="${e}">${e}</button>`).join('')}</div>`);
  document.body.appendChild(pop);
  REACTIONS.forEach(e => pop.querySelector(`[data-e="${e}"]`).onclick = () => { m.reactions = m.reactions || {}; m.reactions[e] = (m.reactions[e] || 0) + 1; pop.remove(); bus.rerender(); });
  setTimeout(() => document.addEventListener('click', function h(ev) { if (!pop.contains(ev.target)) { pop.remove(); document.removeEventListener('click', h); } }), 0);
}
