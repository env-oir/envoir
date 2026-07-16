// ui.js — rendering primitives. Pure DOM, no framework. Icons are inline SVG (no external
// assets). Avatars are deterministic gradients. Includes the MOTE inspector (spec §2.1) and
// the safety-number visuals (spec §3.4 verification).

import { fmtBytes } from './seed.js';

export const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
export const esc = (s) => (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export const timeAgo = (t) => {
  const s = (Date.now() - t) / 1000;
  if (s < 45) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  if (s < 7 * 86400) return Math.floor(s / 86400) + 'd';
  return new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
};
export const fmtClock = (t) => new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
export const fmtDay = (t) => new Date(t).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
export const fmtLong = (t) => new Date(t).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }) + ' · ' + fmtClock(t);

// ---- Icon set (stroke SVGs) --------------------------------------------------------------
const P = {
  inbox: '<path d="M4 13l2.5-8h11L20 13v6H4z"/><path d="M4 13h4l1.5 3h5l1.5-3h4"/>',
  star: '<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17.8 6.6 20l1-6.1L3.2 9.5l6.1-.9z"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/>',
  send: '<path d="M21 3L3 10.5l7 2.5 2.5 7z"/><path d="M21 3l-9 11"/>',
  edit: '<path d="M4 20h4l10-10-4-4L4 16z"/><path d="M14 6l4 4"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v10h14V9"/><path d="M10 13h4"/>',
  shield: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/>',
  trash: '<path d="M5 7h14"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M4 7l8 6 8-6"/>',
  chat: '<path d="M4 5h16v11H9l-5 4z"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2.5"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  contacts: '<circle cx="12" cy="9" r="4"/><path d="M4 20c0-3.5 3.6-5.5 8-5.5s8 2 8 5.5"/>',
  files: '<path d="M4 5h5l2 2h9v12H4z"/>',
  groups: '<circle cx="9" cy="9" r="3.2"/><circle cx="17" cy="10" r="2.4"/><path d="M3 20c0-3 2.7-4.8 6-4.8s6 1.8 6 4.8"/><path d="M15.5 20c0-2.2 1.4-3.6 3.2-3.6 1.3 0 2.5.7 3.1 1.9"/>',
  settings: '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4-4"/>',
  reply: '<path d="M10 8L4 12l6 4"/><path d="M4 12h9c4 0 7 2 7 6"/>',
  forward: '<path d="M14 8l6 4-6 4"/><path d="M20 12h-9c-4 0-7 2-7 6"/>',
  snooze: '<circle cx="12" cy="13" r="7"/><path d="M12 9v4l3 2M9 3h6M5 5l2-1M19 5l-2-1"/>',
  label: '<path d="M3 6a2 2 0 012-2h8l7 8-7 8H5a2 2 0 01-2-2z"/><circle cx="8" cy="12" r="1.4"/>',
  more: '<circle cx="6" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  verified: '<path d="M12 3l2 1.6 2.5-.4 1 2.4 2.4 1-.4 2.5L22 15l-1.6 2 .4 2.5-2.4 1-1 2.4-2.5-.4L12 21l-2-1.6-2.5.4-1-2.4-2.4-1 .4-2.5L2 15l1.6-2-.4-2.5 2.4-1 1-2.4 2.5.4z"/><path d="M8.5 12l2.2 2.2L15.5 9.5" stroke-width="1.6"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 12l8-8M17 6l2 2M15 8l2 2"/>',
  moon: '<path d="M20 14a8 8 0 11-9-9 6.5 6.5 0 009 9z"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.5 4.5l1.8 1.8M17.7 17.7l1.8 1.8M19.5 4.5l-1.8 1.8M6.3 17.7l-1.8 1.8"/>',
  command: '<path d="M9 6a3 3 0 10-3 3h12a3 3 0 10-3-3v12a3 3 0 103-3H6a3 3 0 10-3 3z"/>',
  network: '<circle cx="12" cy="12" r="2.6"/><circle cx="5" cy="6" r="1.8"/><circle cx="19" cy="6" r="1.8"/><circle cx="5" cy="18" r="1.8"/><circle cx="19" cy="18" r="1.8"/><path d="M6.5 7l3.5 3.5m4 0L17.5 7m0 10L14 13.5m-4 0L6.5 17"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  export: '<path d="M12 3v11M8 7l4-4 4 4"/><path d="M5 15v4h14v-4"/>',
  import: '<path d="M12 14V3M8 10l4 4 4-4"/><path d="M5 15v4h14v-4"/>',
  bell: '<path d="M6 9a6 6 0 1112 0c0 6 2 7 2 7H4s2-1 2-7z"/><path d="M10 20a2 2 0 004 0"/>',
  repeat: '<path d="M4 9a5 5 0 015-5h8l-2-2m2 2l-2 2"/><path d="M20 15a5 5 0 01-5 5H7l2 2m-2-2l2-2"/>',
  laptop: '<rect x="4" y="5" width="16" height="11" rx="1.6"/><path d="M2 20h20M9.5 20l.5-2h4l.5 2"/>',
  phone: '<rect x="7" y="3" width="10" height="18" rx="2.4"/><path d="M11 18h2"/>',
  tablet: '<rect x="5" y="3" width="14" height="18" rx="2.2"/><path d="M11 18h2"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1.8"/><rect x="3" y="13" width="18" height="7" rx="1.8"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  rotate: '<path d="M20 11a8 8 0 10-2.3 5.7"/><path d="M20 5v5h-5"/>',
  link: '<path d="M9 15l6-6"/><path d="M11 6l1-1a4 4 0 016 6l-1 1"/><path d="M13 18l-1 1a4 4 0 01-6-6l1-1"/>',
  signout: '<path d="M14 4h4a1 1 0 011 1v14a1 1 0 01-1 1h-4"/><path d="M10 12H3m0 0l3.5-3.5M3 12l3.5 3.5"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.4 2.5 14.6 0 17M12 3.5c-2.5 2.4-2.5 14.6 0 17"/>',
  fingerprint: '<path d="M8 11a4 4 0 018 0v2"/><path d="M6 12a6 6 0 0112 0v1c0 1.5-.2 3-.6 4"/><path d="M12 12v3c0 1.2-.2 2.4-.6 3.5"/><path d="M9 14v1a7 7 0 01-1 3.5"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h8"/>',
  pin: '<path d="M9 4h6l-1 6 3 3v2H7v-2l3-3z"/><path d="M12 15v5"/>',
  smile: '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 14a4 4 0 007 0"/><path d="M9 9.5h.01M15 9.5h.01"/>',
  at: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 006 0c0-5-4-9-10-9a10 10 0 100 20c2 0 4-.6 5.5-1.6"/>',
  bolt: '<path d="M13 3L5 14h5l-1 7 8-11h-5z"/>',
  grid: '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
  rows: '<rect x="4" y="5" width="16" height="4.5" rx="1.4"/><rect x="4" y="14.5" width="16" height="4.5" rx="1.4"/>',
  download: '<path d="M12 3v12M8 11l4 4 4-4"/><path d="M5 19h14"/>',
  share: '<circle cx="6" cy="12" r="2.4"/><circle cx="17" cy="6" r="2.4"/><circle cx="17" cy="18" r="2.4"/><path d="M8.2 11l6.6-3.6M8.2 13l6.6 3.6"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
  hash: '<path d="M9 4L7 20M17 4l-2 16M4 9h16M3 15h16"/>',
  chevUp: '<path d="M6 15l6-6 6 6"/>',
  chevDown: '<path d="M6 9l6 6 6-6"/>',
  grip: '<path d="M9 5.5v.01M9 12v.01M9 18.5v.01M15 5.5v.01M15 12v.01M15 18.5v.01" stroke-width="2.4"/>',
  rows2: '<rect x="4" y="4" width="16" height="3.2" rx="1.1"/><rect x="4" y="10.4" width="16" height="3.2" rx="1.1"/><rect x="4" y="16.8" width="16" height="3.2" rx="1.1"/>',
  density: '<path d="M4 5h16M4 9h16M4 13h16M4 17h16"/>',
  pdf: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 13h1.2a1.3 1.3 0 010 2.6H9zm0 0v4"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2.4"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M4 18l5-5 3.5 3.5L16 12l4 4"/>',
};
export function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

// ---- Envoir brand mark (inline SVG, from brand/logo-mark.svg) -----------------------------
export function brandMark(size = 28) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 128 128" fill="none" aria-label="Envoir">
    <defs><linearGradient id="em-${size}" x1="16" y1="12" x2="112" y2="116" gradientUnits="userSpaceOnUse"><stop stop-color="#4C4DFF"/><stop offset="1" stop-color="#9A4DFF"/></linearGradient></defs>
    <rect x="8" y="8" width="112" height="112" rx="30" fill="url(#em-${size})"/>
    <rect x="30" y="40" width="68" height="48" rx="9" fill="none" stroke="#fff" stroke-width="5"/>
    <path d="M33 45 L64 68 L95 45" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="33" cy="45" r="6" fill="#fff"/><circle cx="95" cy="45" r="6" fill="#fff"/><circle cx="64" cy="68" r="7" fill="#fff"/>
    <path d="M33 45 L95 45" stroke="#fff" stroke-width="2.5" stroke-opacity="0.45" stroke-dasharray="3 5"/>
  </svg>`;
}

// ---- Avatars: deterministic gradient + initials -----------------------------------------
export function initials(name) {
  const parts = (name || '?').replace(/^@/, '').split(/[\s.@]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0] || '?').slice(0, 2).toUpperCase();
}
export function avatar(p, size = 34, opts = {}) {
  const hue = p.hue ?? 220;
  const ring = opts.ring && p.trust === 'verified' ? ' ring' : '';
  const dot = opts.presence ? `<span class="pres ${opts.presence}"></span>` : '';
  return `<span class="av${ring}" style="--h:${hue};width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px" title="${esc(p.name)}">${esc(initials(p.name))}${p.trust === 'verified' && opts.badge ? verifiedGlyph() : ''}${dot}</span>`;
}
export function verifiedGlyph() { return `<span class="vglyph">${icon('verified')}</span>`; }

export function trustPill(trust) {
  const map = {
    verified: `<span class="pill good">${icon('verified')} verified</span>`,
    tofu: `<span class="pill dim">${icon('lock')} pinned</span>`,
    unverified: `<span class="pill warn">unverified</span>`,
    legacy: `<span class="pill legacy">legacy</span>`,
  };
  return map[trust] || '';
}

// ---- Toast --------------------------------------------------------------------------------
export function toast(msg, opts = {}) {
  const t = document.getElementById('toast');
  const ms = opts.ms || 2800;
  t.setAttribute('role', 'status');
  t.setAttribute('aria-live', 'polite');
  t.innerHTML = `<span>${msg}</span>${opts.action ? `<button class="toast-act">${esc(opts.action)}</button>` : ''}`;
  t.classList.remove('hidden'); t.classList.add('show');
  clearTimeout(t._h);
  if (opts.action && opts.onAction) t.querySelector('.toast-act').onclick = () => { clearTimeout(t._h); t.classList.remove('show'); opts.onAction(); };
  t._h = setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 200); }, ms);
  return t;
}

// ---- Modal --------------------------------------------------------------------------------
// Accessible dialog: role=dialog + aria-modal, a Tab focus-trap, initial focus onto the first
// control, and focus restoration to whatever was focused before it opened.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
let _modalReturnFocus = null;
let _modalTrap = null;

export function openModal(html, opts = {}) {
  const m = document.getElementById('modal');
  _modalReturnFocus = document.activeElement;
  const labelAttr = opts.label ? ` aria-label="${esc(opts.label)}"` : '';
  m.innerHTML = `<div class="modal-scrim"></div><div class="modal-card ${opts.wide ? 'wide' : ''} ${opts.compose ? 'compose-card' : ''}" role="dialog" aria-modal="true"${labelAttr}>${html}</div>`;
  m.classList.remove('hidden');
  requestAnimationFrame(() => m.classList.add('show'));
  const card = m.querySelector('.modal-card');
  m.querySelector('.modal-scrim').onclick = () => { if (!opts.sticky) closeModal(); };

  // Focus trap — keep Tab within the dialog.
  _modalTrap = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...card.querySelectorAll(FOCUSABLE)].filter(el => el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  card.addEventListener('keydown', _modalTrap);
  // Initial focus: first field/control, else the dialog itself.
  requestAnimationFrame(() => {
    const target = card.querySelector('input, textarea, select, [autofocus]') || card.querySelector(FOCUSABLE) || card;
    target.focus?.();
  });
  return card;
}
export function closeModal() {
  const m = document.getElementById('modal');
  m.classList.remove('show');
  const ret = _modalReturnFocus; _modalReturnFocus = null; _modalTrap = null;
  setTimeout(() => { m.classList.add('hidden'); m.innerHTML = ''; }, 180);
  if (ret && ret.isConnected) ret.focus?.();
}

// ---- Loading shimmer ----------------------------------------------------------------------
export function shimmerRows(n = 6) {
  return `<div class="shimmer-wrap">${Array.from({ length: n }, () => `<div class="shimmer-row"><div class="sh-av"></div><div class="sh-lines"><div class="sh-line w70"></div><div class="sh-line w40"></div></div></div>`).join('')}</div>`;
}

export function emptyState(iconName, title, sub) {
  return `<div class="empty"><div class="empty-glow">${icon(iconName)}</div><b>${esc(title)}</b><span>${esc(sub)}</span></div>`;
}

// ---- Rich-text body rendering (spec §17#8 rich text/HTML) ----------------------------------
// Messages may carry HTML bodies (composed in the rich editor). We render our own composed HTML
// through a strict allow-list sanitizer — no remote content is ever fetched (no <img src>, no
// scripts, no event handlers), which also closes the tracking-pixel/read-confirmation leak the
// parity audit (§17#8) calls out. Plaintext bodies keep their pre-wrap rendering.
const ALLOWED_TAGS = new Set(['B','STRONG','I','EM','U','A','UL','OL','LI','BR','P','DIV','SPAN','BLOCKQUOTE','CODE','PRE','H1','H2','H3']);
export function sanitizeHtml(html) {
  const tmp = document.createElement('div');
  tmp.innerHTML = String(html || '');
  const walk = (node) => {
    [...node.childNodes].forEach(child => {
      if (child.nodeType === 1) {
        if (!ALLOWED_TAGS.has(child.tagName)) { // unwrap disallowed element, keep text
          const text = document.createTextNode(child.textContent || '');
          child.replaceWith(text); return;
        }
        [...child.attributes].forEach(attr => {
          const n = attr.name.toLowerCase();
          const okHref = child.tagName === 'A' && n === 'href' && /^(https?:|mailto:)/i.test(attr.value);
          if (!okHref) child.removeAttribute(attr.name);
        });
        if (child.tagName === 'A') { child.setAttribute('target', '_blank'); child.setAttribute('rel', 'noopener noreferrer nofollow'); }
        walk(child);
      }
    });
  };
  walk(tmp);
  return tmp.innerHTML;
}
export function renderBody(m) {
  if (m && m.html) return `<div class="msg-rich">${sanitizeHtml(m.body)}</div>`;
  return esc(m ? m.body : '');
}

// ---- MOTE inspector (three-layer visualization, spec §2.1) --------------------------------
export function showInspector(mote, plan) {
  const insp = document.getElementById('inspector');
  const hops = plan.path.map((h, i) => `<span class="hop" data-h="${i}">${esc(h)}</span>`).join('<i class="arrow">→</i>');
  const tierBadge = mote.tier === 'private'
    ? `<span class="pill priv">${icon('shield')} private · mixnet</span>`
    : (plan.kind === 'legacy' ? `<span class="pill legacy">legacy · gateway</span>` : (plan.kind === 'group' ? `<span class="pill accent">${icon('groups')} group fan-out</span>` : `<span class="pill accent">fast · direct</span>`));
  insp.innerHTML = `
    <div class="insp-head">
      <div><h3>MOTE inspector</h3><div class="insp-sub">Why this message is private — the object, three sealed layers (spec §2.1). ${tierBadge}</div></div>
      <button class="icon-btn" id="insp-close" aria-label="Close">${icon('x')}</button>
    </div>
    <div class="layer outer">
      <div class="layer-h">${icon('shield')} OUTER — mixnet / sealed sender</div>
      <div class="kv"><span class="k">tier</span><span class="v">${esc(mote.tier)}</span></div>
      <div class="kv"><span class="k">onion</span><span class="v">${mote.outer.onion ? 'Sphinx, constant-length' : 'direct'}</span></div>
      <div class="kv"><span class="k">sender</span><span class="v">hidden (sealed)</span></div>
      ${mote.outer.fanout ? `<div class="kv"><span class="k">fan-out</span><span class="v">${esc(mote.outer.fanout)}</span></div>` : ''}
      <div class="layer-note">The network sees only this layer: ciphertext to an opaque destination.</div>
    </div>
    <div class="layer env">
      <div class="layer-h">${icon('lock')} ENVELOPE — signed, content-addressed</div>
      <div class="kv"><span class="k">id</span><span class="v">${esc(mote.envelope.id)}</span></div>
      <div class="kv"><span class="k">to</span><span class="v">${esc(mote.envelope.to)}</span></div>
      <div class="kv"><span class="k">kind</span><span class="v">0x${mote.kind.toString(16).padStart(2, '0')}</span></div>
      <div class="kv"><span class="k">suite</span><span class="v">0x01 · Ed25519/X25519/ChaCha20</span></div>
      <div class="layer-note">id = BLAKE3(ciphertext) — content-addressed (SHA-256 stand-in here).</div>
    </div>
    <div class="layer pay">
      <div class="layer-h">${icon('key')} PAYLOAD — end-to-end encrypted</div>
      <div class="kv"><span class="k">from</span><span class="v">${esc(mote.payload.from.slice(0, 22))}…</span></div>
      <div class="kv"><span class="k">signature</span><span class="v">${mote.sigLen ? '✓ real ' + (mote.payload.from ? '' : '') + 'Ed25519/ECDSA, ' + mote.sigLen + ' bytes' : '(unsigned — key unavailable)'}</span></div>
      <div class="kv"><span class="k">subject</span><span class="v">${esc(mote.payload.headers.subject || '—')}</span></div>
      <div class="kv"><span class="k">body</span><span class="v">${esc((mote.payload.body || '').slice(0, 46))}…</span></div>
      <div class="layer-note">Only the recipient can decrypt this. Sender identity + signature live inside.</div>
    </div>
    <div class="insp-path-h">Delivery path <span class="sim-tag">simulated network</span></div>
    <div class="path">${hops}</div>`;
  insp.setAttribute('role', 'complementary');
  insp.setAttribute('aria-label', 'MOTE privacy inspector');
  insp.classList.remove('hidden');
  requestAnimationFrame(() => insp.classList.add('show'));
  insp.querySelector('#insp-close').onclick = hideInspector;
  return insp;
}
export function litHop(i) {
  document.getElementById('inspector')?.querySelectorAll('.hop').forEach((h, j) => h.classList.toggle('lit', j <= i));
}
export function hideInspector() {
  const insp = document.getElementById('inspector');
  insp.classList.remove('show');
  setTimeout(() => insp.classList.add('hidden'), 220);
}

// ---- Safety-number visuals (spec §3.4) ---------------------------------------------------
export function safetyWords(safety) {
  if (!safety) return '';
  const w = safety.words.map((x, i) => `<span class="sw" data-i="${i + 1}">${esc(x)}</span>`).join('');
  return `<div class="safety-words">${w}<span class="sw sum" data-i="✓">${esc(safety.checksum)}</span></div>`;
}
export function safetyGrid(safety) {
  if (!safety) return '';
  const cells = safety.grid.flat().map(b => `<i class="${b ? 'on' : ''}"></i>`).join('');
  return `<div class="safety-grid">${cells}</div>`;
}
export function safetyNumeric(safety) {
  return safety ? `<div class="safety-num mono">${esc(safety.numeric)}</div>` : '';
}

// ---- Command-menu: a keyboard-driven picker (snooze / label / actions) --------------------
// Not a mouse-only dropdown — opens focused, type-to-filter, ↑↓ to move, ↵ to run, Esc closes.
// items: [{ label, sub?, hue?, icon?, checked?, run }]. opts: { anchor, title, icon, filterable }.
export function commandMenu(anchor, opts = {}) {
  document.querySelector('.cmenu')?.remove();
  document.querySelector('.popover')?.remove();
  const items = opts.items || [];
  const filterable = opts.filterable ?? items.length > 7;
  const menu = el(`<div class="cmenu" role="menu" aria-label="${esc(opts.title || 'Menu')}">
    ${opts.title ? `<div class="cmenu-head">${opts.icon ? icon(opts.icon) : ''}${esc(opts.title)}</div>` : ''}
    ${filterable ? `<div class="cmenu-search"><input id="cmq" placeholder="${esc(opts.placeholder || 'Filter…')}" autocomplete="off" spellcheck="false" aria-label="Filter"></div>` : ''}
    <div class="cmenu-list" id="cmlist"></div>
    <div class="cmenu-foot"><span><kbd>↑↓</kbd>move</span><span><kbd>↵</kbd>select</span><span><kbd>esc</kbd>close</span></div>
  </div>`);
  document.body.appendChild(menu);
  const r = anchor.getBoundingClientRect();
  const w = menu.offsetWidth || 260, h = menu.offsetHeight || 220;
  let left = Math.min(r.left, innerWidth - w - 10);
  if (opts.align === 'right') left = Math.max(10, r.right - w);
  let top = r.bottom + 6;
  if (top + h > innerHeight - 10) top = Math.max(10, r.top - h - 6);
  menu.style.left = Math.max(10, left) + 'px';
  menu.style.top = top + 'px';

  const listEl = menu.querySelector('#cmlist');
  const input = menu.querySelector('#cmq');
  let filtered = items, cur = 0;
  const draw = () => {
    listEl.innerHTML = filtered.length ? filtered.map((it, i) => `<button class="cmenu-item ${i === cur ? 'on' : ''} ${it.checked ? 'checked' : ''}" data-i="${i}" role="menuitem">
      ${it.hue != null ? `<i class="dot" style="--h:${it.hue}"></i>` : (it.icon ? icon(it.icon) : '')}
      <span class="cmenu-label">${esc(it.label)}</span>
      ${it.sub ? `<span class="cmenu-sub">${esc(it.sub)}</span>` : ''}
      <span class="cmenu-tick">${icon('check')}</span>
    </button>`).join('') : `<div class="cmenu-empty">No matches</div>`;
    listEl.querySelectorAll('[data-i]').forEach(b => {
      b.onmouseenter = () => { cur = Number(b.dataset.i); highlight(); };
      b.onclick = () => run(Number(b.dataset.i));
    });
  };
  const highlight = () => { listEl.querySelectorAll('.cmenu-item').forEach((b, i) => b.classList.toggle('on', i === cur)); listEl.querySelector('.on')?.scrollIntoView({ block: 'nearest' }); };
  const run = (i) => { const it = filtered[i]; if (!it) return; if (!it.keepOpen) close(); it.run(); };
  const applyFilter = () => { const q = (input?.value || '').trim().toLowerCase(); filtered = q ? items.filter(it => (it.label + ' ' + (it.sub || '')).toLowerCase().includes(q)) : items; cur = 0; draw(); };
  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); cur = Math.min(filtered.length - 1, cur + 1); highlight(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); cur = Math.max(0, cur - 1); highlight(); }
    else if (e.key === 'Enter') { e.preventDefault(); run(cur); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  };
  function close() { document.removeEventListener('keydown', onKeyGlobal, true); document.removeEventListener('click', onOut, true); menu.remove(); opts.onClose?.(); }
  const onKeyGlobal = (e) => { if (!menu.isConnected) return; onKey(e); };
  const onOut = (e) => { if (!menu.contains(e.target) && e.target !== anchor) close(); };
  draw();
  if (input) { input.addEventListener('input', applyFilter); input.addEventListener('keydown', onKey); setTimeout(() => input.focus(), 20); }
  else { menu.tabIndex = -1; setTimeout(() => menu.focus?.(), 20); }
  document.addEventListener('keydown', onKeyGlobal, true);
  setTimeout(() => document.addEventListener('click', onOut, true), 0);
  return menu;
}

// ---- Emoji set with search keywords (self-contained; no external assets) -------------------
export const EMOJI_QUICK = ['👍', '🔥', '💯', '✨', '👀', '🙏', '❤️', '😂', '🎉', '👏'];
export const EMOJI = [
  ['👍','thumbs up yes ok approve like'],['👎','thumbs down no dislike'],['🔥','fire lit hot flame'],['💯','hundred perfect score'],
  ['✨','sparkles shiny nice clean'],['👀','eyes look watching see'],['🙏','pray thanks please hope'],['❤️','heart love red'],
  ['😂','joy laugh lol funny cry'],['🎉','party tada celebrate'],['👏','clap applause bravo'],['🚀','rocket ship launch ship fast'],
  ['✅','check done complete tick'],['❌','cross no wrong fail'],['⭐','star favorite'],['💡','idea bulb light think'],
  ['🎯','target bullseye goal'],['⚡','bolt fast zap energy'],['🐛','bug insect issue'],['🛠️','tools build fix wrench'],
  ['📌','pin pinned tack'],['📎','paperclip attach'],['📝','memo note write edit'],['📊','chart bar stats graph data'],
  ['😀','grin smile happy'],['😃','smile happy joy'],['😄','laugh happy grin'],['😅','sweat smile nervous'],
  ['😊','blush smile happy'],['🙂','slight smile'],['😉','wink'],['😍','heart eyes love adore'],
  ['🤩','star struck wow amazed'],['😎','cool sunglasses'],['🤔','thinking hmm consider'],['🫡','salute yes sir respect'],
  ['🙌','raised hands praise celebrate'],['🤝','handshake deal agree'],['💪','muscle strong flex'],['🫶','love hands heart'],
  ['👋','wave hi hello bye'],['🤞','fingers crossed luck hope'],['🤙','call shaka hang loose'],['✌️','peace victory'],
  ['😇','angel innocent halo'],['🥳','party face celebrate birthday'],['😌','relieved calm content'],['😴','sleep tired zzz'],
  ['😭','sob cry sad tears'],['😢','cry sad tear'],['😩','weary tired frustrated'],['😤','huff angry steam'],
  ['😡','angry mad rage red'],['🤯','mind blown explode wow'],['😱','scream shock fear'],['🥺','pleading puppy please'],
  ['🤨','raised eyebrow skeptical'],['😬','grimace awkward yikes'],['🙄','eye roll annoyed'],['😏','smirk sly'],
  ['🤗','hug hugging warm'],['🤫','shush quiet secret'],['🤓','nerd glasses smart'],['🧐','monocle inspect examine'],
  ['💀','skull dead dying lol'],['👻','ghost boo spooky'],['🤖','robot bot ai'],['👾','alien game invader'],
  ['💜','purple heart'],['💙','blue heart'],['💚','green heart'],['🧡','orange heart'],['💛','yellow heart'],
  ['🖤','black heart'],['🤍','white heart'],['💔','broken heart sad'],['💖','sparkle heart love'],['💗','growing heart'],
  ['🎊','confetti celebrate party'],['🥂','cheers toast drink celebrate'],['🍾','champagne pop celebrate'],['🎈','balloon party'],
  ['☕','coffee tea break'],['🍕','pizza food'],['🍔','burger food'],['🍰','cake dessert birthday'],
  ['🌟','glowing star'],['🌈','rainbow pride color'],['🌍','earth world globe'],['🌙','moon night'],
  ['☀️','sun sunny day'],['⛅','cloud weather'],['❄️','snow cold winter'],['💧','drop water'],
  ['📈','chart up growth trend'],['📉','chart down decline'],['💰','money bag cash'],['💸','money flying spend'],
  ['🔒','lock secure private'],['🔑','key access'],['🛡️','shield protect security'],['⏰','alarm clock time'],
  ['⌛','hourglass wait time'],['📅','calendar date'],['📬','mailbox mail'],['✉️','envelope mail message'],
  ['💬','speech chat message'],['🗣️','speaking talk voice'],['📣','megaphone announce loud'],['🔔','bell notify alert'],
  ['✍️','writing sign hand'],['👌','ok perfect nice'],['🤌','pinch italian chef'],['🫰','fingers snap money'],
  ['🥇','gold medal first win'],['🏆','trophy win champion'],['🎁','gift present'],['🧠','brain smart think'],
];

// A searchable emoji panel: quick row + type-to-filter grid. Keyboard: type filters, ↵ picks
// the first result, Esc closes. Used by chat reactions and the composer emoji button.
export function emojiPanel(anchor, onPick, opts = {}) {
  document.querySelector('.emoji-panel')?.remove();
  document.querySelector('.react-pop')?.remove();
  const panel = el(`<div class="emoji-panel" role="dialog" aria-label="Pick an emoji">
    <div class="emoji-quick">${EMOJI_QUICK.map(e => `<button data-e="${e}" title="${e}">${e}</button>`).join('')}</div>
    <div class="emoji-search"><input id="emq" placeholder="Search emoji…" autocomplete="off" spellcheck="false" aria-label="Search emoji"></div>
    <div class="emoji-grid" id="emgrid"></div>
  </div>`);
  document.body.appendChild(panel);
  const r = anchor.getBoundingClientRect();
  const w = panel.offsetWidth || 306, h = panel.offsetHeight || 300;
  let left = Math.min(r.left, innerWidth - w - 10);
  let top = r.top - h - 8;
  if (top < 10) top = Math.min(innerHeight - h - 10, r.bottom + 8);
  panel.style.left = Math.max(10, left) + 'px';
  panel.style.top = Math.max(10, top) + 'px';

  const grid = panel.querySelector('#emgrid');
  const input = panel.querySelector('#emq');
  let list = EMOJI;
  const draw = () => {
    grid.innerHTML = list.length ? list.map(([e]) => `<button data-e="${e}" title="${esc(e)}">${e}</button>`).join('') : `<div class="emoji-empty">No emoji match</div>`;
    grid.querySelectorAll('[data-e]').forEach(b => b.onclick = () => { onPick(b.dataset.e); close(); });
  };
  const filter = () => { const q = input.value.trim().toLowerCase(); list = q ? EMOJI.filter(([e, k]) => k.includes(q) || e === q) : EMOJI; draw(); };
  const close = () => { document.removeEventListener('click', onOut, true); panel.remove(); };
  const onOut = (e) => { if (!panel.contains(e.target) && e.target !== anchor) close(); };
  panel.querySelectorAll('.emoji-quick [data-e]').forEach(b => b.onclick = () => { onPick(b.dataset.e); close(); });
  input.addEventListener('input', filter);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); if (list[0]) { onPick(list[0][0]); close(); } }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  });
  draw();
  setTimeout(() => input.focus(), 20);
  setTimeout(() => document.addEventListener('click', onOut, true), 0);
  return panel;
}

// ---- Page-load stagger orchestration ------------------------------------------------------
// Applies a cohesive entrance sequence to a view's top-level panes — but ONLY when the view
// changed (not on in-place re-renders like star/read), so nothing flickers mid-interaction.
export function applyStagger(root, animate) {
  root.classList.remove('stagger-in');
  if (!animate) return;
  [...root.children].forEach((c, i) => c.style.setProperty('--stagger-i', i));
  // reflow so re-adding the class restarts the animation reliably
  void root.offsetWidth;
  root.classList.add('stagger-in');
}

export { fmtBytes };
