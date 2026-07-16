// ui.js — rendering primitives for the console. Pure DOM, no framework, no external assets.
// Icons are inline stroke SVGs; avatars are deterministic gradients; the modal is an accessible
// focus-trapped dialog. Shares the reference client's design language (client/js/ui.js) so the
// admin console feels like part of the same product.

export const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
export const esc = (s) => (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export const timeAgo = (t) => {
  const s = (Date.now() - t) / 1000;
  if (s < 45) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 7 * 86400) return Math.floor(s / 86400) + 'd ago';
  return new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
};
export const fmtDate = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
export const fmtLong = (t) => new Date(t).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }) +
  ' · ' + new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

// ---- Icon set (stroke SVGs) --------------------------------------------------------------
const P = {
  home: '<path d="M4 11l8-7 8 7"/><path d="M6 10v9h12v-9"/><path d="M10 19v-5h4v5"/>',
  domain: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17"/>',
  members: '<circle cx="9" cy="9" r="3.2"/><circle cx="17" cy="10" r="2.4"/><path d="M3 20c0-3 2.7-4.8 6-4.8s6 1.8 6 4.8"/><path d="M15.5 20c0-2.2 1.4-3.6 3.2-3.6 1.3 0 2.5.7 3.1 1.9"/>',
  directory: '<rect x="4" y="4" width="16" height="16" rx="2.5"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  groups: '<circle cx="9" cy="9" r="3.2"/><circle cx="17" cy="10" r="2.4"/><path d="M3 20c0-3 2.7-4.8 6-4.8s6 1.8 6 4.8"/><path d="M15.5 20c0-2.2 1.4-3.6 3.2-3.6 1.3 0 2.5.7 3.1 1.9"/>',
  roles: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/><path d="M9.5 12l1.8 1.8 3.4-3.6"/>',
  audit: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13h7M9 16h7M9 10h3"/>',
  shield: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 12l8-8M17 6l2 2M15 8l2 2"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  unlock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 017.5-2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 6.2A9.9 9.9 0 0112 6c6.5 0 10 6 10 6a17 17 0 01-3.4 3.9M6.1 7.6A17 17 0 002 12s3.5 7 10 7a9.7 9.7 0 004-.85"/><path d="M9.5 9.7a3 3 0 004.2 4.2"/>',
  verified: '<path d="M12 3l2 1.6 2.5-.4 1 2.4 2.4 1-.4 2.5L22 15l-1.6 2 .4 2.5-2.4 1-1 2.4-2.5-.4L12 21l-2-1.6-2.5.4-1-2.4-2.4-1 .4-2.5L2 15l1.6-2-.4-2.5 2.4-1 1-2.4 2.5.4z"/><path d="M8.5 12l2.2 2.2L15.5 9.5" stroke-width="1.6"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  more: '<circle cx="6" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4-4"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M5 15V6a2 2 0 012-2h9"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  warn: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  moon: '<path d="M20 14a8 8 0 11-9-9 6.5 6.5 0 009 9z"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.5 4.5l1.8 1.8M17.7 17.7l1.8 1.8M19.5 4.5l-1.8 1.8M6.3 17.7l-1.8 1.8"/>',
  dns: '<rect x="3" y="4" width="18" height="6" rx="1.6"/><rect x="3" y="14" width="18" height="6" rx="1.6"/><path d="M7 7h.01M7 17h.01"/>',
  bell: '<path d="M6 9a6 6 0 1112 0c0 6 2 7 2 7H4s2-1 2-7z"/><path d="M10 20a2 2 0 004 0"/>',
  chat: '<path d="M4 5h16v11H9l-5 4z"/>',
  send: '<path d="M21 3L3 10.5l7 2.5 2.5 7z"/><path d="M21 3l-9 11"/>',
  trash: '<path d="M5 7h14"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/>',
  logout: '<path d="M14 4h4a1 1 0 011 1v14a1 1 0 01-1 1h-4"/><path d="M10 12H3m0 0l4-4m-4 4l4 4"/>',
  refresh: '<path d="M4 9a8 8 0 0114-3l2 2m0-4v4h-4"/><path d="M20 15a8 8 0 01-14 3l-2-2m0 4v-4h4"/>',
  link: '<path d="M9 15l6-6"/><path d="M8 12l-2 2a3 3 0 004 4l2-2"/><path d="M16 12l2-2a3 3 0 00-4-4l-2 2"/>',
  building: '<rect x="4" y="3" width="16" height="18" rx="1.5"/><path d="M8 7h.01M12 7h.01M16 7h.01M8 11h.01M12 11h.01M16 11h.01M10 21v-4h4v4"/>',
  scale: '<path d="M12 3v18M6 21h12"/><path d="M12 6l-6 2 3 5a3 3 0 006 0l3-5z" fill="none"/>',
};
export function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

// ---- Envoir brand mark, tinted for the admin console (amber-violet) -----------------------
export function brandMark(size = 28) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 128 128" fill="none" aria-label="Envoir Console">
    <defs><linearGradient id="cm-${size}" x1="16" y1="12" x2="112" y2="116" gradientUnits="userSpaceOnUse"><stop stop-color="#5B9DFF"/><stop offset="1" stop-color="#7C5CFF"/></linearGradient></defs>
    <rect x="8" y="8" width="112" height="112" rx="30" fill="url(#cm-${size})"/>
    <rect x="30" y="40" width="68" height="48" rx="9" fill="none" stroke="#fff" stroke-width="5"/>
    <path d="M33 45 L64 68 L95 45" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="33" cy="45" r="6" fill="#fff"/><circle cx="95" cy="45" r="6" fill="#fff"/><circle cx="64" cy="68" r="7" fill="#fff"/>
  </svg>`;
}

// ---- Avatars: deterministic gradient + initials -----------------------------------------
export function initials(name) {
  const parts = (name || '?').replace(/^@/, '').split(/[\s.@]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0] || '?').slice(0, 2).toUpperCase();
}
export function avatar(name, hue = 220, size = 34) {
  return `<span class="av" style="--h:${hue};width:${size}px;height:${size}px;font-size:${Math.round(size * 0.38)}px" title="${esc(name)}">${esc(initials(name))}</span>`;
}

// ---- Custody badge: the load-bearing sovereignty affordance (spec §3.10.2, §18.4.7) -------
// SOVEREIGN = the org holds only the name→key binding; it cannot read or impersonate.
// ORG-MANAGED = disclosed escrow; the org holds/escrows the key and CAN read + impersonate.
export function custodyBadge(custody, sm = false) {
  const s = sm ? ' sm' : '';
  if (custody === 'org-managed') return `<span class="pill warn${s}" title="Org holds/escrows this key — disclosed escrow (spec §3.10.2b)">${icon('unlock')} org-managed</span>`;
  return `<span class="pill good${s}" title="Member holds their own key — the org cannot read or impersonate (spec §3.10.2a)">${icon('key')} sovereign</span>`;
}

export function statusPill(status) {
  if (status === 'offboarded') return `<span class="pill dim sm">offboarded</span>`;
  return `<span class="pill accent sm">active</span>`;
}

// ---- Toast --------------------------------------------------------------------------------
export function toast(msg, opts = {}) {
  const t = document.getElementById('toast');
  const ms = opts.ms || 3000;
  t.setAttribute('role', 'status');
  t.setAttribute('aria-live', 'polite');
  t.innerHTML = `<span>${msg}</span>${opts.action ? `<button class="toast-act">${esc(opts.action)}</button>` : ''}`;
  t.classList.remove('hidden'); t.classList.add('show');
  clearTimeout(t._h);
  if (opts.action && opts.onAction) t.querySelector('.toast-act').onclick = () => { clearTimeout(t._h); t.classList.remove('show'); opts.onAction(); };
  t._h = setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 200); }, ms);
  return t;
}

// ---- Modal (accessible dialog: role=dialog + aria-modal, Tab focus-trap, focus restore) ----
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
let _modalReturnFocus = null;
let _modalTrap = null;

export function openModal(html, opts = {}) {
  const m = document.getElementById('modal');
  _modalReturnFocus = document.activeElement;
  const labelAttr = opts.label ? ` aria-label="${esc(opts.label)}"` : '';
  m.innerHTML = `<div class="modal-scrim"></div><div class="modal-card ${opts.wide ? 'wide' : ''}" role="dialog" aria-modal="true"${labelAttr}>${html}</div>`;
  m.classList.remove('hidden');
  requestAnimationFrame(() => m.classList.add('show'));
  const card = m.querySelector('.modal-card');
  m.querySelector('.modal-scrim').onclick = () => { if (!opts.sticky) closeModal(); };
  _modalTrap = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...card.querySelectorAll(FOCUSABLE)].filter(x => x.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  card.addEventListener('keydown', _modalTrap);
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

// ---- Loading + empty + error states -------------------------------------------------------
export function shimmerRows(n = 5) {
  return `<div class="shimmer-wrap">${Array.from({ length: n }, () => `<div class="shimmer-row"><div class="sh-av"></div><div class="sh-lines"><div class="sh-line w70"></div><div class="sh-line w40"></div></div></div>`).join('')}</div>`;
}
export function emptyState(iconName, title, sub, actionHtml = '') {
  return `<div class="empty"><div class="empty-glow">${icon(iconName)}</div><b>${esc(title)}</b><span>${esc(sub)}</span>${actionHtml ? `<div class="empty-act">${actionHtml}</div>` : ''}</div>`;
}
export function errorState(title, sub, retryId = '') {
  return `<div class="empty err"><div class="empty-glow bad">${icon('warn')}</div><b>${esc(title)}</b><span>${esc(sub)}</span>${retryId ? `<div class="empty-act"><button class="btn" id="${retryId}">${icon('refresh')} Retry</button></div>` : ''}</div>`;
}

// ---- Safety-number visuals (spec §3.4) ---------------------------------------------------
export function safetyGrid(safety) {
  if (!safety) return '';
  const cells = safety.grid.flat().map(b => `<i class="${b ? 'on' : ''}"></i>`).join('');
  return `<div class="safety-grid">${cells}</div>`;
}
export function safetyWords(safety) {
  if (!safety) return '';
  const w = safety.words.map((x, i) => `<span class="sw" data-i="${i + 1}">${esc(x)}</span>`).join('');
  return `<div class="safety-words">${w}<span class="sw sum" data-i="✓">${esc(safety.checksum)}</span></div>`;
}

export function copyBtn(text, label = 'Copy') {
  const b = el(`<button class="icon-btn sm" title="${esc(label)}" aria-label="${esc(label)}">${icon('copy')}</button>`);
  b.onclick = () => { navigator.clipboard?.writeText(text); toast(`${icon('check')} Copied`); };
  return b;
}
