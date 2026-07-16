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

// ---- byte + number formatting (billing) ---------------------------------------------------
export function fmtBytes(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
}
export function fmtNum(n) {
  if (n == null) return '—';
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k';
  return String(n);
}
export function fmtUsd(n) {
  return '$' + n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

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
  gateway: '<path d="M4 20V10l8-5 8 5v10"/><path d="M4 20h16"/><path d="M9 20v-5h6v5"/><path d="M12 5V2"/>',
  billing: '<path d="M6 3h9l4 4v14l-2.5-1.5L14 21l-2.5-1.5L9 21l-2.5-1.5L4 21V3z"/><path d="M8 9h8M8 13h5"/>',
  relay: '<path d="M12 13a2 2 0 100-4 2 2 0 000 4z"/><path d="M7.8 16.2a6 6 0 010-8.4M16.2 7.8a6 6 0 010 8.4M5 19a10 10 0 010-14M19 5a10 10 0 010 14"/>',
  wifi: '<path d="M2 8.8a16 16 0 0120 0M5 12a11 11 0 0114 0M8 15.2a6 6 0 018 0"/><circle cx="12" cy="19" r="1.1"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4"/>',
  database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  tag: '<path d="M3 12l9-9 8 8-9 9z"/><circle cx="14.5" cy="9.5" r="1.4"/>',
  kt: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13l1.6 1.6L14 11" stroke-width="1.6"/><path d="M9 17h6"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M4 7l8 6 8-6"/>',
};
export function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

// ---- Envoir brand mark — the leaning "e"/at-symbol on the Aurora Indigo gradient tile ------
// Same mark as ../brand/logo-mark.svg (see ../brand/README.md); each app keeps its own inline
// copy (no runtime cross-reference) with a size-scoped gradient id to avoid collisions.
export function brandMark(size = 28) {
  const id = 'cm-' + size;
  return `<svg width="${size}" height="${size}" viewBox="223 52 244 244" fill="none" aria-label="Envoir Console">
    <defs><linearGradient id="${id}" x1="223" y1="52" x2="467" y2="296" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4C4DFF"/><stop offset=".55" stop-color="#6E4DFF"/><stop offset="1" stop-color="#9A4DFF"/></linearGradient></defs>
    <rect x="223" y="52" width="244" height="244" rx="52" fill="url(#${id})"/>
    <g transform="translate(340 170) skewX(-10) translate(-340 -170)" fill="none" stroke="#ffffff" stroke-width="9" stroke-linecap="round" stroke-linejoin="round">
      <path d="M374 170 A34 34 0 0 0 340 136 A34 34 0 0 0 306 170 A34 34 0 0 0 340 204 A52 34 0 0 0 392 170 A52 58 0 0 0 340 112 A62 58 0 0 0 278 170 A62 66 0 0 0 340 236 A72 66 0 0 0 412 170"/>
      <path d="M306 170 L374 170"/>
    </g>
  </svg>`;
}

// ---- sparkline (inline svg polyline trend) -------------------------------------------------
export function sparkline(values, opts = {}) {
  const w = opts.w || 120, h = opts.h || 30, pad = 2;
  if (!values || !values.length) return '';
  const min = Math.min(...values), max = Math.max(...values);
  const span = max - min || 1;
  const pts = values.map((v, i) => {
    const x = pad + (i / (values.length - 1 || 1)) * (w - 2 * pad);
    const y = h - pad - ((v - min) / span) * (h - 2 * pad);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const cls = opts.cls || 'accent';
  const area = `${pad},${h - pad} ${pts.join(' ')} ${w - pad},${h - pad}`;
  return `<svg class="spark ${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
    <polygon class="spark-area" points="${area}"/><polyline class="spark-line" points="${pts.join(' ')}"/></svg>`;
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
