// ui.js — rendering primitives for Envoir Status. Pure DOM, no framework, no external assets.
// Inline stroke-SVG icons, an accessible focus-trapped modal, and the status-specific visuals
// (status banner, health dot/pill, 90-day uptime bars). Aurora Indigo design language, shared
// with the client / console / superadmin so the whole suite feels like one product.

export const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
export const esc = (s) => (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export const timeAgo = (t) => {
  const s = (Date.now() - t) / 1000;
  if (s < 0) return 'in ' + Math.abs(Math.round(s / 60)) + 'm';
  if (s < 45) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 7 * 86400) return Math.floor(s / 86400) + 'd ago';
  return new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
};
export const fmtLong = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' }) +
  ', ' + new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
export const fmtDate = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });

export function fmtBytes(n) {
  if (n == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
}
export const pct = (n) => (Math.round(n * 100) / 100).toFixed(n >= 99.995 ? 3 : 2) + '%';

// ---- Icon set (stroke SVGs) ---------------------------------------------------------------
const P = {
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M4 7l8 6 8-6"/>',
  gateway: '<path d="M4 20V10l8-5 8 5v10"/><path d="M4 20h16"/><path d="M9 20v-5h6v5"/><path d="M12 5V2"/>',
  mix: '<path d="M3 6h4l10 12h4"/><path d="M17 4l4 2-4 2"/><path d="M3 18h4l3-3.5"/><path d="M14 9.5L17 6"/>',
  kt: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13l1.6 1.6L14 11" stroke-width="1.6"/><path d="M9 17h6"/>',
  directory: '<rect x="4" y="4" width="16" height="16" rx="2.5"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  relay: '<path d="M12 13a2 2 0 100-4 2 2 0 000 4z"/><path d="M7.8 16.2a6 6 0 010-8.4M16.2 7.8a6 6 0 010 8.4M5 19a10 10 0 010-14M19 5a10 10 0 010 14"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  warn: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  bell: '<path d="M6 9a6 6 0 1112 0c0 6 2 7 2 7H4s2-1 2-7z"/><path d="M10 20a2 2 0 004 0"/>',
  refresh: '<path d="M4 9a8 8 0 0114-3l2 2m0-4v4h-4"/><path d="M20 15a8 8 0 01-14 3l-2-2m0 4v-4h4"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.5 4.5l1.8 1.8M17.7 17.7l1.8 1.8M19.5 4.5l-1.8 1.8M6.3 17.7l-1.8 1.8"/>',
  moon: '<path d="M20 14a8 8 0 11-9-9 6.5 6.5 0 009 9z"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 12l8-8M17 6l2 2M15 8l2 2"/>',
  wifi: '<path d="M2 8.8a16 16 0 0120 0M5 12a11 11 0 0114 0M8 15.2a6 6 0 018 0"/><circle cx="12" cy="19" r="1.1"/>',
  up: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  down: '<path d="M12 5v14M6 13l6 6 6-6"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-6 8-6s8 2 8 6"/>',
  send: '<path d="M21 3L3 10.5l7 2.5 2.5 7z"/><path d="M21 3l-9 11"/>',
  inbox: '<path d="M4 13l2.5-8h11L20 13v6H4z"/><path d="M4 13h4l1 2h6l1-2h4"/>',
  shield: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/>',
  x2: '<path d="M6 6l12 12M18 6L6 18"/>',
  more: '<circle cx="6" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/>',
};
export function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

// ---- Envoir brand mark — the leaning "e"/at-symbol on the Aurora Indigo gradient tile ------
// Same mark as ../brand/logo-mark.svg (see ../brand/README.md); each app keeps its own inline
// copy (no runtime cross-reference) with a size-scoped gradient id to avoid collisions.
export function brandMark(size = 30) {
  const id = 'stm-' + size;
  return `<svg width="${size}" height="${size}" viewBox="223 52 244 244" fill="none" aria-label="Envoir">
    <defs><linearGradient id="${id}" x1="223" y1="52" x2="467" y2="296" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4C4DFF"/><stop offset=".55" stop-color="#6E4DFF"/><stop offset="1" stop-color="#9A4DFF"/></linearGradient></defs>
    <rect x="223" y="52" width="244" height="244" rx="52" fill="url(#${id})"/>
    <g transform="translate(340 170) skewX(-10) translate(-340 -170)" fill="none" stroke="#ffffff" stroke-width="9" stroke-linecap="round" stroke-linejoin="round">
      <path d="M374 170 A34 34 0 0 0 340 136 A34 34 0 0 0 306 170 A34 34 0 0 0 340 204 A52 34 0 0 0 392 170 A52 58 0 0 0 340 112 A62 58 0 0 0 278 170 A62 66 0 0 0 340 236 A72 66 0 0 0 412 170"/>
      <path d="M306 170 L374 170"/>
    </g>
  </svg>`;
}

// ---- status vocabulary --------------------------------------------------------------------
// overall: operational | degraded | outage | maintenance   component: up | degraded | down
export const OVERALL = {
  operational: { label: 'All systems operational', cls: 'good', icon: 'check' },
  degraded: { label: 'Degraded performance', cls: 'warn', icon: 'warn' },
  outage: { label: 'Partial outage', cls: 'bad', icon: 'x' },
  maintenance: { label: 'Under maintenance', cls: 'accent', icon: 'clock' },
};
export const COMP = {
  up: { label: 'Operational', cls: 'good' },
  degraded: { label: 'Degraded', cls: 'warn' },
  down: { label: 'Outage', cls: 'bad' },
  maintenance: { label: 'Maintenance', cls: 'accent' },
};
export function healthDot(status) { return `<span class="hdot ${status}" title="${COMP[status]?.label || status}"></span>`; }
export function healthPill(status, sm = true) {
  const c = COMP[status] || { label: status, cls: 'dim' };
  return `<span class="pill ${c.cls}${sm ? ' sm' : ''}">${healthDot(status)}${esc(c.label)}</span>`;
}

// ---- 90-day uptime bars -------------------------------------------------------------------
export function uptimeBars(days) {
  return `<div class="uptime-bars" role="img" aria-label="90-day uptime history">${days.map(d =>
    `<span class="ub ${d.status}" title="${esc(d.label)}"></span>`).join('')}</div>`;
}

// ---- Toast --------------------------------------------------------------------------------
export function toast(msg, opts = {}) {
  const t = document.getElementById('toast');
  t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite');
  t.innerHTML = `<span>${msg}</span>`;
  t.classList.remove('hidden'); t.classList.add('show');
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 200); }, opts.ms || 2600);
  return t;
}

// ---- Modal (accessible dialog) ------------------------------------------------------------
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
let _ret = null, _trap = null, _esc = null;
export function openModal(html, opts = {}) {
  const m = document.getElementById('modal');
  _ret = document.activeElement;
  m.innerHTML = `<div class="modal-scrim"></div><div class="modal-card ${opts.wide ? 'wide' : ''}" role="dialog" aria-modal="true"${opts.label ? ` aria-label="${esc(opts.label)}"` : ''}>${html}</div>`;
  m.classList.remove('hidden');
  requestAnimationFrame(() => m.classList.add('show'));
  const card = m.querySelector('.modal-card');
  m.querySelector('.modal-scrim').onclick = () => { if (!opts.sticky) closeModal(); };
  _trap = (e) => {
    if (e.key !== 'Tab') return;
    const items = [...card.querySelectorAll(FOCUSABLE)].filter(x => x.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  card.addEventListener('keydown', _trap);
  _esc = (e) => { if (e.key === 'Escape' && !opts.sticky) closeModal(); };
  document.addEventListener('keydown', _esc);
  requestAnimationFrame(() => (card.querySelector('input, [autofocus]') || card.querySelector(FOCUSABLE) || card).focus?.());
  return card;
}
export function closeModal() {
  const m = document.getElementById('modal');
  m.classList.remove('show');
  const ret = _ret; _ret = null; _trap = null;
  if (_esc) { document.removeEventListener('keydown', _esc); _esc = null; }
  setTimeout(() => { m.classList.add('hidden'); m.innerHTML = ''; }, 180);
  if (ret && ret.isConnected) ret.focus?.();
}

// ---- Loading + empty + error states -------------------------------------------------------
export function shimmerRows(n = 4) {
  return `<div class="shimmer-wrap">${Array.from({ length: n }, () => `<div class="shimmer-row"><div class="sh-av"></div><div class="sh-lines"><div class="sh-line w70"></div><div class="sh-line w40"></div></div><div class="sh-bars"></div></div>`).join('')}</div>`;
}
export function emptyState(iconName, title, sub) {
  return `<div class="empty"><div class="empty-glow">${icon(iconName)}</div><b>${esc(title)}</b><span>${esc(sub)}</span></div>`;
}
export function errorState(title, sub, retryId = '') {
  return `<div class="empty err"><div class="empty-glow bad">${icon('warn')}</div><b>${esc(title)}</b><span>${esc(sub)}</span>${retryId ? `<div class="empty-act"><button class="btn" id="${retryId}">${icon('refresh')} Retry</button></div>` : ''}</div>`;
}
export function meter(frac, cls = '') {
  const p = Math.max(0, Math.min(1, frac)) * 100;
  const c = cls || (p >= 90 ? 'bad' : p >= 75 ? 'warn' : 'good');
  return `<span class="mbar"><span class="mbar-fill ${c}" style="width:${p}%"></span></span>`;
}
