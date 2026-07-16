// ui.js — rendering primitives for the Envoir Superadmin. Pure DOM, no framework, no external
// assets. Icons are inline stroke SVGs; the modal is an accessible focus-trapped dialog. Shares
// the reference client/console "instrument-panel" design language on the Aurora Indigo palette so
// the operator console feels like part of the same product.

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
export const fmtDate = (t) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
export const fmtLong = (t) => new Date(t).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }) +
  ' · ' + new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

// ---- byte + number formatting -------------------------------------------------------------
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
export const pct = (n) => (Math.round(n * 10) / 10).toFixed(n >= 99.95 ? 2 : n >= 10 ? 1 : 2) + '%';

// ---- Icon set (stroke SVGs) ---------------------------------------------------------------
const P = {
  home: '<path d="M4 11l8-7 8 7"/><path d="M6 10v9h12v-9"/><path d="M10 19v-5h4v5"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4"/>',
  gateway: '<path d="M4 20V10l8-5 8 5v10"/><path d="M4 20h16"/><path d="M9 20v-5h6v5"/><path d="M12 5V2"/>',
  mix: '<path d="M3 6h4l10 12h4"/><path d="M17 4l4 2-4 2"/><path d="M3 18h4l3-3.5"/><path d="M14 9.5L17 6"/>',
  relay: '<path d="M12 13a2 2 0 100-4 2 2 0 000 4z"/><path d="M7.8 16.2a6 6 0 010-8.4M16.2 7.8a6 6 0 010 8.4M5 19a10 10 0 010-14M19 5a10 10 0 010 14"/>',
  fleet: '<rect x="3" y="4" width="8" height="7" rx="1.6"/><rect x="13" y="4" width="8" height="7" rx="1.6"/><rect x="3" y="14" width="8" height="6" rx="1.6"/><rect x="13" y="14" width="8" height="6" rx="1.6"/>',
  billing: '<path d="M6 3h9l4 4v14l-2.5-1.5L14 21l-2.5-1.5L9 21l-2.5-1.5L4 21V3z"/><path d="M8 9h8M8 13h5"/>',
  abuse: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/><path d="M12 8v4M12 15h.01"/>',
  provision: '<path d="M4 7l8-4 8 4-8 4-8-4z"/><path d="M4 7v6l8 4 8-4V7"/><path d="M4 13v4l8 4 8-4v-4"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 2v3M14 2v3M10 19v3M14 19v3M2 10h3M2 14h3M19 10h3M19 14h3"/>',
  database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  more: '<circle cx="6" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4-4"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M5 15V6a2 2 0 012-2h9"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  warn: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  shield: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/>',
  shieldcheck: '<path d="M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6z"/><path d="M8.5 12l2.2 2.2L15.5 9.5" stroke-width="1.6"/>',
  moon: '<path d="M20 14a8 8 0 11-9-9 6.5 6.5 0 009 9z"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.5 4.5l1.8 1.8M17.7 17.7l1.8 1.8M19.5 4.5l-1.8 1.8M6.3 17.7l-1.8 1.8"/>',
  bell: '<path d="M6 9a6 6 0 1112 0c0 6 2 7 2 7H4s2-1 2-7z"/><path d="M10 20a2 2 0 004 0"/>',
  refresh: '<path d="M4 9a8 8 0 0114-3l2 2m0-4v4h-4"/><path d="M20 15a8 8 0 01-14 3l-2-2m0 4v-4h4"/>',
  trash: '<path d="M5 7h14"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7v5l3.5 2"/>',
  zap: '<path d="M13 3L4 14h6l-1 7 9-11h-6z"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="M11 12l8-8M17 6l2 2M15 8l2 2"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M4 7l8 6 8-6"/>',
  tag: '<path d="M3 12l9-9 8 8-9 9z"/><circle cx="14.5" cy="9.5" r="1.4"/>',
  gauge: '<path d="M4 18a8 8 0 1116 0"/><path d="M12 18l4-5"/><circle cx="12" cy="18" r="1.2"/>',
  up: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  down: '<path d="M12 5v14M6 13l6 6 6-6"/>',
  wifi: '<path d="M2 8.8a16 16 0 0120 0M5 12a11 11 0 0114 0M8 15.2a6 6 0 018 0"/><circle cx="12" cy="19" r="1.1"/>',
  box: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',
  users: '<circle cx="9" cy="9" r="3.2"/><circle cx="17" cy="10" r="2.4"/><path d="M3 20c0-3 2.7-4.8 6-4.8s6 1.8 6 4.8"/><path d="M15.5 20c0-2.2 1.4-3.6 3.2-3.6 1.3 0 2.5.7 3.1 1.9"/>',
  block: '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
  flame: '<path d="M12 3s5 4 5 9a5 5 0 01-10 0c0-1.5.6-2.6 1.3-3.4C9 10 9.5 9 9 7c2 .5 3 2.5 3 4 .8-.8 1-2 1-3 0-2-1-5-1-5z"/>',
  kt: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13l1.6 1.6L14 11" stroke-width="1.6"/><path d="M9 17h6"/>',
};
export function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}
export const hasIcon = (n) => !!P[n];

// ---- Envoir brand mark (Aurora Indigo gradient, "@" ring with inner "e") ------------------
export function brandMark(size = 30) {
  const id = 'sam-' + size;
  return `<svg width="${size}" height="${size}" viewBox="0 0 128 128" fill="none" aria-label="Envoir">
    <defs><linearGradient id="${id}" x1="16" y1="12" x2="112" y2="116" gradientUnits="userSpaceOnUse"><stop stop-color="#4C4DFF"/><stop offset="1" stop-color="#9A4DFF"/></linearGradient></defs>
    <rect x="8" y="8" width="112" height="112" rx="30" fill="url(#${id})"/>
    <path d="M64 30a34 34 0 1024 58" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round"/>
    <path d="M50 66a14 14 0 1114 14" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round"/>
    <path d="M50 66h20" stroke="#fff" stroke-width="7" stroke-linecap="round"/>
  </svg>`;
}

// ---- Status dot + health pill (up / degraded / down) --------------------------------------
export const HEALTH = {
  up: { label: 'operational', cls: 'good', dot: 'up' },
  degraded: { label: 'degraded', cls: 'warn', dot: 'degraded' },
  down: { label: 'down', cls: 'bad', dot: 'down' },
};
export function healthDot(status) {
  return `<span class="hdot ${status}" title="${HEALTH[status]?.label || status}"></span>`;
}
export function healthPill(status, sm = true) {
  const h = HEALTH[status] || { label: status, cls: 'dim' };
  return `<span class="pill ${h.cls}${sm ? ' sm' : ''}">${healthDot(status)}${esc(h.label)}</span>`;
}

// ---- Reputation meter (0–100, spec §9.6) --------------------------------------------------
export function repClass(v) { return v >= 85 ? 'good' : v >= 60 ? 'warn' : 'bad'; }
export function repBar(v) {
  const c = repClass(v);
  return `<span class="rep"><span class="rep-track"><span class="rep-fill ${c}" style="width:${Math.max(3, v)}%"></span></span><b class="rep-n ${c}">${v}</b></span>`;
}

// ---- generic meter bar --------------------------------------------------------------------
export function meter(frac, cls = '') {
  const p = Math.max(0, Math.min(1, frac)) * 100;
  const c = cls || (p >= 90 ? 'bad' : p >= 75 ? 'warn' : 'good');
  return `<span class="mbar"><span class="mbar-fill ${c}" style="width:${p}%"></span></span>`;
}

// ---- attestation badge (spec §7.2a / §4.4.8) ----------------------------------------------
export function attestBadge(a, sm = true) {
  const s = sm ? ' sm' : '';
  if (!a || a.status === 'n/a') return `<span class="pill dim${s}" title="Attestation not applicable to this component kind">n/a</span>`;
  if (a.status === 'valid') return `<span class="pill good${s}" title="Domain-anchored attestation verifies (spec §7.2a)">${icon('shieldcheck')} attested</span>`;
  if (a.status === 'stale') return `<span class="pill warn${s}" title="Attestation key rotation pending — re-verify">${icon('warn')} stale</span>`;
  return `<span class="pill bad${s}" title="No valid attestation — component quarantined from serving">${icon('block')} unattested</span>`;
}

// ---- avatars: deterministic gradient + initials -------------------------------------------
export function initials(name) {
  const parts = (name || '?').replace(/^@/, '').split(/[\s.@\-_]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0] || '?').slice(0, 2).toUpperCase();
}

// ---- sparkline (inline svg polyline) ------------------------------------------------------
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

// ---- Toast --------------------------------------------------------------------------------
export function toast(msg, opts = {}) {
  const t = document.getElementById('toast');
  const ms = opts.ms || 3000;
  t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite');
  t.innerHTML = `<span>${msg}</span>`;
  t.classList.remove('hidden'); t.classList.add('show');
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.classList.add('hidden'), 200); }, ms);
  return t;
}

// ---- Modal (accessible dialog: role=dialog + aria-modal, Tab focus-trap, focus restore) ---
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
let _modalReturnFocus = null, _modalTrap = null, _escHandler = null;

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
  _escHandler = (e) => { if (e.key === 'Escape' && !opts.sticky) closeModal(); };
  document.addEventListener('keydown', _escHandler);
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
  if (_escHandler) { document.removeEventListener('keydown', _escHandler); _escHandler = null; }
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

export function copyBtn(text, label = 'Copy') {
  const b = el(`<button class="icon-btn sm" title="${esc(label)}" aria-label="${esc(label)}">${icon('copy')}</button>`);
  b.onclick = () => { navigator.clipboard?.writeText(text); toast(`${icon('check')} Copied`); };
  return b;
}
