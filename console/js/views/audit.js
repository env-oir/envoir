// views/audit.js — the KT-logged, owner-visible audit trail (spec §3.5, §13.5.1). Every
// administrative act — provisioning, offboarding, directory publications, role grants/revokes,
// group changes, and any exercise of an escrowed key — is appended here as a hash-chained record.
// This is the "nothing silent" guarantee: a silently installed admin grant or auto-forward rule
// is visible to the owner's devices and alertable. Presented append-only, newest first.

import { state } from '../store.js';
import { esc, icon, emptyState, timeAgo, fmtLong } from '../ui.js';

const KIND = {
  domain: { icon: 'domain', label: 'Domain', hue: 262 },
  member: { icon: 'members', label: 'Member', hue: 210 },
  directory: { icon: 'directory', label: 'Directory', hue: 150 },
  group: { icon: 'groups', label: 'Group', hue: 46 },
  role: { icon: 'roles', label: 'Role', hue: 190 },
  security: { icon: 'warn', label: 'Security', hue: 8 },
};

export function render(root) {
  root.className = 'view scroll-view';
  const q = state.ui.search.trim().toLowerCase();
  const events = state.audit.filter(e => !q || (e.summary + ' ' + e.kind).toLowerCase().includes(q));

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Audit log <span class="pill accent sm">KT-logged</span></h1>
        <p class="page-sub">An append-only, hash-chained record of every administrative act. Nothing an admin does is silent — a covert grant is detectable and alertable (spec §3.5, §13.5.1).</p>
      </div>
    </header>

    <div class="audit-filter" id="audit-filter">
      <button class="chip on" data-k="">All</button>
      ${Object.entries(KIND).map(([k, m]) => `<button class="chip" data-k="${k}">${icon(m.icon)} ${m.label}</button>`).join('')}
    </div>

    <section class="card">
      <div class="audit-chain" id="chain"></div>
    </section>
  </div>`;

  let filterKind = '';
  const chain = root.querySelector('#chain');
  const draw = () => {
    const list = events.filter(e => !filterKind || e.kind === filterKind);
    if (!list.length) { chain.innerHTML = emptyState('audit', 'No events', q || filterKind ? 'No events match this filter.' : 'Administrative actions will appear here.'); return; }
    chain.innerHTML = list.map((e, i) => {
      const m = KIND[e.kind] || { icon: 'info', label: e.kind, hue: 220 };
      return `<div class="audit-row">
        <div class="audit-rail"><span class="audit-node" style="--h:${m.hue}">${icon(m.icon)}</span>${i < list.length - 1 ? '<span class="audit-line"></span>' : ''}</div>
        <div class="audit-body">
          <div class="audit-top"><span class="pill dim sm">${esc(m.label)}</span><b>${esc(e.summary)}</b>${e.threshold ? `<span class="pill accent sm">${icon('shield')} threshold</span>` : ''}${e.flag === 'escrow-use' || e.kind === 'security' ? `<span class="pill warn sm">${icon('unlock')} escrow</span>` : ''}</div>
          <div class="audit-meta"><span class="mono">${esc(e.hash)}</span> · prev <span class="mono">${esc((e.prev || '').slice(0, 12))}</span> · by <span class="mono">${esc(e.actor || '')}</span></div>
        </div>
        <span class="audit-time" title="${esc(fmtLong(e.ts))}">${esc(timeAgo(e.ts))}</span>
      </div>`;
    }).join('');
  };
  draw();

  root.querySelectorAll('#audit-filter .chip').forEach(b => b.onclick = () => {
    filterKind = b.dataset.k;
    root.querySelectorAll('#audit-filter .chip').forEach(x => x.classList.toggle('on', x === b));
    draw();
  });
}
