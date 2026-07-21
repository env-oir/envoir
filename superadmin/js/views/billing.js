// views/billing.js — the "Usage & metering" view. Reads the SIMULATED dmtap-seam Metering +
// Provisioning read model (crates/dmtap-seam): per-account metered OPERATIONS — hosted storage,
// gateway sends, inbound legacy, relayed bytes, managed domains, native messages — plus tier and
// suspend/resume. It surfaces the inviolable rule loudly: privacy/crypto is NEVER metered or gated
// (there is deliberately no quota for "encryption" or "metadata privacy"). Content-blind metering —
// Envoir computes no price or invoice here; an operator's own billing (if any) attaches externally
// at the `dmtap-seam` `BillingSink` boundary.

import { state, meterTotals, persist } from '../store.js';
import { bus } from '../bus.js';
import { el, esc, icon, emptyState, fmtBytes, fmtNum, fmtDate, toast, meter, openModal, closeModal } from '../ui.js';

const TIERS = {
  key_only: { label: 'Key-only', pill: 'dim', desc: 'Tier A — no domain, no DNS' },
  gateway_domain: { label: 'Gateway domain', pill: 'accent', desc: 'Tier B — name@gateway domain' },
  vanity_domain: { label: 'Vanity domain', pill: 'accent', desc: 'Tier C — name@yourbrand' },
};
const SORTS = [
  { id: 'storage', label: 'Storage', meter: 'storage_bytes', fmt: fmtBytes },
  { id: 'sends', label: 'Gateway sends', meter: 'gateway_sends', fmt: fmtNum },
  { id: 'relay', label: 'Relay bytes', meter: 'relay_bytes', fmt: fmtBytes },
  { id: 'domains', label: 'Domains', meter: 'domains', fmt: fmtNum },
];

export function render(root) {
  root.className = 'view scroll-view';
  const q = state.ui.search.trim().toLowerCase();
  const mt = meterTotals();
  const sortId = state.ui.billingSort || 'storage';
  const sort = SORTS.find(s => s.id === sortId) || SORTS[0];
  const accounts = state.accounts
    .filter(a => !q || (a.name + ' ' + a.id + ' ' + a.tier).toLowerCase().includes(q))
    .slice().sort((a, b) => (b.meters[sort.meter] || 0) - (a.meters[sort.meter] || 0));
  const maxV = Math.max(1, ...accounts.map(a => a.meters[sort.meter] || 0));
  const suspended = state.accounts.filter(a => a.suspended).length;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Usage &amp; metering <span class="pill accent sm">dmtap-seam</span></h1>
        <p class="page-sub">Per-account metered <b>operations</b> from the <span class="mono">Metering</span> + <span class="mono">Provisioning</span> seam — the genuine cost centers. ${state.accounts.length} accounts · ${suspended} suspended.</p>
      </div>
      <div class="page-head-aside"><span class="content-blind" title="The inviolable rule (spec §12.3)">${icon('lock')} content-blind</span></div>
    </header>

    <div class="banner good inviolable">${icon('shield')} <span><b>Privacy is never metered.</b> The seam has quotas for storage, gateway sends, domains and rate — and deliberately <b>none</b> for encryption, metadata privacy, or key access. No billing state can gate a protocol capability or read a message (<span class="mono">dmtap-seam</span> CONTRACT invariant, spec §12.3).</span></div>

    <section class="meter-tiles wide-tiles">
      ${bigTile('database', 'Hosted storage', fmtBytes(mt.storage_bytes), 'StorageBytes')}
      ${bigTile('gateway', 'Gateway sends', fmtNum(mt.gateway_sends), 'GatewaySend')}
      ${bigTile('mail', 'Inbound legacy', fmtNum(mt.inbound_legacy), 'InboundLegacy')}
      ${bigTile('relay', 'Relayed bytes', fmtBytes(mt.relay_bytes), 'RelayBytes')}
      ${bigTile('tag', 'Managed domains', fmtNum(mt.domains), 'VanityDomain')}
      ${bigTile('zap', 'Native messages', fmtNum(mt.messages_sent), 'MessagesSent · not billed')}
    </section>

    <section class="card">
      <div class="card-h">
        <h2>${icon('users')} Accounts <span class="list-count">${accounts.length}</span></h2>
        <div class="seg" role="group" aria-label="Sort accounts by">
          ${SORTS.map(s => `<button data-sort="${s.id}" class="${s.id === sortId ? 'on' : ''}" aria-pressed="${s.id === sortId}">${esc(s.label)}</button>`).join('')}
        </div>
      </div>
      <div class="bill-table" id="bill-table"></div>
    </section>
  </div>`;

  const table = root.querySelector('#bill-table');
  if (!accounts.length) {
    table.innerHTML = emptyState('search', 'No accounts', q ? 'No accounts match your search.' : 'No provisioned accounts.');
  } else {
    table.innerHTML = `
      <div class="bill-th"><span>Account</span><span>Tier</span><span>Seats</span><span>${esc(sort.label)}</span><span>Domains</span><span>Status</span></div>`;
    accounts.forEach(a => {
      const v = a.meters[sort.meter] || 0;
      const row = el(`<div class="bill-tr ${a.suspended ? 'susp' : ''}" data-id="${a.id}" tabindex="0" role="button" aria-label="Account ${esc(a.name)}">
        <span class="bill-acct"><b class="mono">${esc(a.name)}</b><small class="mono">${esc(a.id)}</small></span>
        <span><span class="pill ${TIERS[a.tier].pill} sm">${esc(TIERS[a.tier].label)}</span></span>
        <span class="mono">${fmtNum(a.seats)}</span>
        <span class="bill-metric">${meter(v / maxV, 'accent')}<b class="mono">${sort.fmt(v)}</b></span>
        <span class="mono">${a.meters.domains || '—'}</span>
        <span>${a.suspended ? `<span class="pill bad sm">${icon('block')} suspended</span>` : `<span class="pill good sm">active</span>`}</span>
      </div>`);
      row.onclick = () => accountModal(a);
      row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); accountModal(a); } };
      table.appendChild(row);
    });
  }

  root.querySelectorAll('[data-sort]').forEach(b => b.onclick = () => { state.ui.billingSort = b.dataset.sort; bus.rerender(); });
}

function bigTile(ic, label, value, meterName) {
  return `<div class="card meter-tile big"><span class="mt-ic">${icon(ic)}</span><div class="mt-body"><span class="mt-v">${esc(value)}</span><span class="mt-l">${esc(label)}</span><span class="mt-kind mono">${esc(meterName)}</span></div></div>`;
}

// ---- account detail: metered operations + suspend/resume ----------------------------------
function accountModal(a) {
  const M = a.meters;
  const rows = [
    ['database', 'Hosted storage', fmtBytes(M.storage_bytes), 'StorageBytes'],
    ['gateway', 'Gateway sends', fmtNum(M.gateway_sends), 'GatewaySend'],
    ['mail', 'Inbound legacy', fmtNum(M.inbound_legacy), 'InboundLegacy'],
    ['relay', 'Relayed bytes', fmtBytes(M.relay_bytes), 'RelayBytes'],
    ['tag', 'Managed domains', fmtNum(M.domains), 'VanityDomain'],
    ['zap', 'Native messages', fmtNum(M.messages_sent), 'MessagesSent'],
  ];
  const card = openModal(`
    <div class="modal-head"><h2>${icon('users')} <span class="mono">${esc(a.name)}</span></h2><button class="icon-btn" id="ax" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <div class="acct-meta">
        <span class="pill ${TIERS[a.tier].pill} sm">${esc(TIERS[a.tier].label)}</span>
        <span class="pill dim sm">${esc(a.id)}</span>
        <span class="pill dim sm">${fmtNum(a.seats)} seats</span>
        <span class="pill ${a.suspended ? 'bad' : 'good'} sm">${a.suspended ? 'suspended' : 'active'}</span>
      </div>
      <p class="acct-tierdesc muted">${esc(TIERS[a.tier].desc)} · provisioned ${esc(fmtDate(a.created))}</p>
      <div class="acct-meters">
        ${rows.map(([ic, label, value, kind]) => `<div class="acct-meter"><span class="am-ic">${icon(ic)}</span><div class="am-body"><span class="am-l">${esc(label)}</span><span class="am-kind mono">${esc(kind)}</span></div><b class="am-v mono">${esc(value)}</b></div>`).join('')}
      </div>
      <p class="modal-note warn">${icon('lock')} <span>These are the <b>only</b> dimensions the seam observes for this account. Suspending stops <b>new metered operations</b> — it never touches the account's keys, mailbox contents, or ability to read what it already holds.</span></p>
    </div>
    <div class="modal-foot">
      <button class="btn ghost" id="acancel">Close</button>
      <div class="spacer"></div>
      <button class="btn ${a.suspended ? 'primary' : 'danger'}" id="atoggle">${icon(a.suspended ? 'refresh' : 'block')} ${a.suspended ? 'Resume account' : 'Suspend account'}</button>
    </div>`, { wide: true, label: 'Account billing detail' });
  card.querySelector('#ax').onclick = card.querySelector('#acancel').onclick = closeModal;
  card.querySelector('#atoggle').onclick = () => {
    a.suspended = !a.suspended; persist();
    closeModal();
    toast(`${icon('check')} ${esc(a.name)} ${a.suspended ? 'suspended' : 'resumed'}`);
    bus.rerender();
  };
}
