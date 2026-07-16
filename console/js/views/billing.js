// views/billing.js — the domain's plan + usage view. Reads the same TIERS vocabulary the
// operator's dmtap-seam uses (key_only / gateway_domain / vanity_domain) and shows what this
// domain is actually billed for — which is deliberately narrow: hosted storage, legacy-bridge
// sends/receives, and relay bytes ONLY, and only while the Gateway policy screen says this domain
// draws on operator infrastructure for them. Native DMTAP mail, mixnet routing, the KT log and
// directory resolution are never metered, at any tier — sovereignty isn't a paid feature.

import { state, effectiveMeters, logEvent } from '../store.js';
import { bus } from '../bus.js';
import { esc, icon, toast, fmtBytes, fmtNum, fmtUsd } from '../ui.js';

const TIERS = {
  key_only: { label: 'Key-only', price: 0, blurb: 'Name→key resolution only — no hosted domain, no gateway.' },
  gateway_domain: { label: 'Gateway domain', price: 6, blurb: 'name@ under a shared operator domain, legacy bridge available.' },
  vanity_domain: { label: 'Vanity domain', price: 12, blurb: 'This domain, fully managed — vanity DNS + directory hosting.' },
};

// per-unit illustrative pricing — clearly a demo estimate, not a real invoice
const PRICE = { storage: 0.02 / 1e9, sends: 0.001, legacy: 0.0006, relay: 0.05 / 1e9 };

export function render(root) {
  root.className = 'view scroll-view';
  const d = state.domain;
  const p = d.policy;
  const tier = TIERS[d.billing.tier] || TIERS.gateway_domain;
  const m = effectiveMeters();

  const lines = [
    { icon: 'database', label: 'Hosted storage', used: fmtBytes(m.storage_bytes), cost: m.storage_bytes * PRICE.storage, free: p.selfHost === 'self-hosted', freeNote: 'self-hosted' },
    { icon: 'gateway', label: 'Legacy-bridge sends', used: fmtNum(m.gateway_sends), cost: m.gateway_sends * PRICE.sends, free: !p.legacyBridge, freeNote: 'bridge disabled' },
    { icon: 'mail', label: 'Legacy-bridge receives', used: fmtNum(m.inbound_legacy), cost: m.inbound_legacy * PRICE.legacy, free: !p.legacyBridge, freeNote: 'bridge disabled' },
    { icon: 'relay', label: 'Relay bytes', used: fmtBytes(m.relay_bytes), cost: m.relay_bytes * PRICE.relay, free: false, freeNote: '' },
  ];
  const metered = lines.reduce((n, l) => n + (l.free ? 0 : l.cost), 0);
  const total = tier.price + metered;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Billing <span class="pill accent sm">dmtap-seam</span></h1>
        <p class="page-sub">What <span class="mono">@${esc(d.name)}</span> is actually billed for — the same narrow set of <b>operations</b> the operator's seam meters, never a protocol capability (spec §12.3). Gateway policy decides what's metered here.</p>
      </div>
    </header>

    <div class="banner good inviolable">${icon('shield')} <span><b>Privacy is never metered.</b> Native DMTAP mail, mixnet routing, the KT log and directory resolution are <b>$0 always</b> — at every tier, for every domain. There is deliberately no quota for encryption, metadata privacy, or key access.</span></div>

    <section class="card">
      <div class="card-h"><h2>${icon('billing')} Plan</h2></div>
      <p class="card-sub">Choose the tier that matches how <span class="mono">@${esc(d.name)}</span> is provisioned. Changing tier does not touch any member's key.</p>
      <div class="model-select">
        ${Object.entries(TIERS).map(([id, t]) => `
          <button class="model-opt ${d.billing.tier === id ? 'sel' : ''}" data-tier="${id}">
            <div class="model-opt-h">${icon('billing')} ${esc(t.label)} <span class="spacer"></span><span class="mono">${t.price ? '$' + t.price + '/mo' : 'free'}</span></div>
            <p>${esc(t.blurb)}</p>
          </button>`).join('')}
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('database')} This period's usage</h2><span class="pill dim sm">estimate</span></div>
      <p class="card-sub">Gateway-metered line items — zeroed the moment the corresponding policy in <b>Gateway &amp; relay policy</b> says this domain isn't drawing on operator infrastructure for it.</p>
      <div class="bill-lines" id="bill-lines"></div>
      <button class="btn ghost sm bill-adjust" id="goto-gateway">${icon('gateway')} Adjust in Gateway &amp; relay policy →</button>
      <div class="bill-total">
        <span>Plan (${esc(tier.label)})</span><b class="mono">${fmtUsd(tier.price)}</b>
      </div>
      <div class="bill-total">
        <span>Metered usage</span><b class="mono">${fmtUsd(metered)}</b>
      </div>
      <div class="bill-total grand">
        <span>Estimated this period</span><b class="mono">${fmtUsd(total)}</b>
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('scale')} Always $0</h2></div>
      <p class="card-sub">These are never billed, at any tier, for any domain — the sovereignty guarantee has no price tag.</p>
      <div class="always-free">
        <div class="af-item">${icon('send')} <div><b>Native DMTAP mail</b><small>direct P2P delivery, spec §4</small></div></div>
        <div class="af-item">${icon('directory')} <div><b>Mixnet routing</b><small>metadata-hiding transit, spec §4.4</small></div></div>
        <div class="af-item">${icon('kt')} <div><b>Key Transparency</b><small>log reads &amp; appends, spec §3.5</small></div></div>
        <div class="af-item">${icon('search')} <div><b>Directory resolution</b><small>name→key lookups, spec §3.10</small></div></div>
      </div>
    </section>
  </div>`;

  const linesWrap = root.querySelector('#bill-lines');
  linesWrap.innerHTML = lines.map(l => `
    <div class="bill-line">
      <span class="bl-ic">${icon(l.icon)}</span>
      <div class="bl-main"><b>${esc(l.label)}</b><small class="mono">${esc(l.used)}</small></div>
      ${l.free
        ? `<span class="pill good sm">${icon('check')} $0 · ${esc(l.freeNote)}</span>`
        : `<b class="mono bl-cost">${fmtUsd(l.cost)}</b>`}
    </div>`).join('');

  root.querySelector('#goto-gateway').onclick = () => bus.setView('gateway');

  root.querySelectorAll('[data-tier]').forEach(b => b.onclick = async () => {
    const id = b.dataset.tier;
    if (d.billing.tier === id) return;
    d.billing.tier = id;
    await logEvent('domain', `Billing tier → ${TIERS[id].label}`);
    toast(`${icon('check')} Plan → ${TIERS[id].label}`);
    bus.rerender();
  });
}
