// views/gateway.js — domain-wide gateway & relay policy. Two operator-facing surfaces a domain
// owner controls without ever touching a member's key (spec §3.10.1):
//
//   HOSTING       — whether this domain's mailboxes live on the operator's hosted node
//                   (metered storage) or on a node this domain runs itself (self-hosted, $0).
//   LEGACY BRIDGE — whether SMTP correspondents may reach this domain via the gateway bridge
//                   (spec §7.2a), and which bridge operators are trusted to attest bridged mail.
//   RELAY         — direct-first (default) vs relay-required, and which reachability-relay
//                   operators (spec §4) this domain trusts as a fallback path.
//
// Every change here is KT-logged (nothing an admin does is silent) and read directly by Billing —
// flipping a switch here changes what's metered there, not just a label.

import { state, logEvent } from '../store.js';
import { bus } from '../bus.js';
import { el, esc, icon, emptyState, toast } from '../ui.js';

export function render(root) {
  root.className = 'view scroll-view';
  const d = state.domain;
  const p = d.policy;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Gateway &amp; relay policy</h1>
        <p class="page-sub">Domain-wide policy for the legacy SMTP↔DMTAP bridge (spec §7.2a) and the reachability relay (spec §4) — where <span class="mono">@${esc(d.name)}</span> is hosted, and which operators it trusts to carry bridged and relayed traffic. Read by Billing: self-hosting or disabling a path zeroes its metered cost there.</p>
      </div>
    </header>

    <section class="ov-grid-2">
      <div class="card">
        <div class="card-h"><h2>${icon('server')} Hosting</h2></div>
        <p class="card-sub">Where <span class="mono">@${esc(d.name)}</span> mailboxes live. A policy choice about infrastructure — never about a member's key.</p>
        <div class="seg" id="hostmode" role="group" aria-label="Hosting model">
          <button data-h="org-hosted" aria-pressed="${p.selfHost === 'org-hosted'}" class="${p.selfHost === 'org-hosted' ? 'on' : ''}">${icon('building')} Operator-hosted</button>
          <button data-h="self-hosted" aria-pressed="${p.selfHost === 'self-hosted'}" class="${p.selfHost === 'self-hosted' ? 'on' : ''}">${icon('server')} Self-hosted</button>
        </div>
        <p class="vis-explain">${p.selfHost === 'self-hosted'
          ? `This domain runs its own node. Hosted storage is not metered by the operator — <b>$0</b> (see Billing).`
          : `Mailboxes live on the operator's hosted node. Storage is metered per spec (see Billing).`}</p>
      </div>

      <div class="card">
        <div class="card-h"><h2>${icon('gateway')} Legacy bridge</h2></div>
        <p class="card-sub">Whether legacy SMTP correspondents can reach this domain via the bridge. Disabling makes the domain native-only.</p>
        <div class="seg" id="lbmode" role="group" aria-label="Legacy bridge">
          <button data-l="1" aria-pressed="${p.legacyBridge}" class="${p.legacyBridge ? 'on' : ''}">${icon('check')} Enabled</button>
          <button data-l="0" aria-pressed="${!p.legacyBridge}" class="${!p.legacyBridge ? 'on' : ''}">${icon('x')} Disabled</button>
        </div>
        <p class="vis-explain">${p.legacyBridge
          ? `Legacy sends/receives are metered per-message (see Billing).`
          : `Native-only: no legacy SMTP correspondence. Nothing metered here — <b>$0</b>.`}</p>
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('gateway')} Trusted gateway operators <span class="list-count">${p.trustedGateways.length}</span></h2></div>
      <p class="card-sub">Legacy-bridge operators this domain accepts bridged mail through. An operator not on this list is not trusted to attest bridged mail for <span class="mono">@${esc(d.name)}</span> (spec §7.2a).</p>
      <div class="roster" id="gw-list"></div>
      <div class="trust-add">
        <input id="gw-add" placeholder="gw3.eu-central.envoir.net" ${p.legacyBridge ? '' : 'disabled'} autocomplete="off" spellcheck="false">
        <button class="btn sm" id="gw-add-btn" ${p.legacyBridge ? '' : 'disabled'}>${icon('plus')} Trust</button>
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('relay')} Reachability relay</h2></div>
      <p class="card-sub">Direct P2P is always attempted first; a relay is the fallback path when a node isn't directly reachable (spec §4).</p>
      <div class="seg" id="relaymode" role="group" aria-label="Relay mode">
        <button data-r="direct-first" aria-pressed="${p.relayMode === 'direct-first'}" class="${p.relayMode === 'direct-first' ? 'on' : ''}">${icon('wifi')} Direct-first</button>
        <button data-r="relay-required" aria-pressed="${p.relayMode === 'relay-required'}" class="${p.relayMode === 'relay-required' ? 'on' : ''}">${icon('relay')} Relay-required</button>
      </div>
      <p class="vis-explain">${p.relayMode === 'relay-required'
        ? `All traffic is routed through a trusted relay — fully metered relay bytes.`
        : `Relay is only used as a fallback — most traffic is direct and unmetered.`}</p>
      <div class="roster" id="relay-list" style="margin-top:14px"></div>
      <div class="trust-add">
        <input id="relay-add" placeholder="relay2.eu-west.envoir.net" autocomplete="off" spellcheck="false">
        <button class="btn sm" id="relay-add-btn">${icon('plus')} Trust</button>
      </div>
    </section>
  </div>`;

  drawTrustList(root.querySelector('#gw-list'), p.trustedGateways, 'gateway', async (host) => {
    p.trustedGateways = p.trustedGateways.filter(h => h !== host);
    await logEvent('domain', `Untrusted gateway operator ${host}`);
    toast(`${icon('check')} Untrusted ${esc(host)}`); bus.rerender();
  });
  drawTrustList(root.querySelector('#relay-list'), p.trustedRelays, 'relay', async (host) => {
    p.trustedRelays = p.trustedRelays.filter(h => h !== host);
    await logEvent('domain', `Untrusted relay operator ${host}`);
    toast(`${icon('check')} Untrusted ${esc(host)}`); bus.rerender();
  });

  root.querySelectorAll('#hostmode [data-h]').forEach(b => b.onclick = async () => {
    if (p.selfHost === b.dataset.h) return;
    p.selfHost = b.dataset.h;
    await logEvent('domain', `Hosting policy → ${p.selfHost}`);
    toast(`${icon('check')} Hosting → ${p.selfHost === 'self-hosted' ? 'self-hosted' : 'operator-hosted'}`);
    bus.rerender();
  });
  root.querySelectorAll('#lbmode [data-l]').forEach(b => b.onclick = async () => {
    const on = b.dataset.l === '1';
    if (p.legacyBridge === on) return;
    p.legacyBridge = on;
    await logEvent('domain', `Legacy bridge → ${on ? 'enabled' : 'disabled'}`);
    toast(`${icon('check')} Legacy bridge ${on ? 'enabled' : 'disabled'}`);
    bus.rerender();
  });
  root.querySelectorAll('#relaymode [data-r]').forEach(b => b.onclick = async () => {
    if (p.relayMode === b.dataset.r) return;
    p.relayMode = b.dataset.r;
    await logEvent('domain', `Relay policy → ${p.relayMode}`);
    toast(`${icon('check')} Relay policy → ${p.relayMode}`);
    bus.rerender();
  });

  const addTrust = async (inputId, listKey, kind) => {
    const input = root.querySelector('#' + inputId);
    const host = input.value.trim().toLowerCase();
    if (!host) return toast(`${icon('warn')} Enter a hostname`);
    if (p[listKey].includes(host)) return toast(`${icon('warn')} ${host} is already trusted`);
    p[listKey] = [...p[listKey], host];
    await logEvent('domain', `Trusted ${kind} operator ${host}`);
    toast(`${icon('check')} Trusted ${esc(host)}`);
    bus.rerender();
  };
  root.querySelector('#gw-add-btn').onclick = () => addTrust('gw-add', 'trustedGateways', 'gateway');
  root.querySelector('#relay-add-btn').onclick = () => addTrust('relay-add', 'trustedRelays', 'relay');
}

function drawTrustList(wrap, list, kind, onRemove) {
  if (!list.length) { wrap.innerHTML = emptyState('search', 'No trusted operators', 'Add a hostname to trust it.'); return; }
  wrap.innerHTML = '';
  list.forEach(host => {
    const row = el(`<div class="roster-row">
      <span class="av grp" style="width:32px;height:32px">${icon(kind)}</span>
      <div class="roster-main"><span class="rr-name mono">${esc(host)}</span></div>
      <button class="icon-btn sm" data-rm="${esc(host)}" title="Untrust ${esc(host)}" aria-label="Untrust ${esc(host)}">${icon('minus')}</button>
    </div>`);
    row.querySelector('[data-rm]').onclick = () => onRemove(host);
    wrap.appendChild(row);
  });
}
