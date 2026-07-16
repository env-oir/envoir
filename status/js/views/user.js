// views/user.js — the authenticated "My status" view. Shows the individual user's own service
// health: their mailbox (reachability + storage + last sync), their node's reachability path
// (direct vs relay-fallback), any platform degradation currently affecting THEM, and their recent
// delivery outcomes (native vs legacy-bridge, delivered / delayed / queued). Honest and personal —
// it answers "is MY mail working right now, and if not, why?".

import { state, componentMeta } from '../store.js';
import { esc, icon, healthDot, healthPill, emptyState, meter, timeAgo, fmtLong, fmtBytes, COMP } from '../ui.js';

const DELIVERY = {
  delivered: { cls: 'good', label: 'Delivered', icon: 'check' },
  delayed: { cls: 'warn', label: 'Delayed', icon: 'clock' },
  queued: { cls: 'warn', label: 'Queued · retrying', icon: 'refresh' },
  failed: { cls: 'bad', label: 'Failed', icon: 'x' },
};

export function renderUser(root, actions) {
  const u = state.user;
  if (!u) { root.innerHTML = `<div class="status-page">${emptyState('user', 'Not signed in', 'Sign in to see your personal service health.')}</div>`; return; }

  const mailboxUp = u.mailbox.status === 'up';
  const reachOk = u.reachability.status === 'up';
  const overall = !mailboxUp ? 'down' : (!reachOk || u.legacy.status !== 'up' || u.affecting.length) ? 'degraded' : 'up';
  const heroCls = COMP[overall].cls;

  root.innerHTML = `
  <div class="status-page">
    <section class="user-hero ${heroCls}">
      <span class="uh-ic">${icon(overall === 'up' ? 'check' : overall === 'down' ? 'x' : 'warn')}</span>
      <div class="uh-main">
        <h1>${overall === 'up' ? 'Your mail is working normally' : overall === 'down' ? 'Your mailbox is unreachable' : 'Your mail is working, with some limits'}</h1>
        <p>${heroSub(u, overall)}</p>
        <div class="uh-tags"><span class="pill dim sm">${icon('user')} <span class="mono">${esc(u.address)}</span></span><span class="pill dim sm">${icon('server')} <span class="mono">${esc(u.node)}</span></span></div>
      </div>
    </section>

    ${u.affecting.length ? `
    <section class="affecting">
      <h2 class="affecting-h">${icon('bell')} Affecting you right now</h2>
      ${u.affecting.map(i => `
        <div class="affecting-row">
          <span class="affecting-ic">${icon('warn')}</span>
          <div class="affecting-body">
            <b>${esc(i.title)}</b>
            <p>${esc(i.updates[0].body)}</p>
            <small>${i.components.map(c => `<span class="comp-chip">${esc(componentMeta(c)?.name || c)}</span>`).join('')} · ${esc(timeAgo(i.started))}</small>
          </div>
        </div>`).join('')}
    </section>` : `<div class="all-clear">${icon('check')} <span>No platform incidents are affecting your account.</span></div>`}

    <section class="user-cards">
      <div class="card ucard">
        <div class="ucard-h"><span class="ucard-ic ${u.mailbox.status}">${icon('mail')}</span><h2>Mailbox</h2>${healthPill(u.mailbox.status)}</div>
        <p class="ucard-sub">Your hosted mailbox on <span class="mono">${esc(u.node)}</span>.</p>
        <div class="ucard-figs">
          <div class="ufig"><span class="uf-l">Storage</span><div class="uf-meter">${meter(u.mailbox.usedBytes / u.mailbox.quotaBytes)}<span class="mono">${fmtBytes(u.mailbox.usedBytes)} / ${fmtBytes(u.mailbox.quotaBytes)}</span></div></div>
          <div class="ufig row"><span class="uf-l">Last sync</span><b>${esc(timeAgo(u.mailbox.lastSync))}</b></div>
        </div>
      </div>

      <div class="card ucard">
        <div class="ucard-h"><span class="ucard-ic ${u.reachability.status}">${icon('wifi')}</span><h2>Reachability</h2>${healthPill(u.reachability.status)}</div>
        <p class="ucard-sub">How correspondents reach your node — direct first, relay as fallback (spec §4).</p>
        <div class="ucard-figs">
          <div class="ufig row"><span class="uf-l">Delivery path</span><b class="${u.reachability.path === 'direct' ? 'good' : 'warn'}">${u.reachability.path === 'direct' ? 'Direct P2P' : 'Relay fallback'}</b></div>
          <div class="ufig row"><span class="uf-l">Relay</span><b class="mono">${esc(u.reachability.relayNode)}</b></div>
          ${u.reachability.path !== 'direct' ? `<p class="ucard-hint">${icon('info')} Direct connectivity to your node is impaired; correspondents are being routed through the relay. Mail still flows — with a little added latency.</p>` : ''}
        </div>
      </div>

      <div class="card ucard">
        <div class="ucard-h"><span class="ucard-ic ${u.legacy.status}">${icon('gateway')}</span><h2>Legacy bridge</h2>${healthPill(u.legacy.status)}</div>
        <p class="ucard-sub">Sending to / receiving from legacy (SMTP) correspondents via the gateway.</p>
        <div class="ucard-figs">
          <div class="ufig row"><span class="uf-l">Native mail</span><b class="good">Unaffected</b></div>
          <div class="ufig row"><span class="uf-l">Legacy sends</span><b class="${u.legacy.status === 'up' ? 'good' : u.legacy.status === 'down' ? 'bad' : 'warn'}">${u.legacy.status === 'up' ? 'Normal' : u.legacy.status === 'down' ? 'Queued · retrying' : 'Delayed'}</b></div>
        </div>
      </div>
    </section>

    <section class="card recent">
      <div class="card-h"><h2>${icon('activity')} Recent delivery status</h2><span class="sim-tag">${icon('lock')} outcomes only, never content</span></div>
      <div class="delivery-list" id="delivery-list"></div>
    </section>
  </div>`;

  const dl = root.querySelector('#delivery-list');
  if (!u.deliveries.length) dl.innerHTML = emptyState('inbox', 'No recent activity', 'Your recent sends and receipts will appear here.');
  else dl.innerHTML = u.deliveries.map(d => {
    const s = DELIVERY[d.status] || DELIVERY.delivered;
    return `<div class="delivery-row">
      <span class="dr-dir ${d.dir}" title="${d.dir === 'out' ? 'Sent' : 'Received'}">${icon(d.dir === 'out' ? 'send' : 'inbox')}</span>
      <div class="dr-main"><b class="mono">${esc(d.peer)}</b><small>${d.dir === 'out' ? 'to' : 'from'} · ${d.kind === 'native' ? 'native DMTAP' : 'legacy bridge'}</small></div>
      <span class="pill ${s.cls} sm">${icon(s.icon)} ${esc(s.label)}</span>
      <span class="dr-t">${esc(timeAgo(d.ts))}</span>
    </div>`;
  }).join('');
}

function heroSub(u, overall) {
  if (overall === 'up') return 'Your mailbox is reachable, delivery is flowing, and no incidents touch your account.';
  if (overall === 'down') return 'Your home node is not responding to your client. Inbound mail is being held and retried at senders’ edges — nothing is lost — and will deliver once your node is reachable.';
  const bits = [];
  if (u.reachability.status !== 'up') bits.push('you are on a relay-fallback path');
  if (u.legacy.status !== 'up') bits.push('legacy-bridge sends are ' + (u.legacy.status === 'down' ? 'queued' : 'delayed'));
  if (u.affecting.length) bits.push('a platform incident affects a service you use');
  return 'Native mail is flowing normally' + (bits.length ? ', but ' + bits.join(', ') + '.' : '.');
}
