// views/abuse.js — abuse / moderation ops. Aggregates ANTI-ABUSE SIGNALS and the REPUTATION of
// gateway + mix operators (spec §9, §9.6). The whole point: accountability WITHOUT content. Every
// signal here is metadata — a rate ceiling, an anonymous ARC-token id, a bounce spike, an FBL
// complaint, a spam-trap hit, a PoW clearance — attributed to an accountable-but-anonymous
// credential, never to a message body, a recipient, or a sender's identity in clear (sealed sender
// preserved, spec §6.2). Superadmin can review and, at most, throttle a credential.

import { state, byKind, persist } from '../store.js';
import { bus } from '../bus.js';
import { el, esc, icon, emptyState, timeAgo, repBar, repClass, toast } from '../ui.js';

const SEV = { good: 'good', info: 'accent', warn: 'warn', bad: 'bad' };

export function render(root) {
  root.className = 'view scroll-view';
  const q = state.ui.search.trim().toLowerCase();
  const signals = state.signals.filter(s => !q || (s.label + ' ' + s.subject + ' ' + s.via + ' ' + s.kind).toLowerCase().includes(q));
  const gateways = byKind('gateway').filter(c => c.status !== 'decommissioned' && c.rep != null).sort((a, b) => a.rep - b.rep);
  const mixes = byKind('mix').filter(c => c.status !== 'decommissioned' && c.rep != null).sort((a, b) => a.rep - b.rep);

  const bad = state.signals.filter(s => s.sev === 'bad').length;
  const warn = state.signals.filter(s => s.sev === 'warn').length;
  const lowRep = [...gateways, ...mixes].filter(c => c.rep < 60).length;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Abuse ops</h1>
        <p class="page-sub">Aggregate anti-abuse signals and operator reputation. Accountability without content — the fairness model of spec §9, §9.6.</p>
      </div>
      <div class="page-head-aside"><span class="content-blind" title="The inviolable rule (spec §12.3)">${icon('lock')} content-blind</span></div>
    </header>

    <div class="banner good inviolable">${icon('shield')} <span><b>Metadata only, never content.</b> Every signal below is a rate, a token id, a bounce/complaint statistic or a reputation score. Sealed sender is preserved: abuse is attributed to an anonymous <b>accountable credential</b> (ARC token / postage / PoW), never a message body or a sender identity in clear (spec §6.2, §9).</span></div>

    <section class="abuse-stats">
      ${statTile('flame', bad, 'critical signals', bad ? 'bad' : 'good')}
      ${statTile('gauge', warn, 'warnings', warn ? 'warn' : 'good')}
      ${statTile('block', lowRep, 'operators throttled', lowRep ? 'bad' : 'good')}
      ${statTile('users', state.signals.reduce((n, s) => n + (s.count || 0), 0), 'attributed events', 'accent')}
    </section>

    <section class="ov-grid-2">
      <div class="card">
        <div class="card-h"><h2>${icon('gateway')} Gateway reputation <span class="pill dim sm">spec §9.6</span></h2></div>
        <p class="card-sub">IP + behaviour reputation per legacy gateway. Low reputation throttles egress and de-prioritizes a gateway in send routing — it never reveals what was sent.</p>
        <div class="rep-list">${repList(gateways, 'gateway')}</div>
      </div>
      <div class="card">
        <div class="card-h"><h2>${icon('mix')} Mix operator reputation <span class="pill dim sm">spec §4.4.8, §9.6</span></h2></div>
        <p class="card-sub">Reliability + diversity reputation per mix operator. Poor operators are down-weighted in path selection; the path builder still enforces per-hop operator independence.</p>
        <div class="rep-list">${repList(mixes, 'mix')}</div>
      </div>
    </section>

    <section class="card">
      <div class="card-h">
        <h2>${icon('activity')} Signal feed <span class="list-count">${signals.length}</span></h2>
        <span class="sim-tag">${icon('lock')} attributed to credentials, not identities</span>
      </div>
      <div class="signal-feed" id="signal-feed"></div>
    </section>
  </div>`;

  const feed = root.querySelector('#signal-feed');
  if (!signals.length) {
    feed.innerHTML = emptyState('search', 'No signals', q ? 'No signals match your search.' : 'No anti-abuse signals recorded.');
  } else {
    signals.forEach(s => {
      const row = el(`<div class="signal-row">
        <span class="signal-ic ${SEV[s.sev]}">${icon(s.icon)}</span>
        <div class="signal-main">
          <div class="signal-top"><b>${esc(s.label)}</b><span class="pill ${SEV[s.sev]} sm">${esc(s.sev)}</span>${s.count > 1 ? `<span class="pill dim sm">×${s.count}</span>` : ''}</div>
          <small class="signal-note">${esc(s.note)}</small>
          <small class="signal-meta">credential <span class="mono">${esc(s.subject)}</span> · via <span class="mono">${esc(s.via)}</span></small>
        </div>
        <div class="signal-side">
          <span class="signal-t">${esc(timeAgo(s.ts))}</span>
          ${s.sev === 'bad' || s.sev === 'warn' ? `<button class="btn ghost sm" data-throttle="${s.id}">${icon('block')} Throttle credential</button>` : ''}
        </div>
      </div>`);
      row.querySelector('[data-throttle]')?.addEventListener('click', () => {
        toast(`${icon('check')} Credential ${esc(s.subject)} throttled · no identity learned`);
      });
      feed.appendChild(row);
    });
  }
}

function statTile(ic, n, label, cls) {
  return `<div class="card stat-tile"><span class="st-ic ${cls}">${icon(ic)}</span><span class="st-n ${cls}">${esc(String(n))}</span><span class="st-l">${esc(label)}</span></div>`;
}

function repList(list, kind) {
  if (!list.length) return emptyState('gauge', 'No operators', 'No ' + kind + ' operators enrolled.');
  return list.map(c => `
    <div class="rep-row ${c.rep < 60 ? 'low' : ''}">
      <div class="rep-row-main"><b class="mono ellip">${esc(c.host)}</b><small class="mono">${esc(c.operator)}</small></div>
      ${repBar(c.rep)}
      <span class="pill ${repClass(c.rep)} sm">${c.rep >= 85 ? 'trusted' : c.rep >= 60 ? 'watch' : 'throttled'}</span>
    </div>`).join('');
}
