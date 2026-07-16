// views/overview.js — the console home. Summarises the domain authority (threshold-held), the
// DNS/kt anchor status, the shape of the membership (sovereign vs org-managed), and the standing
// sovereignty guarantee — made legible up front: a domain owner should SEE what they can and
// cannot do to a member (spec §3.10.1–§3.10.2).

import { state, republishDirectory, ktTreeSize, ktRootHash, ktIsFresh, verifyKtCheckpoint, ktTreeHistory, memberGrowthHistory } from '../store.js';
import { collectThreshold } from '../session.js';
import { bus } from '../bus.js';
import { esc, icon, safetyGrid, safetyWords, emptyState, toast, timeAgo, copyBtn, fmtNum, sparkline } from '../ui.js';

export function render(root) {
  root.className = 'view scroll-view';
  const d = state.domain;
  const active = state.members.filter(m => m.status === 'active');
  const sovereign = active.filter(m => m.custody === 'sovereign').length;
  const managed = active.filter(m => m.custody === 'org-managed').length;
  const caps = state.caps.filter(c => !c.revoked).length;
  const treeSize = ktTreeSize();
  const rootHash = ktRootHash();
  const staleCount = d.ktWitnesses.filter(w => !ktIsFresh(w)).length;
  const allFresh = staleCount === 0;
  const dnsRows = [
    ['dmtap', '_dmtap anchor', 'Publishes the domain authority IK and directory locator'],
    ['kt', 'kt= transparency', 'Append-only log of every name→key binding change'],
    ['dkim', 'DKIM', 'Signs outbound legacy-bridge mail'],
    ['dmarc', 'DMARC', 'Rejects spoofed legacy mail for the domain'],
    ['dir', 'dir= locator', 'Where the published DomainDirectory object lives'],
  ];

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Overview</h1>
        <p class="page-sub">Everything the console administers under <span class="mono">@${esc(d.name)}</span> — names and operations, never a sovereign member's key.</p>
      </div>
    </header>

    <section class="ov-grid">
      <div class="card authority-card">
        <div class="card-h"><h2>${icon('domain')} Domain authority</h2><span class="pill accent sm">threshold ${d.threshold.m}-of-${d.threshold.n}</span></div>
        <p class="card-sub">The root of authority for <b>names</b> under the domain — and only for names. It can say which key a <span class="mono">name@${esc(d.name)}</span> points to; it cannot forge, read, or impersonate what a member's key protects.</p>
        <div class="auth-facts">
          <div class="kvr"><span>Authority IK</span><b class="mono ellip">${esc(d.authorityIk.slice(0, 30))}…</b></div>
          <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(d.fingerprint)}</b></div>
          <div class="kvr"><span>Algorithm</span><b class="mono">${esc(d.alg)}</b></div>
          <div class="kvr"><span>Directory key</span><b class="mono">${esc(d.dirSigningKeyId)}</b></div>
        </div>
        <div class="auth-safety">
          <div>
            <div class="mini-h">${icon('verified')} Authority safety number</div>
            ${safetyWords(d.safety)}
          </div>
          ${safetyGrid(d.safety)}
        </div>
        <div class="holders-strip">
          ${d.threshold.holders.map(h => `<span class="holder-chip"><span class="dot on"></span>${esc(h.name.replace(' (owner)', ''))}<i>${esc(h.role)}</i></span>`).join('')}
        </div>
        <div class="card-foot">
          <span class="sim-tag">${icon('shield')} rotating the anchor or directory key needs a quorum</span>
          <div class="spacer"></div>
          <button class="btn sm" id="rotate">${icon('refresh')} Rotate directory key…</button>
        </div>
      </div>

      <div class="stat-col">
        <button class="card stat clickable" data-go="members"><span class="stat-n">${active.length}</span><span class="stat-l">${icon('members')} members</span><span class="stat-sub"><b class="good">${sovereign}</b> sovereign · <b class="warn">${managed}</b> org-managed</span><span class="stat-spark">${sparkline(memberGrowthHistory(14), { cls: 'good sm', w: 140, h: 22 })}</span></button>
        <button class="card stat clickable" data-go="groups"><span class="stat-n">${state.groups.length}</span><span class="stat-l">${icon('groups')} groups</span><span class="stat-sub">distribution lists &amp; channels</span></button>
        <button class="card stat clickable" data-go="roles"><span class="stat-n">${caps}</span><span class="stat-l">${icon('roles')} admin roles</span><span class="stat-sub">delegated capabilities</span></button>
        <button class="card stat clickable" data-go="directory"><span class="stat-n">v${d.dirVersion}</span><span class="stat-l">${icon('directory')} directory</span><span class="stat-sub">${d.membershipVisibility}</span></button>
      </div>
    </section>

    <section class="ov-grid-2">
      <div class="card">
        <div class="card-h"><h2>${icon('dns')} DNS &amp; anchor status</h2></div>
        <p class="card-sub">Control of the zone + the <span class="mono">_dmtap</span> / <span class="mono">kt=</span> anchors is what "controlling <span class="mono">@${esc(d.name)}</span>" means (spec §3.2, §3.10.1).</p>
        <div class="dns-list">
          ${dnsRows.map(([k, name, desc]) => {
            const ok = d.dns[k] === 'ok';
            return `<div class="dns-row"><span class="dns-state ${ok ? 'ok' : 'bad'}">${icon(ok ? 'check' : 'warn')}</span><div class="dns-main"><b>${esc(name)}</b><small>${esc(desc)}</small></div><span class="pill ${ok ? 'good' : 'warn'} sm">${ok ? 'anchored' : 'action needed'}</span></div>`;
          }).join('')}
        </div>
      </div>

      <div class="card guarantee-card">
        <div class="card-h"><h2>${icon('scale')} What you can &amp; cannot do</h2></div>
        <p class="card-sub">The sovereignty invariant, made legible. As the domain owner you hold power over <b>names</b>, not keys.</p>
        <div class="guar-cols">
          <div class="guar can">
            <div class="guar-h good">${icon('check')} You CAN</div>
            <ul>
              <li>Add &amp; remove <span class="mono">name@${esc(d.name)}</span> bindings</li>
              <li>Curate the directory &amp; group rosters</li>
              <li>Delegate &amp; revoke admin roles</li>
              <li>Offboard anyone (revoke their name)</li>
            </ul>
          </div>
          <div class="guar cannot">
            <div class="guar-h bad">${icon('x')} You CANNOT (sovereign members)</div>
            <ul>
              <li>Read a sovereign member's mail</li>
              <li>Impersonate them or sign as them</li>
              <li>Recover or seize their key</li>
              <li>Take their identity when they leave</li>
            </ul>
          </div>
        </div>
        <p class="guar-note">${icon('warn')} <b>${managed}</b> ${managed === 1 ? 'account is' : 'accounts are'} <b>org-managed</b> — a disclosed escrow where the org does hold the key and CAN read + impersonate. Those carry a visible <span class="pill warn sm">${icon('unlock')} org-managed</span> badge everywhere.</p>
      </div>
    </section>

    <section class="card kt-card">
      <div class="card-h">
        <h2>${icon('kt')} Key Transparency — pinned checkpoint</h2>
        <span class="pill ${allFresh ? 'good' : 'warn'} sm">${allFresh ? icon('check') + ' fresh' : icon('warn') + ' stale witness'}</span>
      </div>
      <p class="card-sub">The append-only name→key log this domain pins against (spec §3.5). Freshness and cross-witness consistency are what make a covert re-key or split-view detectable.</p>
      <div class="kt-grid">
        <div class="kvr"><span>Tree size</span><b class="mono">${fmtNum(treeSize)}</b></div>
        <div class="kvr"><span>Pinned root</span><b class="mono ellip">${esc(rootHash)}</b></div>
        <div class="kvr"><span>Last verified</span><b class="mono">${esc(timeAgo(d.ktCheckpointAt))}</b></div>
      </div>
      <div class="kt-trend">
        ${sparkline(ktTreeHistory(14), { cls: 'accent', w: 320, h: 40 })}
        <small>tree size, append-only — never shrinks</small>
      </div>
      <div class="kt-witnesses">
        ${d.ktWitnesses.map(w => {
          const fresh = ktIsFresh(w);
          return `<div class="kt-w ${fresh ? 'ok' : 'stale'}">
            <span class="kt-w-dot ${fresh ? 'good' : 'warn'}"></span>
            <div class="kt-w-main"><b class="mono">${esc(w.name)}</b><small>${fresh ? 'consistent · pinned root confirmed' : "stale — hasn't gossiped a fresh checkpoint"}</small></div>
            <span class="muted">${esc(timeAgo(w.lastSeen))}</span>
          </div>`;
        }).join('')}
      </div>
      ${!allFresh ? `<div class="banner warn">${icon('warn')} <span><b>${staleCount}</b> witness${staleCount === 1 ? '' : 'es'} ${staleCount === 1 ? "hasn't" : "haven't"} gossiped a fresh checkpoint in over 24h. This alone isn't a split-view, but a stale witness can't yet corroborate the pinned root.</span></div>` : ''}
      <div class="card-foot">
        <span class="sim-tag">${icon('info')} witness gossip is simulated</span>
        <div class="spacer"></div>
        <button class="btn sm" id="ktverify">${icon('refresh')} Verify latest checkpoint</button>
      </div>
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('audit')} Recent activity</h2><button class="btn ghost sm" data-go="audit">View full log →</button></div>
      <div class="ov-audit" id="ov-audit"></div>
    </section>
  </div>`;

  const auditWrap = root.querySelector('#ov-audit');
  const recent = state.audit.slice(0, 5);
  if (!recent.length) auditWrap.innerHTML = emptyState('audit', 'No activity yet', 'Administrative actions will appear here, KT-logged.');
  else auditWrap.innerHTML = recent.map(ev => `
    <div class="ov-ev">
      <span class="ov-ev-ic ${ev.kind}">${icon(kindIcon(ev.kind))}</span>
      <div class="ov-ev-main"><span>${esc(ev.summary)}</span><small class="mono">${esc(ev.hash)}${ev.threshold ? ' · threshold' : ''}</small></div>
      <span class="ov-ev-t">${timeAgo(ev.ts)}</span>
    </div>`).join('');

  root.querySelectorAll('[data-go]').forEach(b => b.onclick = () => bus.setView(b.dataset.go));
  root.querySelector('.auth-facts').appendChild(copyBtn(d.authorityIk, 'Copy authority IK'));
  root.querySelector('#rotate').onclick = async () => {
    const ok = await collectThreshold(d.threshold, 'Rotate the directory-signing key',
      `A new directory-signing key will be generated and every future DomainDirectory version signed under it. Existing published versions remain valid under the old key in the KT log.`);
    if (!ok) return;
    d.dirSigningKeyId = Math.random().toString(36).slice(2, 14) + '·dir';
    await republishDirectory('directory-signing key rotated (threshold)');
    toast(`${icon('check')} Directory key rotated · directory re-signed`);
    bus.rerender();
  };

  root.querySelector('#ktverify').onclick = async () => {
    await verifyKtCheckpoint();
    toast(`${icon('check')} Checkpoint re-verified across ${d.ktWitnesses.length} witnesses`);
    bus.rerender();
  };
}

function kindIcon(kind) {
  return { domain: 'domain', member: 'members', directory: 'directory', group: 'groups', role: 'roles', security: 'shield' }[kind] || 'info';
}
