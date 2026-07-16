// views/roles.js — admin roles as capabilities (spec §13.5.1). An admin role is a UCAN-style
// capability rooted at the domain authority and delegated to an admin's identity: delegable,
// attenuable, revocable, and KT-logged. Four roles: domain-owner, domain-admin, user-admin,
// group-admin. Two guarantees are made visible:
//
//   • No unilateral super-admin where it matters: domain-owner (full authority, incl. rotating
//     the anchor / directory key) is a THRESHOLD act, not one admin's capability — granting it
//     goes through quorum collection.
//   • Nothing silent: every grant/revoke is appended to the KT-logged, owner-visible audit trail.

import { state, uid, logEvent, rolesOf } from '../store.js';
import { collectThreshold } from '../session.js';
import { bus } from '../bus.js';
import { el, esc, icon, avatar, openModal, closeModal, emptyState, toast, fmtDate } from '../ui.js';
import { hueFor } from '../store.js';

const ROLES = {
  'domain-owner': { cap: 'Full domain authority — incl. rotating the domain anchor and directory-signing key', from: 'the domain authority itself (a threshold act)', threshold: true, hue: 262 },
  'domain-admin': { cap: 'Provision/offboard members, edit the directory, create org groups, delegate user-/group-admin', from: 'domain-owner', threshold: false, hue: 210 },
  'user-admin': { cap: 'Provision/offboard members and edit their directory entries only', from: 'domain-owner / domain-admin', threshold: false, hue: 150 },
  'group-admin': { cap: 'Create and administer org groups only', from: 'domain-owner / domain-admin', threshold: false, hue: 46 },
};

export function render(root) {
  root.className = 'view scroll-view';
  const q = state.ui.search.trim().toLowerCase();
  const caps = state.caps.filter(c => !q || (c.role + ' ' + c.subject + ' ' + (c.subjectName || '')).toLowerCase().includes(q));
  const active = caps.filter(c => !c.revoked);
  const revoked = caps.filter(c => c.revoked);

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Admin roles</h1>
        <p class="page-sub">Administration is <b>capabilities</b>, not accounts — UCAN-style rights rooted at the domain authority, delegated to an admin's identity, attenuable and revocable (spec §13.5.1).</p>
      </div>
      <button class="btn primary" id="grant">${icon('plus')} Delegate a role</button>
    </header>

    <section class="roles-legend">
      ${Object.entries(ROLES).map(([r, meta]) => `<div class="rl-card"><div class="rl-h"><span class="role-tag role-${r}">${esc(r)}</span>${meta.threshold ? `<span class="pill accent sm">${icon('shield')} threshold</span>` : ''}</div><p>${esc(meta.cap)}</p><small>Delegated from: ${esc(meta.from)}</small></div>`).join('')}
    </section>

    <section class="card">
      <div class="card-h"><h2>${icon('roles')} Active capabilities <span class="list-count">${active.length}</span></h2></div>
      <div class="cap-list" id="cap-active"></div>
    </section>

    ${revoked.length ? `<section class="card">
      <div class="card-h"><h2>${icon('x')} Revoked <span class="list-count">${revoked.length}</span></h2></div>
      <div class="cap-list revoked" id="cap-revoked"></div>
    </section>` : ''}
  </div>`;

  const drawList = (wrap, caps, isRevoked) => {
    if (!caps.length) { wrap.innerHTML = emptyState('roles', 'No capabilities', 'Delegate a role to an admin.'); return; }
    caps.forEach(c => {
      const meta = ROLES[c.role] || {};
      const expired = c.expires && c.expires < Date.now();
      const row = el(`<div class="cap-item ${isRevoked ? 'off' : ''}">
        ${avatar(c.subjectName || c.subject, meta.hue || hueFor(c.subject), 36)}
        <div class="cap-main">
          <div class="cap-top"><span class="role-tag role-${c.role}">${esc(c.role)}</span><b>${esc(c.subjectName || c.subject)}</b>${meta.threshold ? `<span class="pill accent sm">${icon('shield')} threshold-rooted</span>` : ''}${expired && !isRevoked ? `<span class="pill warn sm">expired</span>` : ''}</div>
          <span class="cap-sub mono">${esc(c.subject)}</span>
          <span class="cap-meta">delegated from <b>${esc(c.delegatedFrom)}</b> · ${esc(fmtDate(c.issued))}${c.expires ? ' · expires ' + esc(fmtDate(c.expires)) : ' · no expiry'}${isRevoked ? ' · revoked ' + esc(fmtDate(c.revokedAt)) : ''}</span>
        </div>
        ${!isRevoked ? `<button class="btn danger sm" data-revoke="${c.id}">${icon('x')} Revoke</button>` : `<span class="pill dim sm">revoked</span>`}
      </div>`);
      wrap.appendChild(row);
    });
    wrap.querySelectorAll('[data-revoke]').forEach(b => b.onclick = () => revokeCap(b.dataset.revoke));
  };
  drawList(root.querySelector('#cap-active'), active, false);
  if (revoked.length) drawList(root.querySelector('#cap-revoked'), revoked, true);

  root.querySelector('#grant').onclick = grantModal;
}

function revokeCap(id) {
  const c = state.caps.find(x => x.id === id);
  if (!c) return;
  const card = openModal(`
    <div class="modal-head"><h2>${icon('x')} Revoke ${esc(c.role)}</h2><button class="icon-btn" id="rx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body"><p class="modal-note">${icon('info')} Revokes <b>${esc(c.subjectName || c.subject)}</b>'s <span class="mono">${esc(c.role)}</span> capability by publishing a revocation to the transparency log / status endpoint. It does <b>not</b> require rotating the domain IK (spec §13.4). Offboarding revokes an admin's roles this same way.</p></div>
    <div class="modal-foot"><button class="btn ghost" id="rc">Cancel</button><div class="spacer"></div><button class="btn danger" id="rok">${icon('x')} Revoke capability</button></div>`, { label: 'Revoke capability' });
  card.querySelector('#rx').onclick = card.querySelector('#rc').onclick = closeModal;
  card.querySelector('#rok').onclick = async () => {
    c.revoked = true; c.revokedAt = Date.now();
    await logEvent('role', `Revoked ${c.role} from ${c.subject}`);
    closeModal(); toast(`${icon('check')} ${esc(c.role)} revoked`); bus.rerender();
  };
}

function grantModal() {
  let role = 'user-admin', subject = '', busy = false;
  const candidates = state.members.filter(m => m.status === 'active');
  const card = openModal('<div class="q-loading"></div>', { wide: true, label: 'Delegate a role' });
  const draw = () => {
    const meta = ROLES[role];
    card.innerHTML = `
      <div class="modal-head"><h2>${icon('plus')} Delegate an admin role</h2><button class="icon-btn" id="gx" aria-label="Close">${icon('x')}</button></div>
      <div class="modal-body">
        <label class="cfield"><span>Role</span><select id="grole">${Object.keys(ROLES).map(r => `<option value="${r}" ${r === role ? 'selected' : ''}>${r}</option>`).join('')}</select></label>
        <div class="grant-cap"><span class="role-tag role-${role}">${esc(role)}</span><p>${esc(meta.cap)}</p><small>Delegated from ${esc(meta.from)}</small></div>
        ${meta.threshold ? `<div class="model-explain warn">${icon('shield')} <span><b>domain-owner is a threshold act.</b> Granting full domain authority requires a ${state.domain.threshold.m}-of-${state.domain.threshold.n} quorum — no single admin can mint it (spec §13.5.1).</span></div>` : ''}
        <label class="cfield"><span>Grant to</span><select id="gsubject"><option value="">Select a member…</option>${candidates.map(m => `<option value="${esc(m.address)}" ${m.address === subject ? 'selected' : ''}>${esc(m.name)} — ${esc(m.address)}</option>`).join('')}</select></label>
        <label class="cfield"><span>Expiry <i class="opt">(attenuation — optional)</i></span><select id="gexp"><option value="0">No expiry</option><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option></select></label>
        <p class="modal-note">${icon('info')} Capabilities are attenuable (a delegate can only sub-delegate a subset) and every grant is KT-logged &amp; owner-visible — a silently installed admin grant is detectable (spec §13.5.1).</p>
      </div>
      <div class="modal-foot"><button class="btn ghost" id="gc">Cancel</button><div class="spacer"></div><button class="btn primary" id="gok">${icon('plus')} Delegate role</button></div>`;
    card.querySelector('#gx').onclick = card.querySelector('#gc').onclick = closeModal;
    card.querySelector('#grole').onchange = e => { role = e.target.value; draw(); };
    card.querySelector('#gsubject').onchange = e => { subject = e.target.value; };
    card.querySelector('#gok').onclick = async () => {
      if (busy) return;
      subject = card.querySelector('#gsubject').value;
      if (!subject) return toast(`${icon('warn')} Choose who to grant it to`);
      const m = state.members.find(x => x.address === subject);
      if (rolesOf(subject).includes(role)) return toast(`${icon('warn')} ${esc(subject)} already holds ${role}`);
      const expDays = Number(card.querySelector('#gexp').value);
      if (meta.threshold) {
        busy = true;
        const ok = await collectThreshold(state.domain.threshold, 'Grant domain-owner authority',
          `Granting full domain authority to ${subject}. This holder will be able to participate in rotating the anchor and the directory key.`);
        busy = false;
        if (!ok) return;
      }
      state.caps.push({ id: uid('c'), role, subject, subjectName: m?.name || subject, delegatedFrom: meta.from.includes('threshold') ? 'domain authority (threshold)' : 'domain-owner', issued: Date.now(), expires: expDays ? Date.now() + expDays * 86400e3 : null, revoked: false, threshold: meta.threshold });
      await logEvent('role', `Delegated ${role} to ${subject}`, { threshold: meta.threshold });
      closeModal(); toast(`${icon('check')} ${esc(role)} delegated to ${esc(m?.name || subject)}`); bus.rerender();
    };
  };
  draw();
}
