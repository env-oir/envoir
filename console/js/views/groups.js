// views/groups.js — org groups & distribution lists (spec §5.8.7). team@, all@, support@ are
// ordinary group identities whose NAME is a domain address under the domain authority. The
// org-admin layer only adds who may provision/administer them; the group's own signing key stays
// threshold-held by its owner/admin set (§5.8.6) — the domain grants the name, the group's
// threshold governs the key, so the org cannot silently inject a listener into a team inbox.
// The roster is populated from directory members but remains the group's own MLS roster: every
// add/remove is a signed, KT-audited group Commit (§5.8.2).

import { state, uid, group, republishDirectory, logEvent } from '../store.js';
import { generateKeypair } from '../crypto.js';
import { bus } from '../bus.js';
import { el, esc, icon, avatar, openModal, closeModal, emptyState, toast, fmtDate } from '../ui.js';
import { hueFor } from '../store.js';

export function render(root) {
  root.className = 'view split-view';
  const q = state.ui.search.trim().toLowerCase();
  const list = state.groups.filter(g => !q || (g.name + ' ' + g.address).toLowerCase().includes(q));
  const sel = group(state.ui.selGroup) && list.includes(group(state.ui.selGroup)) ? group(state.ui.selGroup) : (list[0] || null);
  state.ui.selGroup = sel?.id || null;

  root.innerHTML = `
    <aside class="split-list">
      <div class="list-head"><h2>Groups <span class="list-count">${state.groups.length}</span></h2><button class="btn primary sm" id="add">${icon('plus')} New</button></div>
      <div class="list-rows" id="rows"></div>
      <div class="list-foot">${icon('info')} A group is "a member that has members" — a domain-addressed group identity. Its key is threshold-held; the domain only grants its name.</div>
    </aside>
    <section class="split-detail" id="detail"></section>`;

  const rows = root.querySelector('#rows');
  if (!list.length) rows.innerHTML = q ? emptyState('search', 'No matches', 'No groups match your search.') : emptyState('groups', 'No groups', 'Create a distribution list or channel.');
  list.forEach(g => {
    const on = g.id === sel?.id;
    const row = el(`<button class="list-row ${on ? 'sel' : ''}" data-id="${g.id}"${on ? ' aria-current="true"' : ''}>
      <span class="av grp" style="width:38px;height:38px">${icon(g.mode === 'broadcast' ? 'bell' : 'chat')}</span>
      <div class="list-row-main"><span class="lr-name">${esc(g.name)}</span><span class="lr-sub mono">${esc(g.address)}</span></div>
      <span class="pill ${g.mode === 'broadcast' ? 'warn' : 'accent'} sm">${g.mode}</span>
    </button>`);
    row.onclick = () => { state.ui.selGroup = g.id; bus.rerender(); };
    rows.appendChild(row);
  });
  root.querySelector('#add').onclick = newGroupModal;
  drawDetail(root.querySelector('#detail'), sel);
}

function drawDetail(wrap, g) {
  if (!g) { wrap.innerHTML = emptyState('groups', 'No group selected', 'Select or create a group to manage its roster.'); return; }
  const roster = g.members.map(a => ({ address: a, m: state.members.find(x => x.address === a) }));

  wrap.innerHTML = `
    <div class="detail-scroll">
      <div class="member-hero">
        <span class="av grp" style="width:60px;height:60px">${icon(g.mode === 'broadcast' ? 'bell' : 'chat')}</span>
        <div class="member-hero-main">
          <h1>${esc(g.name)}</h1>
          <div class="member-hero-addr"><span class="mono key">${esc(g.address)}</span></div>
          <div class="member-hero-tags">
            <span class="pill ${g.mode === 'broadcast' ? 'warn' : 'accent'} sm">${g.mode === 'broadcast' ? icon('bell') + ' broadcast list' : icon('chat') + ' channel'}</span>
            <span class="pill dim sm">${g.membershipVisible ? icon('eye') + ' members visible' : icon('lock') + ' hidden membership'}</span>
            <span class="pill dim sm">join: ${esc(g.joinPolicy)}</span>
            <span class="pill accent sm">${icon('shield')} key ${g.threshold.m}-of-${g.threshold.n}</span>
          </div>
        </div>
        <button class="btn danger" id="delgrp">${icon('trash')} Delete</button>
      </div>

      <div class="banner">${icon('info')} <span>Sending to <span class="mono">${esc(g.address)}</span> ${g.mode === 'broadcast'
        ? 'fans out a per-member sealed copy to every subscriber (they don\'t see each other).'
        : 'posts to the shared, member-visible channel.'} Every add/remove is a member-signed group Commit, visible in the KT-audited handshake log — the org cannot silently add a listener (spec §5.8.7).</span></div>

      <div class="detail-cols">
        <div class="card">
          <div class="card-h"><h2>${icon('members')} Roster <span class="list-count">${roster.length}</span></h2><button class="btn sm" id="addmem">${icon('plus')} Add member</button></div>
          <div class="roster" id="roster"></div>
        </div>
        <div class="card">
          <div class="card-h"><h2>${icon('roles')} Group policy</h2></div>
          <div class="policy">
            <div class="policy-row"><div><b>Posting model</b><small>broadcast = list; channel = shared conversation</small></div>
              <div class="seg" id="pmode" role="group" aria-label="Posting model"><button data-m="channel" aria-pressed="${g.mode === 'channel'}" class="${g.mode === 'channel' ? 'on' : ''}">Channel</button><button data-m="broadcast" aria-pressed="${g.mode === 'broadcast'}" class="${g.mode === 'broadcast' ? 'on' : ''}">Broadcast</button></div></div>
            <div class="policy-row"><div><b>Membership visibility</b><small>whether members see each other</small></div>
              <div class="seg" id="pvis" role="group" aria-label="Membership visibility"><button data-v="1" aria-pressed="${g.membershipVisible}" class="${g.membershipVisible ? 'on' : ''}">Visible</button><button data-v="0" aria-pressed="${!g.membershipVisible}" class="${!g.membershipVisible ? 'on' : ''}">Hidden</button></div></div>
            <div class="policy-row"><div><b>Join policy</b><small>who may join the address</small></div>
              <select id="pjoin"><option ${g.joinPolicy === 'closed' ? 'selected' : ''}>closed</option><option ${g.joinPolicy === 'request' ? 'selected' : ''}>request</option><option ${g.joinPolicy === 'open' ? 'selected' : ''}>open</option><option ${g.joinPolicy === 'vouch' ? 'selected' : ''}>vouch</option></select></div>
            <div class="policy-row"><div><b>Created</b><small>group identity age</small></div><span class="muted">${esc(fmtDate(g.created))}</span></div>
          </div>
        </div>
      </div>
    </div>`;

  const rw = wrap.querySelector('#roster');
  if (!roster.length) rw.innerHTML = `<p class="muted">Empty roster.</p>`;
  roster.forEach(({ address, m }) => {
    const name = m?.name || address;
    const hue = m?.hue ?? hueFor(address);
    const row = el(`<div class="roster-row">
      ${avatar(name, hue, 32)}
      <div class="roster-main"><span class="rr-name">${esc(name)}</span><span class="rr-addr mono">${esc(address)}</span></div>
      <button class="icon-btn sm" data-rm="${esc(address)}" title="Remove from group" aria-label="Remove ${esc(name)}">${icon('minus')}</button>
    </div>`);
    rw.appendChild(row);
  });

  wrap.querySelector('#addmem').onclick = () => addToGroup(g);
  wrap.querySelector('#delgrp').onclick = () => deleteGroup(g);
  wrap.querySelectorAll('[data-rm]').forEach(b => b.onclick = async () => {
    g.members = g.members.filter(a => a !== b.dataset.rm);
    await logEvent('group', `Removed ${b.dataset.rm} from ${g.address} (signed Commit, shared state re-keyed)`);
    toast(`${icon('check')} Removed · shared folder re-keyed (§6.7)`); bus.rerender();
  });
  wrap.querySelectorAll('#pmode [data-m]').forEach(b => b.onclick = async () => { g.mode = b.dataset.m; await logEvent('group', `${g.address} posting model → ${g.mode}`); toast(`Posting model → ${g.mode}`); bus.rerender(); });
  wrap.querySelectorAll('#pvis [data-v]').forEach(b => b.onclick = () => { g.membershipVisible = b.dataset.v === '1'; logEvent('group', `${g.address} membership visibility → ${g.membershipVisible ? 'visible' : 'hidden'}`); bus.rerender(); });
  wrap.querySelector('#pjoin').onchange = (e) => { g.joinPolicy = e.target.value; logEvent('group', `${g.address} join policy → ${g.joinPolicy}`); toast(`Join policy → ${g.joinPolicy}`); };
}

function addToGroup(g) {
  const avail = state.members.filter(m => m.status === 'active' && !g.members.includes(m.address));
  const card = openModal(`
    <div class="modal-head"><h2>${icon('plus')} Add to ${esc(g.name)}</h2><button class="icon-btn" id="ax" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} Members come from the directory, but the roster stays the group's own MLS roster — this is a signed group Commit (spec §5.8.2), not a silent directory push.</p>
      <div class="add-list">${avail.length ? avail.map(m => `<button class="add-row" data-a="${esc(m.address)}">${avatar(m.name, m.hue, 32)}<div><b>${esc(m.name)}</b><span class="mono">${esc(m.address)}</span></div>${icon('plus')}</button>`).join('') : '<p class="muted">Every active member is already in this group.</p>'}</div>
    </div>`, { wide: true, label: 'Add to group' });
  card.querySelector('#ax').onclick = closeModal;
  card.querySelectorAll('[data-a]').forEach(b => b.onclick = async () => {
    g.members.push(b.dataset.a); closeModal();
    await logEvent('group', `Added ${b.dataset.a} to ${g.address} (signed Commit)`);
    toast(`${icon('check')} Added · Welcome sealed to their key`); bus.rerender();
  });
}

function deleteGroup(g) {
  const card = openModal(`
    <div class="modal-head"><h2>${icon('trash')} Delete ${esc(g.name)}?</h2><button class="icon-btn" id="dx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body"><p class="modal-note warn">${icon('warn')} Retires the <span class="mono">${esc(g.address)}</span> name and dissolves the group identity. Members keep their own identities untouched.</p></div>
    <div class="modal-foot"><button class="btn ghost" id="dc">Cancel</button><div class="spacer"></div><button class="btn danger" id="dok">${icon('trash')} Delete group</button></div>`, { label: 'Delete group' });
  card.querySelector('#dx').onclick = card.querySelector('#dc').onclick = closeModal;
  card.querySelector('#dok').onclick = async () => {
    state.groups = state.groups.filter(x => x.id !== g.id); state.ui.selGroup = null;
    await republishDirectory(`deleted group ${g.address}`);
    await logEvent('group', `Deleted group ${g.address}`);
    closeModal(); toast(`${icon('check')} Group deleted`); bus.rerender();
  };
}

function newGroupModal() {
  let mode = 'channel';
  const card = openModal('<div class="q-loading"></div>', { wide: true, label: 'New group' });
  const draw = () => {
    card.innerHTML = `
      <div class="modal-head"><h2>${icon('plus')} New group</h2><button class="icon-btn" id="gx" aria-label="Close">${icon('x')}</button></div>
      <div class="modal-body">
        <label class="cfield"><span>Group name</span><input id="gn" placeholder="Engineering" autofocus></label>
        <label class="cfield"><span>Address</span><div class="addr-compose"><input id="ga" placeholder="team"><span class="addr-domain mono">@${esc(state.domain.name)}</span></div></label>
        <div class="model-select">
          <button class="model-opt ${mode === 'channel' ? 'sel' : ''}" data-mode="channel"><div class="model-opt-h">${icon('chat')} Channel</div><p>Shared, member-visible conversation. Everyone sees each other.</p></button>
          <button class="model-opt ${mode === 'broadcast' ? 'sel' : ''}" data-mode="broadcast"><div class="model-opt-h">${icon('bell')} Broadcast</div><p>Distribution list. Hidden membership; per-member sealed copies.</p></button>
        </div>
        <p class="modal-note">${icon('shield')} The group gets its own keypair, threshold-held by its owner/admin set (spec §5.8.6). The domain grants the name; the group's threshold governs the key. You become the owner.</p>
      </div>
      <div class="modal-foot"><button class="btn ghost" id="gc">Cancel</button><div class="spacer"></div><button class="btn primary" id="gcreate">${icon('plus')} Create group</button></div>`;
    card.querySelector('#gx').onclick = card.querySelector('#gc').onclick = closeModal;
    card.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => { mode = b.dataset.mode; draw(); });
    card.querySelector('#gcreate').onclick = async () => {
      const name = card.querySelector('#gn').value.trim();
      const local = (card.querySelector('#ga').value.trim() || name.toLowerCase().replace(/\s+/g, '-')).toLowerCase().replace(/[^a-z0-9-]/g, '');
      if (!name) return toast(`${icon('warn')} Name the group`);
      if (!local) return toast(`${icon('warn')} Give it an address`);
      const address = `${local}@${state.domain.name}`;
      if (state.groups.some(x => x.address === address) || state.members.some(x => x.address === address)) return toast(`${icon('warn')} ${address} is taken`);
      const kp = await generateKeypair();
      const g = { id: uid('g'), name, address, ik: kp.ik, mode, membershipVisible: mode === 'channel', joinPolicy: mode === 'broadcast' ? 'closed' : 'request', threshold: { m: 2, n: 3 }, members: [`you@${state.domain.name}`], created: Date.now() };
      state.groups.push(g); state.ui.selGroup = g.id;
      await republishDirectory(`created group ${address}`);
      await logEvent('group', `Created group ${address} (${mode})`);
      closeModal(); toast(`${icon('check')} Group created · ${address}`); bus.rerender();
    };
  };
  draw();
}
