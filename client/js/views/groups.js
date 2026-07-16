// views/groups.js — GROUPS AS ADDRESSES (spec §5.8). A group is an identity that has members:
// it has its own keypair and therefore its own address (team@company.com or @team). Sending to
// the address delivers to all current members. Broadcast (list, hidden members) vs channel
// (collaborative, member-visible); roles owner/admin/member; membership is an MLS roster.

import { state, uid } from '../store.js';
import { person, PEOPLE } from '../seed.js';
import { el, esc, icon, avatar, toast, openModal, closeModal, emptyState } from '../ui.js';
import { bus } from '../bus.js';
import { openCompose } from '../compose.js';

const ROLE_ORDER = { owner: 0, admin: 1, member: 2 };

export function render(root) {
  root.className = 'view groups-view';
  const g = state.groups.find(x => x.id === state.ui.selGroup) || state.groups[0];
  state.ui.selGroup = g?.id || null;

  root.innerHTML = `
    <aside class="gr-list">
      <div class="list-head"><h2>Groups</h2><button class="icon-btn" id="gnew" title="New group">${icon('plus')}</button></div>
      <div class="gr-rows" id="grrows"></div>
      <div class="gr-explain">${icon('info')} An <b>address represents a group</b>. Send to it and every member receives it — the same mechanism behind mailing lists, channels, and shared folders.</div>
    </aside>
    <section class="gr-detail" id="grdetail"></section>`;

  const rows = root.querySelector('#grrows');
  const q = state.ui.search.trim().toLowerCase();
  const list = state.groups.filter(gr => !q || (gr.name + ' ' + gr.address + ' ' + (gr.handle || '')).toLowerCase().includes(q));
  if (!list.length) rows.innerHTML = emptyState('search', 'No groups', 'No groups match your search.');
  list.forEach(gr => {
    const sel = state.ui.selGroup === gr.id;
    const row = el(`<button class="gr-row ${sel ? 'sel' : ''}" data-id="${gr.id}"${sel ? ' aria-current="true"' : ''}>
      <span class="av chgroup" style="--h:250;width:40px;height:40px">${icon(gr.mode === 'broadcast' ? 'bell' : 'groups')}</span>
      <div class="gr-row-main"><span class="gr-name">${esc(gr.name)}</span><span class="gr-addr mono">${esc(gr.address)}</span></div>
      <i class="pill ${gr.mode === 'broadcast' ? 'warn' : 'accent'} sm">${gr.mode}</i>
    </button>`);
    row.onclick = () => { state.ui.selGroup = gr.id; state.ui.mobileDetail = true; bus.rerender(); };
    rows.appendChild(row);
  });
  root.querySelector('#gnew').onclick = newGroupModal;
  root.classList.toggle('detail', state.ui.mobileDetail && !!g);
  drawDetail(root, g);
}

function drawDetail(root, g) {
  const wrap = root.querySelector('#grdetail');
  if (!g) { wrap.innerHTML = emptyState('groups', 'No group selected', 'Create a group to give it an address.'); return; }
  const you = g.members.find(m => m.address.startsWith('you@'));
  const canManage = you && (you.role === 'owner' || you.role === 'admin');
  const members = [...g.members].sort((a, b) => ROLE_ORDER[a.role] - ROLE_ORDER[b.role]);

  wrap.innerHTML = `
    <div class="gr-hero">
      <button class="icon-btn mobile-back" id="gr-back" aria-label="Back to groups list" title="Back">${icon('reply')}</button>
      <span class="av chgroup" style="--h:250;width:56px;height:56px">${icon(g.mode === 'broadcast' ? 'bell' : 'groups')}</span>
      <div class="gr-hero-main">
        <h1 class="display">${esc(g.name)}</h1>
        <div class="gr-hero-addr"><span class="key big">${esc(g.address)}</span> <button class="icon-btn sm" id="gcopy" title="Copy address">${icon('files')}</button></div>
        <div class="gr-hero-tags">
          <span class="pill ${g.mode === 'broadcast' ? 'warn' : 'accent'}">${g.mode === 'broadcast' ? icon('bell') + ' broadcast list' : icon('chat') + ' channel'}</span>
          <span class="pill dim">${g.membershipVisible ? 'members visible' : 'hidden membership'}</span>
          <span class="pill dim">join: ${esc(g.joinPolicy)}</span>
        </div>
      </div>
      <button class="btn primary" id="gpost">${icon('send')} Post to group</button>
    </div>

    <div class="gr-explain-card">${icon('info')} Sending to <span class="key">${esc(g.address)}</span> ${g.mode === 'broadcast'
      ? 'fans out a per-member sealed copy to every subscriber (they don\'t see each other).'
      : 'posts to the shared, ordered channel — every member sees it and each other.'} Membership is the group\'s MLS roster; every add/remove/role change is member-signed and appears in the group\'s hash-chained log (spec §5.8.2).</div>

    <div class="gr-sect-head">
      <h3>Members <span class="list-count">${g.members.length}</span></h3>
      ${canManage ? `<button class="btn" id="gadd">${icon('plus')} Add member</button>` : ''}
    </div>
    <div class="gr-members" id="gmembers"></div>

    ${canManage ? `<div class="gr-sect-head"><h3>Group settings</h3></div>
    <div class="gr-settings">
      <div class="gr-set-row"><div><b>Posting model</b><small>broadcast = distribution list; channel = shared conversation</small></div>
        <div class="seg" id="gmode" role="group" aria-label="Posting model"><button data-m="channel" aria-pressed="${g.mode === 'channel'}" class="${g.mode === 'channel' ? 'on' : ''}">Channel</button><button data-m="broadcast" aria-pressed="${g.mode === 'broadcast'}" class="${g.mode === 'broadcast' ? 'on' : ''}">Broadcast</button></div></div>
      <div class="gr-set-row"><div><b>Membership visibility</b><small>whether members can see each other</small></div>
        <div class="seg" id="gvis" role="group" aria-label="Membership visibility"><button data-v="1" aria-pressed="${g.membershipVisible}" class="${g.membershipVisible ? 'on' : ''}">Visible</button><button data-v="0" aria-pressed="${!g.membershipVisible}" class="${!g.membershipVisible ? 'on' : ''}">Hidden</button></div></div>
      <div class="gr-set-row"><div><b>Join policy</b><small>who may join the address</small></div>
        <select id="gjoin"><option ${g.joinPolicy === 'closed' ? 'selected' : ''}>closed</option><option ${g.joinPolicy === 'request' ? 'selected' : ''}>request</option><option ${g.joinPolicy === 'open' ? 'selected' : ''}>open</option><option ${g.joinPolicy === 'vouch' ? 'selected' : ''}>vouch</option></select></div>
    </div>` : ''}`;

  const mwrap = wrap.querySelector('#gmembers');
  members.forEach(m => {
    if (m.hidden) { mwrap.appendChild(el(`<div class="gr-member hidden-count">${icon('lock')} ${esc(m.address)} — sealed, not shown to other members</div>`)); return; }
    const p = person(m.address);
    const row = el(`<div class="gr-member">
      ${avatar(p, 34, { ring: true, badge: true })}
      <div class="gr-member-main"><span class="gr-member-name">${esc(p.name)}</span><span class="gr-member-addr mono">${esc(m.address)}</span></div>
      <span class="role role-${m.role}">${m.role}</span>
      ${canManage && m.role !== 'owner' ? `<button class="icon-btn sm" data-role="${m.address}" title="Change role">${icon('more')}</button>` : ''}
    </div>`);
    const rb = row.querySelector('[data-role]');
    if (rb) rb.onclick = () => roleMenu(rb, g, m);
    mwrap.appendChild(row);
  });

  wrap.querySelector('#gr-back').onclick = () => { state.ui.mobileDetail = false; bus.rerender(); };
  wrap.querySelector('#gcopy').onclick = () => { navigator.clipboard?.writeText(g.address); toast(`${icon('check')} Copied ${g.address}`); };
  wrap.querySelector('#gpost').onclick = () => openCompose({ to: g.address, subject: '' });
  if (canManage) {
    wrap.querySelector('#gadd').onclick = () => addMemberModal(g);
    wrap.querySelectorAll('#gmode [data-m]').forEach(b => b.onclick = () => { g.mode = b.dataset.m; bus.rerender(); toast('Posting model → ' + g.mode + ' (MLS policy Commit)'); });
    wrap.querySelectorAll('#gvis [data-v]').forEach(b => b.onclick = () => { g.membershipVisible = b.dataset.v === '1'; bus.rerender(); });
    wrap.querySelector('#gjoin').onchange = (e) => { g.joinPolicy = e.target.value; toast('Join policy → ' + g.joinPolicy); };
  }
}

function roleMenu(anchor, g, m) {
  document.querySelector('.popover')?.remove();
  const r = anchor.getBoundingClientRect();
  const items = [['Make admin', 'admin'], ['Make member', 'member'], ['— Remove from group', 'remove']];
  const pop = el(`<div class="popover" style="top:${r.bottom + 6}px;left:${Math.min(r.left, innerWidth - 200)}px">${items.map(([l], i) => `<button data-i="${i}">${esc(l)}</button>`).join('')}</div>`);
  document.body.appendChild(pop);
  items.forEach(([, action], i) => pop.querySelector(`[data-i="${i}"]`).onclick = () => {
    pop.remove();
    if (action === 'remove') { g.members = g.members.filter(x => x.address !== m.address); toast(`${person(m.address).name} removed · file-keys rotated (spec §6.7)`); }
    else { m.role = action; toast(`${person(m.address).name} → ${action} (signed Commit)`); }
    bus.rerender();
  });
  setTimeout(() => document.addEventListener('click', function h(e) { if (!pop.contains(e.target)) { pop.remove(); document.removeEventListener('click', h); } }), 0);
}

function addMemberModal(g) {
  const avail = PEOPLE.filter(p => !g.members.some(m => m.address === p.address) && p.trust !== 'legacy');
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>Add member to ${esc(g.name)}</h2><button class="icon-btn" id="ax">${icon('x')}</button></div>
      <p class="modal-note">Adding uses the invitee's MLS KeyPackage + a Welcome (spec §5.3). The change is signed and logged.</p>
      <div class="add-list">${avail.map(p => `<button class="add-row" data-a="${esc(p.address)}">${avatar(p, 32, { badge: true })}<div><b>${esc(p.name)}</b><span class="mono">${esc(p.address)}</span></div>${icon('plus')}</button>`).join('') || '<div class="ag-empty">Everyone is already a member.</div>'}</div>
    </div>`, { wide: true });
  card.querySelector('#ax').onclick = closeModal;
  card.querySelectorAll('[data-a]').forEach(b => b.onclick = () => {
    g.members.push({ address: b.dataset.a, role: 'member' }); closeModal(); bus.rerender();
    toast(`${icon('check')} ${person(b.dataset.a).name} added — Welcome sealed to their key`);
  });
}

function newGroupModal() {
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>New group</h2><button class="icon-btn" id="gx">${icon('x')}</button></div>
      <label class="cfield"><span>Group name</span><input id="gn" placeholder="Weekend Hikers" autofocus></label>
      <label class="cfield"><span>Address</span><div class="addr-compose"><input id="ga" placeholder="hikers"><span class="addr-domain mono">@envoir.org</span></div></label>
      <div class="ev-new-row">
        <label class="cfield"><span>Posting model</span><select id="gm"><option value="channel">Channel — shared conversation</option><option value="broadcast">Broadcast — distribution list</option></select></label>
        <label class="cfield"><span>Join policy</span><select id="gj"><option>request</option><option>closed</option><option>open</option><option>vouch</option></select></label>
      </div>
      <p class="modal-note">${icon('info')} The group gets its own keypair, so it has its own place on the naming ladder — a key-name, an @handle, or this domain address. You become the owner.</p>
      <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} group identity = its own key</span><div class="spacer"></div><button class="btn primary" id="gcreate">Create group</button></div>
    </div>`, { wide: true });
  card.querySelector('#gx').onclick = closeModal;
  card.querySelector('#gcreate').onclick = () => {
    const name = card.querySelector('#gn').value.trim(); if (!name) return toast('Name the group');
    const local = (card.querySelector('#ga').value.trim() || name.toLowerCase().replace(/\s+/g, '-')).replace(/[^a-z0-9-]/g, '');
    const mode = card.querySelector('#gm').value;
    const g = { id: uid('g'), name, address: local + '@envoir.org', handle: '@' + local, mode,
      joinPolicy: card.querySelector('#gj').value, membershipVisible: mode === 'channel', created: Date.now(),
      members: [{ address: 'you@envoir.org', role: 'owner' }] };
    state.groups.push(g); state.ui.selGroup = g.id; closeModal(); bus.rerender();
    toast(`${icon('check')} Group created · ${g.address} now delivers to all members`);
  };
}
