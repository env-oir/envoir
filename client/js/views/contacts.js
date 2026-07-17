// views/contacts.js — address book (JSContact-style MOTEs, spec §8.4). Each contact card
// shows a KEY VERIFICATION status: verified (safety number compared out-of-band), pinned
// (TOFU, spec §3.4), or legacy. The safety number is the anti-spoofing anchor — the name is
// just a pointer, the key is the identity. Contacts can be created/edited/deleted, organized
// into local TAG groups (spec §17#31: an organizational label with no address of its own —
// distinct from an addressable Group, which lives in Groups) and into real addressable Groups,
// and searched/filtered/sorted. Quick actions jump straight to mail, chat, or a prefilled
// meeting invite.

import { state, uid } from '../store.js';
import { PEOPLE, person, addPerson, removePerson, contactTags } from '../seed.js';
import { el, esc, icon, avatar, trustPill, toast, emptyState, openModal, closeModal, safetyWords, safetyGrid, safetyNumeric, shimmerRows } from '../ui.js';
import { deriveSafetyFromString } from '../safety.js';
import { classifyName, resolverChip, resolverDetail } from '../resolver.js';
import { bus } from '../bus.js';
import { openCompose } from '../compose.js';
import { newEventModal } from './calendar.js';

let selId = null;
let tagFilter = null;
let trustFilter = '';
let groupFilter = '';
let sortMode = 'name';
const TRUST_RANK = { verified: 0, tofu: 1, unverified: 2, legacy: 3 };

export function render(root) {
  root.className = 'view contacts-view';
  if (!selId || !person(selId)) selId = PEOPLE[0]?.id ?? null;
  const tags = contactTags();
  root.innerHTML = `
    <aside class="ct-list">
      <div class="list-head"><h2>Contacts</h2>
        <div class="ct-io">
          <button class="icon-btn" id="ct-new" title="New contact">${icon('plus')}</button>
          <button class="icon-btn" id="ct-import" title="Import vCard">${icon('import')}</button>
          <button class="icon-btn" id="ct-export" title="Export">${icon('export')}</button>
        </div>
      </div>
      ${tags.length ? `<div class="ct-tags-rail" id="cttags">
        <button class="ct-tag-btn ${!tagFilter ? 'on' : ''}" data-tag="">All</button>
        ${tags.map(t => `<button class="ct-tag-btn ${tagFilter === t ? 'on' : ''}" data-tag="${esc(t)}">${esc(t)}</button>`).join('')}
      </div>` : ''}
      <div class="ct-filterbar">
        <select id="cttrust" aria-label="Filter by verification">
          <option value="">All verification</option>
          <option value="verified" ${trustFilter === 'verified' ? 'selected' : ''}>Verified</option>
          <option value="tofu" ${trustFilter === 'tofu' ? 'selected' : ''}>TOFU-pinned</option>
          <option value="unverified" ${trustFilter === 'unverified' ? 'selected' : ''}>Unverified</option>
          <option value="legacy" ${trustFilter === 'legacy' ? 'selected' : ''}>Legacy</option>
        </select>
        ${state.groups.length ? `<select id="ctgroupf" aria-label="Filter by group">
          <option value="">All groups</option>
          ${state.groups.map(g => `<option value="${g.id}" ${groupFilter === g.id ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}
        </select>` : ''}
        <select id="ctsort" aria-label="Sort contacts">
          <option value="name" ${sortMode === 'name' ? 'selected' : ''}>Name A–Z</option>
          <option value="recent" ${sortMode === 'recent' ? 'selected' : ''}>Recently added</option>
          <option value="trust" ${sortMode === 'trust' ? 'selected' : ''}>Verification</option>
        </select>
      </div>
      <div class="ct-rows" id="ctrows"></div>
    </aside>
    <section class="ct-detail" id="ctdetail"></section>`;
  const rows = root.querySelector('#ctrows');
  const q = state.ui.search.trim().toLowerCase();
  let list = PEOPLE.filter(p =>
    (!q || (p.name + ' ' + p.address).toLowerCase().includes(q)) &&
    (!tagFilter || (p.tags || []).includes(tagFilter)) &&
    (!trustFilter || p.trust === trustFilter) &&
    (!groupFilter || state.groups.find(g => g.id === groupFilter)?.members.some(m => m.address === p.address)));
  if (sortMode === 'name') list = list.slice().sort((a, b) => a.name.localeCompare(b.name));
  else if (sortMode === 'recent') list = list.slice().reverse();
  else if (sortMode === 'trust') list = list.slice().sort((a, b) => (TRUST_RANK[a.trust] ?? 9) - (TRUST_RANK[b.trust] ?? 9) || a.name.localeCompare(b.name));
  if (!list.length) rows.innerHTML = emptyState('contacts', 'No contacts', q || tagFilter || trustFilter || groupFilter ? 'Try different filters.' : 'Add someone with the + button.');
  list.forEach(p => {
    const sel = selId === p.id;
    const row = el(`<button class="ct-row ${sel ? 'sel' : ''}" data-id="${p.id}"${sel ? ' aria-current="true"' : ''}>
      ${avatar(p, 38, { ring: true, badge: true })}
      <div class="ct-row-main"><span class="ct-name">${esc(p.name)}</span><span class="ct-addr mono">${esc(p.address)}</span></div>
      ${p.trust === 'verified' ? `<span class="vglyph sm">${icon('verified')}</span>` : ''}
    </button>`);
    row.onclick = () => { selId = p.id; state.ui.mobileDetail = true; bus.rerender(); };
    rows.appendChild(row);
  });
  root.querySelectorAll('#cttags [data-tag]').forEach(b => b.onclick = () => { tagFilter = b.dataset.tag || null; bus.rerender(); });
  root.querySelector('#cttrust').onchange = (e) => { trustFilter = e.target.value; bus.rerender(); };
  root.querySelector('#ctgroupf')?.addEventListener('change', (e) => { groupFilter = e.target.value; bus.rerender(); });
  root.querySelector('#ctsort').onchange = (e) => { sortMode = e.target.value; bus.rerender(); };
  root.querySelector('#ct-new').onclick = () => contactEditor(null);
  root.querySelector('#ct-import').onclick = () => toast(`${icon('import')} Simulated — a production client imports vCard 4.0 / JSContact and pins each key on first contact (TOFU)`, { ms: 4200 });
  root.querySelector('#ct-export').onclick = () => exportContacts();
  root.classList.toggle('detail', state.ui.mobileDetail && !!selId);
  drawDetail(root);
}

async function drawDetail(root) {
  const wrap = root.querySelector('#ctdetail');
  const p = selId ? person(selId) : null;
  if (!p) { wrap.innerHTML = emptyState('contacts', 'Select a contact', 'Verify keys by comparing safety numbers.'); return; }
  const groups = state.groups.filter(g => g.members.some(m => m.address === p.address));
  if (wrap.dataset.for !== p.id) {
    wrap.dataset.for = p.id;
    wrap.innerHTML = `<div class="ct-card"><div class="ct-card-hero" style="--h:${p.hue}">
      ${avatar(p, 84, { ring: true, badge: true })}<h1>${esc(p.name)}</h1>
      <div class="ct-card-sub">${esc([p.title, p.org].filter(Boolean).join(' · ')) || 'Contact'}</div></div>
      <div class="ct-card-body">${shimmerRows(3)}</div></div>`;
  }
  const safety = await deriveSafetyFromString(p.address + p.name);
  if (selId !== p.id) return; // selection changed while awaiting — abandon this stale render
  const addrInfo = classifyName(p.address);

  wrap.innerHTML = `
    <div class="ct-card">
      <div class="ct-card-hero" style="--h:${p.hue}">
        <button class="icon-btn mobile-back" id="ct-back" aria-label="Back to contacts list" title="Back" style="position:absolute;left:14px;top:14px">${icon('reply')}</button>
        <div class="ct-head-actions">
          <button class="icon-btn" id="ct-msg" title="Send message">${icon('mail')}</button>
          <button class="icon-btn" id="ct-chat" title="Start chat">${icon('chat')}</button>
          <button class="icon-btn" id="ct-invite" title="Invite to a meeting">${icon('calendar')}</button>
          <button class="icon-btn" id="ct-edit" title="Edit contact">${icon('edit')}</button>
        </div>
        ${avatar(p, 84, { ring: true, badge: true })}
        <h1>${esc(p.name)}</h1>
        <div class="ct-card-sub">${esc([p.title, p.org].filter(Boolean).join(' · ')) || 'Contact'}</div>
        <div>${trustPill(p.trust)}</div>
        ${(p.tags || []).length ? `<div class="ct-card-tags">${p.tags.map(t => `<i class="chip-lbl" style="--h:200">${esc(t)}</i>`).join('')}</div>` : ''}
      </div>
      <div class="ct-card-body">
        <div class="ct-field"><span class="k">${icon('mail')} Address</span><span class="v mono">${esc(p.address)} ${resolverChip(addrInfo)}</span></div>
        ${(p.addresses || []).length ? `<div class="ct-field"><span class="k">${icon('at')} Also</span><span class="v">${p.addresses.map(a => `<span class="chip-lbl" style="--h:210">${esc(a)}</span> ${resolverChip(classifyName(a))}`).join(' ')}</span></div>` : ''}
        ${p.phone ? `<div class="ct-field"><span class="k">${icon('bell')} Phone</span><span class="v mono">${esc(p.phone)}</span></div>` : ''}
        ${p.note ? `<div class="ct-field"><span class="k">${icon('edit')} Note</span><span class="v">${esc(p.note)}</span></div>` : ''}
        ${groups.length ? `<div class="ct-field"><span class="k">${icon('groups')} Groups</span><span class="v">${groups.map(g => `<i class="chip-lbl" style="--h:250">${esc(g.name)}</i>`).join(' ')}</span></div>` : ''}

        <div class="verify-box ${p.trust}">
          <div class="verify-head">
            ${p.trust === 'verified' ? `${icon('verified')} <b>Key verified</b>` : p.trust === 'legacy' ? `${icon('shield')} <b>Legacy contact — no DMTAP key</b>` : `${icon('lock')} <b>Pinned on first contact (TOFU)</b>`}
          </div>
          ${addrInfo.kind === 'namechain' || addrInfo.kind === 'self'
            ? `<div class="verify-note resolver-context">${resolverChip(addrInfo)} ${esc(resolverDetail(addrInfo, p.trust))}</div>` : ''}
          ${p.trust === 'legacy'
            ? `<div class="verify-note">Reaches you through the gateway. No end-to-end key to verify — messages are marked legacy-origin.</div>`
            : `<div class="verify-note">${p.trust === 'verified'
                ? 'You compared this safety number out-of-band, so a look-alike key would be detected. This is what stops phishing.'
                : 'Compare this safety number with ' + esc(p.name.split(' ')[0]) + ' out-of-band (read aloud, scan, or compare digits) to upgrade to verified.'}</div>
              <div class="verify-visual">
                ${safetyGrid(safety)}
                <div class="verify-words">${safetyWords(safety)}${safetyNumeric(safety)}</div>
              </div>
              ${p.trust !== 'verified' ? `<button class="btn primary" id="verify">${icon('verified')} Mark verified</button>` : `<span class="pill good">${icon('check')} safety number matched</span>`}`}
        </div>
      </div>
    </div>`;

  wrap.querySelector('#ct-back')?.addEventListener('click', () => { state.ui.mobileDetail = false; bus.rerender(); });
  wrap.querySelector('#ct-msg').onclick = () => openCompose({ to: p.address });
  wrap.querySelector('#ct-chat').onclick = () => {
    let c = state.chats.find(x => x.type === 'dm' && x.with === p.id);
    if (!c) { c = { id: uid('dm'), type: 'dm', with: p.id, presence: null, typing: false, unread: 0, msgs: [] }; state.chats.push(c); }
    state.ui.selChat = c.id; state.ui.chatThread = null; state.ui.mobileDetail = true;
    bus.setView('chat');
    toast(`${icon('chat')} Chat opened with ${p.name}`);
  };
  wrap.querySelector('#ct-invite').onclick = () => newEventModal(null, null, [p.address]);
  wrap.querySelector('#ct-edit').onclick = () => contactEditor(p);
  const vb = wrap.querySelector('#verify');
  if (vb) vb.onclick = () => { p.trust = 'verified'; toast(`${icon('verified')} Safety number matched — ${p.name} is now verified`); bus.rerender(); };
}

function splitName(name) {
  const parts = (name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length <= 1) return { given: parts[0] || '', family: '' };
  return { given: parts.slice(0, -1).join(' '), family: parts[parts.length - 1] };
}

// Create or edit a contact card (spec §17#30). Tags are local organizational groups (§17#31);
// Groups here are real addressable Groups (spec §5.8) — checking one adds/removes the contact's
// address from that group's member list.
function contactEditor(existing) {
  const p = existing || { id: uid('c'), name: '', address: '', hue: Math.floor(Math.random() * 360), trust: 'tofu', org: '', title: '', phone: '', note: '', tags: [], avatarUrl: null, addresses: [] };
  const auto = splitName(p.name);
  const givenVal = p.givenName ?? auto.given;
  const familyVal = p.familyName ?? auto.family;
  const originalAddress = p.address;
  const memberGroupIds = new Set(state.groups.filter(g => g.members.some(m => m.address === p.address)).map(g => g.id));
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>${existing ? 'Edit contact' : 'New contact'}</h2><button class="icon-btn" id="cx">${icon('x')}</button></div>

      <div class="pf-avatar-row">
        <div class="pf-preview" id="ctavprev"></div>
        <div class="pf-avatar-fields">
          <label class="cfield"><span>Avatar URL</span><input id="pav" value="${esc(p.avatarUrl || '')}" placeholder="https://example.com/photo.jpg" autocomplete="off"></label>
          <div class="pf-src-hint">Falls back to a deterministic initials tile if unset or unreachable.</div>
        </div>
      </div>

      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Name</span><input id="pgiven" value="${esc(givenVal)}" placeholder="Ada" autofocus></label>
        <label class="cfield"><span>Surname</span><input id="pfamily" value="${esc(familyVal)}" placeholder="Okonkwo"></label>
      </div>
      <label class="cfield"><span>Primary address</span><input id="pa" value="${esc(p.address)}" placeholder="ada@envoir.org, a key-name, alice.eth/.sol, or @handle"></label>
      <div class="resolver-hint" id="paresolver"></div>
      <label class="cfield"><span>Additional addresses (comma-separated)</span><input id="paddrs" value="${esc((p.addresses || []).join(', '))}" placeholder="alias@envoir.org, old@legacy.example"></label>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Title</span><input id="pt" value="${esc(p.title || '')}" placeholder="Protocol lead"></label>
        <label class="cfield"><span>Organization</span><input id="po" value="${esc(p.org || '')}" placeholder="DMTAP Core"></label>
      </div>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Phone</span><input id="pp" value="${esc(p.phone || '')}" placeholder="+1 555 0123"></label>
        <label class="cfield"><span>Tags (comma-separated)</span><input id="pg" value="${esc((p.tags || []).join(', '))}" placeholder="Team, Work"></label>
      </div>
      ${state.groups.length ? `<label class="cfield"><span>Groups</span><div class="toggle-chips" id="ctgroups">
        ${state.groups.map(g => `<button type="button" class="toggle-chip ${memberGroupIds.has(g.id) ? 'on' : ''}" data-g="${g.id}" aria-pressed="${memberGroupIds.has(g.id)}">${esc(g.name)}</button>`).join('')}
      </div></label>` : ''}
      <label class="cfield"><span>Note</span><textarea id="pnote" rows="2" placeholder="How you know them, verification context…">${esc(p.note || '')}</textarea></label>
      <div class="ev-detail-foot">
        <span class="sim-tag">${icon('shield')} JSContact MOTE · E2E-encrypted · synced across your devices</span>
        <div class="spacer"></div>
        ${existing ? `<button class="btn danger" id="pdel">Delete</button>` : ''}
        <button class="btn primary" id="psave">${existing ? 'Save' : 'Add contact'}</button>
      </div>
    </div>`, { wide: true });

  const $ = (s) => card.querySelector(s);
  const drawAvPrev = () => {
    const nm = [$('#pgiven').value.trim(), $('#pfamily').value.trim()].filter(Boolean).join(' ') || 'New contact';
    $('#ctavprev').innerHTML = avatar({ name: nm, hue: p.hue, trust: p.trust, avatarUrl: $('#pav').value.trim() || null }, 64, { ring: true });
  };
  drawAvPrev();
  // Live resolver-type feedback (spec §3.12) as the address is typed — accepts a key-name, a
  // name@domain, an alice.eth/.sol name-chain address, or an @handle, and shows honestly which
  // resolver it would use rather than assuming DNS.
  const drawAddrResolver = () => {
    const info = classifyName($('#pa').value);
    $('#paresolver').innerHTML = $('#pa').value.trim() ? resolverChip(info) + `<span class="resolver-note">${esc(resolverDetail(info))}</span>` : '';
  };
  drawAddrResolver();
  $('#pa').addEventListener('input', drawAddrResolver);
  $('#pav').addEventListener('input', drawAvPrev);
  $('#pgiven').addEventListener('input', drawAvPrev);
  $('#pfamily').addEventListener('input', drawAvPrev);

  const groupSel = new Set(memberGroupIds);
  card.querySelectorAll('#ctgroups .toggle-chip').forEach(b => b.onclick = () => {
    const g = b.dataset.g;
    if (groupSel.has(g)) groupSel.delete(g); else groupSel.add(g);
    b.classList.toggle('on', groupSel.has(g)); b.setAttribute('aria-pressed', groupSel.has(g));
  });

  card.querySelector('#cx').onclick = closeModal;
  card.querySelector('#psave').onclick = () => {
    const givenN = $('#pgiven').value.trim();
    const familyN = $('#pfamily').value.trim();
    const name = [givenN, familyN].filter(Boolean).join(' ');
    const address = $('#pa').value.trim();
    if (!name) return toast('Add a name');
    if (!address) return toast('Add an address');
    p.name = name; p.givenName = givenN; p.familyName = familyN; p.address = address;
    p.avatarUrl = $('#pav').value.trim() || null;
    p.addresses = $('#paddrs').value.split(',').map(s => s.trim()).filter(Boolean);
    p.title = $('#pt').value.trim();
    p.org = $('#po').value.trim();
    p.phone = $('#pp').value.trim();
    p.note = $('#pnote').value.trim();
    p.tags = $('#pg').value.split(',').map(s => s.trim()).filter(Boolean);
    // sync real Group membership against the toggle chips
    state.groups.forEach(g => {
      const has = g.members.some(m => m.address === originalAddress);
      const want = groupSel.has(g.id);
      if (want && !has) g.members.push({ address, role: 'member' });
      else if (!want && has) g.members = g.members.filter(m => m.address !== originalAddress);
      else if (want && has && originalAddress !== address) g.members = g.members.map(m => m.address === originalAddress ? { ...m, address } : m);
    });
    if (!existing) { addPerson(p); selId = p.id; }
    else { const wrap = document.querySelector('#ctdetail'); if (wrap) wrap.dataset.for = ''; } // force re-render of hero
    closeModal(); bus.rerender();
    toast(`${icon('check')} ${existing ? 'Contact updated' : name + ' added'} — pinned to their key (TOFU)`);
  };
  if (existing) card.querySelector('#pdel').onclick = () => {
    if (!confirm(`Delete ${p.name} from Contacts? This can't be undone here.`)) return;
    removePerson(p.id);
    state.groups.forEach(g => { g.members = g.members.filter(m => m.address !== p.address); });
    if (selId === p.id) selId = null;
    closeModal(); bus.rerender();
    toast('Contact deleted');
  };
}

// Export affordance — offers a real JSContact/vCard-shaped JSON download of the address book.
function exportContacts() {
  const data = PEOPLE.map(p => ({ fullName: p.name, address: p.address, otherAddresses: p.addresses || [], organization: p.org || undefined, title: p.title || undefined, phone: p.phone || undefined, tags: p.tags || [], verification: p.trust }));
  try {
    const blob = new Blob([JSON.stringify({ '@type': 'JSContactCollection', contacts: data }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'envoir-contacts.jscontact.json';
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`${icon('export')} Exported ${PEOPLE.length} contacts as JSContact (CardDAV projects this as vCard 4.0)`, { ms: 4200 });
  } catch { toast('Export unavailable in this context'); }
}
