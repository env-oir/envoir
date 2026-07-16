// views/contacts.js — address book (JSContact-style MOTEs, spec §8.4). Each contact card
// shows a KEY VERIFICATION status: verified (safety number compared out-of-band), pinned
// (TOFU, spec §3.4), or legacy. The safety number is the anti-spoofing anchor — the name is
// just a pointer, the key is the identity. Contacts can be created/edited and organized into
// local TAG groups (spec §17#31: an organizational label with no address of its own — distinct
// from an addressable group, which lives in Groups).

import { state, uid } from '../store.js';
import { PEOPLE, person, addPerson, contactTags } from '../seed.js';
import { el, esc, icon, avatar, trustPill, toast, emptyState, openModal, closeModal, safetyWords, safetyGrid, safetyNumeric, shimmerRows } from '../ui.js';
import { deriveSafetyFromString } from '../safety.js';
import { bus } from '../bus.js';
import { openCompose } from '../compose.js';

let selId = null;
let tagFilter = null;

export function render(root) {
  root.className = 'view contacts-view';
  if (!selId || !person(selId)) selId = PEOPLE[0].id;
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
      <div class="ct-rows" id="ctrows"></div>
    </aside>
    <section class="ct-detail" id="ctdetail"></section>`;
  const rows = root.querySelector('#ctrows');
  const q = state.ui.search.trim().toLowerCase();
  const list = PEOPLE.filter(p => (!q || (p.name + ' ' + p.address).toLowerCase().includes(q)) && (!tagFilter || (p.tags || []).includes(tagFilter)));
  if (!list.length) rows.innerHTML = emptyState('contacts', 'No contacts', q ? 'Try a different search.' : 'Add someone with the + button.');
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
  root.querySelector('#ct-new').onclick = () => contactEditor(null);
  root.querySelector('#ct-import').onclick = () => toast(`${icon('import')} Simulated — a production client imports vCard 4.0 / JSContact and pins each key on first contact (TOFU)`, { ms: 4200 });
  root.querySelector('#ct-export').onclick = () => exportContacts();
  root.classList.toggle('detail', state.ui.mobileDetail && !!selId);
  drawDetail(root);
}

async function drawDetail(root) {
  const wrap = root.querySelector('#ctdetail');
  const p = person(selId);
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

  wrap.innerHTML = `
    <div class="ct-card">
      <div class="ct-card-hero" style="--h:${p.hue}">
        <button class="icon-btn mobile-back" id="ct-back" aria-label="Back to contacts list" title="Back" style="position:absolute;left:14px;top:14px">${icon('reply')}</button>
        <div class="ct-head-actions">
          <button class="icon-btn" id="ct-msg" title="Send message">${icon('mail')}</button>
          <button class="icon-btn" id="ct-edit" title="Edit contact">${icon('edit')}</button>
        </div>
        ${avatar(p, 84, { ring: true, badge: true })}
        <h1>${esc(p.name)}</h1>
        <div class="ct-card-sub">${esc([p.title, p.org].filter(Boolean).join(' · ')) || 'Contact'}</div>
        <div>${trustPill(p.trust)}</div>
        ${(p.tags || []).length ? `<div class="ct-card-tags">${p.tags.map(t => `<i class="chip-lbl" style="--h:200">${esc(t)}</i>`).join('')}</div>` : ''}
      </div>
      <div class="ct-card-body">
        <div class="ct-field"><span class="k">${icon('mail')} Address</span><span class="v mono">${esc(p.address)}</span></div>
        ${p.phone ? `<div class="ct-field"><span class="k">${icon('bell')} Phone</span><span class="v mono">${esc(p.phone)}</span></div>` : ''}
        ${p.note ? `<div class="ct-field"><span class="k">${icon('edit')} Note</span><span class="v">${esc(p.note)}</span></div>` : ''}
        ${groups.length ? `<div class="ct-field"><span class="k">${icon('groups')} Groups</span><span class="v">${groups.map(g => `<i class="chip-lbl" style="--h:250">${esc(g.name)}</i>`).join(' ')}</span></div>` : ''}

        <div class="verify-box ${p.trust}">
          <div class="verify-head">
            ${p.trust === 'verified' ? `${icon('verified')} <b>Key verified</b>` : p.trust === 'legacy' ? `${icon('shield')} <b>Legacy contact — no DMTAP key</b>` : `${icon('lock')} <b>Pinned on first contact (TOFU)</b>`}
          </div>
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
  wrap.querySelector('#ct-edit').onclick = () => contactEditor(p);
  const vb = wrap.querySelector('#verify');
  if (vb) vb.onclick = () => { p.trust = 'verified'; toast(`${icon('verified')} Safety number matched — ${p.name} is now verified`); bus.rerender(); };
}

// Create or edit a contact card (spec §17#30). Tags are local organizational groups (§17#31).
function contactEditor(existing) {
  const p = existing || { id: uid('c'), name: '', address: '', hue: Math.floor(Math.random() * 360), trust: 'tofu', org: '', title: '', phone: '', note: '', tags: [] };
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>${existing ? 'Edit contact' : 'New contact'}</h2><button class="icon-btn" id="cx">${icon('x')}</button></div>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Name</span><input id="pn" value="${esc(p.name)}" placeholder="Ada Okonkwo" autofocus></label>
        <label class="cfield"><span>Address</span><input id="pa" value="${esc(p.address)}" placeholder="ada@envoir.org or @handle"></label>
      </div>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Title</span><input id="pt" value="${esc(p.title || '')}" placeholder="Protocol lead"></label>
        <label class="cfield"><span>Organization</span><input id="po" value="${esc(p.org || '')}" placeholder="DMTAP Core"></label>
      </div>
      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Phone</span><input id="pp" value="${esc(p.phone || '')}" placeholder="+1 555 0123"></label>
        <label class="cfield"><span>Tags (comma-separated)</span><input id="pg" value="${esc((p.tags || []).join(', '))}" placeholder="Team, Work"></label>
      </div>
      <label class="cfield"><span>Note</span><textarea id="pnote" rows="2" placeholder="How you know them, verification context…">${esc(p.note || '')}</textarea></label>
      <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} JSContact MOTE · E2E-encrypted · synced across your devices</span><div class="spacer"></div><button class="btn primary" id="psave">${existing ? 'Save' : 'Add contact'}</button></div>
    </div>`, { wide: true });
  card.querySelector('#cx').onclick = closeModal;
  card.querySelector('#psave').onclick = () => {
    const name = card.querySelector('#pn').value.trim();
    const address = card.querySelector('#pa').value.trim();
    if (!name) return toast('Add a name');
    if (!address) return toast('Add an address');
    p.name = name; p.address = address;
    p.title = card.querySelector('#pt').value.trim();
    p.org = card.querySelector('#po').value.trim();
    p.phone = card.querySelector('#pp').value.trim();
    p.note = card.querySelector('#pnote').value.trim();
    p.tags = card.querySelector('#pg').value.split(',').map(s => s.trim()).filter(Boolean);
    if (!existing) { addPerson(p); selId = p.id; }
    else { const wrap = document.querySelector('#ctdetail'); if (wrap) wrap.dataset.for = ''; } // force re-render of hero
    closeModal(); bus.rerender();
    toast(`${icon('check')} ${existing ? 'Contact updated' : name + ' added'} — pinned to their key (TOFU)`);
  };
}

// Export affordance — offers a real JSContact/vCard-shaped JSON download of the address book.
function exportContacts() {
  const data = PEOPLE.map(p => ({ fullName: p.name, address: p.address, organization: p.org || undefined, title: p.title || undefined, phone: p.phone || undefined, tags: p.tags || [], verification: p.trust }));
  try {
    const blob = new Blob([JSON.stringify({ '@type': 'JSContactCollection', contacts: data }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'envoir-contacts.jscontact.json';
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`${icon('export')} Exported ${PEOPLE.length} contacts as JSContact (CardDAV projects this as vCard 4.0)`, { ms: 4200 });
  } catch { toast('Export unavailable in this context'); }
}
