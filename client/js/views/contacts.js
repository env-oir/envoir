// views/contacts.js — address book (JSContact-style MOTEs, spec §8.4). Each contact card
// shows a KEY VERIFICATION status: verified (safety number compared out-of-band), pinned
// (TOFU, spec §3.4), or legacy. The safety number is the anti-spoofing anchor — the name is
// just a pointer, the key is the identity.

import { state } from '../store.js';
import { PEOPLE, person } from '../seed.js';
import { el, esc, icon, avatar, trustPill, toast, emptyState, safetyWords, safetyGrid, safetyNumeric } from '../ui.js';
import { deriveSafetyFromString } from '../safety.js';
import { bus } from '../bus.js';

let selId = null;

export function render(root) {
  root.className = 'view contacts-view';
  selId = selId || PEOPLE[0].id;
  root.innerHTML = `
    <aside class="ct-list">
      <div class="list-head"><h2>Contacts</h2>
        <div class="ct-io">
          <button class="icon-btn" id="ct-import" title="Import vCard">${icon('import')}</button>
          <button class="icon-btn" id="ct-export" title="Export">${icon('export')}</button>
        </div>
      </div>
      <div class="ct-rows" id="ctrows"></div>
    </aside>
    <section class="ct-detail" id="ctdetail"></section>`;
  const rows = root.querySelector('#ctrows');
  const q = state.ui.search.trim().toLowerCase();
  const list = PEOPLE.filter(p => !q || (p.name + ' ' + p.address).toLowerCase().includes(q));
  if (!list.length) rows.innerHTML = emptyState('contacts', 'No contacts', 'Try a different search.');
  list.forEach(p => {
    const row = el(`<button class="ct-row ${selId === p.id ? 'sel' : ''}" data-id="${p.id}">
      ${avatar(p, 38, { ring: true, badge: true })}
      <div class="ct-row-main"><span class="ct-name">${esc(p.name)}</span><span class="ct-addr mono">${esc(p.address)}</span></div>
      ${p.trust === 'verified' ? `<span class="vglyph sm">${icon('verified')}</span>` : ''}
    </button>`);
    row.onclick = () => { selId = p.id; bus.rerender(); };
    rows.appendChild(row);
  });
  root.querySelector('#ct-import').onclick = () => toast(`${icon('import')} Simulated — a production client imports vCard 4.0 / JSContact and pins each key on first contact (TOFU)`, { ms: 4200 });
  root.querySelector('#ct-export').onclick = () => toast(`${icon('export')} Simulated — exports your address book as JSContact MOTEs / vCard 4.0`, { ms: 4200 });
  drawDetail(root);
}

async function drawDetail(root) {
  const wrap = root.querySelector('#ctdetail');
  const p = person(selId);
  if (!p) { wrap.innerHTML = emptyState('contacts', 'Select a contact', 'Verify keys by comparing safety numbers.'); return; }
  const groups = state.groups.filter(g => g.members.some(m => m.address === p.address));
  const safety = await deriveSafetyFromString(p.address + p.name);

  wrap.innerHTML = `
    <div class="ct-card">
      <div class="ct-card-hero" style="--h:${p.hue}">
        ${avatar(p, 84, { ring: true, badge: true })}
        <h1>${esc(p.name)}</h1>
        <div class="ct-card-sub">${esc([p.title, p.org].filter(Boolean).join(' · ')) || 'Contact'}</div>
        <div>${trustPill(p.trust)}</div>
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

  const vb = wrap.querySelector('#verify');
  if (vb) vb.onclick = () => { p.trust = 'verified'; toast(`${icon('verified')} Safety number matched — ${p.name} is now verified`); bus.rerender(); };
}
