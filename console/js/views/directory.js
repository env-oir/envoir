// views/directory.js — the DomainDirectory (GAL): the signed, versioned, KT-logged enumeration
// of the domain's member + group bindings (spec §3.10.3, §18.4.7). Two ideas are made visible:
//
//   1. The directory is a convenience INDEX, not a root of trust. Each DirEntry's name→ik MUST
//      verify forward via DNS + KT before use; an entry that doesn't is rendered UNVERIFIED and
//      cannot be used to address mail (ERR_DIRECTORY_ENTRY_UNVERIFIED). A compromised directory
//      can withhold/mislabel (detectable via KT) but can never make mail encrypt to a wrong key.
//   2. Membership visibility is a disclosed org choice: `public` (world-listable staff page) vs
//      `members-only` (roster served only to authenticated members).

import { state, directoryEntries, republishDirectory, logEvent, member } from '../store.js';
import { bus } from '../bus.js';
import { el, esc, icon, custodyBadge, toast, fmtDate, emptyState, copyBtn } from '../ui.js';

export function render(root) {
  root.className = 'view scroll-view';
  const d = state.domain;
  const entries = directoryEntries();
  const q = state.ui.search.trim().toLowerCase();
  const shown = entries.filter(e => !q || (e.name + ' ' + e.kind).toLowerCase().includes(q));
  const unverified = entries.filter(e => !e.dirVerified).length;

  root.innerHTML = `
  <div class="page">
    <header class="page-head">
      <div>
        <h1>Directory <span class="pill accent sm">GAL</span></h1>
        <p class="page-sub">The signed, versioned, KT-logged enumeration of every <span class="mono">name@${esc(d.name)}</span> binding — the global address list. It <b>indexes</b> bindings; it does not attest them.</p>
      </div>
    </header>

    <section class="dir-summary">
      <div class="card dir-meta">
        <div class="dir-meta-grid">
          <div class="kvr"><span>Version</span><b class="mono">v${d.dirVersion}</b></div>
          <div class="kvr"><span>Entries</span><b class="mono">${entries.length}</b></div>
          <div class="kvr"><span>Signed by</span><b class="mono ellip">${esc(d.fingerprint)}</b></div>
          <div class="kvr"><span>Signature</span><b class="mono ellip">${esc(d.dirSig || '—')}</b></div>
        </div>
        <div class="dir-sig-note">${icon('shield')} Signed under the threshold-held domain authority key (spec §3.10.1). A verifier MUST reject a directory not signed by the pinned authority (<span class="mono">ERR_DOMAIN_DIRECTORY_SIG_INVALID</span>).</div>
      </div>

      <div class="card vis-card">
        <div class="card-h"><h2>${icon(d.membershipVisibility === 'public' ? 'eye' : 'lock')} Membership visibility</h2></div>
        <p class="card-sub">A disclosed org policy choice — mirrors group membership visibility (spec §3.10.3).</p>
        <div class="seg vis-seg" role="group" aria-label="Membership visibility">
          <button data-vis="public" aria-pressed="${d.membershipVisibility === 'public'}" class="${d.membershipVisibility === 'public' ? 'on' : ''}">${icon('eye')} Public</button>
          <button data-vis="members-only" aria-pressed="${d.membershipVisibility === 'members-only'}" class="${d.membershipVisibility === 'members-only' ? 'on' : ''}">${icon('lock')} Members-only</button>
        </div>
        <p class="vis-explain">${d.membershipVisibility === 'public'
          ? 'World-listable — a public staff page. Anyone can enumerate the roster. Individual addresses were resolvable anyway; this makes the <b>list</b> public too.'
          : 'The roster is served only to authenticated members. Each <span class="mono">name@' + esc(d.name) + '</span> stays resolvable if you already know it, but the membership <b>list</b> is not a public artifact.'}</p>
      </div>
    </section>

    ${unverified ? `<div class="banner bad">${icon('warn')} <span><b>${unverified}</b> ${unverified === 1 ? 'entry does' : 'entries do'} not resolve forward via DNS + KT. The directory enumerates them but clients MUST render them unverified and MUST NOT address mail to them (spec §3.10.3).</span></div>` : ''}

    <section class="card">
      <div class="card-h">
        <h2>${icon('directory')} Directory entries <span class="list-count">${shown.length}</span></h2>
        <button class="btn sm" id="reverify">${icon('refresh')} Re-verify all forward bindings</button>
      </div>
      <div class="dir-table" id="dir-table"></div>
    </section>
  </div>`;

  const table = root.querySelector('#dir-table');
  if (!shown.length) {
    table.innerHTML = emptyState('search', 'No entries', q ? 'No entries match your search.' : 'The directory is empty.');
  } else {
    table.innerHTML = `
      <div class="dir-th"><span>Name</span><span>Kind</span><span>Custody</span><span>Roles</span><span>Forward binding</span><span>Added</span></div>`;
    shown.forEach(e => {
      const row = el(`<div class="dir-tr ${e.dirVerified ? '' : 'unv'}">
        <span class="dir-name mono">${esc(e.name)}</span>
        <span>${e.kind === 'group' ? `<span class="pill accent sm">${icon('groups')} group</span>` : `<span class="pill dim sm">${icon('members')} member</span>`}</span>
        <span>${custodyBadge(e.custody, true)}</span>
        <span class="dir-roles">${(e.roles || []).length ? e.roles.map(r => `<span class="pill dim sm">${esc(r)}</span>`).join('') : '<span class="muted">—</span>'}</span>
        <span>${e.dirVerified ? `<span class="fv ok">${icon('check')} verified via DNS+KT</span>` : `<span class="fv bad">${icon('warn')} unverified</span>`}</span>
        <span class="muted">${esc(fmtDate(e.added))}</span>
      </div>`);
      table.appendChild(row);
    });
  }

  root.querySelector('.dir-meta-grid').appendChild(copyBtn(d.authorityIk, 'Copy authority IK'));
  root.querySelectorAll('[data-vis]').forEach(b => b.onclick = async () => {
    if (d.membershipVisibility === b.dataset.vis) return;
    d.membershipVisibility = b.dataset.vis;
    await republishDirectory(`membership visibility → ${b.dataset.vis}`);
    await logEvent('directory', `Membership visibility set to ${b.dataset.vis}`);
    toast(`${icon('check')} Directory visibility → ${b.dataset.vis}`);
    bus.rerender();
  });
  root.querySelector('#reverify').onclick = async () => {
    // Re-check forward resolution. In the sim, an unverified entry's binding is "repaired" by
    // re-publishing the DNS record; a production console would re-query DNS + KT.
    let fixed = 0;
    state.members.filter(m => m.status === 'active' && !m.dirVerified).forEach(m => { m.dirVerified = true; fixed++; });
    if (fixed) { await republishDirectory('re-verified forward bindings'); await logEvent('directory', `Re-verified ${fixed} forward binding(s)`); }
    toast(fixed ? `${icon('check')} ${fixed} binding(s) now resolve forward` : `${icon('check')} All entries already verified`);
    bus.rerender();
  };
}
