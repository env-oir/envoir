// views/members.js — provision, inspect and offboard members. This is where the sovereignty
// distinction is made legible (spec §3.10.2):
//
//   SOVEREIGN (default)   — the member generates their own key on their device; the org publishes
//                           ONLY the name→key binding. The org cannot read, impersonate or recover.
//                           At creation the private key is discarded — it never touches the org.
//   ORG-MANAGED (opt-in)  — the org generates/escrows the key. It buys password-reset, compliance
//                           hold and discovery, at the disclosed cost that the org CAN access and
//                           impersonate the account. Requires an explicit typed consent gate, and
//                           carries a machine-visible `org-managed` badge everywhere afterwards.
//
// Offboarding diverges honestly: a sovereign member's KEY SURVIVES (only the name binding is
// revoked); an org-managed mailbox can be retained by the org (§3.10.5).

import { state, uid, member, rolesOf, republishDirectory, logEvent, hueFor, group } from '../store.js';
import { generateKeypair } from '../crypto.js';
import { escrowStore, escrowDrop, escrowHas, impersonateSign } from '../session.js';
import { bus } from '../bus.js';
import {
  el, esc, icon, avatar, custodyBadge, statusPill, openModal, closeModal, emptyState,
  toast, fmtDate, safetyWords, safetyGrid,
} from '../ui.js';

export function render(root) {
  root.className = 'view split-view';
  const q = state.ui.search.trim().toLowerCase();
  const all = state.members;
  const list = all.filter(m => !q || (m.name + ' ' + m.address + ' ' + (m.title || '')).toLowerCase().includes(q));
  const sel = member(state.ui.selMember) && list.includes(member(state.ui.selMember)) ? member(state.ui.selMember)
    : (list[0] || null);
  state.ui.selMember = sel?.id || null;

  root.innerHTML = `
    <aside class="split-list">
      <div class="list-head">
        <h2>Members <span class="list-count">${all.filter(m => m.status === 'active').length}</span></h2>
        <button class="btn primary sm" id="add">${icon('plus')} Add</button>
      </div>
      <div class="list-legend">
        <span>${custodyBadge('sovereign', true)}</span>
        <span>${custodyBadge('org-managed', true)}</span>
      </div>
      <div class="list-rows" id="rows"></div>
    </aside>
    <section class="split-detail" id="detail"></section>`;

  const rows = root.querySelector('#rows');
  if (!list.length) {
    rows.innerHTML = q ? emptyState('search', 'No matches', 'No members match your search.')
      : emptyState('members', 'No members yet', 'Provision your first member to publish a name→key binding under the domain.');
  } else {
    list.forEach(m => {
      const on = m.id === sel?.id;
      const row = el(`<button class="list-row ${on ? 'sel' : ''} ${m.status === 'offboarded' ? 'off' : ''}" data-id="${m.id}"${on ? ' aria-current="true"' : ''}>
        ${avatar(m.name, m.hue, 38)}
        <div class="list-row-main">
          <span class="lr-name">${esc(m.name)}${!m.dirVerified && m.status === 'active' ? ` <span class="pill bad sm" title="Does not resolve forward via DNS+KT">${icon('warn')} unverified</span>` : ''}</span>
          <span class="lr-sub mono">${esc(m.address)}</span>
        </div>
        ${custodyBadge(m.custody, true)}
      </button>`);
      row.onclick = () => { state.ui.selMember = m.id; bus.rerender(); };
      rows.appendChild(row);
    });
  }
  root.querySelector('#add').onclick = () => addMemberModal();
  drawDetail(root.querySelector('#detail'), sel);
}

// ---- detail: the sovereignty capability matrix ------------------------------------------
function drawDetail(wrap, m) {
  if (!m) { wrap.innerHTML = emptyState('members', 'No member selected', 'Select a member to see their binding and what the org can do.'); return; }
  const roles = rolesOf(m.address);
  const managed = m.custody === 'org-managed';
  const off = m.status === 'offboarded';
  const memberGroups = state.groups.filter(g => g.members.includes(m.address));

  // The load-bearing legibility surface: for a sovereign member every "can the org…?" row is NO.
  const capRow = (label, can, note) =>
    `<div class="cap-row ${can ? 'yes' : 'no'}"><span class="cap-ic">${icon(can ? 'check' : 'x')}</span><b>${esc(label)}</b><small>${esc(note)}</small></div>`;

  wrap.innerHTML = `
    <div class="detail-scroll">
      <div class="member-hero">
        ${avatar(m.name, m.hue, 60)}
        <div class="member-hero-main">
          <h1>${esc(m.name)} ${off ? '<span class="pill dim sm">offboarded</span>' : ''}</h1>
          <div class="member-hero-addr"><span class="mono key">${esc(m.address)}</span></div>
          <div class="member-hero-tags">${custodyBadge(m.custody)}${statusPill(m.status)}${m.dirVerified ? `<span class="pill accent sm">${icon('check')} directory-verified</span>` : `<span class="pill bad sm">${icon('warn')} forward-unverified</span>`}${roles.map(r => `<span class="pill dim sm">${icon('roles')} ${esc(r)}</span>`).join('')}</div>
        </div>
        ${!off ? `<button class="btn danger" id="offboard">${icon('logout')} Offboard</button>` : `<button class="btn" id="restore">${icon('refresh')} Re-bind name</button>`}
      </div>

      ${!m.dirVerified && !off ? `<div class="banner bad">${icon('warn')} <span>This entry's <b>name→key</b> does not resolve forward via DNS + KT (spec §3.9.4). The directory indexes it but a client MUST render it <b>unverified</b> and MUST NOT address mail to it (<span class="mono">ERR_DIRECTORY_ENTRY_UNVERIFIED</span>). Re-publish the binding to fix.</span></div>` : ''}

      <div class="detail-cols">
        <div class="card">
          <div class="card-h"><h2>${icon('key')} Identity binding</h2></div>
          <div class="kv-list">
            <div class="kv"><span class="k">Name</span><span class="v mono">${esc(m.address)}</span></div>
            <div class="kv"><span class="k">Identity key</span><span class="v mono ellip">${esc(m.ik.slice(0, 32))}…</span></div>
            <div class="kv"><span class="k">Fingerprint</span><span class="v mono">${esc(m.fingerprint)}</span></div>
            <div class="kv"><span class="k">Custody</span><span class="v">${custodyBadge(m.custody, true)}</span></div>
            <div class="kv"><span class="k">Provisioned</span><span class="v">${esc(fmtDate(m.added))}</span></div>
            ${m.title ? `<div class="kv"><span class="k">Title</span><span class="v">${esc(m.title)}</span></div>` : ''}
          </div>
          <div class="member-safety">
            <div class="mini-h">${icon('verified')} Safety number</div>
            <div class="member-safety-vis">${safetyGrid(m.safety)}${safetyWords(m.safety)}</div>
          </div>
        </div>

        <div class="card cap-card ${managed ? 'managed' : 'sovereign'}">
          <div class="card-h"><h2>${icon('scale')} What the org can do to this account</h2></div>
          <p class="card-sub">${managed
            ? 'This is an <b>org-managed</b> account: the org holds the escrowed key, so it can act as the user. This is the disclosed cost of the model (spec §3.10.2b).'
            : 'This is a <b>sovereign</b> account: the member holds their own key and the org never had it. The org controls the <b>name</b>, nothing the key protects (spec §3.10.2a).'}</p>
          <div class="cap-matrix">
            ${capRow('Revoke / re-point the name', true, 'Domain authority controls names')}
            ${capRow('Read their mail', managed, managed ? 'Org holds the escrowed key' : 'Never held the key — cannot decrypt')}
            ${capRow('Impersonate / sign as them', managed, managed ? 'Escrowed key can sign' : 'No private key to sign with')}
            ${capRow('Recover / seize their key', managed, managed ? 'Escrow enables recovery' : 'Key is theirs alone')}
          </div>
          ${managed ? `<div class="managed-actions">
            <p class="managed-note">${icon('unlock')} The console can demonstrate this cost by really signing a message with the escrowed key.</p>
            <button class="btn" id="demo-sign">${icon('key')} Sign a message as ${esc(m.name)}</button>
          </div>` : `<div class="sovereign-seal">${icon('shield')} <span>You are looking at a binding, not a mailbox. There is nothing here for the org to read.</span></div>`}
        </div>
      </div>

      <div class="card">
        <div class="card-h"><h2>${icon('groups')} Group memberships <span class="list-count">${memberGroups.length}</span></h2></div>
        ${memberGroups.length ? `<div class="chip-row">${memberGroups.map(g => `<button class="chip-btn" data-grp="${g.id}">${icon(g.mode === 'broadcast' ? 'bell' : 'chat')} ${esc(g.address)}</button>`).join('')}</div>`
          : `<p class="muted">Not a member of any group.</p>`}
      </div>
    </div>`;

  wrap.querySelector('#offboard')?.addEventListener('click', () => offboardModal(m));
  wrap.querySelector('#restore')?.addEventListener('click', async () => {
    m.status = 'active'; m.dirVerified = true;
    await republishDirectory(`re-bound ${m.address}`);
    await logEvent('member', `${m.name} re-bound to ${m.address}`);
    toast(`${icon('check')} ${esc(m.name)} re-bound`); bus.rerender();
  });
  wrap.querySelector('#demo-sign')?.addEventListener('click', () => demoSign(m));
  wrap.querySelectorAll('[data-grp]').forEach(b => b.onclick = () => { state.ui.selGroup = b.dataset.grp; bus.setView('groups'); });
}

// ---- add member: the two provisioning models with a consent gate ------------------------
function addMemberModal() {
  let mode = 'sovereign', consent = false, busy = false;
  const card = openModal('<div class="q-loading"></div>', { wide: true, label: 'Add a member' });

  const draw = () => {
    const managed = mode === 'org-managed';
    card.innerHTML = `
      <div class="modal-head"><h2>${icon('plus')} Add a member to @${esc(state.domain.name)}</h2><button class="icon-btn" id="ax" aria-label="Close">${icon('x')}</button></div>
      <div class="modal-body">
        <div class="model-select" role="radiogroup" aria-label="Provisioning model">
          <button class="model-opt ${!managed ? 'sel' : ''}" data-mode="sovereign" role="radio" aria-checked="${!managed}">
            <div class="model-opt-h">${icon('key')} Sovereign<span class="pill good sm">recommended</span></div>
            <p>The member generates their own key. You publish only the <b>name→key</b> binding. You <b>cannot</b> read their mail, impersonate them, or recover their key.</p>
          </button>
          <button class="model-opt ${managed ? 'sel warn' : ''}" data-mode="org-managed" role="radio" aria-checked="${managed}">
            <div class="model-opt-h">${icon('unlock')} Org-managed<span class="pill warn sm">disclosed escrow</span></div>
            <p>The org generates &amp; escrows the key. Enables password-reset, compliance hold and discovery — at the cost that the org <b>CAN</b> read and impersonate this account.</p>
          </button>
        </div>

        <div class="af-fields">
          <label class="cfield"><span>Full name</span><input id="mname" placeholder="Ada Okonkwo" autofocus></label>
          <label class="cfield"><span>Address</span><div class="addr-compose"><input id="mlocal" placeholder="ada"><span class="addr-domain mono">@${esc(state.domain.name)}</span></div></label>
          <label class="cfield"><span>Title <i class="opt">(optional)</i></span><input id="mtitle" placeholder="Protocol lead"></label>
        </div>

        ${managed ? `
        <div class="consent-gate">
          <div class="consent-h">${icon('warn')} Escrow consent required</div>
          <p>By provisioning this account org-managed, you acknowledge that <b>@${esc(state.domain.name)} will hold this member's key</b> and can therefore read their mail and act as them. This will be <b>machine-visible</b> to the member and their correspondents as <span class="pill warn sm">${icon('unlock')} org-managed</span> — presenting it as sovereign would fail closed (<span class="mono">ERR_ORG_MANAGED_UNDISCLOSED</span>).</p>
          <label class="consent-check"><input type="checkbox" id="consent" ${consent ? 'checked' : ''}> <span>I understand and have a stated compliance need for escrow.</span></label>
        </div>`
        : `<div class="model-explain good">${icon('shield')} <span>A real keypair is generated in this session to represent the member's device. <b>Its private key is discarded immediately</b> — the org keeps only the public key + the name binding, so "your key is your identity" stays true inside the org.</span></div>`}
      </div>
      <div class="modal-foot">
        <button class="btn ghost" id="acancel">Cancel</button>
        <div class="spacer"></div>
        <button class="btn primary" id="acreate" ${managed && !consent ? 'disabled' : ''}>${icon('plus')} Provision ${managed ? 'org-managed' : 'sovereign'} member</button>
      </div>`;

    card.querySelector('#ax').onclick = card.querySelector('#acancel').onclick = closeModal;
    card.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => { mode = b.dataset.mode; if (mode === 'sovereign') consent = false; draw(); });
    const cc = card.querySelector('#consent'); if (cc) cc.onchange = () => { consent = cc.checked; card.querySelector('#acreate').disabled = !consent; };
    card.querySelector('#acreate').onclick = async () => {
      if (busy) return;
      const name = card.querySelector('#mname').value.trim();
      const local = card.querySelector('#mlocal').value.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
      const title = card.querySelector('#mtitle').value.trim();
      if (!name) return toast(`${icon('warn')} Enter a name`);
      if (!local) return toast(`${icon('warn')} Enter an address`);
      const address = `${local}@${state.domain.name}`;
      if (state.members.some(x => x.address === address)) return toast(`${icon('warn')} ${address} already exists`);
      if (managed && !consent) return;
      busy = true;
      const go = card.querySelector('#acreate'); go.disabled = true; go.innerHTML = `${icon('refresh')} Generating key…`;

      const kp = await generateKeypair();
      const m = {
        id: uid('m'), name, local, address, ik: kp.ik, fingerprint: kp.fingerprint, safety: kp.safety, alg: kp.alg,
        custody: mode, dirVerified: true, status: 'active', title, hue: hueFor(address), added: Date.now(), groups: [],
      };
      if (managed) { escrowStore(m.id, kp.priv, kp.alg); m.escrowed = true; }
      // else: kp.priv goes out of scope here — the sovereign private key is discarded.
      state.members.push(m);
      state.ui.selMember = m.id;
      await republishDirectory(`added ${address} (${mode})`);
      await logEvent('member', `Provisioned ${address} — ${mode}`, mode === 'org-managed' ? { flag: 'escrow' } : {});
      closeModal();
      toast(mode === 'org-managed'
        ? `${icon('unlock')} ${esc(name)} provisioned org-managed · escrow disclosed`
        : `${icon('key')} ${esc(name)} provisioned sovereign · private key discarded`);
      bus.rerender();
    };
  };
  draw();
}

// ---- offboard: the honest divergence ----------------------------------------------------
function offboardModal(m) {
  const managed = m.custody === 'org-managed';
  const memberGroups = state.groups.filter(g => g.members.includes(m.address));
  const card = openModal(`
    <div class="modal-head"><h2>${icon('logout')} Offboard ${esc(m.name)}</h2><button class="icon-btn" id="ox" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note">${icon('info')} Offboarding drops the <span class="mono">${esc(m.address)}</span> name binding (KT-logged), revokes their admin roles, and removes them from org groups (re-keying shared state, spec §6.7).</p>
      <div class="offboard-diverge ${managed ? 'managed' : 'sovereign'}">
        <div class="od-h">${managed ? icon('unlock') + ' Mailbox disposition — org-managed' : icon('key') + ' Mailbox disposition — sovereign'}</div>
        <p>${managed
          ? 'Because the org holds/escrows this key, it CAN retain, transfer or archive the mailbox for continuity or compliance — the disclosed cost of this model. The escrowed key can be dropped or kept.'
          : 'Their <b>key survives</b> — the org removes only the <b>name</b>. Their identity, contacts and history are theirs; they can re-bind the same key to a new name elsewhere and correspondents follow them by key. This is a <b>name revocation, not a mailbox seizure</b>.'}</p>
      </div>
      ${memberGroups.length ? `<p class="offboard-groups">${icon('groups')} Removes from: ${memberGroups.map(g => `<span class="mono">${esc(g.address)}</span>`).join(', ')}</p>` : ''}
      ${managed ? `<label class="consent-check"><input type="checkbox" id="dropkey" checked> <span>Also drop the escrowed key (cannot access the mailbox afterwards).</span></label>` : ''}
    </div>
    <div class="modal-foot">
      <button class="btn ghost" id="ocancel">Cancel</button>
      <div class="spacer"></div>
      <button class="btn danger" id="oconfirm">${icon('logout')} Offboard ${esc(m.name)}</button>
    </div>`, { wide: true, label: 'Offboard member' });

  card.querySelector('#ox').onclick = card.querySelector('#ocancel').onclick = closeModal;
  card.querySelector('#oconfirm').onclick = async () => {
    m.status = 'offboarded';
    // revoke roles
    state.caps.filter(c => c.subject === m.address && !c.revoked).forEach(c => { c.revoked = true; c.revokedAt = Date.now(); });
    // remove from groups
    state.groups.forEach(g => { g.members = g.members.filter(a => a !== m.address); });
    const dropKey = managed && card.querySelector('#dropkey')?.checked;
    if (dropKey) { escrowDrop(m.id); m.escrowed = false; }
    await republishDirectory(`offboarded ${m.address}`);
    await logEvent('member', `Offboarded ${m.address} — ${managed ? (dropKey ? 'org-managed, escrow dropped' : 'org-managed, mailbox retained') : 'sovereign key survives (name revoked)'}`);
    closeModal();
    toast(managed ? `${icon('check')} ${esc(m.name)} offboarded` : `${icon('key')} ${esc(m.name)} offboarded · their key survives`);
    bus.rerender();
  };
}

// ---- demonstrate org-managed impersonation (real signature) ------------------------------
function demoSign(m) {
  if (!escrowHas(m.id)) return toast(`${icon('warn')} No escrowed key`);
  const card = openModal(`
    <div class="modal-head"><h2>${icon('unlock')} Sign as ${esc(m.name)}</h2><button class="icon-btn" id="sx" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <p class="modal-note warn">${icon('warn')} This is the disclosed cost of org-managed custody made concrete: the console holds this member's escrowed private key and can produce a valid signature <b>as them</b>. A sovereign member has no such path.</p>
      <label class="cfield"><span>Message to sign as ${esc(m.address)}</span><textarea id="msg" rows="2">I approve the Q3 budget. — ${esc(m.name)}</textarea></label>
      <button class="btn" id="dosign">${icon('key')} Produce signature</button>
      <div id="sigout"></div>
    </div>`, { wide: true, label: 'Sign as member' });
  card.querySelector('#sx').onclick = closeModal;
  card.querySelector('#dosign').onclick = async () => {
    const msg = card.querySelector('#msg').value;
    const sig = await impersonateSign(m.id, msg);
    card.querySelector('#sigout').innerHTML = `<div class="sig-out"><div class="mini-h">${icon('check')} Valid signature by ${esc(m.address)} (real Ed25519)</div><code class="sig-block">${esc(sig)}</code><p class="muted">Any verifier checking against this account's published key would accept it as authentic — that is what escrow buys, and its cost.</p></div>`;
    await logEvent('security', `Escrowed key exercised — signed a message as ${m.address}`, { flag: 'escrow-use' });
  };
}
