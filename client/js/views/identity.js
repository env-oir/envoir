// views/identity.js — IDENTITY as a first-class surface (spec §1, §3.4, §8.5, §13).
//
// This is where sovereignty becomes tangible: the KEY that *is* you, the device cluster it
// spans, the apps it signs into, how it's recovered, and how contacts verify it. Everything
// crypto here is real (safety-number derivation + signatures via ../identity.js); the device
// cluster / sessions are the simulated store, honestly labelled.

import { state } from '../store.js';
import { currentIdentity, displayAddress, displayName, logout, fromB64u, gatewayAlias } from '../identity.js';
import { verifySafety } from '../safety.js';
import { PEOPLE, person } from '../seed.js';
import { el, esc, icon, avatar, initials, brandMark, toast, openModal, closeModal,
  safetyWords, safetyGrid, safetyNumeric, timeAgo, fmtLong } from '../ui.js';
import { classifyName, resolverChip, resolverDetail } from '../resolver.js';
import { bus } from '../bus.js';
import { openEditProfile } from '../profileModal.js';

const DEVICE_ICON = { laptop: 'laptop', phone: 'phone', tablet: 'tablet', server: 'server', desktop: 'laptop' };
const daysAgo = (t) => Math.max(0, Math.round((Date.now() - t) / 86400e3));

export function render(root) {
  const id = currentIdentity();
  root.className = 'view identity-view';
  const keyAge = daysAgo(id.created || Date.now());
  const verified = PEOPLE.filter(p => p.trust === 'verified').length;
  const pinned = PEOPLE.filter(p => p.trust === 'tofu').length;
  const legacy = PEOPLE.filter(p => p.trust === 'legacy').length;
  const gwAlias = gatewayAlias(id);

  root.innerHTML = `<div class="id-scroll"><div class="id-inner">

    <section class="id-hero">
      <div class="id-hero-aura"></div>
      <div class="id-hero-top">
        <div class="id-hero-mark">${id._avatarSrc
          ? `<img class="id-hero-photo" src="${esc(id._avatarSrc)}" alt="${esc(displayName(id))}" referrerpolicy="no-referrer" data-name="${esc(displayName(id))}" data-hue="${id.hue ?? 250}" data-size="76" onerror="window.__avFallback&&window.__avFallback(this)">`
          : `<span class="av ring" style="--h:${id.hue ?? 250};width:76px;height:76px;font-size:28px" title="${esc(displayName(id))}">${esc(initials(displayName(id)))}</span>`}</div>
        <div class="id-hero-body">
          <div class="id-hero-eyebrow">${icon('shield')} Sovereign identity</div>
          <h1 class="display">${esc(displayName(id))}</h1>
          <div class="id-hero-actions">
            <button class="id-addr-copy" id="copyaddr" title="Copy address">
              <span class="mono">${esc(displayAddress(id))}</span>${icon('copy')}
            </button>
            <button class="btn ghost sm" id="editprofile">${icon('edit')} Edit profile</button>
          </div>
          <p class="id-hero-sub">Your <b>key</b> is your identity — no company holds it, so no company can read your data or lock you in. The address and this name/photo are just pointers to the key.</p>
        </div>
      </div>
      <div class="id-hero-stats">
        <div class="id-stat"><b>${keyAge===0?'today':keyAge+'d'}</b><span>key age</span></div>
        <div class="id-stat"><b>${state.devices.length}</b><span>devices</span></div>
        <div class="id-stat"><b>${state.sessions.length}</b><span>app sessions</span></div>
        <div class="id-stat"><b class="teal">${verified}</b><span>verified contacts</span></div>
      </div>
    </section>

    <div class="id-sections">

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('ladder')}</div>
          <h2>Naming ladder</h2>
          <p>Every rung below points at the <b>same key</b> — a ladder from zero-authority floor to human convenience (spec §3.13), never a set of equals. Change any rung any time; you can change these, the key is you.</p>
        </div>
        <div class="id-row-body">
          <div class="id-ladder">
            <div class="id-rung floor">
              <div class="id-rung-badge">${resolverChip({ kind: 'self', label: 'Key-name', icon: 'key', note: 'the zero-authority floor' })}</div>
              <div class="id-rung-main">
                <div class="id-rung-h"><span class="mono">${esc(id.keyName || '—')}</span><span class="pill accent sm">floor</span></div>
                <small>Derived from your key alone — no DNS, no chain, no registration, no <span class="mono">@</span>. Always yours; changes only on the rare full key rotation.</small>
              </div>
              <button class="icon-btn sm" id="copykeyname" title="Copy key-name">${icon('copy')}</button>
            </div>
            ${(id.addresses || []).map(a => ladderRung(a)).join('')}
          </div>
          <div class="id-ladder-note">${icon('shield')} <b>Zero-authority floor:</b> if every domain and every chain you use vanished tomorrow, your key-name above still reaches you — no company, registrar, or chain can take it away. Everything else here is convenience layered over it.</div>
          <div class="id-row-body-head" style="margin-top:14px"><button class="btn ghost sm" id="managealiases">${icon('mail')} Manage addresses in Settings ${icon('forward')}</button></div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('bridge')}</div>
          <h2>Legacy gateway alias</h2>
          <p>Your fallback address for the old email world (Gmail/Outlook) — the same at every dmtap1-compatible gateway, because it's derived from your key rather than registered anywhere.</p>
        </div>
        <div class="id-row-body">
          <div class="id-gwalias">
            <span class="mono">${esc(gwAlias)}</span>
            <button class="icon-btn sm" id="copygw" title="Copy gateway alias">${icon('copy')}</button>
          </div>
          <p class="modal-note" style="margin-top:12px">${icon('info')} Legacy mail can't route a reply to a domain with no MX record, so the gateway rewrites the reply-path to this alias (spec §7.10.1) — your friendly address still displays to the human. It's <b>rotatable and separate from your identity</b>: burn it and your key, your name, and every other address above keep working unchanged.</p>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('fingerprint')}</div>
          <h2>Safety number</h2>
          <p>How a contact confirms your <b>key</b> is really yours and hasn't been swapped for a look-alike. Read the words aloud, scan the grid, or compare the digits — out-of-band. Derived from your public key alone: deterministic, unforgeable, never stored.</p>
        </div>
        <div class="id-row-body">
          <div class="id-row-body-head"><button class="btn ghost sm" id="recompute">${icon('rotate')} Recompute</button></div>
          <div class="id-safety">
            ${safetyGrid(id.safety)}
            <div class="id-safety-words">${safetyWords(id.safety)}${safetyNumeric(id.safety)}
              <div class="id-facts">
                <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(id.fingerprint)}</b></div>
                <div class="kvr"><span>Algorithm</span><b class="mono">${esc(id.alg)}</b></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('laptop')}</div>
          <h2>Devices <span class="list-count">${state.devices.length}</span></h2>
          <p>One identity, many devices. Each holds a <b>device subkey</b> your root key authorizes; data syncs as encrypted MOTEs across the cluster (spec §8.5). Revoking a device rotates it out — your root identity is untouched.</p>
        </div>
        <div class="id-row-body">
          <div class="id-row-body-head"><button class="btn ghost sm" id="adddevice">${icon('link')} Link device</button></div>
          <div class="id-devices" id="devices"></div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('link')}</div>
          <h2>Signed-in apps <span class="list-count">${state.sessions.length}</span></h2>
          <p>Apps you signed into with Envoir (DMTAP-Auth, spec §13) — no passwords, a signature from this key. Revoke access anytime; the app can't act as you afterward.</p>
        </div>
        <div class="id-row-body">
          <div class="id-sessions" id="sessions"></div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('key')}</div>
          <h2>Recovery</h2>
          <p>Honest privacy, not zero-access: if you lose every device you can still get back in — but only <b>you</b> can, never us. Choose the anchors you trust.</p>
        </div>
        <div class="id-row-body">
          <div class="id-recovery">
            <div class="id-rec-row ok"><div class="id-rec-ic">${icon('key')}</div>
              <div class="id-rec-main"><b>Recovery phrase</b><small>12 words · SLIP-0039 · offline. The universal fallback.</small></div>
              <button class="btn sm" id="showphrase">${icon('eye')} Reveal</button></div>
            <div class="id-rec-row ok"><div class="id-rec-ic">${icon('laptop')}</div>
              <div class="id-rec-main"><b>Trusted devices</b><small>${state.devices.length} devices can co-sign a recovery for a new device.</small></div>
              <span class="pill good sm">${icon('check')} active</span></div>
            <div class="id-rec-row"><div class="id-rec-ic">${icon('groups')}</div>
              <div class="id-rec-main"><b>Social recovery guardians</b><small>Split a recovery share across people you trust (opt-in).</small></div>
              <button class="btn ghost sm" id="guardians">Set up</button></div>
          </div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('rotate')}</div>
          <h2>Key lifecycle &amp; portability</h2>
          <p>Rotate, migrate, or export — the key always comes with you, and nothing is ever left behind.</p>
        </div>
        <div class="id-row-body">
          <div class="id-lifecycle">
            <div class="id-life-row"><div class="id-life-ic">${icon('shield')}</div>
              <div class="id-life-main"><b>Rotation</b><small>Rotate the key while keeping continuity — the old key signs the new one, so contacts follow you automatically and history stays readable.</small></div>
              <button class="btn sm" id="rotate">${icon('rotate')} Rotate…</button></div>
            <div class="id-life-row"><div class="id-life-ic">${icon('globe')}</div>
              <div class="id-life-main"><b>Provider migration</b><small>Move your whole life — mail, chat, files, contacts — to another provider or your own domain. The key comes with you.</small></div>
              <button class="btn sm" id="migrate">${icon('globe')} Migrate…</button></div>
            <div class="id-life-row"><div class="id-life-ic">${icon('download')}</div>
              <div class="id-life-main"><b>Export identity</b><small>Download the public identity record (address, fingerprint, safety number). The private key never leaves your device.</small></div>
              <button class="btn sm" id="exportid">${icon('download')} Export</button></div>
          </div>
        </div>
      </section>

      <section class="id-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('verified')}</div>
          <h2>Contact verification</h2>
          <p>Where your contacts' keys stand right now — safety-number verified, trusted on first contact, or still on the legacy gateway.</p>
        </div>
        <div class="id-row-body">
          <div class="id-row-body-head"><button class="btn ghost sm" id="goverify">Open contacts ${icon('forward')}</button></div>
          <div class="id-verify-bars">
            <button class="id-vbar verified" data-trust="verified"><b>${verified}</b><span>${icon('verified')} verified</span><small>safety number compared</small></button>
            <button class="id-vbar pinned" data-trust="tofu"><b>${pinned}</b><span>${icon('lock')} pinned</span><small>trusted on first contact</small></button>
            <button class="id-vbar legacy" data-trust="legacy"><b>${legacy}</b><span>${icon('shield')} legacy</span><small>no end-to-end key</small></button>
          </div>
        </div>
      </section>

      <section class="id-row danger-row">
        <div class="id-row-label">
          <div class="id-row-ic">${icon('signout')}</div>
          <h2>Sign out</h2>
          <p>Clears this identity from this browser. Your key stays recoverable by phrase.</p>
        </div>
        <div class="id-row-body">
          <button class="btn danger" id="signout">${icon('signout')} Sign out</button>
        </div>
      </section>

    </div>
  </div></div>`;

  // ---- wire ----
  root.querySelector('#copyaddr').onclick = () => { navigator.clipboard?.writeText(displayAddress(id)); toast(`${icon('check')} Copied ${displayAddress(id)}`); };
  root.querySelector('#editprofile').onclick = () => openEditProfile();
  root.querySelector('#copykeyname').onclick = () => { navigator.clipboard?.writeText(id.keyName || ''); toast(`${icon('check')} Copied key-name`); };
  root.querySelector('#managealiases').onclick = () => bus.setView('settings');
  root.querySelector('#copygw').onclick = () => { navigator.clipboard?.writeText(gwAlias); toast(`${icon('check')} Copied gateway alias`); };
  root.querySelector('#recompute').onclick = async () => {
    const { match, recomputed } = await verifySafety(fromB64u(id.ik), id.safety.full);
    toast(match ? `${icon('check')} Recomputed identical — ${esc(recomputed)}` : '✗ mismatch: ' + esc(recomputed), { ms: 5000 });
  };
  drawDevices(root);
  drawSessions(root);
  root.querySelector('#adddevice').onclick = () => linkDeviceModal();
  root.querySelector('#showphrase').onclick = () => phraseModal(id);
  root.querySelector('#guardians').onclick = () => toast(`${icon('groups')} Social recovery — split a Shamir share across trusted guardians (spec §1.4). Simulated in this demo.`, { ms: 4600 });
  root.querySelector('#rotate').onclick = () => rotateModal(id);
  root.querySelector('#migrate').onclick = () => migrateModal(id);
  root.querySelector('#exportid').onclick = () => exportIdentity(id);
  root.querySelector('#goverify').onclick = () => bus.setView('contacts');
  root.querySelectorAll('.id-vbar').forEach(b => b.onclick = () => bus.setView('contacts'));
  root.querySelector('#signout').onclick = () => { if (confirm('Sign out and clear this identity from this browser?')) { logout(); location.reload(); } };
}

// One rung of the naming ladder for a published address (spec §3.9.4/§3.13.2). Reuses the same
// resolver classifier compose/contacts use, so "which resolver" reads identically everywhere.
function ladderRung(a) {
  const info = classifyName(a.address);
  const kindLabel = { primary: 'primary', alias: 'alias', legacy: 'kept legacy', handle: 'handle', namechain: 'on-chain' }[a.kind] || a.kind;
  return `<div class="id-rung">
    <div class="id-rung-badge">${resolverChip(info)}</div>
    <div class="id-rung-main">
      <div class="id-rung-h"><span class="mono">${esc(a.address)}</span><span class="pill ${a.kind === 'primary' ? 'accent' : 'dim'} sm">${esc(kindLabel)}</span></div>
      <small>${esc(resolverDetail(info))}</small>
    </div>
  </div>`;
}

function drawDevices(root) {
  const wrap = root.querySelector('#devices');
  wrap.innerHTML = state.devices.map(d => `<div class="id-device ${d.current ? 'current' : ''}" data-id="${d.id}">
    <div class="id-dev-ic">${icon(DEVICE_ICON[d.type] || 'laptop')}</div>
    <div class="id-dev-main">
      <div class="id-dev-name">${esc(d.name)}${d.current ? '<span class="pill accent sm">this device</span>' : ''}</div>
      <div class="id-dev-sub">${esc(d.platform)} · ${esc(d.location)} · <span class="mono">${esc(d.subkey)}</span></div>
    </div>
    <div class="id-dev-side">
      <span class="id-dev-active">${d.current ? '<i class="dot-live"></i> active now' : 'active ' + timeAgo(d.lastActive)}</span>
      ${d.current ? '' : `<button class="icon-btn sm" data-revoke="${d.id}" title="Revoke device">${icon('trash')}</button>`}
    </div>
  </div>`).join('');
  wrap.querySelectorAll('[data-revoke]').forEach(b => b.onclick = () => {
    const d = state.devices.find(x => x.id === b.dataset.revoke); if (!d) return;
    if (!confirm(`Revoke "${d.name}"? Its device subkey is rotated out of your cluster.`)) return;
    state.devices = state.devices.filter(x => x.id !== d.id);
    bus.rerender();
    toast(`${icon('check')} ${esc(d.name)} revoked — subkey rotated out, remaining devices re-keyed`, { ms: 4200 });
  });
}

function drawSessions(root) {
  const wrap = root.querySelector('#sessions');
  if (!state.sessions.length) { wrap.innerHTML = `<div class="id-empty-inline">No apps have access.</div>`; return; }
  wrap.innerHTML = state.sessions.map(s => `<div class="id-session">
    <span class="av" style="--h:${s.avatar};width:34px;height:34px;font-size:13px">${esc(initials(s.app))}</span>
    <div class="id-sess-main"><div class="id-sess-name">${esc(s.app)}</div>
      <div class="id-sess-sub"><span class="mono">${esc(s.origin)}</span> · ${esc(s.scope)}</div></div>
    <div class="id-sess-side"><span class="id-sess-time">used ${timeAgo(s.lastUsed)}</span>
      <button class="btn ghost sm" data-revoke="${s.id}">Revoke</button></div>
  </div>`).join('');
  wrap.querySelectorAll('[data-revoke]').forEach(b => b.onclick = () => {
    const s = state.sessions.find(x => x.id === b.dataset.revoke);
    state.sessions = state.sessions.filter(x => x.id !== b.dataset.revoke);
    bus.rerender();
    toast(`${icon('check')} Access revoked for ${esc(s?.app || 'app')}`);
  });
}

function linkDeviceModal() {
  const words = ['orca', 'cedar', 'quartz', 'delta', 'ember', 'lunar'];
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('link')} Link a new device</h2><button class="icon-btn" id="lx">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} On the new device, choose <b>“Add to my identity”</b> and scan this code. It generates a device subkey and asks your root key to authorize it — the private root key never moves.</p>
    <div class="id-pair">
      <div class="id-pair-qr">${pairGrid()}</div>
      <div class="id-pair-side">
        <div class="id-pair-h">Confirm these words match on both screens</div>
        <div class="safety-words">${words.map((w, i) => `<span class="sw" data-i="${i + 1}">${esc(w)}</span>`).join('')}</div>
        <div class="id-pair-note">${icon('shield')} The words are a channel-binding check — they stop a man-in-the-middle from injecting a rogue device.</div>
      </div>
    </div>
    <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} device subkey · root-authorized · simulated pairing</span><div class="spacer"></div><button class="btn primary" id="lpair">Simulate pairing</button></div>
  </div>`, { wide: true });
  card.querySelector('#lx').onclick = closeModal;
  card.querySelector('#lpair').onclick = () => {
    const now = Date.now();
    state.devices.push({ id: 'd' + now, name: 'New device', type: 'laptop', platform: 'linked', current: false, added: now, lastActive: now, location: 'just now', subkey: 'dk:' + Math.random().toString(16).slice(2, 6) + '…' + Math.random().toString(16).slice(2, 6) });
    closeModal(); bus.rerender();
    toast(`${icon('check')} Device linked — subkey authorized, cluster re-keyed`);
  };
}
function pairGrid() {
  let cells = '';
  for (let i = 0; i < 64; i++) cells += `<i class="${(i * 2654435761 % 3) ? 'on' : ''}"></i>`;
  return `<div class="pair-grid">${cells}</div>`;
}

function phraseModal(id) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('key')} Recovery phrase</h2><button class="icon-btn" id="px">${icon('x')}</button></div>
    <div class="ob-warn">${icon('shield')} Anyone with these 12 words can recover your identity. Write them down offline. Never paste them into a website.</div>
    <div class="ob-phrase">${id.phrase.map((w, i) => `<span data-i="${i + 1}">${esc(w)}</span>`).join('')}</div>
    <div class="ev-detail-foot"><span class="sim-tag">${icon('key')} SLIP-0039 in production · demo word list here</span><div class="spacer"></div><button class="btn" id="pdone">Done</button></div>
  </div>`, { wide: true });
  card.querySelector('#px').onclick = closeModal;
  card.querySelector('#pdone').onclick = closeModal;
}

function rotateModal(id) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('rotate')} Rotate identity key</h2><button class="icon-btn" id="rx">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} Rotation issues a <b>new</b> root key. The <b>current</b> key signs it, so the chain is continuous: contacts follow the link automatically, your address stays the same, and past messages stay readable. Your safety number changes — you'll re-verify with contacts over time.</p>
    <div class="id-rotate-chain">
      <div class="id-chain-node"><b class="mono">${esc((id.fingerprint || '').slice(0, 10))}…</b><span>current key</span></div>
      <div class="id-chain-arrow">${icon('rotate')} signs</div>
      <div class="id-chain-node next"><b class="mono">rotating…</b><span>new key</span></div>
    </div>
    <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} continuity-preserving · simulated</span><div class="spacer"></div><button class="btn" id="rcancel">Cancel</button><button class="btn primary" id="rgo">Rotate with continuity</button></div>
  </div>`, { wide: true });
  card.querySelector('#rx').onclick = closeModal;
  card.querySelector('#rcancel').onclick = closeModal;
  card.querySelector('#rgo').onclick = () => { closeModal(); toast(`${icon('check')} Key rotated with continuity — old key signed the new one, contacts will follow the link automatically`, { ms: 5000 }); };
}

function migrateModal(id) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('globe')} Migrate provider</h2><button class="icon-btn" id="mx">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} Because the identity is the key — not an account on a server — moving provider is a data transfer, not a rebuild. Point your address at a new home (or your own domain); the key, contacts, and history come with you.</p>
    <label class="cfield"><span>New home</span><input id="mhome" placeholder="your own domain, or another Envoir-compatible provider" value="you@yourbrand.com"></label>
    <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} nothing left behind · simulated</span><div class="spacer"></div><button class="btn primary" id="mgo">Prepare migration</button></div>
  </div>`, { wide: true });
  card.querySelector('#mx').onclick = closeModal;
  card.querySelector('#mgo').onclick = () => { const to = card.querySelector('#mhome').value.trim(); closeModal(); toast(`${icon('check')} Migration prepared${to ? ' to ' + esc(to) : ''} — DNS/DKIM to approve, then your key + all data move over`, { ms: 5000 }); };
}

function exportIdentity(id) {
  const record = {
    '@type': 'DMTAPIdentity',
    displayName: displayName(id), primaryAddress: displayAddress(id),
    addresses: (id.addresses || []).map(a => ({ address: a.address, kind: a.kind })),
    fingerprint: id.fingerprint, algorithm: id.alg,
    safetyNumber: id.safety?.full, safetyNumeric: id.safety?.numeric,
    note: 'Public identity record. The private key is never exported.',
  };
  try {
    const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'envoir-identity.public.json';
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`${icon('download')} Exported public identity record — private key stays on device`, { ms: 4200 });
  } catch { toast('Export unavailable in this context'); }
}
