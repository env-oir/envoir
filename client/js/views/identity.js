// views/identity.js — IDENTITY as a first-class surface (spec §1, §3.4, §8.5, §13).
//
// This is where sovereignty becomes tangible: the KEY that *is* you, the device cluster it
// spans, the apps it signs into, how it's recovered, and how contacts verify it. Everything
// crypto here is real (safety-number derivation + signatures via ../identity.js); the device
// cluster / sessions are the simulated store, honestly labelled.

import { state } from '../store.js';
import { currentIdentity, displayAddress, displayName, logout, fromB64u } from '../identity.js';
import { verifySafety } from '../safety.js';
import { PEOPLE, person } from '../seed.js';
import { el, esc, icon, avatar, initials, brandMark, toast, openModal, closeModal,
  safetyWords, safetyGrid, safetyNumeric, timeAgo, fmtLong } from '../ui.js';
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

  root.innerHTML = `<div class="id-scroll"><div class="id-inner">

    <section class="id-hero">
      <div class="id-hero-aura"></div>
      <div class="id-hero-mark">${id._avatarSrc
        ? `<img class="id-hero-photo" src="${esc(id._avatarSrc)}" alt="${esc(displayName(id))}" referrerpolicy="no-referrer" data-name="${esc(displayName(id))}" data-hue="${id.hue ?? 250}" data-size="72" onerror="window.__avFallback&&window.__avFallback(this)">`
        : `<span class="av ring" style="--h:${id.hue ?? 250};width:72px;height:72px;font-size:27px" title="${esc(displayName(id))}">${esc(initials(displayName(id)))}</span>`}</div>
      <div class="id-hero-body">
        <div class="id-hero-eyebrow">${icon('shield')} Sovereign identity</div>
        <h1 class="display">${esc(displayName(id))}</h1>
        <button class="id-addr-copy" id="copyaddr" title="Copy address">
          <span class="mono">${esc(displayAddress(id))}</span>${icon('copy')}
        </button>
        <button class="btn ghost sm" id="editprofile" style="margin-left:8px">${icon('edit')} Edit profile</button>
        <p class="id-hero-sub">Your <b>key</b> is your identity — no company holds it, so no company can read your data or lock you in. The address and this name/photo are just pointers to the key.</p>
        <div class="id-hero-stats">
          <div class="id-stat"><b>${keyAge===0?'today':keyAge+'d'}</b><span>key age</span></div>
          <div class="id-stat"><b>${state.devices.length}</b><span>devices</span></div>
          <div class="id-stat"><b>${state.sessions.length}</b><span>app sessions</span></div>
          <div class="id-stat"><b class="teal">${verified}</b><span>verified contacts</span></div>
        </div>
      </div>
    </section>

    <div class="id-cols">
      <section class="id-card span2">
        <div class="id-card-h"><h2>${icon('fingerprint')} Your safety number</h2>
          <button class="btn ghost sm" id="recompute">${icon('rotate')} Recompute</button></div>
        <p class="id-card-hint">This is how a contact confirms your <b>key</b> is really yours and hasn't been swapped for a look-alike. Read the words aloud, scan the grid, or compare the digits — out-of-band. It's derived from your public key alone: deterministic, unforgeable, never stored.</p>
        <div class="id-safety">
          ${safetyGrid(id.safety)}
          <div class="id-safety-words">${safetyWords(id.safety)}${safetyNumeric(id.safety)}
            <div class="id-facts">
              <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(id.fingerprint)}</b></div>
              <div class="kvr"><span>Algorithm</span><b class="mono">${esc(id.alg)}</b></div>
            </div>
          </div>
        </div>
      </section>

      <section class="id-card">
        <div class="id-card-h"><h2>${icon('laptop')} Devices <span class="list-count">${state.devices.length}</span></h2>
          <button class="btn ghost sm" id="adddevice">${icon('link')} Link device</button></div>
        <p class="id-card-hint">One identity, many devices. Each holds a <b>device subkey</b> your root key authorizes; data syncs as encrypted MOTEs across the cluster (spec §8.5). Revoking a device rotates it out — your root identity is untouched.</p>
        <div class="id-devices" id="devices"></div>
      </section>

      <section class="id-card">
        <div class="id-card-h"><h2>${icon('link')} Signed-in apps <span class="list-count">${state.sessions.length}</span></h2></div>
        <p class="id-card-hint">Apps you signed into with Envoir (DMTAP-Auth, spec §13) — no passwords, a signature from this key. Revoke access anytime; the app can't act as you afterward.</p>
        <div class="id-sessions" id="sessions"></div>
      </section>

      <section class="id-card">
        <div class="id-card-h"><h2>${icon('key')} Recovery</h2></div>
        <p class="id-card-hint">Honest privacy, not zero-access: if you lose every device you can still get back in — but only <b>you</b> can, never us. Choose the anchors you trust.</p>
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
      </section>

      <section class="id-card span2">
        <div class="id-card-h"><h2>${icon('rotate')} Key lifecycle &amp; portability</h2></div>
        <div class="id-lifecycle">
          <div class="id-life-item">
            <div class="id-life-h">${icon('shield')} Rotation</div>
            <p>Rotate the key while keeping continuity — the old key signs the new one, so contacts follow you automatically and history stays readable.</p>
            <button class="btn sm" id="rotate">${icon('rotate')} Rotate key…</button>
          </div>
          <div class="id-life-item">
            <div class="id-life-h">${icon('globe')} Provider migration</div>
            <p>Move your whole life — mail, chat, files, contacts — to another provider or your own domain. The key comes with you; nothing is left behind.</p>
            <button class="btn sm" id="migrate">${icon('globe')} Migrate…</button>
          </div>
          <div class="id-life-item">
            <div class="id-life-h">${icon('download')} Export identity</div>
            <p>Download the public identity record (address, fingerprint, safety number). The private key never leaves your device.</p>
            <button class="btn sm" id="exportid">${icon('download')} Export public record</button>
          </div>
        </div>
      </section>

      <section class="id-card span2 id-verify-card">
        <div class="id-card-h"><h2>${icon('verified')} Contact verification</h2>
          <button class="btn ghost sm" id="goverify">Open contacts ${icon('forward')}</button></div>
        <div class="id-verify-bars">
          <button class="id-vbar verified" data-trust="verified"><b>${verified}</b><span>${icon('verified')} verified</span><small>safety number compared</small></button>
          <button class="id-vbar pinned" data-trust="tofu"><b>${pinned}</b><span>${icon('lock')} pinned</span><small>trusted on first contact</small></button>
          <button class="id-vbar legacy" data-trust="legacy"><b>${legacy}</b><span>${icon('shield')} legacy</span><small>no end-to-end key</small></button>
        </div>
      </section>

      <section class="id-card span2 danger-card">
        <div class="set-row between"><div><b>Sign out</b><small>clears this identity from this browser (your key stays recoverable by phrase)</small></div>
          <button class="btn danger" id="signout">${icon('signout')} Sign out</button></div>
      </section>
    </div>
  </div></div>`;

  // ---- wire ----
  root.querySelector('#copyaddr').onclick = () => { navigator.clipboard?.writeText(displayAddress(id)); toast(`${icon('check')} Copied ${displayAddress(id)}`); };
  root.querySelector('#editprofile').onclick = () => openEditProfile();
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
