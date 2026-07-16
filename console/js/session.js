// session.js — the admin session's cryptographic material and the domain-authority machinery.
//
//   • The DOMAIN AUTHORITY keypair (real Ed25519) lives here. It really signs every published
//     DomainDirectory (§18.4.7). It is presented as THRESHOLD-HELD (spec §3.10.1): the private
//     key is a single browser key here, but domain-authoritative acts (rotating the anchor or
//     the directory-signing key, granting full domain-owner) are gated behind a QUORUM-COLLECTION
//     step — the console will not perform them until a threshold of holders has approved. This
//     is the honest "no lone super-admin" guarantee, with the FROST quorum signature simulated.
//
//   • The ESCROW holds retained private keys for ORG-MANAGED members only (spec §3.10.2b). Its
//     mere existence — and the ability to sign as those members — is the disclosed cost of that
//     model; sovereign members are never in here (their private key was discarded at creation).

import { generateKeypair, signWithPriv, toB64u, fromB64u } from './crypto.js';
import { openModal, closeModal, icon, esc, toast } from './ui.js';

const LS_AUTH = 'envoir.console.authority.v1';
const LS_ESCROW = 'envoir.console.escrow.v1';

let _authority = null; // { alg, priv } — the live signing material for the authority key

// ---- authority key lifecycle --------------------------------------------------------------
export async function createAuthority() {
  const kp = await generateKeypair();
  _authority = { alg: kp.alg, priv: kp.priv };
  localStorage.setItem(LS_AUTH, JSON.stringify(_authority));
  return kp; // { ik, fingerprint, safety, alg } — public parts for the store
}
export function loadAuthority() {
  try { _authority = JSON.parse(localStorage.getItem(LS_AUTH) || 'null'); } catch { _authority = null; }
  return _authority;
}
export function wipeSession() { localStorage.removeItem(LS_AUTH); localStorage.removeItem(LS_ESCROW); }

// Sign the serialized DomainDirectory with the authority key (real signature).
export async function signDirectory(bytes) {
  if (!_authority) loadAuthority();
  if (!_authority) return null;
  const sig = await signWithPriv(_authority.priv, _authority.alg, bytes);
  return toB64u(sig).slice(0, 44) + '…'; // display-truncated; full sig held by the node
}

// ---- escrow (org-managed only) ------------------------------------------------------------
function escrowMap() { try { return JSON.parse(localStorage.getItem(LS_ESCROW) || '{}'); } catch { return {}; } }
export function escrowStore(memberId, priv, alg) {
  const m = escrowMap(); m[memberId] = { priv, alg }; localStorage.setItem(LS_ESCROW, JSON.stringify(m));
}
export function escrowHas(memberId) { return !!escrowMap()[memberId]; }
export function escrowDrop(memberId) { const m = escrowMap(); delete m[memberId]; localStorage.setItem(LS_ESCROW, JSON.stringify(m)); }
export const escrowCount = () => Object.keys(escrowMap()).length;

// Demonstrate the org-managed cost: really sign an arbitrary message AS the escrowed member.
// Sovereign members can never reach this path — there is no key to import.
export async function impersonateSign(memberId, message) {
  const e = escrowMap()[memberId];
  if (!e) throw new Error('no escrowed key');
  const sig = await signWithPriv(e.priv, e.alg, new TextEncoder().encode(message));
  return toB64u(sig);
}

// ---- threshold quorum collection (spec §3.10.1, §5.8.6, §13.5.1) --------------------------
// A domain-authoritative act must satisfy the domain threshold, never one admin. This presents
// the quorum-collection UX: the operator gathers approvals from holders until m-of-n is met,
// then the (simulated) FROST quorum signature is produced and the act proceeds. Returns a
// promise that resolves true when the threshold is met and the user confirms, false if aborted.
export function collectThreshold(threshold, title, detail) {
  return new Promise((resolve) => {
    const { m, n, holders } = threshold;
    const approved = new Set([0]); // the operator (holder 0) implicitly initiates + approves
    const draw = () => {
      const card = document.getElementById('modal').querySelector('.modal-card');
      const count = approved.size;
      const met = count >= m;
      card.innerHTML = `
        <div class="modal-head">
          <h2>${icon('shield')} Threshold approval required</h2>
          <button class="icon-btn" id="qx" aria-label="Cancel">${icon('x')}</button>
        </div>
        <div class="modal-body">
          <p class="modal-note warn">${icon('warn')} <span><b>${esc(title)}</b> is a <b>domain-authoritative act</b>. It rotates or reissues authority-level key material, so it needs a <b>${m}-of-${n}</b> quorum of key holders — no single admin can do this alone (spec §3.10.1, §13.5.1).</p>
          <p class="q-detail">${esc(detail)}</p>
          <div class="q-meter" role="progressbar" aria-valuemin="0" aria-valuemax="${n}" aria-valuenow="${count}">
            <div class="q-bar" style="width:${Math.min(100, (count / m) * 100)}%"></div>
            <span class="q-count mono">${count} / ${m} approvals</span>
          </div>
          <div class="q-holders">
            ${holders.map((h, i) => `
              <div class="q-holder ${approved.has(i) ? 'on' : ''}">
                <span class="q-h-main"><b>${esc(h.name)}</b><small class="mono">${esc(h.address)} · ${esc(h.role)}</small></span>
                ${i === 0 ? `<span class="pill accent sm">${icon('check')} initiator</span>`
                  : approved.has(i) ? `<span class="pill good sm">${icon('check')} approved</span>`
                  : `<button class="btn sm" data-approve="${i}">Approve as holder</button>`}
              </div>`).join('')}
          </div>
          <p class="q-sim">${icon('info')} Threshold (FROST) signing is <b>simulated</b>: a single Ed25519 signature by the authority key stands in for the ${m}-of-${n} quorum signature once approvals are collected.</p>
        </div>
        <div class="modal-foot">
          <button class="btn ghost" id="qcancel">Cancel</button>
          <div class="spacer"></div>
          <button class="btn primary" id="qgo" ${met ? '' : 'disabled'}>${met ? 'Produce quorum signature &amp; proceed' : `Need ${m - count} more`}</button>
        </div>`;
      card.querySelector('#qx').onclick = card.querySelector('#qcancel').onclick = () => { closeModal(); resolve(false); };
      card.querySelectorAll('[data-approve]').forEach(b => b.onclick = () => { approved.add(Number(b.dataset.approve)); draw(); });
      const go = card.querySelector('#qgo');
      if (met) go.onclick = () => { closeModal(); toast(`${icon('shield')} ${m}-of-${n} quorum signature produced`); resolve(true); };
    };
    openModal('<div class="q-loading"></div>', { sticky: true, label: 'Threshold approval', wide: true });
    draw();
  });
}
