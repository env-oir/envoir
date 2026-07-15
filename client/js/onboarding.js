// onboarding.js — create a sovereign identity. The address model is name@domain PRIMARY
// (spec §3.9): you pick a display name + a primary address; the KEY underneath is the identity,
// verified later by safety number (not used as an address). Generates a real keypair.

import { createIdentity, currentIdentity, addAlias } from './identity.js';
import { esc, icon, toast, brandMark, safetyWords, safetyGrid, safetyNumeric } from './ui.js';

export function renderOnboarding(onDone) {
  const o = document.getElementById('onboarding');
  o.classList.remove('hidden');
  let step = 0, mode = 'provider', local = '', domain = '', display = '', legacy = '', ident = null;

  const draw = () => {
    if (step === 0) {
      o.innerHTML = `<div class="ob-card">
        <div class="ob-brand">${brandMark(48)}<span class="ob-word">Envoir</span></div>
        <div class="ob-dots"><i class="on"></i><i></i><i></i></div>
        <h1>Your key is your identity</h1>
        <p class="ob-sub">Envoir gives you sovereign mail, chat, calendar &amp; files on one identity. No company holds your key, so no company can read your data — and you can leave anytime with all of it. First, pick the address people will use to reach you.</p>

        <label class="cfield"><span>Your name</span><input id="disp" placeholder="Ada Okonkwo" value="${esc(display)}"></label>

        <div class="ob-modes">
          <button class="ob-mode ${mode === 'provider' ? 'sel' : ''}" data-m="provider"><b>${icon('mail')} name@envoir.org</b><small>A ready-to-use address on Envoir. The easy default — works with the old email world today.</small></button>
          <button class="ob-mode ${mode === 'domain' ? 'sel' : ''}" data-m="domain"><b>${icon('shield')} Your own domain</b><small>you@yourbrand.com — Envoir auto-configures DNS/DKIM/DMARC (approve once).</small></button>
        </div>
        <div id="addrfield"></div>

        <label class="cfield opt"><span>Keep a legacy address (optional)</span><input id="leg" placeholder="you@oldprovider.com — becomes an alias" value="${esc(legacy)}"></label>

        <button class="btn primary block" id="next">Create my identity</button>
        <p class="ob-fine">${icon('lock')} A real Ed25519 keypair is generated in your browser — the private key never leaves this device.</p>
      </div>`;
      const af = o.querySelector('#addrfield');
      const drawAddr = () => {
        af.innerHTML = mode === 'provider'
          ? `<label class="cfield"><span>Pick your address</span><div class="addr-compose"><input id="local" placeholder="you" value="${esc(local)}"><span class="addr-domain mono">@envoir.org</span></div></label>`
          : `<label class="cfield"><span>Your domain address</span><input id="dom" placeholder="you@yourbrand.com" value="${esc(domain)}"></label>`;
        const li = af.querySelector('#local'); if (li) li.oninput = e => local = e.target.value;
        const di = af.querySelector('#dom'); if (di) di.oninput = e => domain = e.target.value;
      };
      drawAddr();
      o.querySelector('#disp').oninput = e => display = e.target.value;
      o.querySelector('#leg').oninput = e => legacy = e.target.value;
      o.querySelectorAll('.ob-mode').forEach(b => b.onclick = () => { mode = b.dataset.m; draw(); });
      o.querySelector('#next').onclick = async () => {
        let primary;
        if (mode === 'provider') primary = (local.trim() || 'you').toLowerCase().replace(/[^a-z0-9._-]/g, '') + '@envoir.org';
        else { primary = (domain.trim() || 'you@yourbrand.com').toLowerCase(); if (!/@/.test(primary)) primary += '@yourbrand.com'; }
        toast(`${icon('key')} Generating your Ed25519 keypair…`);
        ident = await createIdentity(primary, display.trim() || primary.split('@')[0]);
        if (legacy.trim()) addAlias(legacy.trim(), 'legacy');
        step = 1; draw();
      };
    } else if (step === 1) {
      o.innerHTML = `<div class="ob-card">
        <div class="ob-dots"><i class="on"></i><i class="on"></i><i></i></div>
        <h1>Save your recovery phrase</h1>
        <p class="ob-sub">These 12 words restore your identity if you lose every device. Write them down offline. <span class="dim">(Demo phrase — a real client uses the full SLIP-0039 list, spec §1.4.)</span></p>
        <div class="ob-phrase">${ident.phrase.map((w, i) => `<span data-i="${i + 1}">${esc(w)}</span>`).join('')}</div>
        <div class="ob-warn">${icon('shield')} Anyone with this phrase can recover your identity. Never share it.</div>
        <button class="btn primary block" id="next">I've saved it</button>
      </div>`;
      o.querySelector('#next').onclick = () => { step = 2; draw(); };
    } else {
      const id = currentIdentity();
      o.innerHTML = `<div class="ob-card wide">
        <div class="ob-dots"><i class="on"></i><i class="on"></i><i class="on"></i></div>
        <h1>You're sovereign ${icon('key')}</h1>
        <p class="ob-sub">Your identity is live. People reach you at your address; the safety number below is how they confirm your <b>key</b> — the real you — hasn't been swapped for a look-alike.</p>

        <div class="ob-final">
          <div class="ob-final-l">
            <div class="kvr"><span>Address</span><b class="mono">${esc(id.primary)}</b></div>
            ${id.addresses.filter(a => a.kind === 'legacy').map(a => `<div class="kvr"><span>Legacy alias</span><b class="mono">${esc(a.address)}</b></div>`).join('')}
            <div class="kvr"><span>Fingerprint</span><b class="mono">${esc(id.fingerprint)}</b></div>
            <div class="kvr"><span>Algorithm</span><b class="mono">${esc(id.alg)}</b></div>
          </div>
          <div class="ob-final-r">
            <div class="ob-safety-h">${icon('verified')} Your safety number</div>
            ${safetyGrid(id.safety)}
          </div>
        </div>
        <div class="ob-safety-full">${safetyWords(id.safety)}${safetyNumeric(id.safety)}</div>
        <p class="ob-fine">Compare this with a contact out-of-band to verify each other — it's derived from your key alone, deterministic, and can't be forged. The address is just a pointer; the key is the security boundary.</p>

        <button class="btn primary block" id="go">Open Envoir</button>
      </div>`;
      o.querySelector('#go').onclick = () => { o.classList.add('hidden'); onDone(); };
    }
  };
  draw();
}
