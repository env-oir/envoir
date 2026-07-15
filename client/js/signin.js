// signin.js — "Sign in with Envoir" (DMTAP-Auth, spec §13.3). A mock relying party (no real
// site, no network call — all on this page) runs the real ceremony shape: an origin-bound
// challenge is built, the user approves, and the identity key produces a REAL signature over
// it. Honest limit: a static page can only do the *weaker* user-verified origin mode (§13.7 #1);
// true phishing-resistance needs a trusted client (WebAuthn) to bind the origin (§13.3.1).

import { currentIdentity, displayAddress, sign, sha256, toB64u, hex } from './identity.js';
import { icon, esc } from './ui.js';

let rp = { origin: 'https://example-app.test', status: 'idle', challenge: null, sig: null };

export function renderSignin(box) {
  if (!box) return;
  const id = currentIdentity();
  if (rp.status === 'idle') {
    box.innerHTML = `<div class="rp">
      <div class="rp-head"><span class="dot" style="background:var(--text-faint)"></span><b>${esc(rp.origin)}</b><span class="rp-tag">mock relying party</span></div>
      <p class="rp-sub">A third-party site wants to know who you are. This runs the DMTAP-Auth login ceremony against your real identity key — no passwords, no shared secret.</p>
      <button class="btn primary" id="rpstart">${icon('key')} Sign in with Envoir</button>
    </div>`;
    box.querySelector('#rpstart').onclick = () => { start(); renderSignin(box); };
  } else if (rp.status === 'challenge') {
    const c = rp.challenge;
    box.innerHTML = `<div class="rp">
      <div class="rp-head"><span class="dot" style="background:var(--warn)"></span><b>${esc(rp.origin)}</b><span class="rp-tag">mock relying party</span></div>
      <p class="rp-sub">The site sent this origin-bound challenge. Approving signs it with your identity key.</p>
      <div class="kv-block">
        ${['rp_origin', 'nonce', 'issued_at', 'exp'].map(k => `<div class="kv"><span class="k">${k}</span><span class="v">${esc(c[k])}</span></div>`).join('')}
      </div>
      <div class="rp-note">${icon('info')} Honest limit: this static page just displays <b>${esc(c.rp_origin)}</b> and signs directly — the weaker user-verified mode (§13.7 #1). Production DMTAP-Auth binds the true origin via WebAuthn (§13.3.1), which a static page cannot.</div>
      <div class="rp-actions"><button class="btn primary" id="ok">Approve &amp; sign</button><button class="btn" id="no">Deny</button></div>
    </div>`;
    box.querySelector('#ok').onclick = async () => { await approve(); renderSignin(box); };
    box.querySelector('#no').onclick = () => { rp = { ...rp, status: 'idle', challenge: null }; renderSignin(box); };
  } else {
    box.innerHTML = `<div class="rp">
      <div class="rp-head"><span class="dot" style="background:var(--good)"></span><b>${esc(rp.origin)}</b><span class="pill good">${icon('check')} signed in</span></div>
      <p class="rp-sub">Signed assertion — a real signature over <span class="key">rp_origin ‖ nonce ‖ issued_at ‖ exp ‖ aud</span>:</p>
      <div class="sig-block mono">${esc(rp.sig)}</div>
      <div class="kv-block">
        <div class="kv"><span class="k">signed as</span><span class="v">${esc(displayAddress(id))}</span></div>
        <div class="kv"><span class="k">alg</span><span class="v">${esc(id.alg)}</span></div>
      </div>
      <button class="btn" id="reset">Reset demo</button>
    </div>`;
    box.querySelector('#reset').onclick = () => { rp = { origin: rp.origin, status: 'idle', challenge: null, sig: null }; renderSignin(box); };
  }
}

function start() {
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const issued_at = Date.now();
  rp = { ...rp, status: 'challenge', challenge: { rp_origin: rp.origin, nonce, issued_at, exp: issued_at + 60_000, aud: rp.origin } };
}
async function approve() {
  const c = rp.challenge;
  const bytes = new TextEncoder().encode([c.rp_origin, c.nonce, c.issued_at, c.exp, c.aud].join('|'));
  const sig = await sign(await sha256(bytes)); // REAL signature, same key as your mail
  rp = { ...rp, status: 'done', sig: toB64u(sig) };
}
