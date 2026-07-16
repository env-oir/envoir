// setup.js — "connect your domain" onboarding for the management console. An org that controls
// @abc.com becomes its own DOMAIN AUTHORITY (spec §3.10.1): we generate a real authority keypair,
// establish the threshold-holder set, and (in this simulation) seed a believable org so every
// admin surface has something to manage. A production console would instead verify DNS control
// and publish the `_dmtap` / `kt=` anchor for the domain.

import { createAuthority } from './session.js';
import { seed } from './store.js';
import { esc, icon, brandMark, toast } from './ui.js';

export function renderSetup(onDone) {
  const o = document.getElementById('setup');
  o.classList.remove('hidden');
  let step = 0, domain = '', busy = false;

  const draw = () => {
    if (step === 0) {
      o.innerHTML = `<div class="ob-card wide">
        <div class="ob-brand">${brandMark(46)}<div><span class="ob-word">Envoir</span><span class="ob-kicker">Management Console</span></div></div>
        <div class="ob-dots"><i class="on"></i><i></i></div>
        <h1>Run your organization on a domain you control</h1>
        <p class="ob-sub">The console administers <b>names and operations</b> under your domain — add members, run a directory, manage distribution lists, assign admin roles. One invariant holds throughout: <b>you control names, never a sovereign member's key</b> — and where the org does hold a key, it is disclosed (spec §3.10).</p>

        <label class="cfield"><span>Your domain</span><div class="addr-compose"><span class="addr-at mono">@</span><input id="dom" placeholder="abc.com" value="${esc(domain)}" autocomplete="off" spellcheck="false"></div></label>

        <div class="setup-facts">
          <div class="fact"><b>${icon('domain')} Domain authority</b><small>An Envoir identity published at <span class="mono">_dmtap.&lt;domain&gt;</span> and anchored in key transparency. It states which key each <span class="mono">name@domain</span> points to — and nothing more.</small></div>
          <div class="fact"><b>${icon('shield')} Threshold-held</b><small>The authority key is split across a domain-owner / admin set. Rotating the anchor or the directory key needs a quorum, so no single admin can seize the namespace.</small></div>
        </div>

        <button class="btn primary block" id="next">Continue</button>
        <p class="ob-fine">${icon('lock')} A real Ed25519 authority keypair is generated in your browser. The simulated node stands in for DNS + the mesh + the KT log.</p>
      </div>`;
      const di = o.querySelector('#dom');
      di.oninput = e => domain = e.target.value.trim().toLowerCase().replace(/[^a-z0-9.-]/g, '');
      o.querySelector('#next').onclick = () => {
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) { di.focus(); toast(`${icon('warn')} Enter a valid domain, e.g. abc.com`); return; }
        step = 1; draw();
      };
      di.addEventListener('keydown', e => { if (e.key === 'Enter') o.querySelector('#next').click(); });
    } else {
      o.innerHTML = `<div class="ob-card wide">
        <div class="ob-brand">${brandMark(46)}<div><span class="ob-word">Envoir</span><span class="ob-kicker">Management Console</span></div></div>
        <div class="ob-dots"><i class="on"></i><i class="on"></i></div>
        <h1>Establish authority for <span class="mono grad-text">@${esc(domain)}</span></h1>
        <p class="ob-sub">We'll generate your threshold-held domain authority key, publish the anchor, and load your organization. You can change everything afterwards.</p>

        <div class="setup-threshold">
          <div class="st-head"><b>${icon('shield')} Threshold key holders</b><span class="pill accent sm">2-of-3</span></div>
          <div class="st-holder"><span class="av" style="--h:210;width:30px;height:30px;font-size:11px">YO</span><div><b>You (owner)</b><small class="mono">you@${esc(domain)} · domain-owner</small></div></div>
          <div class="st-holder"><span class="av" style="--h:262;width:30px;height:30px;font-size:11px">PN</span><div><b>Priya Nair</b><small class="mono">priya@${esc(domain)} · domain-admin</small></div></div>
          <div class="st-holder"><span class="av" style="--h:150;width:30px;height:30px;font-size:11px">SW</span><div><b>Sam Whitfield</b><small class="mono">sam@${esc(domain)} · domain-admin</small></div></div>
          <p class="st-note">${icon('info')} A domain-authoritative act — rotating the anchor or the directory-signing key — will require <b>2 of these 3</b> to approve.</p>
        </div>

        <div class="setup-btns">
          <button class="btn ghost" id="back">Back</button>
          <div class="spacer"></div>
          <button class="btn primary" id="go">${icon('key')} Generate authority &amp; open console</button>
        </div>
      </div>`;
      o.querySelector('#back').onclick = () => { step = 0; draw(); };
      o.querySelector('#go').onclick = async () => {
        if (busy) return; busy = true;
        const go = o.querySelector('#go'); go.disabled = true; go.innerHTML = `${icon('refresh')} Generating…`;
        toast(`${icon('key')} Generating your Ed25519 authority keypair…`);
        try {
          const authority = await createAuthority();
          await seed(domain, authority);
          o.classList.add('hidden');
          onDone();
        } catch (err) {
          busy = false; go.disabled = false; go.innerHTML = `${icon('key')} Generate authority &amp; open console`;
          toast(`${icon('warn')} Setup failed: ${esc(err.message)}`);
        }
      };
    }
  };
  draw();
}
