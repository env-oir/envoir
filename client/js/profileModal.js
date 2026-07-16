// profileModal.js — the "Edit profile" modal: self-asserted NAME + AVATAR fields (see
// identity.js header: the KEY is the identity; the name and photo are just pointers to you,
// exactly like the address is a pointer to the key — none of this changes your safety number).
// Shared by Settings and the Identity view so there's one editor, not two.

import { currentIdentity, displayName, setProfile } from './identity.js';
import { esc, icon, avatar, toast, openModal, closeModal } from './ui.js';
import { bus } from './bus.js';

const AVATAR_KIND_LABEL = { url: 'your avatar URL', gravatar: 'Gravatar (opt-in)', identicon: 'key-derived identicon', initials: 'initials (fallback)' };

export function openEditProfile() {
  const id = currentIdentity();
  const card = openModal(`
    <div class="ev-new pf-modal">
      <div class="ev-detail-head"><h2>${icon('edit')} Edit profile</h2><button class="icon-btn" id="pfx">${icon('x')}</button></div>

      <div class="pf-avatar-row">
        <div class="pf-preview" id="pfprev"></div>
        <div class="pf-avatar-fields">
          <label class="cfield"><span>Avatar URL</span><input id="pfurl" value="${esc(id.avatarUrl || '')}" placeholder="https://example.com/me.jpg" autocomplete="off"></label>
          <div class="set-row between pf-grav-row">
            <div><b>Use Gravatar</b><small>derives an avatar from a hash of your address — opt-in, off by default</small></div>
            <label class="switch sm"><input type="checkbox" id="pfgrav" ${id.gravatarEnabled ? 'checked' : ''}><i></i></label>
          </div>
          <div class="pf-src-hint" id="pfsrc"></div>
        </div>
      </div>
      <p class="modal-note">${icon('info')} <b>The avatar standard:</b> your URL, if set, always wins. Otherwise, if you opt into Gravatar, that's used. Otherwise a deterministic <b>identicon</b> is derived from your key — the same picture every time, nothing to upload, and it can never collide with anyone else's key. Gravatar is never on by default.</p>

      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Given name</span><input id="pfgiven" value="${esc(id.givenName || '')}" placeholder="Ada" autocomplete="off"></label>
        <label class="cfield"><span>Family name</span><input id="pffamily" value="${esc(id.familyName || '')}" placeholder="Okonkwo" autocomplete="off"></label>
      </div>
      <label class="cfield"><span>Display name override (optional)</span><input id="pfdisp" value="${esc(id.displayName || '')}" placeholder="auto: given + family name" autocomplete="off"></label>
      <p class="modal-note">${icon('info')} These are self-asserted profile fields — a pointer to you, like your address is a pointer to your key. Changing your name or photo never changes your <b>safety number</b>.</p>
      <div class="ev-detail-foot"><span class="sim-tag">saved to this device</span><div class="spacer"></div><button class="btn primary" id="pfdone">Done</button></div>
    </div>`, { wide: true, label: 'Edit profile' });

  const $ = (s) => card.querySelector(s);
  const drawPreview = () => {
    $('#pfprev').innerHTML = avatar({ name: displayName(id), hue: id.hue ?? 250, trust: 'verified', avatarUrl: id.avatarUrl || null, _avatarSrc: id._avatarSrc }, 84, { ring: true });
    const label = AVATAR_KIND_LABEL[id._avatarKind] || '';
    $('#pfsrc').textContent = label ? `Currently showing: ${label}` : '';
  };
  drawPreview();

  let debounceT = null;
  const debounced = (fn) => { clearTimeout(debounceT); debounceT = setTimeout(fn, 260); };

  const commitAvatar = async () => {
    await setProfile({ avatarUrl: $('#pfurl').value.trim() || null, gravatarEnabled: $('#pfgrav').checked });
    drawPreview(); bus.refreshChrome(); bus.rerender();
  };
  $('#pfurl').oninput = () => debounced(commitAvatar);
  $('#pfgrav').onchange = commitAvatar;

  const commitName = async () => {
    await setProfile({ givenName: $('#pfgiven').value.trim(), familyName: $('#pffamily').value.trim(), displayName: $('#pfdisp').value.trim() });
    drawPreview(); bus.refreshChrome(); bus.rerender();
  };
  $('#pfgiven').oninput = () => debounced(commitName);
  $('#pffamily').oninput = () => debounced(commitName);
  $('#pfdisp').oninput = () => debounced(commitName);

  const done = () => { clearTimeout(debounceT); closeModal(); toast(`${icon('check')} Profile updated`); };
  $('#pfx').onclick = done;
  $('#pfdone').onclick = done;
}
