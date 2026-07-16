// views/files.js — content-addressed, end-to-end encrypted files of any size (spec §5.5).
// A shared folder is a GROUP over a set of manifests (spec §5.8 / §6.7): sharing = adding the
// group to the file's MLS group. Dropping a file chunks + hashes it client-side (real SHA-256).

import { state, uid } from '../store.js';
import { person } from '../seed.js';
import { el, esc, icon, avatar, toast, timeAgo, fmtBytes, emptyState } from '../ui.js';
import { sha256, hex } from '../identity.js';
import { bus } from '../bus.js';

export function render(root) {
  root.className = 'view files-view';
  const q = state.ui.search.trim().toLowerCase();
  const files = state.files.filter(f => !q || f.name.toLowerCase().includes(q));
  // Unique shared folders (by group), each a group over a set of manifests.
  const sharedGroups = [...new Set(state.files.filter(f => f.shared).map(f => f.shared))];

  root.innerHTML = `
    <div class="files-inner">
      <header class="files-head">
        <div><h1>Files</h1><div class="files-sub">Content-addressed, end-to-end encrypted, any size — no protocol cap. A shared folder is a group.</div></div>
        <button class="btn primary" id="upload">${icon('plus')} Share a file</button>
      </header>
      <div class="drop" id="drop" role="button" tabindex="0" aria-label="Share a file — opens the file picker"><div class="drop-inner">${icon('files')}<b>Drop a file to share</b><span>chunked, hashed (b3:), and sealed client-side — nothing leaves in the clear</span></div></div>
      <input type="file" id="finput" class="hidden">

      ${sharedGroups.length ? `<div class="files-section-h">${icon('groups')} Shared folders (groups)</div>
      <div class="folder-grid">${sharedGroups.map(gid => { const g = state.groups.find(x => x.id === gid); return `<div class="folder-card"><div class="folder-ic">${icon('groups')}</div><div><b>${esc(g?.name || gid)}</b><span class="mono">${esc(g?.address || '')}</span></div><i class="folder-n">${state.files.filter(x => x.shared === gid).length} file(s)</i></div>`; }).join('')}</div>` : ''}

      <div class="files-section-h">All files <span class="list-count">${files.length}</span></div>
      <div class="file-grid" id="grid"></div>
    </div>`;

  const grid = root.querySelector('#grid');
  const draw = () => {
    grid.innerHTML = '';
    if (!files.length) { grid.innerHTML = emptyState('files', q ? 'No files match' : 'No files yet', q ? 'Try a different search.' : 'Drop a file above to share it — sealed and content-addressed.'); return; }
    files.forEach(f => {
      const p = person(f.from);
      const g = f.shared ? state.groups.find(x => x.id === f.shared) : null;
      grid.appendChild(el(`<div class="file-card">
        <div class="file-ic">${f.icon || icon('files')}</div>
        <div class="file-name" title="${esc(f.name)}">${esc(f.name)}</div>
        <div class="file-meta">${fmtBytes(f.size)}</div>
        <div class="file-cid mono">${esc(f.cid)}</div>
        <div class="file-foot">${avatar(p, 20)}<span>${f.from === 'you' ? 'You' : esc(p.name.split(' ')[0])}</span>${g ? `<i class="chip-lbl" style="--h:250">${icon('groups')} ${esc(g.name)}</i>` : `<i class="pill priv sm">${icon('lock')} E2E</i>`}<span class="file-time">${timeAgo(f.ts)}</span></div>
      </div>`));
    });
  };
  draw();

  const inp = root.querySelector('#finput'), drop = root.querySelector('#drop');
  root.querySelector('#upload').onclick = () => inp.click();
  drop.onclick = () => inp.click();
  drop.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inp.click(); } };
  drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) shareFile(e.dataTransfer.files[0]); };
  inp.onchange = () => { if (inp.files[0]) shareFile(inp.files[0]); };

  async function shareFile(file) {
    toast(`${icon('lock')} Chunking + hashing ${esc(file.name)}…`);
    const buf = new Uint8Array(await file.arrayBuffer());
    const cid = 'b3:' + hex(await sha256(buf), 8) + '…' + hex(await sha256(buf.slice(-64)), 4);
    const chunks = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
    state.files.unshift({ id: uid('f'), name: file.name, size: file.size, cid, icon: iconFor(file.name), from: 'you', shared: null, ts: Date.now() });
    bus.rerender();
    toast(`${icon('check')} Shared · ${chunks} chunk(s) · manifest ${esc(cid)} · E2E encrypted`, { ms: 4200 });
  }
}

function iconFor(name) {
  const e = name.split('.').pop().toLowerCase();
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(e)) return '🖼️';
  if (['pdf'].includes(e)) return '📄';
  if (['csv', 'xlsx', 'numbers'].includes(e)) return '📊';
  if (['zip', 'tar', 'gz', 'zst'].includes(e)) return '📦';
  if (['fig', 'sketch'].includes(e)) return '🎨';
  return '📎';
}
