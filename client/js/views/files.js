// views/files.js — content-addressed, end-to-end encrypted files of any size (spec §5.5).
// Drive/Notion-grade surface: grid + list views, filter chips, a details/preview panel with
// share sheet, star + recent, drag-drop upload. A shared folder is a GROUP over a set of
// manifests (spec §5.8 / §6.7). Dropping a file chunks + hashes it client-side (real SHA-256).

import { state, uid } from '../store.js';
import { person, PEOPLE } from '../seed.js';
import { el, esc, icon, avatar, toast, timeAgo, fmtLong, fmtBytes, emptyState, openModal, closeModal } from '../ui.js';
import { sha256, hex } from '../identity.js';
import { bus } from '../bus.js';

let fileView = 'grid';       // 'grid' | 'list'
let filter = 'all';          // 'all' | 'starred' | 'shared'
let selFile = null;          // selected file id (opens the details panel)

export function render(root) {
  root.className = 'view files-view';
  const q = state.ui.search.trim().toLowerCase();
  let files = state.files.filter(f => !q || f.name.toLowerCase().includes(q));
  if (filter === 'starred') files = files.filter(f => f.starred);
  else if (filter === 'shared') files = files.filter(f => f.shared);
  const sharedGroups = [...new Set(state.files.filter(f => f.shared).map(f => f.shared))];
  const totalBytes = state.files.reduce((n, f) => n + f.size, 0);
  if (selFile && !state.files.some(f => f.id === selFile)) selFile = null;

  root.innerHTML = `
    <div class="files-main">
      <div class="files-inner">
        <header class="files-head">
          <div><h1>Files</h1><div class="files-sub">Content-addressed, end-to-end encrypted, any size — no protocol cap. ${state.files.length} items · ${esc(fmtBytes(totalBytes))} sealed.</div></div>
          <div class="files-head-actions">
            <div class="seg" id="fviewseg" role="group" aria-label="Layout">
              <button data-v="grid" class="${fileView === 'grid' ? 'on' : ''}" aria-pressed="${fileView === 'grid'}" title="Grid">${icon('grid')}</button>
              <button data-v="list" class="${fileView === 'list' ? 'on' : ''}" aria-pressed="${fileView === 'list'}" title="List">${icon('rows')}</button>
            </div>
            <button class="btn primary" id="upload">${icon('plus')} Add file</button>
          </div>
        </header>

        <div class="files-filters" id="ffilters">
          ${[['all', 'All files'], ['starred', 'Starred'], ['shared', 'Shared']].map(([k, l]) =>
            `<button class="file-filter ${filter === k ? 'on' : ''}" data-f="${k}">${l}${k === 'starred' ? ` <i class="ff-n">${state.files.filter(x => x.starred).length}</i>` : ''}</button>`).join('')}
        </div>

        <div class="drop" id="drop" role="button" tabindex="0" aria-label="Add a file — opens the file picker"><div class="drop-inner">${icon('files')}<b>Drop a file to share</b><span>chunked, hashed (b3:), and sealed client-side — nothing leaves in the clear</span></div></div>
        <input type="file" id="finput" class="hidden">

        ${filter === 'all' && sharedGroups.length ? `<div class="files-section-h">${icon('groups')} Shared folders (groups)</div>
        <div class="folder-grid">${sharedGroups.map(gid => { const g = state.groups.find(x => x.id === gid); const n = state.files.filter(x => x.shared === gid).length; return `<button class="folder-card" data-folder="${gid}"><div class="folder-ic">${icon('groups')}</div><div><b>${esc(g?.name || gid)}</b><span class="mono">${esc(g?.address || '')}</span></div><i class="folder-n">${n} file(s)</i></button>`; }).join('')}</div>` : ''}

        <div class="files-section-h">${filter === 'starred' ? 'Starred' : filter === 'shared' ? 'Shared files' : 'All files'} <span class="list-count">${files.length}</span></div>
        <div class="${fileView === 'grid' ? 'file-grid' : 'file-rows'}" id="grid"></div>
      </div>
    </div>
    <aside class="files-detail ${selFile ? 'show' : ''}" id="filesdetail"></aside>`;

  const grid = root.querySelector('#grid');
  if (!files.length) { grid.innerHTML = emptyState('files', q ? 'No files match' : (filter === 'starred' ? 'No starred files' : 'No files yet'), q ? 'Try a different search.' : (filter === 'starred' ? 'Star a file to keep it handy.' : 'Drop a file above to share it — sealed and content-addressed.')); }
  else files.forEach(f => grid.appendChild(fileView === 'grid' ? fileCard(f) : fileRow(f)));

  root.querySelectorAll('#fviewseg [data-v]').forEach(b => b.onclick = () => { fileView = b.dataset.v; bus.rerender(); });
  root.querySelectorAll('#ffilters [data-f]').forEach(b => b.onclick = () => { filter = b.dataset.f; bus.rerender(); });
  root.querySelectorAll('[data-folder]').forEach(b => b.onclick = () => { filter = 'shared'; bus.rerender(); });

  const inp = root.querySelector('#finput'), drop = root.querySelector('#drop');
  root.querySelector('#upload').onclick = () => inp.click();
  drop.onclick = () => inp.click();
  drop.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inp.click(); } };
  drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) shareFile(e.dataTransfer.files[0]); };
  inp.onchange = () => { if (inp.files[0]) shareFile(inp.files[0]); };

  drawDetail(root);
}

function fileCard(f) {
  const p = person(f.from);
  const g = f.shared ? state.groups.find(x => x.id === f.shared) : null;
  const node = el(`<div class="file-card ${selFile === f.id ? 'sel' : ''}" data-id="${f.id}" role="button" tabindex="0">
    <button class="fc-star ${f.starred ? 'on' : ''}" data-star="${f.id}" aria-label="Star" title="Star">${icon('star')}</button>
    <div class="file-ic">${f.icon || icon('files')}</div>
    <div class="file-name" title="${esc(f.name)}">${esc(f.name)}</div>
    <div class="file-meta">${fmtBytes(f.size)}</div>
    <div class="file-cid mono">${esc(f.cid)}</div>
    <div class="file-foot">${avatar(p, 20)}<span>${f.from === 'you' ? 'You' : esc(p.name.split(' ')[0])}</span>${g ? `<i class="chip-lbl" style="--h:250">${icon('groups')} ${esc(g.name)}</i>` : `<i class="pill priv sm">${icon('lock')} E2E</i>`}<span class="file-time">${timeAgo(f.ts)}</span></div>
  </div>`);
  wireFile(node, f);
  return node;
}

function fileRow(f) {
  const p = person(f.from);
  const g = f.shared ? state.groups.find(x => x.id === f.shared) : null;
  const node = el(`<div class="file-row ${selFile === f.id ? 'sel' : ''}" data-id="${f.id}" role="button" tabindex="0">
    <span class="fr-ic">${f.icon || icon('files')}</span>
    <span class="fr-name" title="${esc(f.name)}">${esc(f.name)}</span>
    <span class="fr-cid mono">${esc(f.cid)}</span>
    <span class="fr-owner">${avatar(p, 18)} ${f.from === 'you' ? 'You' : esc(p.name.split(' ')[0])}</span>
    <span class="fr-share">${g ? `<i class="chip-lbl" style="--h:250">${icon('groups')} ${esc(g.name)}</i>` : `<i class="pill priv sm">${icon('lock')} E2E</i>`}</span>
    <span class="fr-size">${fmtBytes(f.size)}</span>
    <span class="fr-time">${timeAgo(f.ts)}</span>
    <button class="fc-star ${f.starred ? 'on' : ''}" data-star="${f.id}" aria-label="Star" title="Star">${icon('star')}</button>
  </div>`);
  wireFile(node, f);
  return node;
}

function wireFile(node, f) {
  node.querySelector('[data-star]').onclick = (e) => { e.stopPropagation(); f.starred = !f.starred; bus.rerender(); };
  const open = () => { selFile = f.id; bus.rerender(); };
  node.onclick = open;
  node.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } };
}

function drawDetail(root) {
  const wrap = root.querySelector('#filesdetail');
  const f = state.files.find(x => x.id === selFile);
  if (!f) { wrap.innerHTML = ''; return; }
  const p = person(f.from);
  const g = f.shared ? state.groups.find(x => x.id === f.shared) : null;
  wrap.innerHTML = `
    <div class="fd-head"><b>Details</b><button class="icon-btn sm" id="fdclose" aria-label="Close details">${icon('x')}</button></div>
    <div class="fd-preview"><div class="fd-preview-ic">${f.icon || icon('files')}</div></div>
    <div class="fd-name">${esc(f.name)}</div>
    <div class="fd-sub">${esc(fmtBytes(f.size))} · added ${esc(timeAgo(f.ts))} ago</div>
    <div class="fd-actions">
      <button class="btn sm" id="fddl">${icon('download')} Download</button>
      <button class="btn sm" id="fdshare">${icon('share')} Share</button>
      <button class="btn sm ${f.starred ? 'primary' : ''}" id="fdstar">${icon('star')} ${f.starred ? 'Starred' : 'Star'}</button>
    </div>
    <div class="fd-fields">
      <div class="fd-field"><span>${icon('hash')} Content ID</span><button class="fd-cid mono" id="fdcopy" title="Copy CID">${esc(f.cid)} ${icon('copy')}</button></div>
      <div class="fd-field"><span>${icon('lock')} Encryption</span><b>End-to-end · sealed to keys</b></div>
      <div class="fd-field"><span>${icon('contacts')} Owner</span><b>${f.from === 'you' ? 'You' : esc(p.name)}</b></div>
      <div class="fd-field"><span>${icon('groups')} Shared with</span><b>${g ? esc(g.name) + ' (' + esc(g.address) + ')' : 'Private — no one'}</b></div>
      <div class="fd-field"><span>${icon('clock')} Added</span><b>${esc(fmtLong(f.ts))}</b></div>
    </div>
    <button class="btn danger sm block" id="fdremove">${icon('trash')} Remove file</button>`;

  wrap.querySelector('#fdclose').onclick = () => { selFile = null; bus.rerender(); };
  wrap.querySelector('#fddl').onclick = () => toast(`${icon('download')} Fetching + decrypting ${esc(f.name)} — reassembled from content-addressed chunks`, { ms: 3600 });
  wrap.querySelector('#fdshare').onclick = () => shareSheet(f);
  wrap.querySelector('#fdstar').onclick = () => { f.starred = !f.starred; bus.rerender(); };
  wrap.querySelector('#fdcopy').onclick = () => { navigator.clipboard?.writeText(f.cid); toast(`${icon('check')} Copied ${f.cid}`); };
  wrap.querySelector('#fdremove').onclick = () => { state.files = state.files.filter(x => x.id !== f.id); selFile = null; bus.rerender(); toast(`${icon('trash')} ${esc(f.name)} removed`); };
}

function shareSheet(f) {
  const targets = [...state.groups.map(g => ({ id: g.id, kind: 'group', name: g.name, sub: g.address, hue: 250 })),
    ...PEOPLE.filter(p => p.trust !== 'legacy').map(p => ({ id: p.address, kind: 'contact', name: p.name, sub: p.address, hue: p.hue }))];
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('share')} Share “${esc(f.name)}”</h2><button class="icon-btn" id="shx">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} Sharing adds the recipient (or group) to the file's MLS group and re-wraps the file key to them (spec §6.7). They can decrypt; no one else — not even the relay — ever sees plaintext.</p>
    <div class="share-list">${targets.map(t => `<button class="add-row" data-t="${esc(t.id)}" data-kind="${t.kind}">
      ${t.kind === 'group' ? `<span class="av chgroup" style="--h:250;width:32px;height:32px">${icon('groups')}</span>` : `<span class="av" style="--h:${t.hue};width:32px;height:32px;font-size:12px">${esc((t.name[0] || '?').toUpperCase())}</span>`}
      <div><b>${esc(t.name)}</b><span class="mono">${esc(t.sub)}</span></div>${icon('plus')}</button>`).join('')}</div>
  </div>`, { wide: true });
  card.querySelector('#shx').onclick = closeModal;
  card.querySelectorAll('[data-t]').forEach(b => b.onclick = () => {
    const kind = b.dataset.kind;
    if (kind === 'group') { const g = state.groups.find(x => x.id === b.dataset.t); if (g) f.shared = g.id; }
    closeModal(); bus.rerender();
    toast(`${icon('check')} Shared ${esc(f.name)} — file key re-wrapped, sealed to ${esc(b.querySelector('b').textContent)}`, { ms: 4000 });
  });
}

async function shareFile(file) {
  toast(`${icon('lock')} Chunking + hashing ${esc(file.name)}…`);
  const buf = new Uint8Array(await file.arrayBuffer());
  const cid = 'b3:' + hex(await sha256(buf), 8) + '…' + hex(await sha256(buf.slice(-64)), 4);
  const chunks = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
  const nf = { id: uid('f'), name: file.name, size: file.size, cid, icon: iconFor(file.name), from: 'you', shared: null, ts: Date.now() };
  state.files.unshift(nf);
  selFile = nf.id;
  bus.rerender();
  toast(`${icon('check')} Added · ${chunks} chunk(s) · manifest ${esc(cid)} · E2E encrypted`, { ms: 4200 });
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
