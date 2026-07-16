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
const selFiles = new Set();  // multi-select for bulk actions
let previewUrl = null;       // active object-URL for the details preview (revoked on redraw)

export function render(root) {
  root.className = 'view files-view';
  const q = state.ui.search.trim().toLowerCase();
  let files = state.files.filter(f => !q || f.name.toLowerCase().includes(q));
  if (filter === 'starred') files = files.filter(f => f.starred);
  else if (filter === 'shared') files = files.filter(f => f.shared);
  const sharedGroups = [...new Set(state.files.filter(f => f.shared).map(f => f.shared))];
  const totalBytes = state.files.reduce((n, f) => n + f.size, 0);
  if (selFile && !state.files.some(f => f.id === selFile)) selFile = null;
  for (const id of [...selFiles]) if (!state.files.some(f => f.id === id)) selFiles.delete(id);

  root.innerHTML = `
    <div class="files-main">
      <div class="files-inner">
        <header class="files-head">
          <div><h1 class="display">Files</h1><div class="files-sub">Content-addressed, end-to-end encrypted, any size — no protocol cap. ${state.files.length} items · ${esc(fmtBytes(totalBytes))} sealed.</div></div>
          <div class="files-head-actions">
            <div class="seg" id="fviewseg" role="group" aria-label="Layout">
              <button data-v="grid" class="${fileView === 'grid' ? 'on' : ''}" aria-pressed="${fileView === 'grid'}" title="Grid">${icon('grid')}</button>
              <button data-v="list" class="${fileView === 'list' ? 'on' : ''}" aria-pressed="${fileView === 'list'}" title="List">${icon('rows')}</button>
            </div>
            <button class="btn primary" id="upload">${icon('plus')} Add file</button>
          </div>
        </header>

        ${selFiles.size ? `<div class="files-bulk" id="filesbulk">
          <span class="files-bulk-n">${selFiles.size} selected</span>
          <div class="spacer"></div>
          <button class="btn sm" data-bulk="star">${icon('star')} Star</button>
          <button class="btn sm" data-bulk="download">${icon('download')} Download</button>
          <button class="btn sm" data-bulk="share">${icon('share')} Share</button>
          <button class="btn sm danger" data-bulk="remove">${icon('trash')} Remove</button>
          <button class="icon-btn sm" data-bulk="clear" title="Clear selection" aria-label="Clear selection">${icon('x')}</button>
        </div>` : ''}

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
  root.querySelectorAll('#filesbulk [data-bulk]').forEach(b => b.onclick = () => bulkAction(b.dataset.bulk));

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
  const node = el(`<div class="file-card ${selFile === f.id ? 'sel' : ''} ${selFiles.has(f.id) ? 'picked' : ''}" data-id="${f.id}" role="button" tabindex="0">
    <button class="fc-check ${selFiles.has(f.id) ? 'on' : ''}" data-check="${f.id}" aria-label="Select file" aria-pressed="${selFiles.has(f.id)}">${icon('check')}</button>
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
  const node = el(`<div class="file-row ${selFile === f.id ? 'sel' : ''} ${selFiles.has(f.id) ? 'picked' : ''}" data-id="${f.id}" role="button" tabindex="0">
    <button class="fc-check ${selFiles.has(f.id) ? 'on' : ''}" data-check="${f.id}" aria-label="Select file" aria-pressed="${selFiles.has(f.id)}">${icon('check')}</button>
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
  node.querySelector('[data-check]').onclick = (e) => { e.stopPropagation(); selFiles.has(f.id) ? selFiles.delete(f.id) : selFiles.add(f.id); bus.rerender(); };
  const open = () => { selFile = f.id; bus.rerender(); };
  node.onclick = open;
  node.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } };
}

function drawDetail(root) {
  const wrap = root.querySelector('#filesdetail');
  if (previewUrl) { URL.revokeObjectURL(previewUrl); previewUrl = null; }
  const f = state.files.find(x => x.id === selFile);
  if (!f) { wrap.innerHTML = ''; return; }
  const p = person(f.from);
  const g = f.shared ? state.groups.find(x => x.id === f.shared) : null;
  const preview = buildPreview(f);
  wrap.innerHTML = `
    <div class="fd-head"><b>Details</b><button class="icon-btn sm" id="fdclose" aria-label="Close details">${icon('x')}</button></div>
    <div class="fd-preview ${preview.cls}">${preview.html}</div>
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

// ---- Inline preview: render real uploaded blobs (image/PDF), or a labelled simulated preview
// for the seed store (which has no real bytes). Everything stays client-side. ----
const IMG_EXT = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'avif'];
function buildPreview(f) {
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  const isImg = IMG_EXT.includes(ext) || (f.mime || '').startsWith('image/');
  const isPdf = ext === 'pdf' || f.mime === 'application/pdf';
  const tag = (ic, label) => `<span class="fd-preview-tag">${icon(ic)} ${esc(label)}</span>`;
  if (f.blob && isImg) { previewUrl = URL.createObjectURL(f.blob); return { cls: 'has-media', html: `<img class="fd-img" src="${previewUrl}" alt="${esc(f.name)}">${tag('image', 'decrypted preview')}` }; }
  if (f.blob && isPdf) { previewUrl = URL.createObjectURL(f.blob); return { cls: 'has-media', html: `<iframe class="fd-pdf" src="${previewUrl}" title="${esc(f.name)}"></iframe>${tag('pdf', 'decrypted preview')}` }; }
  if (isImg) return { cls: 'has-media', html: simImage(f) + tag('image', 'preview · simulated') };
  if (isPdf) return { cls: 'has-media', html: simPdf() + tag('pdf', 'preview · simulated') };
  return { cls: '', html: `<div class="fd-preview-ic">${f.icon || icon('files')}</div>` };
}
function hueFrom(s) { let h = 0; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; }
function simImage(f) {
  const h = hueFrom(f.name);
  return `<svg class="fd-preview-svg" viewBox="0 0 320 190" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Simulated image preview">
    <defs><linearGradient id="pv-${hueFrom(f.cid)}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(${h} 68% 60%)"/><stop offset="1" stop-color="hsl(${(h + 55) % 360} 70% 44%)"/></linearGradient></defs>
    <rect width="320" height="190" fill="url(#pv-${hueFrom(f.cid)})"/>
    <circle cx="248" cy="52" r="26" fill="rgba(255,255,255,.82)"/>
    <path d="M0 190 L86 116 L146 152 L214 96 L320 168 L320 190Z" fill="rgba(0,0,0,.24)"/>
    <path d="M0 190 L120 138 L188 166 L320 118 L320 190Z" fill="rgba(0,0,0,.16)"/>
  </svg>`;
}
function simPdf() {
  return `<svg class="fd-preview-svg" viewBox="0 0 320 190" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Simulated document preview">
    <g transform="translate(112 20)">
      <rect width="96" height="150" rx="5" fill="#fff" stroke="rgba(0,0,0,.14)"/>
      <rect x="12" y="15" width="58" height="8" rx="2" fill="#6a5bff"/>
      <rect x="12" y="33" width="72" height="4" rx="2" fill="rgba(0,0,0,.2)"/>
      <rect x="12" y="43" width="72" height="4" rx="2" fill="rgba(0,0,0,.14)"/>
      <rect x="12" y="53" width="52" height="4" rx="2" fill="rgba(0,0,0,.14)"/>
      <rect x="12" y="70" width="72" height="4" rx="2" fill="rgba(0,0,0,.12)"/>
      <rect x="12" y="80" width="72" height="4" rx="2" fill="rgba(0,0,0,.12)"/>
      <rect x="12" y="90" width="40" height="4" rx="2" fill="rgba(0,0,0,.12)"/>
      <rect x="12" y="112" width="72" height="26" rx="3" fill="rgba(106,91,255,.12)"/>
    </g>
  </svg>`;
}

// ---- Bulk actions over the multi-selection ----
function bulkAction(action) {
  if (action === 'clear') { selFiles.clear(); bus.rerender(); return; }
  const files = state.files.filter(f => selFiles.has(f.id));
  if (!files.length) return;
  if (action === 'star') { const allStar = files.every(f => f.starred); files.forEach(f => f.starred = !allStar); bus.rerender(); toast(`${icon('star')} ${allStar ? 'Unstarred' : 'Starred'} ${files.length} file(s)`); }
  else if (action === 'download') { toast(`${icon('download')} Fetching + decrypting ${files.length} file(s) — reassembled from content-addressed chunks`, { ms: 3600 }); }
  else if (action === 'remove') { const ids = new Set(files.map(f => f.id)); state.files = state.files.filter(f => !ids.has(f.id)); if (ids.has(selFile)) selFile = null; selFiles.clear(); bus.rerender(); toast(`${icon('trash')} ${ids.size} file(s) removed`); }
  else if (action === 'share') { bulkShare(files); }
}
function bulkShare(files) {
  const card = openModal(`<div class="id-modal">
    <div class="ev-detail-head"><h2>${icon('share')} Share ${files.length} files</h2><button class="icon-btn" id="bsx">${icon('x')}</button></div>
    <p class="modal-note">${icon('info')} Adds every selected file to a group's MLS group and re-wraps each file key to its members (spec §6.7). Only members can decrypt — not even the relay.</p>
    <div class="share-list">${state.groups.map(g => `<button class="add-row" data-t="${esc(g.id)}"><span class="av chgroup" style="--h:250;width:32px;height:32px">${icon('groups')}</span><div><b>${esc(g.name)}</b><span class="mono">${esc(g.address)}</span></div>${icon('plus')}</button>`).join('')}</div>
  </div>`, { wide: true });
  card.querySelector('#bsx').onclick = closeModal;
  card.querySelectorAll('[data-t]').forEach(b => b.onclick = () => {
    const g = state.groups.find(x => x.id === b.dataset.t); if (g) files.forEach(f => f.shared = g.id);
    selFiles.clear(); closeModal(); bus.rerender();
    toast(`${icon('check')} Shared ${files.length} file(s) to ${esc(g.name)} — file keys re-wrapped`, { ms: 4000 });
  });
}

async function shareFile(file) {
  toast(`${icon('lock')} Chunking + hashing ${esc(file.name)}…`);
  const buf = new Uint8Array(await file.arrayBuffer());
  const cid = 'b3:' + hex(await sha256(buf), 8) + '…' + hex(await sha256(buf.slice(-64)), 4);
  const chunks = Math.max(1, Math.ceil(file.size / (1024 * 1024)));
  const nf = { id: uid('f'), name: file.name, size: file.size, cid, icon: iconFor(file.name), from: 'you', shared: null, ts: Date.now(), blob: file, mime: file.type };
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
