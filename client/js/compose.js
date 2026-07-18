// compose.js — the rich compose modal: recipients (with contact autocomplete), subject, a
// RICH-TEXT/HTML body (spec §17#8) with a formatting toolbar + signature (§17#9), attachments
// (§17#7), privacy tier, scheduled send (§17#15), draft AUTOSAVE (§17#6), and SEND with an
// UNDO window (§17#17). Building a message constructs a REAL MOTE (real signature) and animates
// its simulated delivery through the inspector.

import { openModal, closeModal, toast, icon, esc, avatar, showInspector, litHop, sanitizeHtml, trustPill } from './ui.js';
import { buildMote, KIND } from './mote.js';
import { planDelivery, animatePath } from './mesh-sim.js';
import { sendMail, sendMode } from './net/send.js';
import { currentIdentity, displayAddress, selfPerson } from './identity.js';
import { state, thread, uid, stripHtml } from './store.js';
import { person, PEOPLE, fmtBytes } from './seed.js';
import { bus } from './bus.js';
import { classifyName, resolverChip, resolverDetail, RESOLVER_TYPES } from './resolver.js';

const UNDO_MS = 5000;

// plaintext (with \n) → simple HTML for the contentEditable editor
function textToHtml(s) { return esc(s || '').replace(/\n/g, '<br>'); }

// The honest footer note, keyed to how THIS message will actually go out (net/send.js sendMode):
//   real → delivered by the node's Send API   seam → live node but send not provisioned
//   sim  → the labeled simulation (no real delivery)
function composeNote() {
  switch (sendMode()) {
    case 'real': return 'sealed · signed with your real key · delivered by your node';
    case 'seam': return 'sealed · signed with your real key · add a send token in Settings → Node to deliver for real';
    default: return 'sealed · signed with your real key · simulated delivery — connect your node to send for real';
  }
}

export function openCompose(opts = {}) {
  const id = currentIdentity();
  const sig = state.settings.signatures.find(s => s.default);
  const initialBody = opts.body != null
    ? (opts.html ? opts.body : textToHtml(opts.body))
    : (sig ? '<br><br>' + textToHtml(sig.body) : '');
  const draft = {
    threadId: opts.threadId || null,
    to: opts.to || '', subject: opts.subject || '', body: initialBody,
    tier: opts.tier || state.settings.tierDefault, replyThread: opts.replyThread || null,
    scheduleAt: opts.scheduleAt || null, attach: (opts.attach || []).slice(),
  };

  const card = openModal(`
    <div class="compose">
      <div class="compose-top">
        <b>${opts.replyThread ? 'Reply' : (opts.threadId ? 'Edit draft' : 'New message')}</b>
        <span class="save-state mono" id="csave"></span>
        <div class="spacer"></div>
        <button class="icon-btn" id="cx" aria-label="Close">${icon('x')}</button>
      </div>
      <label class="cfield"><span>From</span><div class="from-chip">${avatar(selfPerson(), 22)}${esc(displayAddress(id))}</div></label>
      <label class="cfield"><span>To</span><div class="ac-wrap"><input id="cto" value="${esc(draft.to)}" placeholder="name@domain, a key-name, alice.eth/.sol, @handle, or a group address" autocomplete="off" role="combobox" aria-autocomplete="list" aria-expanded="false"><div class="ac-list" id="cac" role="listbox"></div></div></label>
      <div class="resolver-hint" id="cresolver"></div>
      <label class="cfield"><span>Subject</span><input id="csubj" value="${esc(draft.subject)}" placeholder="Subject"></label>
      <div class="rt-toolbar" role="toolbar" aria-label="Formatting">
        <button class="rt-btn" data-cmd="bold" title="Bold (Ctrl-B)"><b>B</b></button>
        <button class="rt-btn" data-cmd="italic" title="Italic (Ctrl-I)"><i>I</i></button>
        <button class="rt-btn" data-cmd="underline" title="Underline (Ctrl-U)"><u>U</u></button>
        <span class="rt-sep"></span>
        <button class="rt-btn" data-cmd="insertUnorderedList" title="Bulleted list">${icon('label')}</button>
        <button class="rt-btn" data-cmd="insertOrderedList" title="Numbered list">1.</button>
        <button class="rt-btn" data-cmd="createLink" title="Insert link">${icon('key')}</button>
        <button class="rt-btn" data-cmd="removeFormat" title="Clear formatting">${icon('x')}</button>
      </div>
      <div id="cbody" class="rt-body" contenteditable="true" role="textbox" aria-multiline="true" aria-label="Message body" data-ph="Write your message — sealed to the recipient's key and routed privately.">${sanitizeHtml(draft.body)}</div>
      <div id="cattach" class="attach-row"></div>
      <div class="compose-foot">
        <button class="btn primary" id="csend">${icon('send')} Send</button>
        <div class="tier-seg" id="ctier" role="group" aria-label="Privacy tier">
          <button data-t="private" aria-pressed="${draft.tier === 'private'}" class="${draft.tier === 'private' ? 'on' : ''}">${icon('shield')} Private</button>
          <button data-t="fast" aria-pressed="${draft.tier === 'fast'}" class="${draft.tier === 'fast' ? 'on' : ''}">Fast</button>
        </div>
        <div class="spacer"></div>
        <button class="icon-btn" id="cattachbtn" title="Attach file">${icon('files')}</button>
        <button class="icon-btn" id="cschedule" title="Schedule send">${icon('clock')}</button>
        <button class="icon-btn" id="csig" title="Insert signature">${icon('edit')}</button>
        <input type="file" id="cfile" class="hidden" multiple>
      </div>
      <div class="compose-note"><span class="sim-tag">${composeNote()}</span></div>
      <div id="csched-row" class="sched-row hidden"></div>
    </div>`, { compose: true, sticky: true });

  const $ = (s) => card.querySelector(s);
  const bodyEl = $('#cbody');
  const readBody = () => sanitizeHtml(bodyEl.innerHTML);
  const bodyText = () => stripHtml(bodyEl.innerHTML.replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li)>/gi, '\n')).trim();

  // ----- draft autosave (Gmail-parity §17#6): upsert into Drafts as you type -----
  let saveTimer = null, dirty = false;
  const markDirty = () => { dirty = true; $('#csave').textContent = 'Saving…'; clearTimeout(saveTimer); saveTimer = setTimeout(commitAutosave, 1200); };
  function commitAutosave() {
    draft.to = $('#cto').value.trim(); draft.subject = $('#csubj').value.trim(); draft.body = readBody();
    if (!draft.to && !draft.subject && !bodyText() && !draft.attach.length) { $('#csave').textContent = ''; return; }
    upsertDraft(draft, bodyText());
    dirty = false; $('#csave').textContent = 'Saved to Drafts';
    bus.refreshChrome();
    if (state.view === 'mail' && (state.ui.mailFolder === 'drafts')) bus.rerender();
  }

  $('#cx').onclick = () => { clearTimeout(saveTimer); if (dirty || draft.threadId) commitAutosave(); closeModal(); if (state.view === 'mail') bus.rerender(); };
  $('#csubj').oninput = markDirty;
  bodyEl.oninput = markDirty;

  // recipient autocomplete from contacts + groups (spec §17#33), plus a live resolver-type
  // indicator (spec §3.12 the pluggable resolver framework) so the sender sees, honestly,
  // which resolver a typed name would use and its verification state — never a silent guess.
  const updateResolverHint = () => drawResolverHint($('#cto'), $('#cresolver'));
  wireAutocomplete($('#cto'), $('#cac'), markDirty, updateResolverHint);
  $('#cto').addEventListener('input', updateResolverHint);
  updateResolverHint();

  // rich-text toolbar
  card.querySelectorAll('.rt-btn').forEach(b => b.onmousedown = (e) => {
    e.preventDefault(); // keep selection/focus in the editor
    bodyEl.focus();
    const cmd = b.dataset.cmd;
    if (cmd === 'createLink') { const url = prompt('Link URL:', 'https://'); if (url) document.execCommand('createLink', false, url); }
    else document.execCommand(cmd, false, null);
    markDirty();
  });
  bodyEl.addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey) { const k = e.key.toLowerCase();
      if (k === 'b' || k === 'i' || k === 'u') { e.preventDefault(); document.execCommand({ b: 'bold', i: 'italic', u: 'underline' }[k]); markDirty(); } }
  });

  $('#ctier').querySelectorAll('[data-t]').forEach(b => b.onclick = () => {
    draft.tier = b.dataset.t; $('#ctier').querySelectorAll('button').forEach(x => { const on = x.dataset.t === draft.tier; x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); });
  });
  $('#csig').onclick = () => {
    const s = state.settings.signatures.find(x => x.default);
    if (s) { document.execCommand('insertHTML', false, '<br><br>' + textToHtml(s.body)); markDirty(); }
  };

  // attachments (spec §17#7)
  const drawAttach = () => {
    const row = $('#cattach');
    row.innerHTML = draft.attach.map((a, i) => `<span class="att-chip">${icon('files')} ${esc(a.name)} · ${fmtBytes(a.size)} <button class="att-x" data-ai="${i}" aria-label="Remove">${icon('x')}</button></span>`).join('');
    row.querySelectorAll('[data-ai]').forEach(b => b.onclick = () => { draft.attach.splice(Number(b.dataset.ai), 1); drawAttach(); markDirty(); });
  };
  $('#cattachbtn').onclick = () => $('#cfile').click();
  $('#cfile').onchange = () => { [...$('#cfile').files].forEach(f => draft.attach.push({ name: f.name, size: f.size })); $('#cfile').value = ''; drawAttach(); markDirty(); };
  drawAttach();

  $('#cschedule').onclick = () => {
    const row = $('#csched-row');
    if (!row.classList.contains('hidden')) { row.classList.add('hidden'); draft.scheduleAt = null; $('#csend').innerHTML = icon('send') + ' Send'; return; }
    row.classList.remove('hidden');
    const opt = (label, ms) => `<button class="chip" data-ms="${ms}">${label}</button>`;
    const h = new Date().getHours();
    row.innerHTML = `<span class="sched-lbl">${icon('clock')} Schedule:</span>
      ${opt('In 1 hour', 3600e3)} ${opt('This evening', ((h < 18 ? 18 : 21) - h) * 3600e3)} ${opt('Tomorrow 9am', tomorrow9())} ${opt('Monday 9am', monday9())}`;
    row.querySelectorAll('[data-ms]').forEach(b => b.onclick = () => {
      draft.scheduleAt = Date.now() + Number(b.dataset.ms);
      row.querySelectorAll('.chip').forEach(c => c.classList.remove('on')); b.classList.add('on');
      $('#csend').innerHTML = icon('clock') + ' Schedule';
    });
  };
  $('#csend').onclick = () => {
    draft.to = $('#cto').value.trim(); draft.subject = $('#csubj').value.trim(); draft.body = readBody();
    if (!draft.to) return toast('Add a recipient');
    clearTimeout(saveTimer);
    // sending consumes any autosaved draft
    if (draft.threadId) { state.mail = state.mail.filter(t => t.id !== draft.threadId); draft.threadId = null; }
    draft._text = bodyText();
    if (draft.scheduleAt) return doSchedule(draft);
    doSendWithUndo(draft);
  };
  setTimeout(() => $('#cto').focus(), 50);
}

function tomorrow9() { const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(9, 0, 0, 0); return d.getTime() - Date.now(); }
function monday9() { const d = new Date(); const add = ((8 - d.getDay()) % 7) || 7; d.setDate(d.getDate() + add); d.setHours(9, 0, 0, 0); return d.getTime() - Date.now(); }

// ----- recipient autocomplete (contacts + groups) -----
function wireAutocomplete(input, listEl, onChange, onPick) {
  const suggestions = [
    ...PEOPLE.map(p => ({ name: p.name, addr: p.address, hue: p.hue, kind: 'contact' })),
    ...state.groups.map(g => ({ name: g.name, addr: g.address, hue: 250, kind: 'group' })),
  ];
  let active = -1, matches = [];
  const close = () => { listEl.classList.remove('show'); input.setAttribute('aria-expanded', 'false'); active = -1; };
  const draw = () => {
    // autocomplete the last comma-separated token
    const parts = input.value.split(','); const frag = parts[parts.length - 1].trim().toLowerCase();
    matches = frag ? suggestions.filter(s => (s.name + ' ' + s.addr).toLowerCase().includes(frag)).slice(0, 6) : [];
    if (!matches.length) return close();
    listEl.innerHTML = matches.map((m, i) => `<button class="ac-item ${i === active ? 'on' : ''}" data-i="${i}" role="option"><span class="ac-av" style="--h:${m.hue}"></span><span class="ac-main"><b>${esc(m.name)}</b><span class="mono">${esc(m.addr)}</span></span><i class="ac-kind">${m.kind}</i></button>`).join('');
    listEl.querySelectorAll('[data-i]').forEach(b => b.onmousedown = (e) => { e.preventDefault(); pick(Number(b.dataset.i)); });
    listEl.classList.add('show'); input.setAttribute('aria-expanded', 'true');
  };
  const pick = (i) => {
    const m = matches[i]; if (!m) return;
    const parts = input.value.split(','); parts[parts.length - 1] = ' ' + m.addr;
    input.value = parts.join(',').replace(/^\s+/, '') + ', ';
    close(); onChange && onChange(); onPick && onPick(m); input.focus();
  };
  input.oninput = () => { draw(); onChange && onChange(); };
  input.onkeydown = (e) => {
    if (!listEl.classList.contains('show')) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(matches.length - 1, active + 1); draw(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); draw(); }
    else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); pick(active); }
    else if (e.key === 'Escape') { close(); }
  };
  input.onblur = () => setTimeout(close, 150);
}

// Live resolver-type feedback for the last comma-separated token in the To field (spec §3.12).
// A typed name matching an existing contact's DISPLAY NAME (not its literal address) resolves
// as a petname (§3.9.3, local, no lookup) using that contact's real trust state; otherwise the
// raw text is pattern-classified (key-name / DNS / name-chain / @handle / unrecognized) — never
// a silent guess, matching the spec §3.12.2 fail-closed discipline for an unrecognized form.
function drawResolverHint(input, hintEl) {
  const parts = input.value.split(',');
  const frag = parts[parts.length - 1].trim();
  if (!frag) { hintEl.innerHTML = ''; return; }
  const byAddr = PEOPLE.find(p => p.address.toLowerCase() === frag.toLowerCase());
  const byName = !byAddr && PEOPLE.find(p => p.name.toLowerCase() === frag.toLowerCase());
  let info, trust;
  if (byName) { info = RESOLVER_TYPES.petname; trust = byName.trust; }
  else { info = classifyName(frag); trust = byAddr ? byAddr.trust : undefined; }
  hintEl.innerHTML = resolverChip(info) + (trust ? trustPill(trust) : '') +
    `<span class="resolver-note">${esc(resolverDetail(info, trust))}</span>`;
}

// ----- draft persistence (autosave upsert) -----
function upsertDraft(draft, text) {
  const msg = { id: uid('m'), from: 'you', me: true, to: splitRecips(draft.to), time: Date.now(), tier: draft.tier, body: draft.body, html: true, text, attach: draft.attach.slice() };
  if (draft.threadId) {
    const t = thread(draft.threadId);
    if (t) { t.subject = draft.subject || '(no subject)'; t.tier = draft.tier; t.scheduledAt = draft.scheduleAt || null; t.msgs = [msg]; return; }
  }
  const t = { id: uid('t'), subject: draft.subject || '(no subject)', labels: [], folder: 'drafts', read: true, starred: false, snoozeUntil: null, tier: draft.tier, verified: false, legacy: false, scheduledAt: draft.scheduleAt || null, msgs: [msg] };
  state.mail.unshift(t);
  draft.threadId = t.id;
}
const splitRecips = (s) => (s || '').split(',').map(x => x.trim()).filter(Boolean);

// Send with an UNDO window (Gmail's undo-send — a client-side pre-dispatch delay, spec §17#17).
let _pending = null;
function doSendWithUndo(draft) {
  closeModal();
  clearTimeout(_pending?.timer);
  _pending = { draft };
  toast(`${icon('send')} Sending…`, {
    ms: UNDO_MS, action: 'Undo',
    onAction: () => { clearTimeout(_pending.timer); _pending = null; openCompose({ ...draft, html: true }); },
  });
  _pending.timer = setTimeout(() => { _pending = null; commitSend(draft); }, UNDO_MS);
}

// Dispatch, honestly, by how this session can actually send (net/send.js):
//   real → POST /v1/send genuinely seals + dispatches a MOTE on the node    (commitSendReal)
//   seam → live node but no send token: NEVER fake a send, keep it as a draft (commitSendSeam)
//   sim  → the labeled mesh-sim animation over a real, locally-signed MOTE   (commitSendSim)
async function commitSend(draft) {
  switch (sendMode()) {
    case 'real': return commitSendReal(draft);
    case 'seam': return commitSendSeam(draft);
    default: return commitSendSim(draft);
  }
}

// Build the client-side "sent" thread object for a just-sent message (shared by real + sim paths).
function sentThread(draft, sentMsg) {
  const to0 = splitRecips(draft.to)[0] || draft.to;
  const recip = person(to0);
  return { id: uid('t'), subject: draft.subject || '(no subject)', labels: [], folder: 'sent', read: true, starred: false, snoozeUntil: null, tier: draft.tier, verified: recip.trust === 'verified', legacy: recip.trust === 'legacy', msgs: [sentMsg] };
}
const composedText = (draft) => draft._text || stripHtml(draft.body);

// REAL send over the node's Send API. On success the message lands in Sent with the node's real
// content-id; on ANY failure it is surfaced verbatim and the message is kept in Drafts — never a
// fake "Delivered".
async function commitSendReal(draft) {
  const to0 = splitRecips(draft.to)[0] || draft.to;
  const text = composedText(draft);
  toast(`${icon('send')} Sending via your node…`, { ms: 2200 });
  let receipt;
  try {
    receipt = await sendMail({ to: to0, subject: draft.subject, body: text });
  } catch (err) {
    const reason = (err && err.message) ? err.message : 'send failed';
    upsertDraft(draft, text);
    bus.rerender(); bus.refreshChrome();
    toast(`${icon('shield')} Send failed: ${esc(reason)} — kept in Drafts.`, { ms: 6500 });
    return;
  }
  const sentMsg = { id: uid('m'), from: 'you', me: true, to: splitRecips(draft.to), time: Date.now(), tier: draft.tier, body: draft.body, html: true, text, attach: draft.attach.slice() };
  if (draft.replyThread) {
    const t = thread(draft.replyThread);
    if (t) { t.msgs.push(sentMsg); t.read = true; } else state.mail.unshift(sentThread(draft, sentMsg));
  } else {
    state.mail.unshift(sentThread(draft, sentMsg));
  }
  bus.rerender(); bus.refreshChrome();
  const idShort = receipt.id ? esc(receipt.id.slice(0, 16)) + '…' : '';
  const via = receipt.transport ? ` · ${esc(receipt.transport)}` : '';
  toast(`${icon('check')} Sent via your node${via}${idShort ? ' · ' + idShort : ''}`, { ms: 4600 });
}

// Live node, but no send token provisioned. Do NOT simulate a send in real mode: hold the message
// as a draft and tell the user exactly what's missing (the send-token seam).
function commitSendSeam(draft) {
  upsertDraft(draft, composedText(draft));
  bus.rerender(); bus.refreshChrome();
  toast(`${icon('shield')} Real send needs a send token — add one in Settings → Node. Saved to Drafts.`, { ms: 7000 });
}

// SIMULATION: build a real, locally-signed MOTE and animate its delivery through the inspector.
async function commitSendSim(draft) {
  const to0 = splitRecips(draft.to)[0] || draft.to;
  const group = state.groups.find(g => g.address === to0 || g.handle === to0);
  const mote = await buildMote({ to: to0, kind: group ? KIND.group : KIND.mail, subject: draft.subject, body: composedText(draft), tier: draft.tier, group: group || null });
  const plan = planDelivery(mote, to0);

  const sentMsg = { id: uid('m'), from: 'you', me: true, to: splitRecips(draft.to), time: Date.now(), tier: draft.tier, body: draft.body, html: true, text: draft._text, attach: draft.attach.slice() };
  if (draft.replyThread) {
    const t = thread(draft.replyThread);
    if (t) { t.msgs.push(sentMsg); t.read = true; }
  } else {
    state.mail.unshift(sentThread(draft, sentMsg));
  }
  bus.rerender(); bus.refreshChrome();
  showInspector(mote, plan);
  toast(plan.kind === 'mixnet' ? 'Routing through the mixnet…' : plan.kind === 'legacy' ? 'Bridging to legacy via gateway…' : plan.kind === 'group' ? 'Fanning out to group members…' : 'Delivering direct…');
  await animatePath(plan, (i) => litHop(i));
  toast(`${icon('check')} Delivered (simulated) · MOTE ${esc(mote.contentId.slice(0, 16))}…`);
}

function doSchedule(draft) {
  closeModal();
  upsertDraft(draft, draft._text);      // scheduled mail waits as a draft with scheduledAt set
  const when = new Date(draft.scheduleAt).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' });
  toast(`${icon('clock')} Scheduled to send ${when} · held encrypted on your node until then`);
  bus.rerender(); bus.refreshChrome();
}
