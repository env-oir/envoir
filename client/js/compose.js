// compose.js — the rich compose modal: recipients, subject, body, signature, privacy tier,
// scheduled send, and SEND with an UNDO window (Gmail-parity). Building a message constructs a
// REAL MOTE (real signature) and animates its simulated delivery through the inspector.

import { openModal, closeModal, toast, icon, esc, showInspector, litHop } from './ui.js';
import { buildMote, KIND } from './mote.js';
import { planDelivery, animatePath } from './mesh-sim.js';
import { currentIdentity, displayAddress } from './identity.js';
import { state, thread, uid, lastTime } from './store.js';
import { person } from './seed.js';
import { bus } from './bus.js';

const UNDO_MS = 5000;

export function openCompose(opts = {}) {
  const id = currentIdentity();
  const sig = state.settings.signatures.find(s => s.default);
  const draft = {
    to: opts.to || '', subject: opts.subject || '', body: opts.body || (sig ? '\n\n' + sig.body : ''),
    tier: state.settings.tierDefault, replyThread: opts.replyThread || null, scheduleAt: null,
  };
  const contacts = state.people.map(p => `<option value="${esc(p.address)}">${esc(p.name)}</option>`).join('');

  const card = openModal(`
    <div class="compose">
      <div class="compose-top">
        <b>${opts.replyThread ? 'Reply' : 'New message'}</b>
        <div class="spacer"></div>
        <button class="icon-btn" id="cx" aria-label="Close">${icon('x')}</button>
      </div>
      <label class="cfield"><span>From</span><div class="from-chip">${esc(displayAddress(id))}</div></label>
      <label class="cfield"><span>To</span><input id="cto" list="cpeople" value="${esc(draft.to)}" placeholder="name@domain, @handle, or a group address" autocomplete="off"></label>
      <datalist id="cpeople">${contacts}</datalist>
      <label class="cfield"><span>Subject</span><input id="csubj" value="${esc(draft.subject)}" placeholder="Subject"></label>
      <textarea id="cbody" placeholder="Write your message — it is sealed to the recipient's key and routed privately.">${esc(draft.body)}</textarea>
      <div class="compose-foot">
        <button class="btn primary" id="csend">${icon('send')} Send</button>
        <div class="tier-seg" id="ctier">
          <button data-t="private" class="${draft.tier === 'private' ? 'on' : ''}">${icon('shield')} Private</button>
          <button data-t="fast" class="${draft.tier === 'fast' ? 'on' : ''}">Fast</button>
        </div>
        <div class="spacer"></div>
        <button class="icon-btn" id="cschedule" title="Schedule send">${icon('clock')}</button>
        <button class="icon-btn" id="csig" title="Signature">${icon('edit')}</button>
        <span class="sim-tag">sealed · signed with your real key</span>
      </div>
      <div id="csched-row" class="sched-row hidden"></div>
    </div>`, { compose: true, sticky: true });

  const $ = (s) => card.querySelector(s);
  $('#cx').onclick = () => { saveDraft(draft, card); closeModal(); };
  $('#ctier').querySelectorAll('[data-t]').forEach(b => b.onclick = () => {
    draft.tier = b.dataset.t; $('#ctier').querySelectorAll('button').forEach(x => x.classList.toggle('on', x.dataset.t === draft.tier));
  });
  $('#csig').onclick = () => {
    const s = state.settings.signatures.find(x => x.default);
    if (s) { $('#cbody').value = ($('#cbody').value.trimEnd()) + '\n\n' + s.body; }
  };
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
    draft.to = $('#cto').value.trim(); draft.subject = $('#csubj').value.trim(); draft.body = $('#cbody').value;
    if (!draft.to) return toast('Add a recipient');
    if (draft.scheduleAt) return doSchedule(draft);
    doSendWithUndo(draft);
  };
  setTimeout(() => $('#cto').focus(), 50);
}

function tomorrow9() { const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(9, 0, 0, 0); return d.getTime() - Date.now(); }
function monday9() { const d = new Date(); const add = ((8 - d.getDay()) % 7) || 7; d.setDate(d.getDate() + add); d.setHours(9, 0, 0, 0); return d.getTime() - Date.now(); }

function saveDraft(draft, card) {
  if (!draft.to && !draft.subject && !draft.body.trim()) return;
  const t = { id: uid('t'), subject: draft.subject || '(no subject)', labels: [], folder: 'drafts', read: true, starred: false, snoozeUntil: null, tier: draft.tier, verified: false, legacy: false,
    msgs: [{ id: uid('m'), from: 'you', me: true, to: [draft.to], time: Date.now(), tier: draft.tier, body: draft.body.trim() }] };
  state.mail.unshift(t);
  toast('Draft saved');
  bus.refreshChrome();
}

// Send with an UNDO window: the message sits in a pending state for 5s before it actually
// "sends" (Gmail's undo-send). Clicking Undo re-opens the composer.
let _pending = null;
function doSendWithUndo(draft) {
  closeModal();
  clearTimeout(_pending?.timer);
  _pending = { draft };
  const t = toast(`${icon('send')} Sending…`, {
    ms: UNDO_MS, action: 'Undo',
    onAction: () => { clearTimeout(_pending.timer); _pending = null; openCompose(draft); },
  });
  _pending.timer = setTimeout(() => { _pending = null; commitSend(draft); }, UNDO_MS);
}

async function commitSend(draft) {
  const group = state.groups.find(g => g.address === draft.to || g.handle === draft.to);
  const recip = person(draft.to);
  const mote = await buildMote({ to: draft.to, kind: group ? KIND.group : KIND.mail, subject: draft.subject, body: draft.body, tier: draft.tier, group: group || null });
  const plan = planDelivery(mote, draft.to);

  // Reflect in the mailbox: append to the replied thread, else a new Sent thread.
  const sentMsg = { id: uid('m'), from: 'you', me: true, to: [draft.to], time: Date.now(), tier: draft.tier, body: draft.body.trim() };
  if (draft.replyThread) {
    const t = thread(draft.replyThread);
    if (t) { t.msgs.push(sentMsg); t.read = true; }
  } else {
    state.mail.unshift({ id: uid('t'), subject: draft.subject || '(no subject)', labels: [], folder: 'sent', read: true, starred: false, snoozeUntil: null, tier: draft.tier, verified: recip.trust === 'verified', legacy: recip.trust === 'legacy', msgs: [sentMsg] });
  }
  bus.rerender(); bus.refreshChrome();
  showInspector(mote, plan);
  toast(plan.kind === 'mixnet' ? 'Routing through the mixnet…' : plan.kind === 'legacy' ? 'Bridging to legacy via gateway…' : plan.kind === 'group' ? 'Fanning out to group members…' : 'Delivering direct…');
  await animatePath(plan, (i) => litHop(i));
  toast(`${icon('check')} Delivered · MOTE ${esc(mote.contentId.slice(0, 16))}…`);
}

function doSchedule(draft) {
  closeModal();
  const t = { id: uid('t'), subject: draft.subject || '(no subject)', labels: [], folder: 'drafts', read: true, starred: false, snoozeUntil: null, tier: draft.tier, verified: false, legacy: false, scheduledAt: draft.scheduleAt,
    msgs: [{ id: uid('m'), from: 'you', me: true, to: [draft.to], time: Date.now(), tier: draft.tier, body: draft.body.trim() }] };
  state.mail.unshift(t);
  const when = new Date(draft.scheduleAt).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' });
  toast(`${icon('clock')} Scheduled to send ${when}`);
  bus.rerender(); bus.refreshChrome();
}
