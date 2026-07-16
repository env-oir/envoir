// views/calendar.js — month / week / day calendar. Events are MOTEs on your node (kind=calendar,
// spec §8.4) — no central CalDAV server. Recurring events, peer-to-peer invitations + RSVP
// (iTIP-style, a message not a server query), reminders, and free/busy. An always-visible agenda
// panel mirrors Google's "Today / this week" rail; invitees are picked straight from Contacts.

import { state, uid } from '../store.js';
import { person, PEOPLE } from '../seed.js';
import { el, esc, icon, avatar, openModal, closeModal, toast, showInspector, fmtClock } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { bus } from '../bus.js';

const DAY = 86400e3;
const DAY_START = 6, DAY_END = 23; // visible hours in week/day grid
const RSVP = { yes: 'Going', no: 'No', maybe: 'Maybe', pending: 'Pending' };
const COLORS = [210, 262, 330, 150, 46, 8, 190]; // preset event color/label swatches (hues)
const REMINDER_OPTS = [[0, 'At start'], [10, '10 min before'], [30, '30 min before'], [60, '1 hour before'], [1440, '1 day before']];

// Persistent (module-level) UI state — same pattern as contacts.js's selId/tagFilter: it must
// survive the full-innerHTML re-render every view refresh does.
let agendaOpen = false;

export function render(root) {
  root.className = 'view cal-view';
  root.innerHTML = `
    <header class="cal-head">
      <div class="cal-nav">
        <button class="btn" id="today">Today</button>
        <button class="icon-btn" id="prev">${icon('reply')}</button>
        <button class="icon-btn" id="next">${icon('forward')}</button>
        <h1 id="cal-title" class="display">${esc(title())}</h1>
      </div>
      <div class="cal-right">
        <div class="seg" id="calseg" role="group" aria-label="Calendar range">
          ${['month', 'week', 'day'].map(v => `<button data-v="${v}" aria-pressed="${state.ui.calView === v}" class="${state.ui.calView === v ? 'on' : ''}">${v[0].toUpperCase() + v.slice(1)}</button>`).join('')}
        </div>
        <button class="icon-btn cal-agenda-toggle" id="agtoggle" aria-expanded="${agendaOpen}" aria-controls="cal-agenda" title="Agenda">${icon('calendar')}<span class="sr-only">Agenda</span></button>
        <button class="btn primary" id="newev">${icon('plus')} Event</button>
      </div>
    </header>
    <div class="cal-content">
      <div class="cal-main"><div class="cal-body" id="cal-body"></div></div>
      <aside class="cal-agenda" id="cal-agenda"><h3>Agenda</h3><div id="cal-agenda-list"></div></aside>
    </div>`;

  root.classList.toggle('agenda-open', agendaOpen);
  root.querySelector('#today').onclick = () => { state.ui.calCursor = Date.now(); bus.rerender(); };
  root.querySelector('#prev').onclick = () => { shift(-1); };
  root.querySelector('#next').onclick = () => { shift(1); };
  root.querySelector('#calseg').querySelectorAll('[data-v]').forEach(b => b.onclick = () => { state.ui.calView = b.dataset.v; bus.rerender(); });
  root.querySelector('#newev').onclick = () => eventModal(null);
  root.querySelector('#agtoggle').onclick = () => { agendaOpen = !agendaOpen; bus.rerender(); };

  const body = root.querySelector('#cal-body');
  if (state.ui.calView === 'month') drawMonth(body);
  else if (state.ui.calView === 'day') drawDay(body, new Date(state.ui.calCursor));
  else drawWeek(body);
  drawAgenda(root);
}

function title() {
  const c = new Date(state.ui.calCursor);
  if (state.ui.calView === 'day') return c.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
  if (state.ui.calView === 'month') return c.toLocaleDateString([], { month: 'long', year: 'numeric' });
  const s = startOfWeek(c); const e = new Date(s.getTime() + 6 * DAY);
  return `${s.toLocaleDateString([], { month: 'short', day: 'numeric' })} – ${e.toLocaleDateString([], { month: 'short', day: 'numeric' })}`;
}
function shift(dir) {
  const c = new Date(state.ui.calCursor);
  if (state.ui.calView === 'day') c.setDate(c.getDate() + dir);
  else if (state.ui.calView === 'month') c.setMonth(c.getMonth() + dir);
  else c.setDate(c.getDate() + 7 * dir);
  state.ui.calCursor = c.getTime(); bus.rerender();
}
function startOfWeek(d) { const x = new Date(d); x.setDate(x.getDate() - x.getDay()); x.setHours(0, 0, 0, 0); return x; }
function sameDay(a, b) { return new Date(a).toDateString() === new Date(b).toDateString(); }
function eventsOn(day) { return state.events.filter(e => sameDay(e.start, day)).sort((a, b) => a.start - b.start); }
function splitAllDay(evs) { return { allDay: evs.filter(e => e.allDay), timed: evs.filter(e => !e.allDay) }; }
function isMeeting(e) { return (e.attendees || []).some(a => !a.address.startsWith('you@')); }
function fmtReminder(m) { return m === 0 ? 'At start' : m >= 1440 ? Math.round(m / 1440) + ' day before' : m + ' min before'; }

function timePos(t) {
  const d = new Date(t); const h = d.getHours() + d.getMinutes() / 60;
  return ((h - DAY_START) / (DAY_END - DAY_START)) * 100;
}
function evBlockHtml(e) {
  const top = timePos(e.start), h = Math.max(4, timePos(e.end) - top);
  return `<button class="ev-block" style="top:${top}%;height:${h}%;--h:${e.color}">
    <b>${isMeeting(e) ? icon('groups') + ' ' : ''}${esc(e.title)}</b><span>${fmtClock(e.start)}–${fmtClock(e.end)}</span></button>`;
}
function alldayChipHtml(e) {
  return `<button class="allday-chip" data-id="${e.id}" style="--h:${e.color}">${isMeeting(e) ? icon('groups') : ''}${esc(e.title)}</button>`;
}

// ---- Agenda panel — "Today" + "this week", always visible on desktop (Google-style rail) -----
function agendaItemHtml(e) {
  return `<button class="ag-item" data-id="${e.id}"><i style="--h:${e.color}"></i>
    <div><b>${esc(e.title)}</b><span>${e.allDay ? 'All day' : fmtClock(e.start) + '–' + fmtClock(e.end)}${e.recurrence ? ' · ' + icon('repeat') : ''}</span></div>
    ${isMeeting(e) ? `<i class="ag-meet" title="Meeting">${icon('groups')}</i>` : ''}</button>`;
}
function drawAgenda(root) {
  const list = root.querySelector('#cal-agenda-list');
  const now = new Date();
  const todays = eventsOn(now);
  let weekHtml = '';
  for (let i = 1; i <= 6; i++) {
    const day = new Date(now.getTime() + i * DAY);
    const evs = eventsOn(day);
    if (!evs.length) continue;
    weekHtml += `<div class="ag-day-h">${day.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })}</div>${evs.map(agendaItemHtml).join('')}`;
  }
  list.innerHTML = `
    <div class="ag-section-h">Today</div>
    ${todays.length ? todays.map(agendaItemHtml).join('') : '<div class="ag-empty">Nothing scheduled today.</div>'}
    <div class="ag-section-h ag-week">This week</div>
    ${weekHtml || '<div class="ag-empty">Nothing else this week.</div>'}`;
  list.querySelectorAll('.ag-item').forEach(b => b.onclick = () => eventModal(state.events.find(e => e.id === b.dataset.id)));
}

// ---- Week view (default) ------------------------------------------------------------------
function drawWeek(body) {
  const s = startOfWeek(new Date(state.ui.calCursor));
  const days = Array.from({ length: 7 }, (_, i) => new Date(s.getTime() + i * DAY));
  const hours = Array.from({ length: DAY_END - DAY_START + 1 }, (_, i) => DAY_START + i);
  const split = days.map(d => splitAllDay(eventsOn(d)));
  const anyAllDay = split.some(x => x.allDay.length);
  body.className = 'cal-body week';
  body.innerHTML = `
    <div class="wk-head">
      <div class="wk-gutter"></div>
      ${days.map(d => `<div class="wk-day ${sameDay(d, Date.now()) ? 'today' : ''}"><span class="wk-dow">${d.toLocaleDateString([], { weekday: 'short' })}</span><span class="wk-dom">${d.getDate()}</span></div>`).join('')}
    </div>
    ${anyAllDay ? `<div class="wk-allday">
      <div class="wk-gutter"></div>
      ${days.map((d, di) => `<div class="wk-allday-col">${split[di].allDay.map(alldayChipHtml).join('')}</div>`).join('')}
    </div>` : ''}
    <div class="wk-grid" id="wkgrid">
      <div class="wk-hours">${hours.map(h => `<div class="wk-hr"><span>${fmtHour(h)}</span></div>`).join('')}</div>
      ${days.map((d, di) => `<div class="wk-col" data-di="${di}">${hours.map(() => '<div class="wk-cell"></div>').join('')}<div class="wk-events" data-di="${di}"></div></div>`).join('')}
    </div>`;
  days.forEach((d, di) => {
    const layer = body.querySelector(`.wk-events[data-di="${di}"]`);
    split[di].timed.forEach(e => { const block = el(evBlockHtml(e)); block.onclick = () => eventModal(e); layer.appendChild(block); });
  });
  body.querySelectorAll('.allday-chip').forEach(b => b.onclick = () => eventModal(state.events.find(e => e.id === b.dataset.id)));
}
function fmtHour(h) { const ap = h < 12 ? 'am' : 'pm'; const hh = h % 12 || 12; return hh + ap; }

// ---- Day view -----------------------------------------------------------------------------
function drawDay(body, day) {
  const hours = Array.from({ length: DAY_END - DAY_START + 1 }, (_, i) => DAY_START + i);
  const { allDay, timed } = splitAllDay(eventsOn(day));
  body.className = 'cal-body day';
  body.innerHTML = `
    ${allDay.length ? `<div class="day-allday"><div class="wk-gutter"></div><div class="day-allday-col">${allDay.map(alldayChipHtml).join('')}</div></div>` : ''}
    <div class="day-grid">
      <div class="wk-hours">${hours.map(h => `<div class="wk-hr"><span>${fmtHour(h)}</span></div>`).join('')}</div>
      <div class="wk-col wide">${hours.map(() => '<div class="wk-cell"></div>').join('')}<div class="wk-events" id="daylayer"></div></div>
    </div>`;
  const layer = body.querySelector('#daylayer');
  timed.forEach(e => { const block = el(evBlockHtml(e)); block.onclick = () => eventModal(e); layer.appendChild(block); });
  body.querySelectorAll('.allday-chip').forEach(b => b.onclick = () => eventModal(state.events.find(e => e.id === b.dataset.id)));
}

// ---- Month view ---------------------------------------------------------------------------
function drawMonth(body) {
  const c = new Date(state.ui.calCursor); c.setDate(1);
  const first = startOfWeek(c);
  const cells = Array.from({ length: 42 }, (_, i) => new Date(first.getTime() + i * DAY));
  body.className = 'cal-body month';
  body.innerHTML = `
    <div class="mo-dow">${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(d => `<span>${d}</span>`).join('')}</div>
    <div class="mo-grid">${cells.map(d => {
      const evs = eventsOn(d);
      const other = d.getMonth() !== new Date(state.ui.calCursor).getMonth();
      return `<div class="mo-cell ${other ? 'other' : ''} ${sameDay(d, Date.now()) ? 'today' : ''}" data-day="${d.getTime()}">
        <span class="mo-num">${d.getDate()}</span>
        ${evs.slice(0, 3).map(e => `<button class="mo-ev" data-id="${e.id}" style="--h:${e.color}"><i></i>${isMeeting(e) ? icon('groups') : ''}${esc(e.title)}</button>`).join('')}
        ${evs.length > 3 ? `<span class="mo-more">+${evs.length - 3}</span>` : ''}
      </div>`;
    }).join('')}</div>`;
  body.querySelectorAll('.mo-ev').forEach(b => b.onclick = (e) => { e.stopPropagation(); eventModal(state.events.find(x => x.id === b.dataset.id)); });
  body.querySelectorAll('.mo-cell').forEach(c => c.onclick = () => { state.ui.calCursor = Number(c.dataset.day); eventModal(null, new Date(Number(c.dataset.day))); });
}

// ---- Event detail + RSVP ------------------------------------------------------------------
function eventModal(e, presetDay) {
  if (!e) return newEventModal(presetDay);
  const me = e.attendees.find(a => a.address.startsWith('you@'));
  const meeting = isMeeting(e);
  const isUrl = e.location && /^https?:\/\//i.test(e.location);
  const card = openModal(`
    <div class="ev-detail">
      <div class="ev-detail-bar" style="--h:${e.color}"></div>
      <div class="ev-detail-body">
        <div class="ev-detail-head"><h2>${esc(e.title)}${meeting ? ` <span class="pill accent sm">${icon('groups')} Meeting</span>` : ''}</h2><button class="icon-btn" id="evx">${icon('x')}</button></div>
        <div class="ev-meta">${icon('clock')} ${esc(new Date(e.start).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }))} · ${e.allDay ? 'All day' : fmtClock(e.start) + '–' + fmtClock(e.end)}</div>
        ${e.recurrence ? `<div class="ev-meta">${icon('repeat')} ${esc(e.recurrence)}</div>` : ''}
        ${e.location ? `<div class="ev-meta">${icon(isUrl ? 'link' : 'label')} ${isUrl ? `<a href="${esc(e.location)}" target="_blank" rel="noopener noreferrer">${esc(e.location)}</a>` : esc(e.location)}</div>` : ''}
        ${e.reminders?.length ? `<div class="ev-meta">${icon('bell')} ${e.reminders.map(fmtReminder).join(', ')}</div>` : ''}
        ${e.description ? `<p class="ev-desc">${esc(e.description)}</p>` : ''}
        <div class="ev-att-h">${meeting ? 'Attendees' : 'Guests'} · organized by ${esc(person(e.organizer).name)}</div>
        <div class="ev-atts">${e.attendees.map(a => `<div class="ev-att">${avatar(person(a.address), 26)}<span>${esc(person(a.address).name)}</span><i class="rsvp ${a.rsvp}">${RSVP[a.rsvp]}</i></div>`).join('') || '<span class="ev-att-none">No guests</span>'}</div>
        ${me ? `<div class="rsvp-row"><span>Your RSVP</span><div class="seg rsvp-seg">
          ${['yes', 'maybe', 'no'].map(r => `<button data-r="${r}" class="${me.rsvp === r ? 'on' : ''}">${RSVP[r]}</button>`).join('')}
        </div></div>` : ''}
        <div class="ev-detail-foot">
          <span class="sim-tag">${icon('shield')} encrypted MOTE · kind=calendar · your node</span>
          <div class="spacer"></div>
          ${e.organizer.startsWith('you@') ? `<button class="btn" id="evedit">${icon('edit')} Edit</button>` : ''}
          <button class="btn danger" id="evdel">Delete</button>
        </div>
      </div>
    </div>`, { wide: true });
  card.querySelector('#evx').onclick = closeModal;
  // Replace the detail modal with the editor in place. Do NOT closeModal() first — its deferred
  // innerHTML clear (180ms) would wipe the editor we open synchronously right after.
  card.querySelector('#evedit')?.addEventListener('click', () => newEventModal(null, e));
  card.querySelector('#evdel').onclick = () => { state.events = state.events.filter(x => x.id !== e.id); closeModal(); bus.rerender(); toast('Event deleted'); };
  if (me) card.querySelectorAll('[data-r]').forEach(b => b.onclick = async () => {
    me.rsvp = b.dataset.r;
    const mote = await buildMote({ to: e.organizer, kind: KIND.calendar, subject: 'RSVP: ' + e.title, body: JSON.stringify({ rsvp: me.rsvp }), tier: state.settings.tierDefault });
    card.querySelectorAll('[data-r]').forEach(x => x.classList.toggle('on', x.dataset.r === me.rsvp));
    toast(`${icon('check')} RSVP '${RSVP[me.rsvp]}' sent to ${person(e.organizer).name} — peer-to-peer, no server`);
    bus.rerender();
  });
}

// New/edit event modal. `presetGuestAddrs` lets another view (e.g. Contacts → "invite to a
// meeting") open this pre-filled with one invitee already picked.
export function newEventModal(presetDay, existing, presetGuestAddrs) {
  const base = existing ? new Date(existing.start) : (presetDay || new Date(state.ui.calCursor));
  const dstr = `${base.getFullYear()}-${String(base.getMonth() + 1).padStart(2, '0')}-${String(base.getDate()).padStart(2, '0')}`;
  const hm = (t) => { const d = new Date(t); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
  const startV = existing ? hm(existing.start) : '09:00';
  const endV = existing ? hm(existing.end) : '10:00';
  const repOpt = (v) => `<option ${existing && existing.recurrence === v ? 'selected' : ''}${v === '' ? ' value=""' : ''}>${v || 'Does not repeat'}</option>`;
  const initialGuests = existing
    ? existing.attendees.filter(a => !a.address.startsWith('you@')).map(a => a.address)
    : (presetGuestAddrs || []);
  const initialReminders = new Set(existing ? (existing.reminders || []) : [10]);
  const initialColor = existing ? existing.color : 210;
  const isAllDay = !!(existing && existing.allDay);

  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>${existing ? 'Edit event' : 'New event'}</h2><button class="icon-btn" id="evx">${icon('x')}</button></div>
      <label class="cfield"><span>Title</span><input id="nt" placeholder="Coffee with Ada" value="${esc(existing ? existing.title : '')}" autofocus></label>

      <div class="set-row between ev-allday-row">
        <div><b>All day</b><small>No specific time — spans the whole day</small></div>
        <label class="switch sm"><input type="checkbox" id="nallday" ${isAllDay ? 'checked' : ''}><i></i></label>
      </div>

      <div class="ev-new-row" id="ev-time-row">
        <label class="cfield"><span>Date</span><input id="nd" type="date" value="${dstr}"></label>
        <label class="cfield" id="ev-start-field"><span>Start</span><input id="ns" type="time" value="${startV}"></label>
        <label class="cfield" id="ev-end-field"><span>End</span><input id="ne" type="time" value="${endV}"></label>
      </div>

      <div class="ev-new-row" style="grid-template-columns:1fr 1fr">
        <label class="cfield"><span>Repeat</span><select id="nr">${['', 'Weekly', 'Weekdays', 'Monthly'].map(repOpt).join('')}</select></label>
        <label class="cfield"><span>Color / label</span><div class="color-swatches" id="colorsw">
          ${COLORS.map(h => `<button type="button" class="color-swatch ${initialColor === h ? 'on' : ''}" data-h="${h}" style="--h:${h}" aria-pressed="${initialColor === h}" aria-label="Color ${h}"></button>`).join('')}
        </div></label>
      </div>

      <label class="cfield"><span>Reminders</span><div class="toggle-chips" id="remchips">
        ${REMINDER_OPTS.map(([v, l]) => `<button type="button" class="toggle-chip ${initialReminders.has(v) ? 'on' : ''}" data-v="${v}" aria-pressed="${initialReminders.has(v)}">${esc(l)}</button>`).join('')}
      </div></label>

      <label class="cfield"><span>Invitees — picked from Contacts (a guest turns this into a meeting)</span>
        <div class="invitee-picker">
          <div class="invitee-chips" id="invchips"></div>
          <input id="invq" placeholder="Search contacts by name or address…" autocomplete="off" spellcheck="false">
          <div class="invitee-results" id="invresults" hidden></div>
        </div>
      </label>
      <p class="modal-note">${icon('info')} Invitations ride as signed MOTEs (kind=calendar, peer-to-peer iTIP-style) straight to each guest's key — this is the honest client surface for that; no central scheduler ever sees the guest list.</p>

      <label class="cfield"><span>Location or video-call link</span><input id="nl" value="${esc(existing ? (existing.location || '') : '')}" placeholder="Office, or https://meet.envoir.org/…"></label>
      <label class="cfield"><span>Description</span><textarea id="ndesc" rows="3" placeholder="Agenda, notes, dial-in details…">${esc(existing ? (existing.description || '') : '')}</textarea></label>

      <div class="ev-detail-foot">
        <span class="sim-tag">${icon('shield')} sealed to guests · no central scheduler</span>
        <div class="spacer"></div>
        ${existing ? `<button class="btn danger" id="evdel2">Delete</button>` : ''}
        <button class="btn primary" id="evsave">${existing ? 'Save changes' : 'Create'}</button>
      </div>
    </div>`, { wide: true });

  // -- all-day toggle: time inputs are meaningless (and hidden) while it's on -----------------
  const alldayEl = card.querySelector('#nallday');
  const startField = card.querySelector('#ev-start-field'), endField = card.querySelector('#ev-end-field');
  const syncAllDay = () => { const on = alldayEl.checked; startField.style.display = on ? 'none' : ''; endField.style.display = on ? 'none' : ''; };
  alldayEl.onchange = syncAllDay; syncAllDay();

  // -- color / label swatches -----------------------------------------------------------------
  let selectedColor = initialColor;
  card.querySelectorAll('#colorsw .color-swatch').forEach(b => b.onclick = () => {
    selectedColor = Number(b.dataset.h);
    card.querySelectorAll('#colorsw .color-swatch').forEach(x => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-pressed', on); });
  });

  // -- reminders (multi-select toggle chips) ---------------------------------------------------
  const selectedReminders = new Set(initialReminders);
  card.querySelectorAll('#remchips .toggle-chip').forEach(b => b.onclick = () => {
    const v = Number(b.dataset.v);
    if (selectedReminders.has(v)) selectedReminders.delete(v); else selectedReminders.add(v);
    b.classList.toggle('on', selectedReminders.has(v)); b.setAttribute('aria-pressed', selectedReminders.has(v));
  });

  // -- invitee picker: search Contacts, add as avatar chips, or invite a raw address ----------
  let guestAddrs = [...initialGuests];
  const chipsEl = card.querySelector('#invchips'), resultsEl = card.querySelector('#invresults'), invq = card.querySelector('#invq');
  const drawChips = () => {
    chipsEl.innerHTML = guestAddrs.map(addr => {
      const p = person(addr);
      return `<span class="invitee-chip">${avatar(p, 22)}<span>${esc(p.name)}</span><button type="button" class="ic-x" data-addr="${esc(addr)}" aria-label="Remove ${esc(p.name)}">${icon('x')}</button></span>`;
    }).join('');
    chipsEl.querySelectorAll('.ic-x').forEach(b => b.onclick = () => { guestAddrs = guestAddrs.filter(a => a !== b.dataset.addr); drawChips(); });
  };
  const addGuest = (addr) => {
    addr = (addr || '').trim();
    if (!addr || guestAddrs.includes(addr) || addr.startsWith('you@')) return;
    guestAddrs.push(addr); drawChips(); invq.value = ''; resultsEl.hidden = true;
  };
  const searchResults = () => {
    const q = invq.value.trim().toLowerCase();
    if (!q) { resultsEl.hidden = true; resultsEl.innerHTML = ''; return; }
    const matches = PEOPLE.filter(p => !guestAddrs.includes(p.address) && !p.address.startsWith('you@') &&
      (p.name.toLowerCase().includes(q) || p.address.toLowerCase().includes(q))).slice(0, 6);
    resultsEl.innerHTML = matches.length
      ? matches.map(p => `<button type="button" class="invitee-result" data-addr="${esc(p.address)}">${avatar(p, 24)}<span class="ir-main"><b>${esc(p.name)}</b><small>${esc(p.address)}</small></span>${p.trust === 'verified' ? icon('verified') : ''}</button>`).join('')
      : `<button type="button" class="invitee-result invitee-raw" data-addr="${esc(invq.value.trim())}">${icon('at')} Invite "${esc(invq.value.trim())}" directly</button>`;
    resultsEl.hidden = false;
    resultsEl.querySelectorAll('[data-addr]').forEach(b => b.onclick = () => addGuest(b.dataset.addr));
  };
  invq.addEventListener('input', searchResults);
  invq.addEventListener('focus', () => { if (invq.value.trim()) searchResults(); });
  invq.addEventListener('blur', () => setTimeout(() => { resultsEl.hidden = true; }, 150));
  invq.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); const first = resultsEl.querySelector('[data-addr]'); if (first) addGuest(first.dataset.addr); else if (invq.value.trim()) addGuest(invq.value.trim()); }
    else if (e.key === 'Escape') { resultsEl.hidden = true; }
  });
  drawChips();

  card.querySelector('#evx').onclick = closeModal;
  card.querySelector('#evsave').onclick = async () => {
    const title = card.querySelector('#nt').value.trim(); if (!title) return toast('Add a title');
    const [y, mo, da] = card.querySelector('#nd').value.split('-').map(Number);
    const allDay = alldayEl.checked;
    let start, end;
    if (allDay) { start = new Date(y, mo - 1, da, 0, 0).getTime(); end = new Date(y, mo - 1, da, 23, 59).getTime(); }
    else {
      const [sh, sm] = card.querySelector('#ns').value.split(':').map(Number);
      const [eh, em] = card.querySelector('#ne').value.split(':').map(Number);
      start = new Date(y, mo - 1, da, sh, sm).getTime();
      end = new Date(y, mo - 1, da, eh, em).getTime();
    }
    const guests = guestAddrs.slice();
    const reminders = [...selectedReminders].sort((a, b) => a - b);
    const location = card.querySelector('#nl').value.trim() || null;
    const description = card.querySelector('#ndesc').value.trim() || null;
    const recurrence = card.querySelector('#nr').value || null;
    const color = selectedColor;
    if (existing) {
      const oldGuests = new Set(existing.attendees.filter(a => !a.address.startsWith('you@')).map(a => a.address));
      existing.title = title; existing.start = start; existing.end = end; existing.location = location;
      existing.recurrence = recurrence; existing.reminders = reminders; existing.color = color;
      existing.allDay = allDay; existing.description = description;
      // preserve RSVPs for guests still invited; add pending for new ones
      existing.attendees = existing.attendees.filter(a => a.address.startsWith('you@') || guests.includes(a.address));
      guests.filter(g => !oldGuests.has(g)).forEach(g => existing.attendees.push({ address: g, rsvp: 'pending' }));
      closeModal(); bus.rerender();
      toast(`${icon('check')} Event updated — changes re-sealed to guests`);
      return;
    }
    const ev = { id: uid('e'), title, color, start, end, recurrence, location, reminders, allDay, description,
      organizer: 'you@envoir.org',
      attendees: [{ address: 'you@envoir.org', rsvp: 'yes' }, ...guests.map(g => ({ address: g, rsvp: 'pending' }))] };
    state.events.push(ev);
    const mote = await buildMote({ to: guests[0] || 'you@envoir.org', kind: KIND.calendar, subject: title, body: JSON.stringify({ start, end }), tier: state.settings.tierDefault });
    closeModal(); bus.rerender();
    if (guests.length) showInspector(mote, { path: ['your node', 'mixnet', 'guests'], latencyMs: 0, kind: 'mixnet' });
    toast(`${icon('check')} Event created${guests.length ? ' · meeting invitations sealed to ' + guests.length + ' guest(s)' : ''}`);
  };
  if (existing) card.querySelector('#evdel2').onclick = () => { state.events = state.events.filter(x => x.id !== existing.id); closeModal(); bus.rerender(); toast('Event deleted'); };
}
