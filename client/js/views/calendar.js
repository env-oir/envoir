// views/calendar.js — month / week / day calendar. Events are MOTEs on your node (kind=calendar,
// spec §8.4) — no central CalDAV server. Recurring events, peer-to-peer invitations + RSVP
// (iTIP-style, a message not a server query), reminders, and free/busy.

import { state, uid } from '../store.js';
import { person } from '../seed.js';
import { el, esc, icon, avatar, openModal, closeModal, toast, showInspector, fmtClock } from '../ui.js';
import { buildMote, KIND } from '../mote.js';
import { bus } from '../bus.js';

const DAY = 86400e3;
const DAY_START = 6, DAY_END = 23; // visible hours in week/day grid
const RSVP = { yes: 'Going', no: 'No', maybe: 'Maybe', pending: 'Pending' };

export function render(root) {
  root.className = 'view cal-view';
  const cur = new Date(state.ui.calCursor);
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
        <button class="btn primary" id="newev">${icon('plus')} Event</button>
      </div>
    </header>
    <div class="cal-body" id="cal-body"></div>`;

  root.querySelector('#today').onclick = () => { state.ui.calCursor = Date.now(); bus.rerender(); };
  root.querySelector('#prev').onclick = () => { shift(-1); };
  root.querySelector('#next').onclick = () => { shift(1); };
  root.querySelector('#calseg').querySelectorAll('[data-v]').forEach(b => b.onclick = () => { state.ui.calView = b.dataset.v; bus.rerender(); });
  root.querySelector('#newev').onclick = () => eventModal(null);

  const body = root.querySelector('#cal-body');
  if (state.ui.calView === 'month') drawMonth(body);
  else if (state.ui.calView === 'day') drawDay(body, new Date(state.ui.calCursor));
  else drawWeek(body);
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

function timePos(t) {
  const d = new Date(t); const h = d.getHours() + d.getMinutes() / 60;
  return ((h - DAY_START) / (DAY_END - DAY_START)) * 100;
}

// ---- Week view (default) ------------------------------------------------------------------
function drawWeek(body) {
  const s = startOfWeek(new Date(state.ui.calCursor));
  const days = Array.from({ length: 7 }, (_, i) => new Date(s.getTime() + i * DAY));
  const hours = Array.from({ length: DAY_END - DAY_START + 1 }, (_, i) => DAY_START + i);
  body.className = 'cal-body week';
  body.innerHTML = `
    <div class="wk-head">
      <div class="wk-gutter"></div>
      ${days.map(d => `<div class="wk-day ${sameDay(d, Date.now()) ? 'today' : ''}"><span class="wk-dow">${d.toLocaleDateString([], { weekday: 'short' })}</span><span class="wk-dom">${d.getDate()}</span></div>`).join('')}
    </div>
    <div class="wk-grid" id="wkgrid">
      <div class="wk-hours">${hours.map(h => `<div class="wk-hr"><span>${fmtHour(h)}</span></div>`).join('')}</div>
      ${days.map((d, di) => `<div class="wk-col" data-di="${di}">${hours.map(() => '<div class="wk-cell"></div>').join('')}<div class="wk-events" data-di="${di}"></div></div>`).join('')}
    </div>`;
  days.forEach((d, di) => {
    const layer = body.querySelector(`.wk-events[data-di="${di}"]`);
    eventsOn(d).forEach(e => {
      const top = timePos(e.start), h = Math.max(4, timePos(e.end) - top);
      const block = el(`<button class="ev-block" style="top:${top}%;height:${h}%;--h:${e.color}">
        <b>${esc(e.title)}</b><span>${fmtClock(e.start)}</span></button>`);
      block.onclick = () => eventModal(e);
      layer.appendChild(block);
    });
  });
}
function fmtHour(h) { const ap = h < 12 ? 'am' : 'pm'; const hh = h % 12 || 12; return hh + ap; }

// ---- Day view -----------------------------------------------------------------------------
function drawDay(body, day) {
  const hours = Array.from({ length: DAY_END - DAY_START + 1 }, (_, i) => DAY_START + i);
  const evs = eventsOn(day);
  body.className = 'cal-body day';
  body.innerHTML = `
    <div class="day-grid">
      <div class="wk-hours">${hours.map(h => `<div class="wk-hr"><span>${fmtHour(h)}</span></div>`).join('')}</div>
      <div class="wk-col wide">${hours.map(() => '<div class="wk-cell"></div>').join('')}<div class="wk-events" id="daylayer"></div></div>
    </div>
    <aside class="day-agenda">
      <h3>Agenda</h3>
      ${evs.length ? evs.map(e => `<button class="ag-item" data-id="${e.id}"><i style="--h:${e.color}"></i><div><b>${esc(e.title)}</b><span>${fmtClock(e.start)}–${fmtClock(e.end)}${e.recurrence ? ' · ' + icon('repeat') : ''}</span></div></button>`).join('') : '<div class="ag-empty">Nothing scheduled.</div>'}
    </aside>`;
  const layer = body.querySelector('#daylayer');
  evs.forEach(e => {
    const top = timePos(e.start), h = Math.max(4, timePos(e.end) - top);
    const block = el(`<button class="ev-block" style="top:${top}%;height:${h}%;--h:${e.color}"><b>${esc(e.title)}</b><span>${fmtClock(e.start)}–${fmtClock(e.end)}</span></button>`);
    block.onclick = () => eventModal(e); layer.appendChild(block);
  });
  body.querySelectorAll('.ag-item').forEach(b => b.onclick = () => eventModal(state.events.find(e => e.id === b.dataset.id)));
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
        ${evs.slice(0, 3).map(e => `<button class="mo-ev" data-id="${e.id}" style="--h:${e.color}"><i></i>${esc(e.title)}</button>`).join('')}
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
  const card = openModal(`
    <div class="ev-detail">
      <div class="ev-detail-bar" style="--h:${e.color}"></div>
      <div class="ev-detail-body">
        <div class="ev-detail-head"><h2>${esc(e.title)}</h2><button class="icon-btn" id="evx">${icon('x')}</button></div>
        <div class="ev-meta">${icon('clock')} ${esc(new Date(e.start).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' }))} · ${fmtClock(e.start)}–${fmtClock(e.end)}</div>
        ${e.recurrence ? `<div class="ev-meta">${icon('repeat')} ${esc(e.recurrence)}</div>` : ''}
        ${e.location ? `<div class="ev-meta">${icon('label')} ${esc(e.location)}</div>` : ''}
        ${e.reminders?.length ? `<div class="ev-meta">${icon('bell')} ${e.reminders.map(m => m + ' min before').join(', ')}</div>` : ''}
        ${e.description ? `<p class="ev-desc">${esc(e.description)}</p>` : ''}
        <div class="ev-att-h">Guests · organized by ${esc(person(e.organizer).name)}</div>
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

function newEventModal(presetDay, existing) {
  const base = existing ? new Date(existing.start) : (presetDay || new Date(state.ui.calCursor));
  const dstr = `${base.getFullYear()}-${String(base.getMonth() + 1).padStart(2, '0')}-${String(base.getDate()).padStart(2, '0')}`;
  const hm = (t) => { const d = new Date(t); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
  const startV = existing ? hm(existing.start) : '09:00';
  const endV = existing ? hm(existing.end) : '10:00';
  const repOpt = (v) => `<option ${existing && existing.recurrence === v ? 'selected' : ''}${v === '' ? ' value=""' : ''}>${v || 'Does not repeat'}</option>`;
  const remV = existing ? String(existing.reminders?.[0] ?? '') : '10';
  const guestsExisting = existing ? existing.attendees.filter(a => !a.address.startsWith('you@')).map(a => a.address).join(', ') : '';
  const card = openModal(`
    <div class="ev-new">
      <div class="ev-detail-head"><h2>${existing ? 'Edit event' : 'New event'}</h2><button class="icon-btn" id="evx">${icon('x')}</button></div>
      <label class="cfield"><span>Title</span><input id="nt" placeholder="Coffee with Ada" value="${esc(existing ? existing.title : '')}" autofocus></label>
      <div class="ev-new-row">
        <label class="cfield"><span>Date</span><input id="nd" type="date" value="${dstr}"></label>
        <label class="cfield"><span>Start</span><input id="ns" type="time" value="${startV}"></label>
        <label class="cfield"><span>End</span><input id="ne" type="time" value="${endV}"></label>
      </div>
      <div class="ev-new-row">
        <label class="cfield"><span>Repeat</span><select id="nr">${['', 'Weekly', 'Weekdays', 'Monthly'].map(repOpt).join('')}</select></label>
        <label class="cfield"><span>Reminder</span><select id="nrem">
          ${[['10', '10 min before'], ['30', '30 min before'], ['60', '1 hour before'], ['', 'None']].map(([v, l]) => `<option value="${v}" ${remV === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select></label>
      </div>
      <label class="cfield"><span>Guests (invitations sent as MOTEs)</span><input id="ng" value="${esc(guestsExisting)}" placeholder="ada@envoir.org, grace@navy.mil"></label>
      <label class="cfield"><span>Location</span><input id="nl" value="${esc(existing ? (existing.location || '') : '')}" placeholder="Optional"></label>
      <div class="ev-detail-foot"><span class="sim-tag">${icon('shield')} sealed to guests · no central scheduler</span><div class="spacer"></div><button class="btn primary" id="evsave">${existing ? 'Save changes' : 'Create'}</button></div>
    </div>`, { wide: true });
  card.querySelector('#evx').onclick = closeModal;
  card.querySelector('#evsave').onclick = async () => {
    const title = card.querySelector('#nt').value.trim(); if (!title) return toast('Add a title');
    const [y, mo, da] = card.querySelector('#nd').value.split('-').map(Number);
    const [sh, sm] = card.querySelector('#ns').value.split(':').map(Number);
    const [eh, em] = card.querySelector('#ne').value.split(':').map(Number);
    const start = new Date(y, mo - 1, da, sh, sm).getTime();
    const end = new Date(y, mo - 1, da, eh, em).getTime();
    const guests = card.querySelector('#ng').value.split(',').map(s => s.trim()).filter(Boolean);
    const rem = card.querySelector('#nrem').value;
    const location = card.querySelector('#nl').value.trim() || null;
    const recurrence = card.querySelector('#nr').value || null;
    const reminders = rem ? [Number(rem)] : [];
    if (existing) {
      const oldGuests = new Set(existing.attendees.filter(a => !a.address.startsWith('you@')).map(a => a.address));
      existing.title = title; existing.start = start; existing.end = end; existing.location = location;
      existing.recurrence = recurrence; existing.reminders = reminders;
      // preserve RSVPs for guests still invited; add pending for new ones
      existing.attendees = existing.attendees.filter(a => a.address.startsWith('you@') || guests.includes(a.address));
      guests.filter(g => !oldGuests.has(g)).forEach(g => existing.attendees.push({ address: g, rsvp: 'pending' }));
      closeModal(); bus.rerender();
      toast(`${icon('check')} Event updated — changes re-sealed to guests`);
      return;
    }
    const ev = { id: uid('e'), title, color: 210, start, end, recurrence, location, reminders,
      organizer: 'you@envoir.org', description: null,
      attendees: [{ address: 'you@envoir.org', rsvp: 'yes' }, ...guests.map(g => ({ address: g, rsvp: 'pending' }))] };
    state.events.push(ev);
    const mote = await buildMote({ to: guests[0] || 'you@envoir.org', kind: KIND.calendar, subject: title, body: JSON.stringify({ start, end }), tier: state.settings.tierDefault });
    closeModal(); bus.rerender();
    if (guests.length) showInspector(mote, { path: ['your node', 'mixnet', 'guests'], latencyMs: 0, kind: 'mixnet' });
    toast(`${icon('check')} Event created${guests.length ? ' · invitations sealed to ' + guests.length + ' guest(s)' : ''}`);
  };
}
