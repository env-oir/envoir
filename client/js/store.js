// store.js — central in-memory app state + a thin settings-persistence layer.
//
// Mail/chat/calendar/etc. live here as mutable state seeded from seed.js (the simulated
// network). SETTINGS (theme, default tier, signatures, vacation, filters) persist to
// localStorage so they survive reloads — a real client would sync these as MOTEs across the
// device cluster (spec §8.5). Views mutate `state` and call the shell's rerender().

import { seedMail, seedChats, seedCalendar, seedFiles, seedGroups, seedSignatures, seedFilters, seedDevices, seedSessions, LABELS, PEOPLE, person } from './seed.js';

const LS_SETTINGS = 'envoir.settings.v2';

const defaultSettings = {
  theme: 'dark',
  mailDensity: 'comfortable',   // 'comfortable' | 'compact' (Superhuman-style density toggle)
  tierDefault: 'private',
  gateway: true,
  presence: true,               // opt-in presence (labeled metadata-sensitive)
  signatures: seedSignatures(),
  filters: seedFilters(),
  vacation: { enabled: false, subject: 'Away — back Monday', message: 'I\'m away and will reply when I return. Urgent? Reach me on the Core channel.', from: '', to: '' },
  // Recipient-local block/allow lists (spec §9.2 Policy{allow, block}). Enforced client-side
  // here against the simulated store; a real node enforces before decryption for cold senders.
  blocked: [],
  allowed: ['ada@envoir.org'],
};

export const state = {
  view: 'mail',
  // data (simulated network)
  mail: [], chats: [], events: [], files: [], groups: [], devices: [], sessions: [], labels: LABELS, people: PEOPLE,
  // ui selection state
  ui: {
    mailFolder: 'inbox', mailLabel: null, selThread: null, selChat: null, selGroup: null,
    chatThread: null,               // { cid, idx } open message-thread in Chat, or null
    calView: 'week', calCursor: Date.now(), selEvent: null,
    selected: new Set(),            // multi-select mail ids
    search: '',
    mobileDetail: false,            // mobile master/detail: false = list pane, true = detail pane
    compose: null,                  // active compose draft object or null
  },
  settings: { ...defaultSettings },
};

export function initStore() {
  state.mail = seedMail();
  state.chats = seedChats();
  state.events = seedCalendar();
  state.files = seedFiles();
  state.groups = seedGroups();
  state.devices = seedDevices();
  state.sessions = seedSessions();
  loadSettings();
  state.ui.selThread = state.mail.find(t => t.folder === 'inbox')?.id || null;
  state.ui.selChat = state.chats[0]?.id || null;
  state.ui.selGroup = state.groups[0]?.id || null;
}

// ---- Wake-ping demo: simulate a fresh incoming calendar invite arriving over the mesh --------
// Wired from app.js's onWakeSync handler. Both a REAL Push event and the Settings "Send test
// wake-ping" button funnel through the exact same service-worker message (sw.js), so this one
// path exercises the whole push -> sync -> new content loop honestly, end-to-end, in-browser.
// Like the rest of the seed data, the INCOMING side is simulated (we can't sign as someone
// else's key in this demo) — only messages *you* send build a real MOTE (mote.js).
const INVITE_TITLES = ['Quick sync', 'Roadmap check-in', 'Coffee chat', 'Relay planning', 'Spec walkthrough', 'Design pairing'];
const INVITE_COLORS = [210, 262, 330, 150, 46, 8, 190];
let _inviteSeq = 0;
export function simulateIncomingInvite() {
  const candidates = PEOPLE.filter(p => p.trust !== 'legacy' && !(p.address || '').startsWith('you@'));
  const organizer = candidates[_inviteSeq++ % candidates.length];
  const title = INVITE_TITLES[Math.floor(Math.random() * INVITE_TITLES.length)];
  const start = new Date();
  start.setDate(start.getDate() + 1 + Math.floor(Math.random() * 4));
  start.setHours(9 + Math.floor(Math.random() * 7), 0, 0, 0);
  const startMs = start.getTime();
  const endMs = startMs + (30 + Math.floor(Math.random() * 3) * 15) * 60e3;
  const ev = {
    id: uid('e'), title, color: INVITE_COLORS[Math.floor(Math.random() * INVITE_COLORS.length)],
    start: startMs, end: endMs, recurrence: null, location: null, reminders: [10], allDay: false,
    description: 'Arrived just now over the mesh — a calendar MOTE sealed to your key.',
    organizer: organizer.address,
    attendees: [{ address: organizer.address, rsvp: 'yes' }, { address: 'you@envoir.org', rsvp: 'pending' }],
  };
  state.events.push(ev);
  const when = new Date(startMs).toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' }) +
    ' at ' + new Date(startMs).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const inviteThread = {
    id: uid('t'), subject: `Invitation: ${title}`, labels: [], folder: 'inbox', read: false, starred: false,
    snoozeUntil: null, tier: 'private', verified: organizer.trust === 'verified', legacy: false,
    calendarEventId: ev.id,
    msgs: [{
      id: uid('m'), from: organizer.id, to: ['you@envoir.org'], time: Date.now(), tier: 'private',
      provenance: { tier: 'private', profile: 'standard', origin: 'pure-mesh', minHops: 3, observedAt: Date.now(), gateways: [] },
      body: `${organizer.name} invited you to "${title}" — ${when}. Sealed as a calendar MOTE straight to your key; RSVP below or from Calendar.`,
    }],
  };
  state.mail.unshift(inviteThread);
  return { event: ev, thread: inviteThread, organizer };
}

export function saveSettings() {
  localStorage.setItem(LS_SETTINGS, JSON.stringify(state.settings));
}
export function loadSettings() {
  try {
    const s = JSON.parse(localStorage.getItem(LS_SETTINGS) || 'null');
    if (s) state.settings = { ...defaultSettings, ...s,
      vacation: { ...defaultSettings.vacation, ...(s.vacation || {}) },
      blocked: Array.isArray(s.blocked) ? s.blocked : defaultSettings.blocked.slice(),
      allowed: Array.isArray(s.allowed) ? s.allowed : defaultSettings.allowed.slice() };
  } catch { /* ignore */ }
  document.documentElement.setAttribute('data-theme', state.settings.theme);
}

// ---- Mail helpers -------------------------------------------------------------------------
export function threadsIn(folder, label) {
  return state.mail.filter(t => {
    if (label) return t.labels.includes(label) && t.folder !== 'trash' && t.folder !== 'spam';
    if (folder === 'starred') return t.starred && t.folder !== 'trash';
    if (folder === 'snoozed') return t.snoozeUntil && t.folder !== 'trash';
    return t.folder === folder;
  }).sort((a, b) => lastTime(b) - lastTime(a));
}
export const lastTime = (t) => t.msgs[t.msgs.length - 1].time;
export const thread = (id) => state.mail.find(t => t.id === id);
export function unreadCount(folder) {
  return state.mail.filter(t => t.folder === folder && !t.read).length;
}

let _idc = 1000;
export const uid = (p = 'x') => p + (++_idc) + Date.now().toString(36).slice(-3);

// ---- On-device search with operators (spec §17#4, §0.7 no server-side index) ---------------
// Gmail-style operators: from: to: subject: label: in: is:unread is:starred has:attachment.
// Everything else is free-text. Parsed and matched entirely on-device — a real client indexes
// its own plaintext mailbox locally; no provider ever builds a searchable index.
export const SEARCH_OPERATORS = ['from', 'to', 'subject', 'label', 'in', 'is', 'has'];
export function parseSearch(raw) {
  const q = (raw || '').trim();
  const p = { text: [], from: null, to: null, subject: null, label: null, in: null, flags: {} };
  if (!q) return p;
  // token split that keeps "quoted phrases" together
  const tokens = q.match(/(\w+):"[^"]*"|(\w+):\S+|"[^"]*"|\S+/g) || [];
  for (let tok of tokens) {
    const m = tok.match(/^(\w+):(.*)$/);
    if (m && SEARCH_OPERATORS.includes(m[1].toLowerCase())) {
      const key = m[1].toLowerCase();
      const val = m[2].replace(/^"|"$/g, '').toLowerCase();
      if (key === 'is') { if (val === 'unread') p.flags.unread = true; else if (val === 'read') p.flags.read = true; else if (val === 'starred' || val === 'flagged') p.flags.starred = true; }
      else if (key === 'has') { if (val === 'attachment' || val === 'attach') p.flags.attachment = true; }
      else if (key === 'in') p.in = val;
      else p[key] = val;
    } else {
      p.text.push(tok.replace(/^"|"$/g, '').toLowerCase());
    }
  }
  p.text = p.text.join(' ').trim();
  return p;
}
// Does this parsed query reference a scope operator (label:/in:)? Those search globally.
export function searchIsGlobal(p) { return !!(p.label || p.in); }

export function matchThread(t, p) {
  if (!p) return true;
  const has = (arr, v) => arr.some(x => (x || '').toLowerCase().includes(v));
  const froms = t.msgs.map(m => m.from === 'you' ? 'you you@envoir.org' : (person(m.from).name + ' ' + person(m.from).address));
  const tos = t.msgs.flatMap(m => m.to || []);
  if (p.from && !has(froms, p.from)) return false;
  if (p.to && !has(tos, p.to)) return false;
  if (p.subject && !(t.subject || '').toLowerCase().includes(p.subject)) return false;
  if (p.label && !(t.labels || []).some(l => l.toLowerCase() === p.label || (LABELS.find(x => x.id === l)?.name || '').toLowerCase().includes(p.label))) return false;
  if (p.in && t.folder !== p.in && !(p.in === 'starred' && t.starred) && !(p.in === 'anywhere')) return false;
  if (p.flags.unread && t.read) return false;
  if (p.flags.read && !t.read) return false;
  if (p.flags.starred && !t.starred) return false;
  if (p.flags.attachment && !t.msgs.some(m => (m.attach || []).length)) return false;
  if (p.text) {
    const hay = (t.subject + ' ' + t.msgs.map(m => (m.from === 'you' ? 'you' : person(m.from).name) + ' ' + stripHtml(m.body)).join(' ')).toLowerCase();
    if (!hay.includes(p.text)) return false;
  }
  return true;
}

export function stripHtml(s) {
  return (s == null ? '' : String(s)).replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}

// ---- Client-side filters/rules (spec §17#3) -----------------------------------------------
// Rules run on the owner's own always-on node — functionally "server-side" (applies while the
// client is closed) without a third party ever seeing plaintext (§8.2). Here they run over the
// simulated store. A real node MAY reuse Sieve (RFC 5228) verbatim; this is the client UX for it.
export function ruleMatches(rule, t) {
  if (!rule.enabled) return false;
  const from = rule.from ? rule.from.trim().toLowerCase() : '';
  const subj = rule.subject ? rule.subject.trim().toLowerCase() : '';
  if (!from && !subj) return false;
  if (from) {
    const senders = t.msgs.map(m => m.from === 'you' ? 'you@envoir.org' : person(m.from).address.toLowerCase());
    const wild = from.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    const re = new RegExp('^' + wild + '$');
    if (!senders.some(s => re.test(s) || s.includes(from))) return false;
  }
  if (subj && !(t.subject || '').toLowerCase().includes(subj)) return false;
  return true;
}
// Apply all enabled rules to a set of threads. Returns count of threads changed.
export function applyFilters(threads = state.mail) {
  let changed = 0;
  for (const t of threads) {
    if (t.folder === 'trash' || t.folder === 'sent' || t.folder === 'drafts') continue;
    for (const rule of state.settings.filters) {
      if (!ruleMatches(rule, t)) continue;
      let did = false;
      if (rule.action === 'label' && rule.label && !t.labels.includes(rule.label)) { t.labels.push(rule.label); did = true; }
      else if (rule.action === 'star' && !t.starred) { t.starred = true; did = true; }
      else if (rule.action === 'archive' && t.folder === 'inbox') { t.folder = 'archive'; did = true; }
      else if (rule.action === 'spam' && t.folder !== 'spam') { t.folder = 'spam'; did = true; }
      else if (rule.action === 'read' && !t.read) { t.read = true; did = true; }
      if (did) changed++;
    }
  }
  return changed;
}

// ---- Block / allow lists (spec §9.2) ------------------------------------------------------
export const normAddr = (a) => (a || '').trim().toLowerCase();
export function isBlocked(addr) { return state.settings.blocked.includes(normAddr(addr)); }
export function isAllowed(addr) { return state.settings.allowed.includes(normAddr(addr)); }
export function blockSender(addr) { const a = normAddr(addr); if (a && !state.settings.blocked.includes(a)) state.settings.blocked.push(a); state.settings.allowed = state.settings.allowed.filter(x => x !== a); saveSettings(); }
export function unblockSender(addr) { const a = normAddr(addr); state.settings.blocked = state.settings.blocked.filter(x => x !== a); saveSettings(); }
export function allowSender(addr) { const a = normAddr(addr); if (a && !state.settings.allowed.includes(a)) state.settings.allowed.push(a); state.settings.blocked = state.settings.blocked.filter(x => x !== a); saveSettings(); }
// The sender address of a thread (first non-you message), for block/allow actions.
export function threadSender(t) { const m = t.msgs.find(x => x.from !== 'you') || t.msgs[0]; return m.from === 'you' ? (m.to?.[0] || '') : person(m.from).address; }
