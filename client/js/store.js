// store.js — central in-memory app state + a thin settings-persistence layer.
//
// Mail/chat/calendar/etc. live here as mutable state seeded from seed.js (the simulated
// network). SETTINGS (theme, default tier, signatures, vacation, filters) persist to
// localStorage so they survive reloads — a real client would sync these as MOTEs across the
// device cluster (spec §8.5). Views mutate `state` and call the shell's rerender().

import { seedMail, seedChats, seedCalendar, seedFiles, seedGroups, seedSignatures, seedFilters, LABELS, PEOPLE } from './seed.js';

const LS_SETTINGS = 'envoir.settings.v2';

const defaultSettings = {
  theme: 'dark',
  tierDefault: 'private',
  gateway: true,
  presence: true,               // opt-in presence (labeled metadata-sensitive)
  signatures: seedSignatures(),
  filters: seedFilters(),
  vacation: { enabled: false, subject: 'Away — back Monday', message: 'I\'m away and will reply when I return. Urgent? Reach me on the Core channel.', from: '', to: '' },
};

export const state = {
  view: 'mail',
  // data (simulated network)
  mail: [], chats: [], events: [], files: [], groups: [], labels: LABELS, people: PEOPLE,
  // ui selection state
  ui: {
    mailFolder: 'inbox', mailLabel: null, selThread: null, selChat: null, selGroup: null,
    calView: 'week', calCursor: Date.now(), selEvent: null,
    selected: new Set(),            // multi-select mail ids
    search: '',
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
  loadSettings();
  state.ui.selThread = state.mail.find(t => t.folder === 'inbox')?.id || null;
  state.ui.selChat = state.chats[0]?.id || null;
  state.ui.selGroup = state.groups[0]?.id || null;
}

export function saveSettings() {
  localStorage.setItem(LS_SETTINGS, JSON.stringify(state.settings));
}
export function loadSettings() {
  try {
    const s = JSON.parse(localStorage.getItem(LS_SETTINGS) || 'null');
    if (s) state.settings = { ...defaultSettings, ...s, vacation: { ...defaultSettings.vacation, ...(s.vacation || {}) } };
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
