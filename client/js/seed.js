// seed.js — rich, believable SEED DATA for every module. This is the "simulated network":
// there are no real peers, no real mailbox on a node, no real mixnet. A production client
// replaces this with a libp2p connection to the user's node (spec §4) + JMAP sync (§8.1).
// Everything here is in-memory and honestly labeled "simulated network" in the UI.

const HOUR = 3600e3, DAY = 86400e3, MIN = 60e3;
const now = Date.now();

// ---- People (shared across mail, chat, calendar, contacts, groups) -----------------------
// trust ∈ verified (safety number compared) | tofu (pinned on first contact) | unverified | legacy
export const PEOPLE = [
  { id: 'ada',    name: 'Ada Okonkwo',    address: 'ada@envoir.org',      hue: 210, trust: 'verified',   org: 'DMTAP Core',        title: 'Protocol lead',   phone: '+1 555 0182', note: 'Wrote the MOTE framing.', tags: ['Team', 'Core'] },
  { id: 'grace',  name: 'Grace Vasquez',  address: 'grace@navy.mil',      hue: 262, trust: 'verified',   org: 'Naval Research',    title: 'Cryptographer',   phone: '+1 555 0143', note: 'Verified in person at RWC.', tags: ['Work'] },
  { id: 'linus',  name: 'Linus Bergström',address: 'linus@kernel.dev',    hue: 150, trust: 'tofu',       org: 'Kernel',            title: 'Maintainer',      phone: null,          note: 'Pinned on first contact.', tags: ['Work'] },
  { id: 'mira',   name: 'Mira Chen',       address: 'mira@studio.design',  hue: 330, trust: 'verified',   org: 'Studio Chen',       title: 'Design partner',  phone: '+1 555 0119', note: 'Brand + product design.', tags: ['Design'] },
  { id: 'theo',   name: 'Theo Marsh',      address: 'theo@envoir.org',     hue: 24,  trust: 'verified',   org: 'DMTAP Core',        title: 'Mesh & relays',   phone: '+1 555 0164', note: null, tags: ['Team', 'Core'] },
  { id: 'nadia',  name: 'Nadia Farouk',    address: 'nadia@envoir.org',    hue: 190, trust: 'tofu',       org: 'DMTAP Core',        title: 'Gateway & interop', phone: null,        note: 'Compare safety number next call.', tags: ['Team', 'Core'] },
  { id: 'omar',   name: 'Omar Haddad',     address: 'omar@fieldwork.io',   hue: 46,  trust: 'verified',   org: 'Fieldwork',         title: 'Ops',             phone: '+44 20 7946', note: null, tags: ['Work'] },
  { id: 'satoshi',name: 'satoshi',         address: '@satoshi',            hue: 120, trust: 'unverified', org: null,                title: 'Key-only identity', phone: null,        note: 'Handle only — no domain.', tags: [] },
  { id: 'carol',  name: 'Carol Reyes',     address: 'carol@gmail.com',     hue: 8,   trust: 'legacy',     org: null,                title: 'Old-world contact', phone: '+1 555 0177', note: 'Reaches you via the gateway.', tags: ['Personal'] },
];

// Add or update a contact (JSContact MOTE, spec §8.4). Mutating PEOPLE keeps person() resolving
// the same reference everywhere. A real client syncs these as encrypted MOTEs across devices.
export function addPerson(p) { PEOPLE.push(p); return p; }
// All organizational tags in use (spec §17#31 local-tag contact groups — no address of their own).
export function contactTags() { return [...new Set(PEOPLE.flatMap(p => p.tags || []))].sort(); }

export const person = (idOrAddr) =>
  PEOPLE.find(p => p.id === idOrAddr || p.address === idOrAddr) ||
  { id: idOrAddr, name: idOrAddr, address: idOrAddr, hue: 220, trust: 'unverified' };

// ---- Labels (Gmail-style, color-coded) ---------------------------------------------------
export const LABELS = [
  { id: 'sovereign', name: 'Sovereign', hue: 262 },
  { id: 'team',      name: 'Team',      hue: 210 },
  { id: 'design',    name: 'Design',    hue: 330 },
  { id: 'travel',    name: 'Travel',    hue: 150 },
  { id: 'receipts',  name: 'Receipts',  hue: 46 },
];

// ---- Mail: threads of messages (conversation threading) -----------------------------------
// folder ∈ inbox | sent | drafts | archive | spam | trash ; plus starred/read/snoozeUntil flags.
export function seedMail() {
  return [
    {
      id: 't1', subject: 'Welcome to Envoir — you are sovereign now',
      labels: ['sovereign'], folder: 'inbox', read: false, starred: true, snoozeUntil: null,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't1m1', from: 'ada', to: ['you@envoir.org'], time: now - 2 * HOUR, tier: 'private',
          body: "You're on the sovereign network now.\n\nHere's the one idea that changes everything: your KEY is your identity. The address you@envoir.org is just a memorable pointer to it — like a phone number pointing at a person. No provider holds the key, so no provider can read your mail, and you can move your whole life to another provider (or your own domain) without losing a single message or contact.\n\nThe blue ✓ next to my name means you compared my safety number out-of-band, so you KNOW this is really me and not a look-alike. That's the anti-spoofing win: phishing stops working when identity is a key, not a display name.\n\nTry replying — open the ⓘ inspector on any message to see the three encrypted layers of the MOTE it becomes.\n\n— Ada" },
      ],
    },
    {
      id: 't2', subject: 'Re: MOTE v2 framing — envelope size buckets',
      labels: ['team', 'sovereign'], folder: 'inbox', read: false, starred: false, snoozeUntil: null,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't2m1', from: 'theo', to: ['you@envoir.org', 'ada@envoir.org'], time: now - 5 * HOUR, tier: 'private',
          body: "I benchmarked the padding buckets on the three relays. 4 KiB / 16 KiB / 64 KiB covers 98.6% of traffic without leaking length. Anything bigger falls back to the file path (content-addressed chunks).\n\nNumbers attached." , attach: [{ name: 'bucket-bench.csv', size: 48213 }] },
        { id: 't2m2', from: 'ada', to: ['you@envoir.org', 'theo@envoir.org'], time: now - 4 * HOUR, tier: 'private',
          body: "Nice. Let's lock 4/16/64 for v2. Can you write it up for §6.3?" },
        { id: 't2m3', from: 'you', to: ['ada@envoir.org', 'theo@envoir.org'], time: now - 3 * HOUR, tier: 'private',
          body: "+1 from me. I'll take the spec paragraph if Theo takes the reference impl.", me: true },
      ],
    },
    {
      id: 't3', subject: 'Design review — new mail three-pane',
      labels: ['design'], folder: 'inbox', read: true, starred: true, snoozeUntil: null,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't3m1', from: 'mira', to: ['you@envoir.org'], time: now - 26 * HOUR, tier: 'private',
          body: "Pushed the new three-pane comps. Key moves:\n\n• The verified ✓ is now a first-class glyph next to the sender, not buried in a menu.\n• Legacy-origin messages get a dotted amber rail so you always know what wasn't E2E before the gateway.\n• The MOTE inspector is a 'why this is private' drawer, not a debug panel.\n\nLook when you can — this is the flagship, it has to feel inevitable.", attach: [{ name: 'three-pane-v3.fig', size: 2_100_400 }] },
      ],
    },
    {
      id: 't4', subject: 'lunch thursday?',
      labels: [], folder: 'inbox', read: false, starred: false, snoozeUntil: null,
      tier: 'legacy', verified: false, legacy: true,
      msgs: [
        { id: 't4m1', from: 'carol', to: ['you@envoir.org'], time: now - 30 * HOUR, tier: 'legacy',
          body: "hey! are you free thursday around 1? there's a new place near the office.\n\n(this came in from the old world via the gateway — authenticated by DKIM but not end-to-end encrypted before the gateway, so Envoir marks it legacy-origin. once you're both on the network it upgrades automatically.)" },
      ],
    },
    {
      id: 't5', subject: 'Grace lands Friday 14:20 — safety number',
      labels: ['travel'], folder: 'inbox', read: true, starred: false, snoozeUntil: null,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't5m1', from: 'grace', to: ['you@envoir.org'], time: now - 2 * DAY, tier: 'private',
          body: "Flight lands 14:20 Friday, I'll come straight over.\n\nWhen we meet let's read safety numbers so this thread goes from TOFU-pinned to verified. Mine starts otter-heron-wolf — bring yours." },
      ],
    },
    {
      id: 't6', subject: 'Your Envoir receipt — Sovereign plan',
      labels: ['receipts'], folder: 'inbox', read: true, starred: false, snoozeUntil: null,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't6m1', from: 'ada', to: ['you+billing@envoir.org'], time: now - 3 * DAY, tier: 'private',
          body: "Receipt for the Sovereign plan. Note this was sent to you+billing@envoir.org — plus-addressing routes to the same key, so you can filter billing without a second account.\n\nAmount: your storage + relay bandwidth. Privacy is never the paid part.", plusTag: 'billing' },
      ],
    },
    {
      id: 't7', subject: 'patch series v3 — one nit inline',
      labels: ['team'], folder: 'archive', read: true, starred: false, snoozeUntil: null,
      tier: 'private', verified: false, legacy: false,
      msgs: [
        { id: 't7m1', from: 'linus', to: ['you@envoir.org'], time: now - 4 * DAY, tier: 'private',
          body: "Applied v3. One nit inline — the return value on the mixnet path isn't checked. Otherwise good. This whole thread is metadata-private; an observer can't even tell we correspond." },
      ],
    },
    {
      id: 't8', subject: 'Field report — relay uptime JHB',
      labels: [], folder: 'inbox', read: true, starred: false, snoozeUntil: now + 2 * DAY,
      tier: 'private', verified: true, legacy: false,
      msgs: [
        { id: 't8m1', from: 'omar', to: ['you@envoir.org'], time: now - 6 * HOUR, tier: 'private',
          body: "Snoozing this to you for Monday: the Johannesburg relay held 99.98% this week. Egress cost is the story — worth a call. I set this to resurface Monday morning." },
      ],
    },
    {
      id: 't9', subject: 'Draft: proposal for the mesh working group',
      labels: [], folder: 'drafts', read: true, starred: false, snoozeUntil: null,
      tier: 'private', verified: false, legacy: false,
      msgs: [
        { id: 't9m1', from: 'you', to: ['team@envoir.org'], time: now - 20 * MIN, tier: 'private', me: true,
          body: "Proposal: move the weekly sync to a broadcast group so the notes fan out to everyone automatically. Draft — still editing the agenda…" },
      ],
    },
  ];
}

// ---- Chat: DMs + channels (channels are GROUPS with addresses, spec §5.8) -----------------
export function seedChats() {
  return [
    { id: 'dm-ada', type: 'dm', with: 'ada', presence: 'online', typing: false, unread: 0, msgs: [
      { from: 'ada', me: false, t: now - 12 * MIN, body: 'chat and mail are the same MOTE underneath — kind=chat instead of kind=mail. one substrate.', reactions: { '🔥': 2 } },
      { from: 'ada', me: false, t: now - 11 * MIN, body: 'this one just uses the fast tier since we\'re both online right now' },
      { from: 'you', me: true, t: now - 9 * MIN, body: 'so one identity carries mail, chat, files, calendar — all sealed to the same key' },
      { from: 'ada', me: false, t: now - 8 * MIN, body: 'exactly. and presence is opt-in — you only broadcast "online" if you choose to.', reactions: { '💯': 1 } },
    ]},
    { id: 'dm-mira', type: 'dm', with: 'mira', presence: 'away', typing: true, unread: 1, msgs: [
      { from: 'mira', me: false, t: now - 40 * MIN, body: 'sending the updated palette in a sec' },
      { from: 'you', me: true, t: now - 38 * MIN, body: 'perfect, the violet→blue accent is exactly it' },
    ]},
    { id: 'ch-core', type: 'channel', group: 'team', presence: null, typing: false, unread: 3, msgs: [
      { from: 'theo', me: false, t: now - 2 * HOUR, body: 'relays are green across EU + JHB 🌍' },
      { from: 'ada', me: false, t: now - 100 * MIN, body: 'shipping the v2 framing today. @nadia can you take the gateway interop note?', reactions: { '👀': 3 } },
      { from: 'nadia', me: false, t: now - 96 * MIN, body: 'on it', thread: [
        { from: 'ada', me: false, t: now - 94 * MIN, body: 'thanks — link the DKIM delegation bit' },
        { from: 'nadia', me: false, t: now - 90 * MIN, body: 'will do 👍' },
      ]},
      { from: 'you', me: true, t: now - 30 * MIN, body: 'notes for the sync are in the shared folder' },
    ]},
    { id: 'ch-design', type: 'channel', group: 'design-crit', presence: null, typing: false, unread: 0, msgs: [
      { from: 'mira', me: false, t: now - 3 * HOUR, body: 'crit at 3pm — bring the three-pane comps' },
      { from: 'you', me: true, t: now - 2.5 * HOUR, body: 'the empty states finally feel right' , reactions: { '✨': 2 } },
    ]},
  ];
}

// ---- Calendar: events with recurrence, attendees + RSVP, reminders (spec §8.4) ------------
export function seedCalendar() {
  const d = (offsetDays, h, m = 0) => { const x = new Date(now + offsetDays * DAY); x.setHours(h, m, 0, 0); return x.getTime(); };
  return [
    { id: 'e1', title: 'Mesh working group sync', color: 210, start: d(0, 10), end: d(0, 11),
      recurrence: 'Weekly on Wednesday', location: 'team@envoir.org (group call)', reminders: [10],
      organizer: 'you@envoir.org', description: 'Weekly protocol sync. Notes fan out to the group after.',
      attendees: [{ address: 'ada@envoir.org', rsvp: 'yes' }, { address: 'theo@envoir.org', rsvp: 'yes' }, { address: 'nadia@envoir.org', rsvp: 'maybe' }] },
    { id: 'e2', title: 'Design crit — three-pane', color: 330, start: d(0, 15), end: d(0, 16),
      recurrence: null, location: 'design-crit channel', reminders: [15],
      organizer: 'mira@studio.design', description: 'Review the new mail comps.',
      attendees: [{ address: 'you@envoir.org', rsvp: 'pending' }, { address: 'mira@studio.design', rsvp: 'yes' }] },
    { id: 'e3', title: 'Coffee with Ada', color: 262, start: d(1, 9, 30), end: d(1, 10),
      recurrence: null, location: 'Blue Bottle, 3rd St', reminders: [30],
      organizer: 'ada@envoir.org', description: null,
      attendees: [{ address: 'you@envoir.org', rsvp: 'yes' }, { address: 'ada@envoir.org', rsvp: 'yes' }] },
    { id: 'e4', title: 'Grace lands (SFO)', color: 150, start: d(2, 14, 20), end: d(2, 15),
      recurrence: null, location: 'SFO Terminal 2', reminders: [60],
      organizer: 'grace@navy.mil', description: 'Read safety numbers when we meet.',
      attendees: [{ address: 'you@envoir.org', rsvp: 'yes' }] },
    { id: 'e5', title: 'Deep work — spec §6.3', color: 46, start: d(2, 9), end: d(2, 12),
      recurrence: 'Weekdays', location: null, reminders: [],
      organizer: 'you@envoir.org', description: 'Padding buckets write-up.',
      attendees: [] },
    { id: 'e6', title: 'Relay cost review w/ Omar', color: 190, start: d(4, 13), end: d(4, 13, 45),
      recurrence: null, location: 'call', reminders: [10],
      organizer: 'omar@fieldwork.io', description: 'JHB egress numbers.',
      attendees: [{ address: 'you@envoir.org', rsvp: 'pending' }, { address: 'omar@fieldwork.io', rsvp: 'yes' }] },
  ];
}

// ---- Files: content-addressed, E2E, any size; some shared with a group (spec §5.5, §6.7) --
export function seedFiles() {
  return [
    { id: 'f1', name: 'MOTE-v2-framing.pdf', size: 2_400_000, cid: 'b3:9f2c…a71e', icon: '📄', from: 'ada', shared: 'team', ts: now - 3 * HOUR },
    { id: 'f2', name: 'three-pane-v3.fig',   size: 2_100_400, cid: 'b3:1a4b…c93d', icon: '🎨', from: 'mira', shared: 'design-crit', ts: now - 26 * HOUR },
    { id: 'f3', name: 'bucket-bench.csv',     size: 48_213,    cid: 'b3:77e0…12ff', icon: '📊', from: 'theo', shared: null, ts: now - 5 * HOUR },
    { id: 'f4', name: 'relay-map-JHB.png',    size: 840_000,   cid: 'b3:3d10…8b02', icon: '🗺️', from: 'omar', shared: null, ts: now - 6 * HOUR },
    { id: 'f5', name: 'sovereign-backup.tar.zst', size: 5_100_000_000, cid: 'b3:aa19…4e7c', icon: '📦', from: 'you', shared: null, ts: now - 2 * DAY },
  ];
}

// ---- Groups: an address that has members (spec §5.8). Sending to it posts to all. ---------
// mode ∈ broadcast (list, hidden members) | channel (collaborative, member-visible)
export function seedGroups() {
  return [
    { id: 'team', name: 'DMTAP Core', address: 'team@envoir.org', handle: '@core', mode: 'channel',
      joinPolicy: 'request', membershipVisible: true, created: now - 90 * DAY,
      members: [
        { address: 'you@envoir.org', role: 'owner' },
        { address: 'ada@envoir.org', role: 'admin' },
        { address: 'theo@envoir.org', role: 'admin' },
        { address: 'nadia@envoir.org', role: 'member' },
      ] },
    { id: 'design-crit', name: 'Design Crit', address: 'design-crit@envoir.org', handle: '@crit', mode: 'channel',
      joinPolicy: 'closed', membershipVisible: true, created: now - 40 * DAY,
      members: [
        { address: 'mira@studio.design', role: 'owner' },
        { address: 'you@envoir.org', role: 'member' },
      ] },
    { id: 'announce', name: 'Envoir Announce', address: 'announce@envoir.org', handle: '@announce', mode: 'broadcast',
      joinPolicy: 'open', membershipVisible: false, created: now - 120 * DAY,
      members: [
        { address: 'you@envoir.org', role: 'owner' },
        { address: 'ada@envoir.org', role: 'admin' },
        { address: '(2,481 subscribers)', role: 'member', hidden: true },
      ] },
  ];
}

// ---- Signatures & filters (Settings seed) ------------------------------------------------
export function seedSignatures() {
  return [
    { id: 's1', name: 'Full', body: 'You\n— sent sovereign from Envoir · verify my key by safety number', default: true },
    { id: 's2', name: 'Short', body: '— You', default: false },
  ];
}
export function seedFilters() {
  return [
    { id: 'flt1', from: '*@envoir.org', subject: '', label: 'team', action: 'label', enabled: true },
    { id: 'flt2', from: 'carol@gmail.com', subject: '', label: '', action: 'legacy-flag', enabled: true },
    { id: 'flt3', from: '', subject: 'receipt', label: 'receipts', action: 'label', enabled: true },
  ];
}

export const FOLDERS = [
  { id: 'inbox',   name: 'Inbox',    icon: 'inbox' },
  { id: 'starred', name: 'Starred',  icon: 'star' },
  { id: 'snoozed', name: 'Snoozed',  icon: 'clock' },
  { id: 'sent',    name: 'Sent',     icon: 'send' },
  { id: 'drafts',  name: 'Drafts',   icon: 'edit' },
  { id: 'archive', name: 'Archive',  icon: 'archive' },
  { id: 'spam',    name: 'Spam',     icon: 'shield' },
  { id: 'trash',   name: 'Trash',    icon: 'trash' },
];

export function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}
