// store.js — Envoir Status' SIMULATED STORE / SEAM. Stands in for the operator's public status
// feed + the authenticated per-user health probe. A production status page replaces exactly this
// module with (a) a poll of the public component/incident feed and (b) an authenticated call to
// the user's home node for their mailbox / reachability / recent-delivery health. Everything here
// is in-memory and honestly labeled.
//
// A "scenario" control (operational | degraded | outage) regenerates the feed so every state of
// the page is demonstrable — it is a demo affordance, clearly labeled, not a production control.

const LS = 'envoir.status.v1';
const DAY = 86400e3, HOUR = 3600e3, MIN = 60e3;

export const state = {
  view: 'public',        // public | user
  theme: 'dark',
  scenario: 'operational',
  signedIn: false,
  components: [],
  incidents: [],
  overall: 'operational',
  user: null,
  loading: false,
  transparency: null, // KT consistency + gateway attestation freshness (public "Transparency" panel)
};

// The six public components (spec-mapped surfaces of the protocol).
export const COMPONENTS = [
  { id: 'mail', name: 'Mail delivery', icon: 'mail', desc: 'Native JMAP send + receive across the mesh' },
  { id: 'gateway', name: 'Legacy gateway', icon: 'gateway', desc: 'SMTP ↔ DMTAP bridge for legacy correspondents (spec §7)' },
  { id: 'mixnet', name: 'Mixnet', icon: 'mix', desc: 'Private-tier metadata-hiding routing (spec §4.4)' },
  { id: 'kt', name: 'Key Transparency', icon: 'kt', desc: 'Append-only name→key log (spec §3.5)' },
  { id: 'directory', name: 'Directory', icon: 'directory', desc: 'Name resolution + DomainDirectory (spec §3.10)' },
  { id: 'relay', name: 'Reachability relay', icon: 'relay', desc: 'Direct-first, relay-fallback delivery path (spec §4)' },
];
export const componentMeta = (id) => COMPONENTS.find(c => c.id === id);

export function persist() {
  localStorage.setItem(LS, JSON.stringify({ theme: state.theme, scenario: state.scenario, signedIn: state.signedIn }));
}
export function loadPrefs() {
  try {
    const s = JSON.parse(localStorage.getItem(LS) || '{}');
    if (s.theme) state.theme = s.theme;
    if (s.scenario) state.scenario = s.scenario;
    state.signedIn = !!s.signedIn;
  } catch { /* ignore */ }
  document.documentElement.setAttribute('data-theme', state.theme);
}

// ---- deterministic uptime history ---------------------------------------------------------
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function history(seed, blips, todayStatus) {
  const rnd = mulberry32(seed);
  const now = Date.now();
  const days = [];
  for (let i = 89; i >= 0; i--) {
    const date = new Date(now - i * DAY);
    let status = 'up';
    if (blips.includes(i)) status = rnd() < 0.4 ? 'down' : 'degraded';
    if (i === 0 && todayStatus) status = todayStatus;
    const up = status === 'up' ? 100 : status === 'degraded' ? 97 + rnd() * 2 : 88 + rnd() * 6;
    days.push({ status, up, label: `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} · ${status === 'up' ? '100% uptime' : up.toFixed(2) + '% uptime'}` });
  }
  return days;
}
function uptime90(days) {
  const s = days.reduce((a, d) => a + d.up, 0) / days.length;
  return s;
}

// ---- scenario generation ------------------------------------------------------------------
export function rebuild() {
  const sc = state.scenario;
  const now = Date.now();

  // per-component current status by scenario
  const statusMap = {
    operational: {},
    degraded: { gateway: 'degraded', mixnet: 'degraded' },
    outage: { gateway: 'down', relay: 'degraded' },
  }[sc] || {};

  // seeded blips (indices of days-ago that had trouble), plus today from the scenario
  const blipMap = {
    mail: [63, 41], gateway: [77, 52, 20, 3], mixnet: [58, 12], kt: [], directory: [47], relay: [70, 31, 9],
  };

  state.components = COMPONENTS.map((c, idx) => {
    const status = statusMap[c.id] || 'up';
    const days = history(0x51A + idx * 7, blipMap[c.id] || [], status === 'up' ? null : status);
    return { ...c, status, uptime: uptime90(days), history: days };
  });

  // overall status
  const worst = state.components.reduce((w, c) => c.status === 'down' ? 'outage' : (c.status === 'degraded' && w !== 'outage') ? 'degraded' : w, 'operational');
  state.overall = worst;

  // incidents by scenario
  if (sc === 'operational') {
    state.incidents = [
      { id: 'inc-r1', title: 'Directory resolver failover', impact: 'minor', status: 'resolved', components: ['directory'], started: now - 8 * DAY, updates: [
        { ts: now - 8 * DAY + 40 * MIN, status: 'resolved', body: 'Resolver failed over cleanly; name resolution restored. No mail was lost — delivery is edge-durable.' },
        { ts: now - 8 * DAY, status: 'investigating', body: 'A directory replica in eu-central returned stale reads. Investigating.' },
      ] },
    ];
  } else if (sc === 'degraded') {
    state.incidents = [
      { id: 'inc-d1', title: 'Elevated latency on the legacy gateway & mixnet', impact: 'minor', status: 'monitoring', components: ['gateway', 'mixnet'], started: now - 46 * MIN, updates: [
        { ts: now - 6 * MIN, status: 'monitoring', body: 'Mitigation applied; queues draining. Native mail is unaffected — only legacy-bridge sends and private-tier routing see added delay.' },
        { ts: now - 30 * MIN, status: 'identified', body: 'A saturated egress path in eu-central is adding latency to gateway sends and mix hops. Rerouting.' },
        { ts: now - 46 * MIN, status: 'investigating', body: 'We are seeing elevated delivery latency on the legacy gateway and mixnet.' },
      ] },
    ];
  } else { // outage
    state.incidents = [
      { id: 'inc-o1', title: 'Legacy gateway outage in af-south', impact: 'major', status: 'investigating', components: ['gateway', 'relay'], started: now - 22 * MIN, updates: [
        { ts: now - 4 * MIN, status: 'investigating', body: 'The Johannesburg legacy gateway is not responding. Egress to legacy (SMTP) correspondents is failing over to eu-central; some legacy sends are queued. Reachability relays in af-south are degraded and re-homing tunnels.' },
        { ts: now - 22 * MIN, status: 'investigating', body: 'We are investigating a loss of the legacy gateway in af-south.' },
      ] },
      { id: 'inc-o0', title: 'Scheduled KT log compaction', impact: 'none', status: 'resolved', components: ['kt'], started: now - 3 * DAY, updates: [
        { ts: now - 3 * DAY + 25 * MIN, status: 'resolved', body: 'Compaction completed with no interruption to reads or appends.' },
        { ts: now - 3 * DAY, status: 'maintenance', body: 'Routine KT log compaction. No impact expected.' },
      ] },
    ];
  }

  state.transparency = buildTransparency(sc, now);
  if (state.signedIn) buildUser();
  state.loading = false;
}

// ---- transparency: KT consistency + gateway attestation freshness (spec §3.5, §7.2a) ------
// The public counterpart to the superadmin's KT-log-health + attestation views: cross-witness
// consistency and how fresh the last re-verification was, without exposing any operator detail
// beyond what a correspondent needs to trust the log and the bridge.
function buildTransparency(sc, now) {
  return {
    kt: {
      consistent: true, // a real split-view would be its own incident, surfaced above like any other
      treeSize: 118402 + Math.floor(now / 3.6e9), // ticks up slowly — a standing append-only counter
      checkpointAgeMin: sc === 'outage' ? 34 : sc === 'degraded' ? 12 : 4,
      witnesses: 4,
    },
    gateway: {
      status: sc === 'outage' ? 'stale' : 'valid',
      lastVerifiedMin: sc === 'outage' ? 46 : sc === 'degraded' ? 18 : 7,
    },
  };
}

// ---- authenticated per-user health --------------------------------------------------------
export function signIn() { state.signedIn = true; buildUser(); persist(); }
export function signOut() { state.signedIn = false; state.user = null; state.view = 'public'; persist(); }

function buildUser() {
  const now = Date.now();
  const comp = (id) => state.components.find(c => c.id === id) || { status: 'up' };
  const gateway = comp('gateway').status, relay = comp('relay').status, mail = comp('mail').status;

  // which open incidents touch a surface this user relies on
  const affecting = state.incidents.filter(i => i.status !== 'resolved' && i.components.some(c => ['mail', 'gateway', 'mixnet', 'relay', 'directory', 'kt'].includes(c)));

  const deliveries = [
    { peer: 'ada@abc.com', dir: 'out', kind: 'native', status: 'delivered', ts: now - 4 * MIN },
    { peer: 'billing@contoso.example', dir: 'out', kind: 'legacy', status: gateway === 'down' ? 'queued' : gateway === 'degraded' ? 'delayed' : 'delivered', ts: now - 21 * MIN },
    { peer: 'theo@abc.com', dir: 'in', kind: 'native', status: 'delivered', ts: now - 55 * MIN },
    { peer: 'newsletter@news.example', dir: 'in', kind: 'legacy', status: 'delivered', ts: now - 2 * HOUR },
    { peer: 'priya@abc.com', dir: 'out', kind: 'native', status: 'delivered', ts: now - 5 * HOUR },
  ];

  state.user = {
    address: 'you@abc.com',
    node: 'mx1.eu-central.envoir.net',
    mailbox: {
      status: mail === 'down' ? 'down' : 'up',
      usedBytes: 3.1 * 1024 ** 3, quotaBytes: 10 * 1024 ** 3,
      lastSync: now - 40 * 1000,
    },
    reachability: {
      status: relay === 'down' ? 'down' : relay === 'degraded' ? 'degraded' : 'up',
      path: relay === 'up' ? 'direct' : 'relay-fallback',
      relayNode: 'relay1.eu-central.envoir.net',
    },
    legacy: { status: gateway },
    deliveries,
    affecting,
  };
}

export function setScenario(sc) { state.scenario = sc; persist(); rebuild(); }
export function setTheme(t) { state.theme = t; document.documentElement.setAttribute('data-theme', t); persist(); }
