// store.js — the SUPERADMIN'S SIMULATED SEAM. This is the single place standing in for the
// operator control-plane's view of a running Envoir/DMTAP fleet. A production superadmin replaces
// exactly this module with a read model over the operator's own data plane: the node/gateway/mix
// enrollment registry, the `dmtap-seam` Metering/Provisioning/Policy/GatewayAuthz endpoints
// (crates/dmtap-seam), and the alerting bus. The view layer never changes.
//
// THE INVIOLABLE RULE (spec §12.3, and dmtap-seam CONTRACT invariants): nothing surfaced here may
// gate or observe a privacy/crypto capability. We meter OPERATIONS (storage, gateway sends,
// domains, relay bytes) and aggregate ANTI-ABUSE SIGNALS (rates, tokens, reputation) — never
// message content, recipients, or a user's keys. The console is content-blind BY CONSTRUCTION.

const LS = 'envoir.superadmin.v1';
const DAY = 86400e3, HOUR = 3600e3, MIN = 60e3;

// ---- deterministic PRNG so the demo fleet is stable across reloads ------------------------
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const state = {
  view: 'overview',
  ready: false,
  fleet: [],       // unified component list (node | gateway | mix | relay)
  accounts: [],    // billing seam metering, per account (operations only)
  signals: [],     // aggregate anti-abuse signals (metadata only — content-blind)
  incidents: [],   // ops incident / alert feed
  pool: [],        // warm-pool / capacity per region
  kt: null,        // Key Transparency log health: tree size, root, witness gossip
  ui: { search: '', theme: 'dark', selNode: null, fleetKind: 'all', billingSort: 'storage', ackd: {} },
};

export const REGIONS = [
  { id: 'eu-central', name: 'EU · Frankfurt', flag: '🇩🇪', primary: true },
  { id: 'eu-west', name: 'EU · Amsterdam', flag: '🇳🇱' },
  { id: 'af-south', name: 'Africa · Johannesburg', flag: '🇿🇦' },
  { id: 'us-east', name: 'US · Ashburn', flag: '🇺🇸' },
];
export const regionName = (id) => REGIONS.find(r => r.id === id)?.name || id;
export const regionFlag = (id) => REGIONS.find(r => r.id === id)?.flag || '🏳️';

export const KIND = {
  node: { label: 'Node', plural: 'Nodes', icon: 'server', desc: 'Hosted mailbox + files substrate (spec §7)' },
  gateway: { label: 'Gateway', plural: 'Gateways', icon: 'gateway', desc: 'Legacy SMTP↔DMTAP bridge; carries IP reputation (spec §7.2a, §9)' },
  mix: { label: 'Mix node', plural: 'Mix nodes', icon: 'mix', desc: 'Loopix-style mixnet relay; operator diversity required (spec §4.4.8)' },
  relay: { label: 'Relay', plural: 'Relays', icon: 'relay', desc: 'Reachability / bandwidth relay (spec §4)' },
};

let _seq = 100;
export const uid = (p = 'x') => p + '_' + (++_seq).toString(36) + Date.now().toString(36).slice(-4);

// ---- persistence --------------------------------------------------------------------------
export function persist() {
  const { fleet, accounts, signals, incidents, pool, kt, ui } = state;
  localStorage.setItem(LS, JSON.stringify({ fleet, accounts, signals, incidents, pool, kt, theme: ui.theme, ackd: ui.ackd }));
}
export function hasSession() { return !!localStorage.getItem(LS); }
export function wipe() { localStorage.removeItem(LS); }

export async function load() {
  const raw = localStorage.getItem(LS);
  if (!raw) return false;
  try {
    const s = JSON.parse(raw);
    Object.assign(state, { fleet: s.fleet, accounts: s.accounts, signals: s.signals, incidents: s.incidents, pool: s.pool, kt: s.kt });
    state.ui.theme = s.theme || 'dark';
    state.ui.ackd = s.ackd || {};
    document.documentElement.setAttribute('data-theme', state.ui.theme);
    state.ready = true;
    return true;
  } catch { return false; }
}

// ---- derived selectors --------------------------------------------------------------------
export const component = (id) => state.fleet.find(c => c.id === id);
export const byKind = (k) => state.fleet.filter(c => c.kind === k);
export const liveFleet = () => state.fleet.filter(c => c.status !== 'decommissioned');
export function counts(kind) {
  const list = kind ? byKind(kind).filter(c => c.status !== 'decommissioned') : liveFleet();
  return {
    total: list.length,
    up: list.filter(c => c.status === 'up').length,
    degraded: list.filter(c => c.status === 'degraded').length,
    down: list.filter(c => c.status === 'down').length,
  };
}
export function meterTotals() {
  const t = { storage_bytes: 0, gateway_sends: 0, inbound_legacy: 0, relay_bytes: 0, messages_sent: 0, domains: 0 };
  state.accounts.forEach(a => { for (const k in t) t[k] += a.meters[k] || 0; });
  return t;
}
export const openIncidents = () => state.incidents.filter(i => i.status !== 'resolved');

// ---- Key Transparency log health (spec §3.5) — split-view + freshness ---------------------
// A witness is STALE once its gossip is older than the freshness SLA (not itself a split-view —
// just a witness that can't yet corroborate the pinned root). A SPLIT is any witness whose last
// gossiped root hash disagrees with the canonical published root — the severe case.
export const ktWitnessFresh = (w) => (Date.now() - w.lastGossip) < (state.kt?.freshnessSla ?? 30 * 60e3);
export const ktWitnessSplit = (w) => w.rootHash !== state.kt?.rootHash;
export function ktStaleCount() { return state.kt ? state.kt.witnesses.filter(w => !ktWitnessFresh(w)).length : 0; }
export function ktSplitCount() { return state.kt ? state.kt.witnesses.filter(w => ktWitnessSplit(w)).length : 0; }

// Force a fresh gossip round: every witness re-confirms the published root right now. KT-logged
// implicitly by the incident feed staying honest — this is the operator's own re-verification,
// not a silent auto-heal.
export function ktReverify() {
  if (!state.kt) return;
  const now = Date.now();
  state.kt.publishedAt = now;
  state.kt.witnesses = state.kt.witnesses.map(w => ({ ...w, lastGossip: now, rootHash: state.kt.rootHash }));
  persist();
}

// ---- seed a believable operator fleet -----------------------------------------------------
export function seed() {
  const rnd = mulberry32(0xE9701);
  const now = Date.now();
  const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const between = (a, b) => a + rnd() * (b - a);
  const iBetween = (a, b) => Math.floor(between(a, b + 1));
  const series = (base, jitter, n = 24, floor = 0) => Array.from({ length: n }, () => Math.max(floor, base + (rnd() - 0.5) * jitter));

  const VER = ['0.4.2', '0.4.2', '0.4.2', '0.4.1', '0.4.3-rc1', '0.4.0'];
  const OPERATORS = ['envoir-cloud', 'nym-collective', 'c3-mix-e.V.', 'sovrn.host', 'lantern-ops', 'meshworks'];

  const mkComp = (kind, host, region, opts = {}) => {
    const status = opts.status || pick(['up', 'up', 'up', 'up', 'up', 'up', 'degraded', 'down']);
    const rep = kind === 'gateway' || kind === 'mix'
      ? (status === 'down' ? iBetween(30, 55) : status === 'degraded' ? iBetween(58, 78) : iBetween(82, 99))
      : null;
    let attest;
    if (kind === 'node' || kind === 'gateway') {
      attest = { status: status === 'down' ? 'unattested' : pick(['valid', 'valid', 'valid', 'valid', 'stale']), key: b64key(rnd), verifiedAt: now - iBetween(1, 40) * HOUR };
    } else if (kind === 'mix') {
      attest = { status: pick(['valid', 'valid', 'valid', 'stale']), key: b64key(rnd), verifiedAt: now - iBetween(1, 60) * HOUR };
    } else attest = { status: 'n/a' };
    const load = status === 'down' ? 0 : between(kind === 'relay' ? 0.35 : 0.2, status === 'degraded' ? 0.97 : 0.82);
    const c = {
      id: uid(kind), kind, host, region,
      status, version: opts.version || pick(VER),
      uptime: status === 'down' ? between(90, 97) : between(99.5, 99.999),
      load, cpu: status === 'down' ? 0 : Math.round(load * between(60, 95)),
      memGB: kind === 'node' ? iBetween(8, 64) : iBetween(2, 16),
      enrolledAt: now - iBetween(20, 400) * DAY,
      lastSeen: status === 'down' ? now - iBetween(4, 90) * MIN : now - iBetween(2, 55) * 1000,
      operator: pick(OPERATORS),
      attest, rep,
      loadHistory: series(load * 100, 40, 24, 0),
    };
    // per-kind operational metrics (operations only — never content)
    if (kind === 'node') { c.mailboxes = iBetween(120, 4200); c.storageBytes = c.mailboxes * iBetween(4e6, 40e6); }
    if (kind === 'gateway') { c.sends24h = status === 'down' ? 0 : iBetween(400, 9000); c.bounceRate = between(0.2, status === 'degraded' ? 6 : 2.4); c.complaintRate = between(0.01, 0.14); c.mixLayer = null; }
    if (kind === 'mix') { c.layer = opts.layer; c.forwarded24h = status === 'down' ? 0 : iBetween(50000, 900000); c.latencyMs = iBetween(120, 640); }
    if (kind === 'relay') { c.bandwidth24h = status === 'down' ? 0 : iBetween(80e9, 2.4e12); c.tunnels = status === 'down' ? 0 : iBetween(20, 600); }
    return c;
  };

  // pull the region out of a hostname like "mx1.eu-central"
  const regOf = (h) => REGIONS.find(r => h.includes(r.id))?.id || 'eu-central';

  const fleet = [];
  // Nodes — mailbox/storage substrate, EU-weighted
  [['mx1.eu-central'], ['mx2.eu-central'], ['mx3.eu-central'], ['mx1.eu-west'], ['mx2.eu-west', 'degraded'], ['store1.eu-central'], ['mx1.af-south'], ['mx1.us-east']]
    .forEach(([h, st]) => fleet.push(mkComp('node', h + '.envoir.net', regOf(h), st ? { status: st } : {})));
  // Gateways — legacy bridges
  [['gw1.eu-central'], ['gw2.eu-central'], ['gw1.eu-west'], ['gw1.af-south', 'down'], ['gw1.us-east']]
    .forEach(([h, st]) => fleet.push(mkComp('gateway', h + '.envoir.net', regOf(h), st ? { status: st } : {})));
  // Mix nodes — three layers, operator diversity (spec §4.4.8)
  for (let layer = 1; layer <= 3; layer++)
    for (let k = 0; k < 3; k++)
      fleet.push(mkComp('mix', `mix-l${layer}-${k + 1}.envoir.net`, pick(['eu-central', 'eu-west', 'af-south', 'us-east']), { layer }));
  // Relays
  ['relay1.eu-central', 'relay1.af-south', 'relay2.eu-central', 'relay1.us-east']
    .forEach(h => fleet.push(mkComp('relay', h + '.envoir.net', h.includes('af-south') ? 'af-south' : h.includes('us-east') ? 'us-east' : 'eu-central', {})));

  state.fleet = fleet;

  // ---- Billing seam: per-account metering (crates/dmtap-seam metering.rs UsageKind) --------
  const NAMES = ['acme.co', 'nordwind.de', 'kliniek.nl', 'ubuntu.africa', 'contoso.example', 'longtail.dev', 'studiofive', 'harbor.works', 'meridian.health', 'grün.energy', 'blackwood.legal', 'tindall.io'];
  const TIER = ['gateway_domain', 'gateway_domain', 'vanity_domain', 'key_only', 'vanity_domain', 'gateway_domain'];
  state.accounts = NAMES.map((n, i) => {
    const tier = pick(TIER);
    const seats = tier === 'key_only' ? iBetween(1, 4) : iBetween(3, 180);
    return {
      id: 'acct_' + (1000 + i).toString(36), name: n, tier, seats,
      region: pick(['eu-central', 'eu-west', 'af-south', 'us-east']),
      created: now - iBetween(30, 380) * DAY,
      suspended: rnd() < 0.08,
      meters: {
        storage_bytes: seats * iBetween(80e6, 900e6),
        gateway_sends: tier === 'key_only' ? 0 : iBetween(20, 8000),
        inbound_legacy: tier === 'key_only' ? 0 : iBetween(10, 6000),
        relay_bytes: iBetween(2e9, 400e9),
        messages_sent: iBetween(200, 60000),
        domains: tier === 'vanity_domain' ? iBetween(1, 4) : 0,
      },
    };
  });

  // ---- Anti-abuse signals — METADATA ONLY, content-blind (spec §9, §9.6) -------------------
  const SIGKIND = [
    { k: 'rate_limit', label: 'Send-rate limit tripped', icon: 'gauge', sev: 'warn', note: 'Per-token rate ceiling reached — no identity learned' },
    { k: 'postage_reject', label: 'Insufficient postage', icon: 'tag', sev: 'info', note: 'Anonymous send lacked postage/PoW (spec §9.4–9.5)' },
    { k: 'arc_revoked', label: 'ARC token revoked', icon: 'block', sev: 'bad', note: 'Anonymous-rate-limited-credential blocklisted for abuse' },
    { k: 'bounce_spike', label: 'Bounce-rate spike', icon: 'up', sev: 'warn', note: 'Gateway egress bounce rate crossed threshold' },
    { k: 'complaint', label: 'Feedback-loop complaint', icon: 'flame', sev: 'bad', note: 'ISP FBL complaint attributed to a send credential' },
    { k: 'spamtrap', label: 'Spam-trap hit', icon: 'warn', sev: 'bad', note: 'Egress reached a known trap address' },
    { k: 'pow_ok', label: 'PoW challenge cleared', icon: 'zap', sev: 'good', note: 'Proof-of-work admitted an anonymous sender' },
  ];
  state.signals = Array.from({ length: 26 }, () => {
    const s = pick(SIGKIND);
    const gw = pick(byKind('gateway'));
    return {
      id: uid('sig'), kind: s.k, label: s.label, icon: s.icon, sev: s.sev, note: s.note,
      subject: pick(['tok_' + b64key(rnd).slice(0, 10), 'acct_' + (1000 + iBetween(0, 11)).toString(36), 'postage-voucher', 'anon']),
      via: gw.host, ts: now - iBetween(1, 2600) * MIN,
      count: iBetween(1, 340),
    };
  }).sort((a, b) => b.ts - a.ts);

  // ---- Incidents / alerts feed --------------------------------------------------------------
  state.incidents = [
    { id: uid('inc'), sev: 'major', status: 'monitoring', title: 'Elevated delivery latency in af-south', body: 'relay1.af-south saturated; traffic shifted to eu-central. Bandwidth backpressure clearing.', components: ['af-south'], started: now - 52 * MIN, updated: now - 6 * MIN },
    { id: uid('inc'), sev: 'critical', status: 'investigating', title: 'gw1.af-south unreachable', body: 'Legacy gateway in Johannesburg not answering health probes. Egress failing over to eu-central; inbound-legacy queued.', components: ['gateway', 'af-south'], started: now - 18 * MIN, updated: now - 3 * MIN },
    { id: uid('inc'), sev: 'minor', status: 'resolved', title: 'Attestation key rotation on gw2.eu-central', body: 'Rotated the domain-anchored attestation key; recipients re-verified within one TTL. No egress interruption.', components: ['gateway'], started: now - 5 * HOUR, updated: now - 4.2 * HOUR },
    { id: uid('inc'), sev: 'minor', status: 'resolved', title: 'Warm-pool drained in eu-west', body: 'Claim spike consumed the eu-west warm pool; autoscaler refilled to target in 4m.', components: ['eu-west'], started: now - 2 * DAY, updated: now - 2 * DAY + 9 * MIN },
    { id: uid('inc'), sev: 'critical', status: 'resolved', title: 'KT witness split-view detected (community-audit.example)', body: 'A gossiping witness briefly reported a divergent root hash after a network partition. Cross-witness quorum confirmed the canonical root within one gossip round; the divergent witness was flagged and re-synced. No name→key binding was ever served inconsistently to clients.', components: ['kt'], started: now - 9 * DAY, updated: now - 9 * DAY + 40 * MIN },
  ];

  // ---- Key Transparency log health (spec §3.5) — split-view + freshness monitoring ---------
  // Content-blind like everything else here: this is metadata about the LOG (tree size, root
  // hash, witness gossip timing), never about what any binding resolves to for whom.
  const ktRoot = b64key(rnd).slice(0, 24);
  state.kt = {
    treeSize: 118402 + iBetween(400, 1600),
    rootHash: ktRoot,
    publishedAt: now - iBetween(2, 14) * MIN,
    freshnessSla: 30 * MIN,
    witnesses: [
      { name: 'witness-eu.envoir.dev', region: 'eu-central', rootHash: ktRoot, lastGossip: now - iBetween(1, 8) * MIN },
      { name: 'witness-af.mesh.example', region: 'af-south', rootHash: ktRoot, lastGossip: now - iBetween(2, 12) * MIN },
      { name: 'witness-us.gossip.example', region: 'us-east', rootHash: ktRoot, lastGossip: now - 5 * HOUR },
      { name: 'community-audit.example', region: 'eu-west', rootHash: ktRoot, lastGossip: now - iBetween(3, 20) * MIN },
    ],
  };

  // ---- Warm-pool / capacity per region (conceptual provisioning view) ----------------------
  state.pool = REGIONS.map(r => {
    const active = liveFleet().filter(c => c.region === r.id).length;
    const warm = r.id === 'eu-west' ? 0 : iBetween(1, 5);
    const target = r.primary ? 6 : 3;
    return {
      region: r.id, active, warm, target,
      claimed24h: iBetween(2, 40),
      capacity: between(r.id === 'af-south' ? 0.82 : 0.4, r.id === 'af-south' ? 0.98 : 0.78),
      provider: r.primary ? 'Fly.io' : r.id === 'af-south' ? 'Hetzner + Vultr' : r.id === 'us-east' ? 'Fly.io' : 'Hetzner',
    };
  });

  state.ready = true;
  persist();
}

function b64key(rnd) {
  const cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let s = '';
  for (let i = 0; i < 43; i++) s += cs[Math.floor(rnd() * cs.length)];
  return s;
}
