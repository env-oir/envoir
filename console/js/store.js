// store.js — the CONSOLE'S SIMULATED STORE / SEAM. This is the single place that stands in for
// the domain's node + DNS zone + key-transparency log. A production console replaces exactly
// this module with a client to the domain authority's node (publishing real `_dmtap` DNS
// records, DomainDirectory objects over the mesh, and KT-log appends) — the views above never
// change. Everything here is in-memory, persisted to localStorage, and honestly labeled.
//
// Data model (spec references):
//   domain    — the administered domain + its threshold-held authority + DNS/kt anchor status (§3.10.1)
//   members   — name→key bindings, each sovereign or org-managed (§3.10.2, §18.4.7 DirEntry)
//   groups    — org groups / distribution lists (§5.8.7)
//   caps      — admin role capabilities, UCAN-style, delegable + revocable (§13.5.1)
//   audit     — the KT-logged, owner-visible event trail (§3.5, §13.5.1 "KT-logged & owner-visible")

import { generateKeypair, deriveSafetyFromString, sha256, toB64u } from './crypto.js';

const LS = 'envoir.console.v1';

export const state = {
  view: 'overview',
  ready: false,
  domain: null,
  members: [],
  groups: [],
  caps: [],
  audit: [],
  ui: { search: '', theme: 'dark', selMember: null, selGroup: null },
};

const HUES = [210, 262, 150, 330, 24, 190, 46, 120, 8, 285, 175, 300];
export const hueFor = (s) => HUES[[...(s || 'x')].reduce((a, c) => a + c.charCodeAt(0), 0) % HUES.length];

let _seq = 100;
export const uid = (p = 'x') => p + '_' + (++_seq).toString(36) + Date.now().toString(36).slice(-4);

// ---- persistence --------------------------------------------------------------------------
export function persist() {
  const { domain, members, groups, caps, audit, ui } = state;
  localStorage.setItem(LS, JSON.stringify({ domain, members, groups, caps, audit, theme: ui.theme }));
}
export function hasSession() { return !!localStorage.getItem(LS); }

export async function load() {
  const raw = localStorage.getItem(LS);
  if (!raw) return false;
  try {
    const s = JSON.parse(raw);
    Object.assign(state, { domain: s.domain, members: s.members, groups: s.groups, caps: s.caps, audit: s.audit });
    state.ui.theme = s.theme || 'dark';
    document.documentElement.setAttribute('data-theme', state.ui.theme);
    state.ready = true;
    return true;
  } catch { return false; }
}

export function wipe() { localStorage.removeItem(LS); }

// ---- KT-logged audit trail (spec §3.5, §13.5.1) -------------------------------------------
// Every domain-administrative act is appended here as an append-only, hash-chained record —
// the "owner-visible grants" discipline: nothing an admin does is silent (§13.5.1).
export async function logEvent(kind, summary, extra = {}) {
  const prev = state.audit[0]?.hash || 'genesis';
  const body = JSON.stringify({ kind, summary, ts: Date.now(), prev, ...extra });
  const hash = 'kt:' + toB64u(await sha256(new TextEncoder().encode(body))).slice(0, 14);
  state.audit.unshift({ id: uid('ev'), ts: Date.now(), kind, summary, prev, hash, threshold: !!extra.threshold, actor: extra.actor || adminActor() });
  persist();
}
export function adminActor() { return state.domain ? `you@${state.domain.name}` : 'you'; }

// ---- directory (GAL) versioning + signing (spec §3.10.3, §18.4.7) -------------------------
// Publishing a new DomainDirectory version: bump the monotonic version, re-sign the entry set
// with the (threshold-held) authority key, KT-log the new root. The signature is REAL — this
// is the console actually exercising the domain authority key.
export async function republishDirectory(reasonSummary) {
  const d = state.domain;
  d.dirVersion += 1;
  const entries = directoryEntries();
  const bytes = new TextEncoder().encode(JSON.stringify({ domain: d.name, version: d.dirVersion, vis: d.membershipVisibility, entries }));
  const { signDirectory } = await import('./session.js');
  d.dirSig = await signDirectory(bytes);
  await logEvent('directory', `DomainDirectory v${d.dirVersion} published — ${reasonSummary}`, { threshold: false });
  persist();
}

// A DirEntry projection (spec §18.4.7): active members + org groups, each with its custody +
// forward-verification status. The directory INDEXES; each entry is independently verifiable.
export function directoryEntries() {
  const mem = state.members.filter(m => m.status === 'active').map(m => ({
    name: m.address, ik: m.ik, custody: m.custody, dirVerified: m.dirVerified, kind: 'member', roles: rolesOf(m.address), added: m.added,
  }));
  const grp = state.groups.map(g => ({
    name: g.address, ik: g.ik, custody: 'sovereign', dirVerified: true, kind: 'group', roles: [g.mode], added: g.created,
  }));
  return mem.concat(grp);
}

export const rolesOf = (address) => state.caps.filter(c => c.subject === address && !c.revoked).map(c => c.role);
export const member = (id) => state.members.find(m => m.id === id);
export const group = (id) => state.groups.find(g => g.id === id);

// ---- billing: gateway-metered vs self-host $0 (spec §7.2a legacy bridge, §4 relay) ---------
// The seam only ever meters OPERATIONS that actually cross operator infrastructure — never a
// protocol capability. Native DMTAP mail, mixnet routing, KT reads/appends and directory
// resolution are always $0. Hosted storage / legacy-bridge sends / relay bytes are $0 too the
// moment the corresponding policy switch says this domain isn't drawing on operator infra.
export function effectiveMeters() {
  const raw = state.domain.meters;
  const p = state.domain.policy;
  return {
    storage_bytes: p.selfHost === 'self-hosted' ? 0 : raw.storage_bytes,
    gateway_sends: p.legacyBridge ? raw.gateway_sends : 0,
    inbound_legacy: p.legacyBridge ? raw.inbound_legacy : 0,
    // direct-first still falls back to relay occasionally; relay-required routes everything.
    relay_bytes: p.relayMode === 'relay-required' ? raw.relay_bytes : Math.round(raw.relay_bytes * 0.12),
  };
}

// ---- Key Transparency pin (spec §3.5) -------------------------------------------------------
// The tree size is derived from the domain's own KT-logged audit trail (every admin act is an
// append) plus a base offset standing in for the rest of the global log this domain shares.
export const ktTreeSize = () => 118402 + state.audit.length;
export const ktRootHash = () => state.audit[0]?.hash || 'kt:genesis';
export const KT_FRESHNESS_MS = 24 * 3600e3;
export const ktIsFresh = (w) => (Date.now() - w.lastSeen) < KT_FRESHNESS_MS;

// A deterministic recent-growth trend for the pinned tree size, purely derived from the current
// size (no extra state to persist) — enough to show the log is monotonically append-only, never
// shrinking, at a glance.
export function ktTreeHistory(n = 14) {
  const cur = ktTreeSize();
  return Array.from({ length: n }, (_, i) => Math.round(cur - (n - 1 - i) * (34 + (i % 3) * 6)));
}

// Real derived data: how many of today's active members had already been added as of each of
// the last N days — an honest membership-growth trend, not a fabricated series.
export function memberGrowthHistory(days = 14) {
  const now = Date.now(), DAY = 86400e3;
  const added = state.members.filter(m => m.status === 'active').map(m => m.added);
  return Array.from({ length: days }, (_, i) => {
    const cutoff = now - (days - 1 - i) * DAY;
    return added.filter(a => a <= cutoff).length;
  });
}

// Re-gossip: every witness re-confirms the pinned root right now. This is the console's own
// re-verification, not a silent auto-refresh — it is KT-logged like any other administrative act.
export async function verifyKtCheckpoint() {
  const d = state.domain;
  const now = Date.now();
  d.ktCheckpointAt = now;
  d.ktWitnesses = d.ktWitnesses.map(w => ({ ...w, lastSeen: now }));
  await logEvent('directory', `KT checkpoint re-verified across ${d.ktWitnesses.length} witnesses — consistent, no split-view`);
}

// ---- seed a believable demo domain --------------------------------------------------------
// Produces @abc.com with a threshold-held authority, a mix of sovereign + org-managed members,
// standing groups, delegated admin roles, and an initial KT trail. `authority` is created by
// session.js (real keypair); this fills the rest.
export async function seed(domainName, authority) {
  const now = Date.now();
  const DAY = 86400e3, HOUR = 3600e3, MIN = 60e3;
  state.domain = {
    name: domainName,
    authorityIk: authority.ik,
    fingerprint: authority.fingerprint,
    safety: authority.safety,
    alg: authority.alg,
    threshold: {
      m: 2, n: 3,
      holders: [
        { name: 'You (owner)', address: `you@${domainName}`, role: 'domain-owner' },
        { name: 'Priya Nair', address: `priya@${domainName}`, role: 'domain-admin' },
        { name: 'Sam Whitfield', address: `sam@${domainName}`, role: 'domain-admin' },
      ],
    },
    dns: { dmtap: 'ok', kt: 'ok', dkim: 'ok', dmarc: 'ok', dir: 'ok' },
    dirVersion: 0,
    dirSig: null,
    dirSigningKeyId: authority.fingerprint.slice(0, 12) + '·dir',
    membershipVisibility: 'members-only',
    created: now - 210 * DAY,

    // ---- gateway / relay policy (spec §7.2a legacy bridge, §4 relay) — who may self-host, and
    // which operators this domain trusts to bridge/relay its traffic. Read by Billing to decide
    // what's gateway-metered vs $0 self-hosted.
    policy: {
      selfHost: 'org-hosted', // 'org-hosted' | 'self-hosted'
      legacyBridge: true,
      trustedGateways: [`gw1.eu-central.envoir.net`, `gw1.eu-west.envoir.net`],
      relayMode: 'direct-first', // 'direct-first' | 'relay-required'
      trustedRelays: [`relay1.eu-central.envoir.net`],
    },

    // ---- billing tier (mirrors the superadmin's dmtap-seam TIERS: key_only / gateway_domain /
    // vanity_domain) + the raw metered usage this period. Billing.js derives what's actually
    // charged (effectiveMeters) from these + the policy above.
    billing: { tier: 'gateway_domain' },
    meters: { storage_bytes: 0, gateway_sends: 1830, inbound_legacy: 940, relay_bytes: 64e9 },

    // ---- Key Transparency pin (spec §3.5) — the checkpoint this domain trusts, cross-checked
    // by independent gossiping witnesses. A stale witness doesn't mean a split-view, but it can't
    // yet corroborate the pinned root; "Verify latest checkpoint" re-gossips and re-timestamps.
    ktCheckpointAt: now - 42 * MIN,
    ktWitnesses: [
      { name: 'witness-eu.envoir.dev', lastSeen: now - 6 * MIN },
      { name: 'witness-af.mesh.example', lastSeen: now - 11 * MIN },
      { name: 'community-audit.example', lastSeen: now - 26 * HOUR },
    ],
  };

  const mk = async (name, local, custody, opts = {}) => {
    // Real keypairs. Sovereign: private key discarded (org never held it). Org-managed:
    // private key retained in the disclosed escrow so the console can sign as them.
    const kp = await generateKeypair();
    const address = `${local}@${domainName}`;
    const m = {
      id: uid('m'), name, local, address,
      ik: kp.ik, fingerprint: kp.fingerprint, safety: kp.safety, alg: kp.alg,
      custody, dirVerified: opts.dirVerified !== false, status: opts.status || 'active',
      title: opts.title || '', hue: hueFor(address), added: opts.added || (now - 60 * DAY), groups: opts.groups || [],
    };
    if (custody === 'org-managed') { const { escrowStore } = await import('./session.js'); escrowStore(m.id, kp.priv, kp.alg); m.escrowed = true; }
    return m;
  };

  state.members = [
    await mk('You', 'you', 'sovereign', { title: 'Founder · domain owner', added: now - 210 * DAY }),
    await mk('Ada Okonkwo', 'ada', 'sovereign', { title: 'Protocol lead', added: now - 180 * DAY }),
    await mk('Theo Marsh', 'theo', 'sovereign', { title: 'Mesh & relays', added: now - 150 * DAY }),
    await mk('Priya Nair', 'priya', 'sovereign', { title: 'Head of eng', added: now - 175 * DAY }),
    await mk('Sam Whitfield', 'sam', 'sovereign', { title: 'Security', added: now - 172 * DAY }),
    await mk('Reception Desk', 'reception', 'org-managed', { title: 'Shared front-desk mailbox · compliance hold', added: now - 90 * DAY }),
    await mk('Billing', 'billing', 'org-managed', { title: 'Finance shared inbox · legal discovery', added: now - 120 * DAY }),
    await mk('Jordan Lee', 'jordan', 'sovereign', { title: 'Contractor', added: now - 20 * DAY, dirVerified: false }),
  ];
  state.domain.meters.storage_bytes = state.members.filter(m => m.status === 'active').length * 620e6 + 1.4e9;

  const gk = async (name, local, mode, memberLocals, opts = {}) => {
    const kp = await generateKeypair();
    return {
      id: uid('g'), name, address: `${local}@${domainName}`, ik: kp.ik, mode,
      membershipVisible: opts.membershipVisible ?? (mode === 'channel'),
      joinPolicy: opts.joinPolicy || 'closed', threshold: { m: 2, n: memberLocals.length >= 3 ? 3 : 2 },
      members: memberLocals.map(l => `${l}@${domainName}`), created: opts.created || (now - 100 * DAY),
    };
  };
  state.groups = [
    await gk('All staff', 'all', 'broadcast', ['you', 'ada', 'theo', 'priya', 'sam'], { membershipVisible: false, joinPolicy: 'closed' }),
    await gk('Engineering', 'team', 'channel', ['ada', 'theo', 'priya'], { joinPolicy: 'request' }),
    await gk('Support', 'support', 'channel', ['reception', 'jordan'], { joinPolicy: 'closed' }),
  ];

  // Admin capabilities (spec §13.5.1). domain-owner is the threshold root; others delegated.
  state.caps = [
    { id: uid('c'), role: 'domain-owner', subject: `you@${domainName}`, subjectName: 'You', delegatedFrom: 'domain authority (threshold)', issued: now - 210 * DAY, expires: null, revoked: false, threshold: true },
    { id: uid('c'), role: 'domain-admin', subject: `priya@${domainName}`, subjectName: 'Priya Nair', delegatedFrom: 'domain-owner', issued: now - 175 * DAY, expires: null, revoked: false },
    { id: uid('c'), role: 'user-admin', subject: `sam@${domainName}`, subjectName: 'Sam Whitfield', delegatedFrom: 'domain-admin', issued: now - 100 * DAY, expires: null, revoked: false },
    { id: uid('c'), role: 'group-admin', subject: `theo@${domainName}`, subjectName: 'Theo Marsh', delegatedFrom: 'domain-admin', issued: now - 80 * DAY, expires: now + 90 * DAY, revoked: false },
  ];

  state.audit = [];
  await logEvent('domain', `Domain authority for ${domainName} established — threshold ${state.domain.threshold.m}-of-${state.domain.threshold.n}`, { threshold: true });
  await logEvent('member', `${state.members.length} members provisioned during setup`, {});
  await logEvent('role', `4 admin capabilities delegated from the domain authority`, {});
  await republishDirectory('initial member + group set');
  state.ready = true;
  persist();
}
