// mesh-sim.js — a SIMULATED DMTAP mesh + mixnet.
//
// IMPORTANT: there are no real peers. This fakes discovery, mixnet hops, delivery latency,
// and the @handle directory so the UI can demonstrate the protocol end to end. A real client
// replaces this with a libp2p connection to the user's node (spec §4). Everywhere the UI shows
// network activity, it is this simulation — and the UI says so.

import { person } from './seed.js';

const MIX_PATH = ['entry-mix', 'mix-α', 'mix-β', 'exit-mix'];

// Build a delivery plan for a MOTE: the path + latency, given the recipient. Private tier =
// mixnet (metadata-private, slower); fast = direct; legacy recipient = gateway → SMTP.
export function planDelivery(mote, recipientAddr) {
  const p = person(recipientAddr);
  if (mote.group) {
    const n = mote.group.mode === 'broadcast' ? 'per-member sealed ×N' : 'MLS group tree';
    return { path: ['your node', 'group committer', n, 'members'], latencyMs: 1600, kind: 'group' };
  }
  if (p.trust === 'legacy' || /@(gmail|outlook|yahoo|proton)\./.test(recipientAddr || '')) {
    return { path: ['your node', 'gateway', 'SMTP', (recipientAddr || '').split('@')[1] || 'legacy'], latencyMs: 1400, kind: 'legacy' };
  }
  if (mote.tier === 'fast') {
    return { path: ['your node', 'direct (IPv6)', 'their node'], latencyMs: 300, kind: 'direct' };
  }
  return { path: ['your node', ...MIX_PATH, 'their node'], latencyMs: 2400, kind: 'mixnet' };
}

export async function animatePath(plan, onHop) {
  const step = plan.latencyMs / plan.path.length;
  for (let i = 0; i < plan.path.length; i++) {
    onHop(i, plan.path[i]);
    await new Promise(r => setTimeout(r, Math.min(step, 420)));
  }
}

// ---- Simulated @handle directory (spec §3.9.2) -------------------------------------------
const TAKEN_HANDLES = new Set(['ada', 'linus', 'grace', 'satoshi', 'admin', 'root', 'support', 'envoir', 'core', 'crit', 'announce']);

export function normalizeHandle(h) {
  return (h || '').trim().toLowerCase().replace(/^@/, '').replace(/\.{2,}/g, '.');
}
export function checkHandle(h) {
  const n = normalizeHandle(h);
  if (!n) return { ok: false, reason: 'Enter a handle.' };
  if (!/^[a-z0-9][a-z0-9.-]{1,19}$/.test(n)) return { ok: false, reason: '3–20 chars, letters/digits/./- , must start alphanumeric.' };
  if (TAKEN_HANDLES.has(n)) return { ok: false, reason: '@' + n + ' is already taken.' };
  return { ok: true, normalized: n };
}
export async function claimHandle(h) {
  const chk = checkHandle(h);
  if (!chk.ok) return chk;
  TAKEN_HANDLES.add(chk.normalized);
  const { sha256, hex } = await import('./identity.js');
  const leaf = await sha256(new TextEncoder().encode(chk.normalized + ':' + Date.now() + ':' + Math.random()));
  return { ok: true, handle: chk.normalized, kt: 'kt:' + hex(leaf, 12) + '…' };
}
