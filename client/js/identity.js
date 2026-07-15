// identity.js — DMTAP identity (spec §1). Uses REAL Web Crypto.
//
// ADDRESSING MODEL (spec §3.9, finalized): the identity is the KEYPAIR. What people see and
// give out is a PRIMARY address `name@domain` (e.g. you@envoir.org). An identity MAY hold many
// addresses at once — aliases, a kept legacy address, an optional @handle — all resolving to
// the same key (§3.9.4). The key is verified out-of-band via a SAFETY NUMBER (safety.js), not
// used as an address.
//
// Real: Ed25519 keypair generation + signing (ECDSA-P256 fallback, labeled), SHA-256 hashing,
// deterministic safety-number derivation. Stand-in: SHA-256 substitutes for BLAKE3 content-
// addressing; the recovery phrase uses a small demo word list (real = SLIP-0039). Persistence
// is localStorage (a real node holds keys in an OS keystore).

import { deriveSafety } from './safety.js';

const LS_KEY = 'envoir.identity.v2';

const WORDS = ('acid apex atlas basin blade cedar cobalt comet coral delta ember fable flint ' +
  'garnet glide harbor helix ionic ivory jasper karma linen lunar maple mesa nova onyx opal ' +
  'petal quartz raven relay river sable slate spark tidal umbra vertex willow xenon yarrow zephyr')
  .split(' ');

let _identity = null;

async function genSigningKey() {
  try {
    return { kp: await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']), alg: 'Ed25519' };
  } catch {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { kp, alg: 'ECDSA-P256 (Ed25519 unsupported here)' };
  }
}

export async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}
export function toB64u(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(s) {
  return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
export function hex(bytes, max) {
  const s = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return max ? s.slice(0, max) : s;
}

// An alias record. kind ∈ primary | alias | legacy | handle. All resolve to the same key.
function alias(address, kind, extra = {}) {
  return { address, kind, ...extra };
}

function persist() {
  if (!_identity) return;
  const s = localStorage.getItem(LS_KEY);
  const base = s ? JSON.parse(s) : {};
  localStorage.setItem(LS_KEY, JSON.stringify({
    ...base,
    name: _identity.name, primary: _identity.primary, addresses: _identity.addresses,
    alg: _identity.alg, ik: _identity.ik, fingerprint: _identity.fingerprint,
    phrase: _identity.phrase, safety: _identity.safety, created: _identity.created,
    displayName: _identity.displayName,
  }));
}

export async function createIdentity(primary, displayName) {
  const { kp, alg } = await genSigningKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)
    .catch(async () => new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))));
  const ik = toB64u(raw);
  const fingerprint = hex(await sha256(raw), 16);
  const safety = await deriveSafety(raw);
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const phrase = [...rnd].map(b => WORDS[b % WORDS.length]);

  _identity = {
    name: primary, primary, displayName: displayName || primary.split('@')[0],
    addresses: [alias(primary, 'primary')],
    alg, ik, fingerprint, phrase, safety, created: Date.now(),
    _kp: kp,
  };
  const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const s = { pk8: toB64u(pk8), pub: toB64u(raw) };
  localStorage.setItem(LS_KEY, JSON.stringify(s));
  persist();
  return _identity;
}

export async function loadIdentity() {
  const j = localStorage.getItem(LS_KEY);
  if (!j) return null;
  const s = JSON.parse(j);
  if (!s.ik) return null;
  const alg = (s.alg || '').startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  let kp = null;
  try {
    const priv = await crypto.subtle.importKey('pkcs8', fromB64u(s.pk8), alg, true, ['sign']);
    kp = { privateKey: priv };
  } catch { /* key unavailable — signing disabled, UI still works */ }
  _identity = { ...s, _kp: kp };
  if (!_identity.safety) _identity.safety = await deriveSafety(fromB64u(s.pub || s.ik));
  if (!_identity.addresses) _identity.addresses = [alias(_identity.primary || _identity.name, 'primary')];
  return _identity;
}

export function currentIdentity() { return _identity; }
export function logout() { localStorage.removeItem(LS_KEY); _identity = null; }

// --- Aliases (spec §3.9.4): one identity, many name@domain addresses, all → same key. ---
export function addAlias(address, kind = 'alias') {
  if (!_identity) return { ok: false, reason: 'No identity.' };
  const a = (address || '').trim().toLowerCase();
  if (!a) return { ok: false, reason: 'Enter an address.' };
  const isHandle = a.startsWith('@');
  if (!isHandle && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a)) return { ok: false, reason: 'Use name@domain (or @handle).' };
  if (_identity.addresses.some(x => x.address === a)) return { ok: false, reason: 'Already an address on this identity.' };
  _identity.addresses.push(alias(a, isHandle ? 'handle' : kind));
  persist();
  return { ok: true };
}
export function removeAlias(address) {
  if (!_identity) return;
  const a = _identity.addresses.find(x => x.address === address);
  if (!a || a.kind === 'primary') return; // can't remove the primary
  _identity.addresses = _identity.addresses.filter(x => x.address !== address);
  persist();
}
export function makePrimary(address) {
  if (!_identity) return;
  const target = _identity.addresses.find(x => x.address === address);
  if (!target || target.kind === 'handle') return;
  _identity.addresses.forEach(x => { if (x.kind === 'primary') x.kind = 'alias'; });
  target.kind = 'primary';
  _identity.primary = _identity.name = address;
  persist();
}

// Sign bytes with the identity's device/root key (spec §2.4 payload signature).
export async function sign(bytes) {
  const id = _identity;
  if (!id?._kp?.privateKey) return new Uint8Array(0);
  const alg = id.alg.startsWith('Ed25519') ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  return new Uint8Array(await crypto.subtle.sign(alg, id._kp.privateKey, bytes));
}

// The address people see and give out (spec §3.9): the PRIMARY name@domain.
export function displayAddress(id) {
  id = id || _identity;
  return id ? id.primary || id.name || '' : '';
}
export function displayName(id) {
  id = id || _identity;
  return id ? (id.displayName || (id.primary || '').split('@')[0]) : '';
}

// Split a plus-addressed local part (spec §3.9.4): you+tag@domain → { base, tag }.
export function parsePlus(address) {
  const [local, domain] = (address || '').split('@');
  const plus = local.indexOf('+');
  if (plus < 0) return { base: address, tag: null };
  return { base: local.slice(0, plus) + (domain ? '@' + domain : ''), tag: local.slice(plus + 1) };
}

export { WORDS };
