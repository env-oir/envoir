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

import { deriveSafety, deriveKeyName } from './safety.js';
import { resolveIdentityAvatar } from './avatar.js';

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
    alg: _identity.alg, ik: _identity.ik, fingerprint: _identity.fingerprint, keyName: _identity.keyName,
    phrase: _identity.phrase, safety: _identity.safety, created: _identity.created,
    displayName: _identity.displayName, givenName: _identity.givenName, familyName: _identity.familyName,
    avatarUrl: _identity.avatarUrl, gravatarEnabled: _identity.gravatarEnabled,
  }));
}

export async function createIdentity(primary, displayName) {
  const { kp, alg } = await genSigningKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)
    .catch(async () => new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))));
  const ik = toB64u(raw);
  const fingerprint = hex(await sha256(raw), 16);
  const safety = await deriveSafety(raw);
  const keyName = await deriveKeyName(raw);
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const phrase = [...rnd].map(b => WORDS[b % WORDS.length]);

  _identity = {
    name: primary, primary, displayName: displayName || primary.split('@')[0],
    givenName: '', familyName: '', avatarUrl: null, gravatarEnabled: false,
    addresses: [alias(primary, 'primary')],
    alg, ik, fingerprint, keyName, phrase, safety, created: Date.now(),
    _kp: kp,
  };
  const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const s = { pk8: toB64u(pk8), pub: toB64u(raw) };
  localStorage.setItem(LS_KEY, JSON.stringify(s));
  persist();
  await refreshAvatar(_identity, raw);
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
  if (!_identity.keyName) _identity.keyName = await deriveKeyName(fromB64u(s.pub || s.ik));
  if (!_identity.addresses) _identity.addresses = [alias(_identity.primary || _identity.name, 'primary')];
  if (_identity.givenName == null) _identity.givenName = '';
  if (_identity.familyName == null) _identity.familyName = '';
  if (_identity.avatarUrl == null) _identity.avatarUrl = null;
  if (_identity.gravatarEnabled == null) _identity.gravatarEnabled = false;
  await refreshAvatar(_identity, fromB64u(s.pub || s.ik));
  return _identity;
}

// Re-derive the effective avatar (the ladder in avatar.js) after load/create or a profile
// edit, and cache it on the identity as a transient field. `rawKeyBytes` may be omitted if
// already known to be unchanged — it's re-derived from the stored public key in that case.
export async function refreshAvatar(id = _identity, rawKeyBytes) {
  if (!id) return null;
  const raw = rawKeyBytes || fromB64u(id.ik);
  return resolveIdentityAvatar(id, raw);
}

// Self-asserted profile fields (spec framing: the KEY is the identity; name + photo are only
// pointers to it, exactly like the address — see identity.js header comment). Persists and
// re-resolves the avatar ladder; callers should re-render + refresh chrome afterward.
export async function setProfile(fields = {}) {
  if (!_identity) return _identity;
  const allowed = ['givenName', 'familyName', 'displayName', 'avatarUrl', 'gravatarEnabled'];
  for (const k of allowed) if (k in fields) _identity[k] = fields[k];
  persist();
  await refreshAvatar(_identity);
  return _identity;
}

// A lightweight "person" shape for the self-identity, so the SAME avatar()/name rendering used
// for contacts/senders also renders "you" consistently (rail, compose From, mail/chat "me").
export function selfPerson() {
  const id = _identity;
  if (!id) return { name: 'You', hue: 220, address: 'you', trust: 'verified' };
  return {
    name: displayName(id), address: id.primary || 'you', hue: id.hue ?? 220, trust: 'verified',
    avatarUrl: id.avatarUrl || null, _avatarSrc: id._avatarSrc || null,
  };
}

export function currentIdentity() { return _identity; }
export function logout() { localStorage.removeItem(LS_KEY); _identity = null; }

// --- Aliases (spec §3.9.4): one identity, many name@domain addresses, all → same key. ---
// Also accepts the `name-chain` resolver form (§3.12.4/§3.12.5, e.g. `alice.eth`/`alice.sol`) —
// bare, no "@", the everyday ENS/SNS-style spelling — auto-classified to kind 'namechain' so the
// naming-ladder UI (identity view, §3.13.2) can show its bidirectional on-chain binding honestly.
export function addAlias(address, kind = 'alias') {
  if (!_identity) return { ok: false, reason: 'No identity.' };
  const a = (address || '').trim().toLowerCase();
  if (!a) return { ok: false, reason: 'Enter an address.' };
  const isHandle = a.startsWith('@');
  const isNameChain = !isHandle && !a.includes('@') && /\.(eth|sol)$/.test(a);
  const isDnsShaped = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a);
  if (!isHandle && !isNameChain && !isDnsShaped) return { ok: false, reason: 'Use name@domain, alice.eth/.sol, or @handle.' };
  if (_identity.addresses.some(x => x.address === a)) return { ok: false, reason: 'Already an address on this identity.' };
  const finalKind = isHandle ? 'handle' : isNameChain ? 'namechain' : kind;
  _identity.addresses.push(alias(a, finalKind));
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
// Composes GIVEN + FAMILY name, unless a single explicit "display name" override is set (spec
// framing, §3.9): these are self-asserted profile fields — a pointer to you, like the address —
// never the identity itself. The address is a pointer to the key; the name is a pointer to you.
export function displayName(id) {
  id = id || _identity;
  if (!id) return '';
  if (id.displayName) return id.displayName;
  const composed = [id.givenName, id.familyName].filter(Boolean).join(' ').trim();
  if (composed) return composed;
  return (id.primary || id.name || '').split('@')[0];
}

// A stable, KEY-DERIVED legacy/gateway fallback address — the client's simplified presentation
// of the spec §7.10 gateway alias. The spec's "Encoded" form (§7.10.2) packs `localpart +
// nativedomain` so it is a pure, near-stateless function of the pair — but that needs a native
// *domain*, which a Tier A key-only identity (§3.8) doesn't have. Deriving instead from the
// identity's own fingerprint keeps the same self-describing, near-stateless property (no
// per-gateway registration, no state table) while working for every identity, domain or not: the
// result is the SAME at every dmtap1-compatible gateway. It is still, honestly, a *separate,
// rotatable* pointer (§7.10.4) — burn or regenerate it and every other name on the key is
// unaffected.
export function gatewayAlias(id = _identity, gatewayDomain = 'gw.envoir.org') {
  if (!id?.fingerprint) return '';
  return `dmtap1-${id.fingerprint.slice(0, 12)}@${gatewayDomain}`;
}

// Split a plus-addressed local part (spec §3.9.4): you+tag@domain → { base, tag }.
export function parsePlus(address) {
  const [local, domain] = (address || '').split('@');
  const plus = local.indexOf('+');
  if (plus < 0) return { base: address, tag: null };
  return { base: local.slice(0, plus) + (domain ? '@' + domain : ''), tag: local.slice(plus + 1) };
}

export { WORDS };
