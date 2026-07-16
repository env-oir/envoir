// avatar.js — THE AVATAR STANDARD (documented ladder for a public profile picture).
//
// Priority, highest first:
//   1. a user-set PUBLIC avatarUrl (you paste a link to a photo you host anywhere)
//   2. an OPT-IN Gravatar-style avatar derived from the account email — off by default,
//      never a hard dependency (a third party would otherwise learn "this address exists
//      and looked itself up" just from rendering a message; opt-in keeps that honest)
//   3. a deterministic, KEY-DERIVED IDENTICON rendered as an inline SVG data: URI — same
//      visual language as the safety-number QR-grid (safety.js / ui.js safetyGrid), so
//      "your identicon" and "your safety grid" read as the same fingerprint, no network
//      fetch, works offline, and can never collide with someone else's key
//   4. an initials tile (ui.js avatar()) — the universal fallback if all else fails
//
// (1) and (4) need no code here — they're plain fields / the existing gradient tile. This
// module implements the two derived rungs, (2) and (3), plus the resolver that picks among
// them per the ladder above.

const GRAVATAR_BASE = 'https://www.gravatar.com/avatar/';

// Gravatar's documented normalization: trim whitespace, lowercase, then hash. Gravatar's
// current API accepts a SHA-256 hash of the address (in addition to the legacy MD5) — we use
// SHA-256 via native Web Crypto, so this needs no hand-rolled hash implementation and still
// matches Gravatar's own normalization rule exactly.
export async function gravatarHash(email) {
  const norm = (email || '').trim().toLowerCase();
  const bytes = new TextEncoder().encode(norm);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest].map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function gravatarUrl(email, opts = {}) {
  const hash = await gravatarHash(email);
  const d = opts.d || 'identicon'; // Gravatar's own server-side fallback for an unregistered hash
  const s = opts.s || 160;
  return `${GRAVATAR_BASE}${hash}?d=${encodeURIComponent(d)}&s=${s}`;
}

// A deterministic identicon derived from raw public-key bytes: an 8×8 grid, left half random,
// right half mirrored (the classic identicon symmetry), hue picked from the same digest — so
// two different keys are visually distinct but the SAME key always renders identically. Pure
// function of the input bytes; renders as an inline SVG data: URI (no external asset, no
// network fetch, works with zero connectivity).
export async function identiconDataUri(keyBytes, size = 128) {
  const d1 = new Uint8Array(await crypto.subtle.digest('SHA-256', keyBytes));
  const d2 = new Uint8Array(await crypto.subtle.digest('SHA-256', d1)); // a second, distinct hash for the cell bits
  const cell = size / 8;
  const hue = Math.round((d1[0] / 255) * 360);
  let rects = '';
  for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 5; c++) {
      if ((d2[r * 5 + c] & 1) !== 1) continue;
      const y = r * cell;
      rects += `<rect x="${c * cell}" y="${y}" width="${cell}" height="${cell}"/>`;
      const mirrorC = 7 - c;
      if (mirrorC !== c) rects += `<rect x="${mirrorC * cell}" y="${y}" width="${cell}" height="${cell}"/>`;
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">` +
    `<rect width="${size}" height="${size}" fill="hsl(${hue} 32% 13%)"/>` +
    `<g fill="hsl(${hue} 72% 60%)">${rects}</g></svg>`;
  return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
}

// Resolve the effective avatar source for an identity, following the standard ladder above.
// Caches the result on id._avatarSrc / id._avatarKind — a TRANSIENT, never-persisted derived
// value (it can always be re-derived from the persisted fields: avatarUrl, gravatarEnabled,
// and the public key). Call after load/create and after any profile edit, then re-render.
export async function resolveIdentityAvatar(id, rawPublicKeyBytes) {
  if (!id) return null;
  if (id.avatarUrl) { id._avatarSrc = id.avatarUrl; id._avatarKind = 'url'; return id._avatarSrc; }
  if (id.gravatarEnabled) {
    try {
      id._avatarSrc = await gravatarUrl(id.primary || id.name);
      id._avatarKind = 'gravatar';
      return id._avatarSrc;
    } catch { /* fall through to the identicon rung */ }
  }
  try {
    id._avatarSrc = await identiconDataUri(rawPublicKeyBytes);
    id._avatarKind = 'identicon';
    return id._avatarSrc;
  } catch {
    id._avatarSrc = null; id._avatarKind = 'initials';
    return null;
  }
}
