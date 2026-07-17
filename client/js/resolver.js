// resolver.js — classify a typed/known name against the DMTAP pluggable resolver-type ladder
// (spec §3.12 the resolver framework, §3.13 the naming ladder). This is presentation only: it
// pattern-matches a string so compose/contacts/identity can show WHICH resolver a name would use
// and an honest trust/verification state. It performs no real DNS, KT, or on-chain lookup — this
// client has no real network (see seed.js) — and it never invents a binding: an unrecognized
// form is honestly `unknown`, mirroring the spec §3.12.2 discipline that a real implementation
// must fail closed on an unrecognized resolver type rather than guess.

import { icon, esc } from './ui.js';

export const RESOLVER_TYPES = {
  self:      { kind: 'self',      label: 'Key-name',    icon: 'key',      note: 'derived from the key alone — no lookup, no DNS, no registration (spec §3.9.6)' },
  petname:   { kind: 'petname',   label: 'Petname',     icon: 'contacts', note: 'a label you assigned locally — resolves via an already-pinned key, never leaves this device' },
  dns:       { kind: 'dns',       label: 'DNS',          icon: 'globe',    note: 'DNS discovery, audited by key transparency (KT)' },
  namechain: { kind: 'namechain', label: 'Name-chain',   icon: 'link',     note: 'an on-chain record — resolution reads a public record, free and read-only' },
  directory: { kind: 'directory', label: '@handle',      icon: 'at',       note: 'a KT-audited global handle directory — an introduction, not a trust root' },
  unknown:   { kind: 'unknown',   label: 'Unrecognized', icon: 'info',     note: 'no resolver recognizes this form — it fails closed, not a guess' },
};

const KEY_NAME_RE = /^[a-z]+(?:\.[a-z]+){7}$/i;         // 8 dot-joined words (§3.9.6)
const HANDLE_RE = /^@[a-z0-9][a-z0-9._-]{0,63}$/i;       // §3.9.2
const NAMECHAIN_RE = /\.(eth|sol)$/i;                    // ENS / SNS (§3.12.5)
const DNS_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;             // local@domain.tld

// Classify a raw typed string into one resolver type. Order matters: an ENS/SNS name is ALSO
// local@domain-shaped when written with an "@", so the name-chain TLD check runs before the
// generic DNS check; the key-name check (no "@" at all) runs last among the positive matches.
export function classifyName(raw) {
  const s = (raw || '').trim();
  if (!s) return { ...RESOLVER_TYPES.unknown, input: s };
  if (HANDLE_RE.test(s)) return { ...RESOLVER_TYPES.directory, input: s };
  if (s.includes('@')) {
    const domain = s.slice(s.indexOf('@') + 1);
    if (NAMECHAIN_RE.test(domain)) return { ...RESOLVER_TYPES.namechain, input: s };
    if (DNS_RE.test(s)) return { ...RESOLVER_TYPES.dns, input: s };
    return { ...RESOLVER_TYPES.unknown, input: s };
  }
  if (NAMECHAIN_RE.test(s)) return { ...RESOLVER_TYPES.namechain, input: s };
  if (KEY_NAME_RE.test(s)) return { ...RESOLVER_TYPES.self, input: s };
  return { ...RESOLVER_TYPES.unknown, input: s };
}

// A small inline chip naming the resolver a typed/known name would use. Kept visually distinct
// from (but consistent with) the ordinary .pill trust colors used everywhere else in the app.
export function resolverChip(info) {
  return `<span class="resolver-chip rc-${esc(info.kind)}" title="${esc(info.note)}">${icon(info.icon)}${esc(info.label)}</span>`;
}

// A longer, honest sentence for detail surfaces (contact cards, the identity naming ladder).
// `trust` is the ordinary verified/tofu/unverified/legacy state already used across the app;
// this pairs the resolver TYPE with that state rather than inventing a second verification
// concept. Omit `trust` for the user's OWN addresses, where "verification" doesn't apply the
// same way (you inherently control what you publish about yourself).
export function resolverDetail(info, trust) {
  if (info.kind === 'namechain') {
    if (trust === 'verified') return 'Bidirectional binding confirmed: the key claims this name AND the chain record points back to it (KT-audited, spec §3.12.5b).';
    if (trust) return 'Binding not yet confirmed both ways — treat as unverified until the key‑claims‑name and chain‑record‑points‑back directions are both checked.';
    return 'On-chain record. Claiming costs the registrant once; resolving and messaging is free and needs no wallet (spec §3.12.5c).';
  }
  if (info.kind === 'dns') {
    if (trust === 'verified') return 'Forward DNS binding verified against key transparency, and the safety number was compared out-of-band.';
    if (trust === 'tofu') return 'Pinned on first contact (TOFU) via DNS + key transparency — not yet compared out-of-band.';
    if (trust === 'legacy') return 'Reaches you through the legacy gateway — no end-to-end key to verify yet.';
    if (trust) return 'Unverified — a DNS pointer that has not been checked against key transparency yet.';
    return info.note;
  }
  if (info.kind === 'self') return 'Self-resolving: the binding IS the key, so there is nothing to look up or audit — the strongest, zero-authority form.';
  if (info.kind === 'petname') return trust ? `A local label — this contact's real address is verified separately (${trust}).` : info.note;
  if (info.kind === 'directory') return 'A thin, KT-audited handle registry. It only introduces you — messages still route by the pinned key.';
  return info.note;
}
