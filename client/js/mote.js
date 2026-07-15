// mote.js — build a MOTE, the DMTAP message object (spec §2).
//
// Three nested layers (spec §2.1): outer (mixnet / sealed sender), envelope (signed,
// content-addressed), payload (E2E-encrypted). The payload signature is REAL (Web Crypto);
// "encryption" and the outer onion are represented structurally (the demo has no real
// recipient key exchange / mixnet). The content-address id is SHA-256 (stand-in for BLAKE3,
// spec §2.2). Every data class — mail, chat, calendar, contact, group post, file offer — is
// the same object with a different `kind` (spec §8.5, one substrate).

import { sha256, sign, toB64u, hex, currentIdentity } from './identity.js';

export const KIND = { mail: 0x00, chat: 0x01, calendar: 0x02, contact: 0x03, group: 0x04, file_offer: 0x05 };
export const TIER = { private: 'private', fast: 'fast' };

const enc = new TextEncoder();

export async function buildMote({ to, kind, subject, body, tier, attach, group }) {
  const id = currentIdentity();
  const ts = Date.now();

  const payload = {
    from: id.ik,
    headers: { subject: subject || null, mime: 'text/plain', thread: null, cc: [] },
    body: body || '',
    refs: [],
    attach: attach || [],
    group: group || null,   // group post = an MLS group message (spec §5.8)
    expires: null,
  };
  const payloadBytes = enc.encode(JSON.stringify(payload));
  const sig = await sign(payloadBytes);           // REAL signature over the payload
  payload.sig = toB64u(sig);

  const ciphertext = payloadBytes;                 // (marked sealed; not actually encrypted here)
  const contentId = 'b3:' + hex(await sha256(ciphertext), 32);

  const envelope = {
    v: 0, suite: 0x01, id: contentId, to, ts, kind,
    sealed: true, sig_present: sig.length > 0,
    group: group ? group.address : null,
  };
  const outer = {
    tier,
    onion: tier === 'private',
    padded: true,
    sender_visible: false,
    fanout: group ? (group.mode === 'broadcast' ? 'per-member sealed (hidden list)' : 'MLS tree') : null,
  };

  return { outer, envelope, payload, contentId, ts, kind, tier, sigLen: sig.length, group: group || null };
}

export function kindName(k) {
  return Object.entries(KIND).find(([, v]) => v === k)?.[0] || 'unknown';
}
