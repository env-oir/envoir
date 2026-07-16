//! The Double Ratchet (spec §5.2.1(b)) — a direct, std/lean implementation of Perrin &
//! Marlinspike's algorithm: a DH ratchet plus symmetric-key sending/receiving chains, giving
//! per-message forward secrecy and (on bidirectional traffic) per-message post-compromise
//! security. Every message is authenticated by the AEAD tag under its per-message key — a
//! **shared-key MAC**, never a signature (§5.2.1(a), the deniability crux).

use std::collections::BTreeMap;

use x25519_dalek::StaticSecret;

use crate::crypto::{aead_open, aead_seal, dh, gen_keypair, kdf_ck, kdf_rk, public_of, Pub};
use crate::DeniableError;

/// Upper bound on message keys skipped within one chain (out-of-order / lost messages). A
/// `DeniableInit`/`DeniableMessage` claiming a wild jump is rejected rather than allowed to
/// exhaust memory (§16.9 rate-limit posture).
const MAX_SKIP: u32 = 1000;

/// Global upper bound on the *total* number of out-of-order message keys retained across the whole
/// session (every receiving chain), independent of the per-chain [`MAX_SKIP`] budget. Without it a
/// long-lived session — or a peer that repeatedly forces near-`MAX_SKIP` gaps across successive
/// DH-ratchet steps — accumulates skipped keys without bound. Set to `2 * MAX_SKIP`: ample headroom
/// for legitimate out-of-order delivery spanning a couple of chains, while capping worst-case
/// retention at ~64 KiB of key material. Exceeding it is rejected ([`DeniableError::TooManySkipped`])
/// rather than allocated.
const MAX_SKIPPED_KEYS: usize = 2 * MAX_SKIP as usize;

/// The per-message ratchet header (the cleartext `dh`/`pn`/`n` of a [`dmtap_core::deniable::DeniableMessage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub dh: Pub, // sender's current ratchet public key
    pub pn: u32, // messages in the sender's previous sending chain
    pub n: u32,  // message number in the sender's current sending chain
}

impl Header {
    /// The header bytes folded into the AEAD associated data, so any `dh`/`pn`/`n` tamper breaks
    /// the tag: `dh(32) ‖ pn(LE32) ‖ n(LE32)`.
    fn ad_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[..32].copy_from_slice(&self.dh);
        b[32..36].copy_from_slice(&self.pn.to_le_bytes());
        b[36..].copy_from_slice(&self.n.to_le_bytes());
        b
    }
}

/// A Double-Ratchet session. `Clone` is intentional: the property tests clone a party's state to
/// model an offline judge / a forger who holds exactly the shared symmetric material.
#[derive(Clone)]
pub struct DoubleRatchet {
    rk: [u8; 32],              // root key
    dhs: StaticSecret,         // our current ratchet secret
    dhs_pub: Pub,              // our current ratchet public
    dhr: Option<Pub>,          // their current ratchet public (None until first receive)
    cks: Option<[u8; 32]>,     // sending chain key
    ckr: Option<[u8; 32]>,     // receiving chain key
    ns: u32,                   // messages sent in the current sending chain
    nr: u32,                   // messages received in the current receiving chain
    pn: u32,                   // messages sent in the previous sending chain
    skipped: BTreeMap<(Pub, u32), [u8; 32]>, // out-of-order message keys, held to MAX_SKIP
}

impl DoubleRatchet {
    /// Initiator init (Signal `RatchetInitAlice`): the responder's **signed prekey** `spk_b` is
    /// the responder's initial ratchet public key; we immediately take one root step so our
    /// first message advances the DH ratchet.
    pub fn init_alice(sk: [u8; 32], spk_b: Pub) -> Self {
        let (dhs, dhs_pub) = gen_keypair();
        let (rk, cks) = kdf_rk(&sk, &dh(&dhs, &spk_b));
        DoubleRatchet {
            rk,
            dhs,
            dhs_pub,
            dhr: Some(spk_b),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
        }
    }

    /// Responder init (Signal `RatchetInitBob`): our **signed prekey** keypair is our initial
    /// ratchet keypair; the first received message drives the first DH-ratchet step.
    pub fn init_bob(sk: [u8; 32], spk_secret: StaticSecret) -> Self {
        let dhs_pub = public_of(&spk_secret);
        DoubleRatchet {
            rk: sk,
            dhs: spk_secret,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: BTreeMap::new(),
        }
    }

    /// Encrypt `plaintext` (a serialized `DeniablePayload`) under a fresh per-message key. `ad`
    /// is the session prefix `AD = IK_A ‖ IK_B`; the header is appended so it is authenticated.
    pub fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> (Header, Vec<u8>) {
        let ck = self.cks.expect("a sending chain exists once the session is established");
        let (next, mk) = kdf_ck(&ck);
        self.cks = Some(next);
        let header = Header { dh: self.dhs_pub, pn: self.pn, n: self.ns };
        self.ns += 1;
        let ct = aead_seal(&mk, &full_ad(ad, &header), plaintext);
        (header, ct)
    }

    /// Decrypt one message. Handles out-of-order delivery (skipped keys) and DH-ratchet steps.
    /// A wrong key / tampered ciphertext / tampered header fails the AEAD tag.
    pub fn decrypt(&mut self, ad: &[u8], header: Header, ct: &[u8]) -> Result<Vec<u8>, DeniableError> {
        // Deniable messages carry no signature, so the cleartext header (`dh`/`pn`/`n`) is entirely
        // attacker-controllable until the AEAD tag proves the message genuine. Every state mutation
        // the decrypt path performs — evicting a skipped key, advancing/stashing the receiving chain
        // (`skip`), and the DH-ratchet root/keypair roll (`dh_ratchet`) — is therefore staged on a
        // working COPY and committed to `self` ONLY after `aead_open` verifies. On any failure the
        // staged copy is dropped and `self` is byte-for-byte unchanged, so a single forged packet can
        // neither corrupt the root key (permanent session DoS) nor persist skipped keys (unbounded
        // memory). The success path derives exactly the same keys and leaves exactly the same state as
        // before.
        let mut staged = self.clone();
        let pt = staged.decrypt_staged(ad, header, ct)?;
        *self = staged; // commit — reached only when the tag verified
        Ok(pt)
    }

    /// The mutating decrypt body. It is only ever run against a staged clone produced by
    /// [`DoubleRatchet::decrypt`]; the caller discards the clone (and thus every mutation made here)
    /// unless this returns `Ok`, which happens only after the AEAD tag verifies.
    fn decrypt_staged(&mut self, ad: &[u8], header: Header, ct: &[u8]) -> Result<Vec<u8>, DeniableError> {
        // A message key we previously skipped (arrived late) — one-shot, removed on use. The removal
        // is on the staged copy, so a bad tag here does not consume the genuine stashed key either.
        if let Some(mk) = self.skipped.remove(&(header.dh, header.n)) {
            return aead_open(&mk, &full_ad(ad, &header), ct);
        }
        if self.dhr != Some(header.dh) {
            self.skip(header.pn)?; // finish the current receiving chain before ratcheting
            self.dh_ratchet(&header);
        }
        self.skip(header.n)?; // advance to this message's index (skipping any gap)
        let ck = self.ckr.expect("a receiving chain exists after the first DH-ratchet step");
        let (next, mk) = kdf_ck(&ck);
        self.ckr = Some(next);
        self.nr += 1;
        aead_open(&mk, &full_ad(ad, &header), ct)
    }

    /// Advance the receiving chain to index `until`, stashing intermediate message keys. Refuses
    /// to move backwards (`until < nr` is a no-op ⇒ an old message decrypts with the *current*
    /// key and fails the tag — the concrete forward-secrecy failure) or to skip more than
    /// [`MAX_SKIP`].
    fn skip(&mut self, until: u32) -> Result<(), DeniableError> {
        if until < self.nr {
            return Ok(()); // cannot rewind; caller will derive the wrong (current) key and fail
        }
        if until - self.nr > MAX_SKIP {
            return Err(DeniableError::TooManySkipped);
        }
        if self.ckr.is_none() && until > self.nr {
            return Err(DeniableError::DecryptFailed);
        }
        while self.nr < until {
            // Global cap across all chains — the per-call `MAX_SKIP` gate above bounds one skip, but
            // not cumulative retention; refuse rather than allocate unboundedly.
            if self.skipped.len() >= MAX_SKIPPED_KEYS {
                return Err(DeniableError::TooManySkipped);
            }
            let ck = self.ckr.expect("checked above");
            let (next, mk) = kdf_ck(&ck);
            self.ckr = Some(next);
            let dhr = self.dhr.expect("a receiving chain implies a peer ratchet key");
            self.skipped.insert((dhr, self.nr), mk);
            self.nr += 1;
        }
        Ok(())
    }

    /// One DH-ratchet step (Double Ratchet §3.5): reset chains, root-KDF the incoming DH into a
    /// new receiving chain, roll a fresh ratchet keypair, and root-KDF it into a new sending chain.
    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);
        let (rk1, ckr) = kdf_rk(&self.rk, &dh(&self.dhs, &header.dh));
        self.rk = rk1;
        self.ckr = Some(ckr);
        let (dhs, dhs_pub) = gen_keypair();
        self.dhs = dhs;
        self.dhs_pub = dhs_pub;
        let (rk2, cks) = kdf_rk(&self.rk, &dh(&self.dhs, &header.dh));
        self.rk = rk2;
        self.cks = Some(cks);
    }

    /// **Constructive proof of repudiation (§5.2.1(e)).** Using ONLY this party's receiving-chain
    /// state — the shared symmetric material any receiver legitimately holds — forge a message
    /// that appears to come from the peer. It touches no signing key and no peer secret; the
    /// result is byte-shaped identically to a genuine peer message and is accepted by a copy of
    /// this session's receiving state. Because the receiver can mint it, a captured transcript
    /// proves nothing about the peer's authorship. Test-only.
    ///
    /// Forges the peer's *next* message in the current receiving chain (index `nr`).
    pub fn forge_incoming(&self, ad: &[u8], plaintext: &[u8]) -> Option<(Header, Vec<u8>)> {
        let ck = self.ckr?;
        let dhr = self.dhr?;
        let (_next, mk) = kdf_ck(&ck);
        let header = Header { dh: dhr, pn: self.pn, n: self.nr };
        let ct = aead_seal(&mk, &full_ad(ad, &header), plaintext);
        Some((header, ct))
    }

    /// Test-only: the number of out-of-order message keys currently retained (bounded by
    /// [`MAX_SKIPPED_KEYS`]).
    #[cfg(test)]
    pub(crate) fn skipped_len(&self) -> usize {
        self.skipped.len()
    }
}

/// `AD = (IK_A ‖ IK_B) ‖ header` — the session identity binding plus the per-message header.
fn full_ad(session_ad: &[u8], header: &Header) -> Vec<u8> {
    let hb = header.ad_bytes();
    let mut v = Vec::with_capacity(session_ad.len() + hb.len());
    v.extend_from_slice(session_ad);
    v.extend_from_slice(&hb);
    v
}
