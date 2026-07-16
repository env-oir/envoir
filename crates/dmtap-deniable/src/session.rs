//! The deniable 1:1 session (spec §5.2.1) — X3DH over the dedicated `idk`, the responder prekey
//! store with replay defense, and the established Double-Ratchet session that seals/opens
//! [`DeniablePayload`]s.
//!
//! Orientation is pinned once and for all: **A = initiator, B = responder**, and the AEAD
//! associated data is `AD = IK_A ‖ IK_B` (the two Ed25519 identity keys), never reordered.

use std::collections::BTreeMap;

use dmtap_core::deniable::{
    DeniableInit, DeniableMessage, DeniablePayload, DeniablePrekeyBundle, DENIABLE_IDK_DS,
};
use dmtap_core::id::ContentId;
use dmtap_core::identity::{verify_domain, IdentityKey};
use dmtap_core::suite::Suite;
use dmtap_core::TimestampMs;
use x25519_dalek::StaticSecret;

use crate::crypto::{dh, gen_keypair, parse_pub, x3dh_root, Pub};
use crate::ratchet::{DoubleRatchet, Header};
use crate::DeniableError;

/// `AD = IK_A ‖ IK_B`, initiator‖responder (§18.3.9). Pinned orientation.
fn associated_data(ik_a: &[u8], ik_b: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(ik_a.len() + ik_b.len());
    ad.extend_from_slice(ik_a);
    ad.extend_from_slice(ik_b);
    ad
}

// --- one party's long-term deniable identity --------------------------------------------------

/// A party's long-term deniable identity: the Ed25519 `IK` (which only *certifies*, never does DH)
/// plus the dedicated long-term X25519 `idk` it certifies (§5.2.1(a)). Keeping `IK` DH-free is
/// what lets it live in a sign-only hardware keystore.
pub struct DeniableIdentity {
    ik: IdentityKey,
    idk: StaticSecret,
    idk_pub: Pub,
    idk_cert: Vec<u8>, // IK's signature over idk_pub, DS `DMTAP-v0/deniable-idk`
}

impl DeniableIdentity {
    /// Provision a fresh `idk` and certify it under `ik` (§5.2.1(a), §18.9.10).
    pub fn new(ik: IdentityKey) -> Self {
        let (idk, idk_pub) = gen_keypair();
        let idk_cert = ik.sign_domain(DENIABLE_IDK_DS, &idk_pub);
        DeniableIdentity { ik, idk, idk_pub, idk_cert }
    }

    /// The Ed25519 `IK` public bytes (used for AD binding and `idk` certification).
    pub fn ik_public(&self) -> Vec<u8> {
        self.ik.public()
    }
}

// --- responder: prekey store + replay defense -------------------------------------------------

/// The responder half: publishes a [`DeniablePrekeyBundle`] and consumes incoming
/// [`DeniableInit`]s, enforcing the §5.2.1 first-message replay defense.
pub struct DeniableResponder {
    id: DeniableIdentity,
    spk: StaticSecret,
    spk_pub: Pub,
    /// One-time prekeys keyed by their content address (`ContentId::of(pub)`), removed on use.
    opks: BTreeMap<Vec<u8>, StaticSecret>,
    bundle: DeniablePrekeyBundle,
    /// Replay cache of consumed last-resort initiator ephemerals: `ek_a ‖ idk_a` (§5.2.1).
    consumed_lastresort: std::collections::BTreeSet<Vec<u8>>,
}

impl DeniableResponder {
    /// Provision `spk` + `num_opks` one-time prekeys and issue the signed bundle (§18.4.8). The
    /// bundle's `idk`/`idk_sig`/`spk_sig`/`sig` are all produced by [`DeniablePrekeyBundle::issue`]
    /// under `ik` (the reference uses `IK` itself as the IK-authorized device key).
    pub fn new(id: DeniableIdentity, num_opks: usize, version: u64, ts: TimestampMs) -> Self {
        let (spk, spk_pub) = gen_keypair();
        let mut opks = BTreeMap::new();
        let mut opk_pubs = Vec::with_capacity(num_opks);
        for _ in 0..num_opks {
            let (s, p) = gen_keypair();
            opk_pubs.push(p.to_vec());
            opks.insert(ContentId::of(&p).as_bytes().to_vec(), s);
        }
        let bundle = DeniablePrekeyBundle::issue(
            &id.ik,
            id.idk_pub.to_vec(),
            spk_pub.to_vec(),
            opk_pubs,
            version,
            ts,
        );
        DeniableResponder {
            id,
            spk,
            spk_pub,
            opks,
            bundle,
            consumed_lastresort: Default::default(),
        }
    }

    /// The published, signed bundle an initiator consumes.
    pub fn bundle(&self) -> &DeniablePrekeyBundle {
        &self.bundle
    }

    /// Number of unspent one-time prekeys remaining.
    pub fn opks_remaining(&self) -> usize {
        self.opks.len()
    }

    /// Accept a `DeniableInit` (§5.2.1(a)): verify the initiator's `idk_a` certification, enforce
    /// the replay defense, run the responder side of X3DH, boot the Double Ratchet, and decrypt
    /// the embedded first message into a [`DeniablePayload`]. Consumes any referenced one-time
    /// prekey.
    pub fn accept(
        &mut self,
        init: &DeniableInit,
    ) -> Result<(DeniableSession, DeniablePayload), DeniableError> {
        if init.suite != Suite::Classical {
            return Err(DeniableError::UnsupportedSuite(init.suite.as_u8()));
        }
        // The one long-term signature on the initiator side certifies a *public DH key*, not a
        // message — verify it under the initiator's IK (deniability-neutral, §5.2.1(a)).
        verify_domain(&init.ik_a, DENIABLE_IDK_DS, &init.idk_a, &init.idk_a_cert)
            .map_err(|_| DeniableError::BadCertification)?;

        // The init must target our current signed prekey (a rotated/withdrawn spk ⇒ reject).
        if init.spk_ref != ContentId::of(&self.spk_pub) {
            return Err(DeniableError::X3dhFailed);
        }

        let idk_a = parse_pub(&init.idk_a)?;
        let ek_a = parse_pub(&init.ek_a)?;

        // --- replay defense (§5.2.1, last-resort init) -------------------------------------
        let opk_secret: Option<StaticSecret> = match &init.opk_ref {
            Some(opk_ref) => {
                // Consuming path: the one-time prekey must still be unspent; reuse ⇒ reject
                // (this also rejects a replayed opk-consuming init, since it is now gone).
                Some(
                    self.opks
                        .remove(opk_ref.as_bytes())
                        .ok_or(DeniableError::X3dhFailed)?,
                )
            }
            None => {
                // Last-resort / signed-prekey-only path.
                // (i) Prefer a one-time prekey: reject last-resort while any opk is unspent.
                if !self.opks.is_empty() {
                    return Err(DeniableError::X3dhFailed);
                }
                // (ii) Replay cache of consumed (ek_a ‖ idk_a): drop repeats.
                let mut tag = ek_a.to_vec();
                tag.extend_from_slice(&idk_a);
                if !self.consumed_lastresort.insert(tag) {
                    return Err(DeniableError::ReplayRejected);
                }
                None
            }
        };

        // --- responder X3DH (mirror of the initiator's DH ordering) ------------------------
        // DH1 = DH(spk_b, idk_a), DH2 = DH(idk_b, ek_a), DH3 = DH(spk_b, ek_a), DH4 = DH(opk_b, ek_a)
        let mut dhs = vec![
            dh(&self.spk, &idk_a),
            dh(&self.id.idk, &ek_a),
            dh(&self.spk, &ek_a),
        ];
        if let Some(opk) = &opk_secret {
            dhs.push(dh(opk, &ek_a));
        }
        let sk = x3dh_root(&dhs);

        let ad = associated_data(&init.ik_a, &self.id.ik_public());
        let mut ratchet = DoubleRatchet::init_bob(sk, self.spk.clone());

        let header = header_from_message(&init.msg)?;
        let pt = ratchet.decrypt(&ad, header, &init.msg.ct)?;
        let payload = DeniablePayload::from_det_cbor(&pt)?;

        let session = DeniableSession { ratchet, ad };
        Ok((session, payload))
    }
}

// --- initiator --------------------------------------------------------------------------------

/// Run the initiator side of X3DH against `bundle` and produce the [`DeniableInit`] (embedding the
/// first ratchet message) plus the live [`DeniableSession`] (§5.2.1(a)). Consumes a one-time
/// prekey when the bundle offers one (the replay-resistant path).
pub fn initiate(
    me: &DeniableIdentity,
    bundle: &DeniablePrekeyBundle,
    first: &DeniablePayload,
) -> Result<(DeniableSession, DeniableInit), DeniableError> {
    if bundle.suite != Suite::Classical {
        return Err(DeniableError::UnsupportedSuite(bundle.suite.as_u8()));
    }
    // Verify the responder's whole bundle: idk_sig, spk_sig, and the bundle sig (§18.9.10).
    bundle.verify().map_err(|_| DeniableError::BadCertification)?;

    let idk_b = parse_pub(&bundle.idk)?;
    let spk_b = parse_pub(&bundle.spk)?;

    // Prefer a one-time prekey when offered (replay resistance, §5.2.1).
    let opk_b: Option<(Pub, ContentId)> = match bundle.opks.first() {
        Some(o) => {
            let p = parse_pub(o)?;
            Some((p, ContentId::of(&p)))
        }
        None => None,
    };

    let (ek, ek_pub) = gen_keypair();

    // DH1 = DH(idk_a, spk_b), DH2 = DH(ek_a, idk_b), DH3 = DH(ek_a, spk_b), DH4 = DH(ek_a, opk_b)
    let mut dhs = vec![
        dh(&me.idk, &spk_b),
        dh(&ek, &idk_b),
        dh(&ek, &spk_b),
    ];
    if let Some((opk, _)) = &opk_b {
        dhs.push(dh(&ek, opk));
    }
    let sk = x3dh_root(&dhs);

    let ad = associated_data(&me.ik_public(), &bundle.ik);
    let mut ratchet = DoubleRatchet::init_alice(sk, spk_b);
    let (header, ct) = ratchet.encrypt(&ad, &first.det_cbor());

    let msg = DeniableMessage { dh: header.dh.to_vec(), pn: header.pn, n: header.n, ct };
    let init = DeniableInit {
        suite: Suite::Classical,
        ik_a: me.ik_public(),
        idk_a: me.idk_pub.to_vec(),
        idk_a_cert: me.idk_cert.clone(),
        ek_a: ek_pub.to_vec(),
        spk_ref: ContentId::of(&spk_b),
        opk_ref: opk_b.map(|(_, r)| r),
        kem_ct: None,
        kem_ref: None,
        msg,
    };
    Ok((DeniableSession { ratchet, ad }, init))
}

// --- the established session ------------------------------------------------------------------

/// A live deniable session: a Double Ratchet plus the pinned `AD = IK_A ‖ IK_B`. `encrypt`/
/// `decrypt` move whole [`DeniablePayload`]s; authentication is the ratchet's AEAD tag.
pub struct DeniableSession {
    ratchet: DoubleRatchet,
    ad: Vec<u8>,
}

impl DeniableSession {
    /// Seal a payload into a `DeniableMessage` (no signature — the tag is the MAC).
    pub fn encrypt(&mut self, payload: &DeniablePayload) -> DeniableMessage {
        let (header, ct) = self.ratchet.encrypt(&self.ad, &payload.det_cbor());
        DeniableMessage { dh: header.dh.to_vec(), pn: header.pn, n: header.n, ct }
    }

    /// Open a `DeniableMessage` back into a payload. A tampered header/ciphertext, a wrong key, or
    /// a rewound (already-consumed) message fails.
    pub fn decrypt(&mut self, msg: &DeniableMessage) -> Result<DeniablePayload, DeniableError> {
        let header = header_from_message(msg)?;
        let pt = self.ratchet.decrypt(&self.ad, header, &msg.ct)?;
        Ok(DeniablePayload::from_det_cbor(&pt)?)
    }

    /// **Constructive repudiation (§5.2.1(e)), test/demonstration surface.** Using only this
    /// party's own receiving-chain state, forge a `DeniableMessage` that appears authored by the
    /// peer — no signing key, no peer secret involved. A peer message and a forgery are
    /// indistinguishable, which is precisely why the transcript is deniable. Returns `None` if no
    /// receiving chain exists yet.
    pub fn forge_peer_message(&self, payload: &DeniablePayload) -> Option<DeniableMessage> {
        let (header, ct) = self.ratchet.forge_incoming(&self.ad, &payload.det_cbor())?;
        Some(DeniableMessage { dh: header.dh.to_vec(), pn: header.pn, n: header.n, ct })
    }

    /// Clone the session (models an offline judge / a party that keeps a snapshot). Test-only.
    pub fn snapshot(&self) -> DeniableSession {
        DeniableSession { ratchet: self.ratchet.clone(), ad: self.ad.clone() }
    }
}

/// Reconstruct a ratchet [`Header`] from a wire [`DeniableMessage`], validating the `dh` length.
fn header_from_message(msg: &DeniableMessage) -> Result<Header, DeniableError> {
    Ok(Header { dh: parse_pub(&msg.dh)?, pn: msg.pn, n: msg.n })
}
