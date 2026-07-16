//! Deniable 1:1 mode objects — spec §5.2.1, §18.3.9 / §18.3.10 / §18.4.8.
//!
//! The optional Signal-style (X3DH/PQXDH + Double Ratchet) channel. Its signing story is
//! **deliberately asymmetric** (§18.9.10): a [`DeniablePrekeyBundle`] carries two signatures over
//! *public prekeys only* (never any message), while the transport frames
//! ([`DeniableFrame`] = [`DeniableInit`] / [`DeniableMessage`]) and the sealed [`DeniablePayload`]
//! carry **no signature at all** — authentication is the Double-Ratchet shared-key MAC (the AEAD
//! tag), which either party could compute, and that absence is exactly what makes the mode
//! repudiable.
//!
//! All objects are integer-keyed canonical CBOR (§18.1.2). The transport frames use key `0` as a
//! variant discriminator (`DeniableInit`=1, `DeniableMessage`=2), matching the tagged-choice
//! convention of [`crate::mote::ChallengeResponse`].

use crate::cbor::{self, as_array, as_bytes, as_u32, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::mote::{Attachment, Headers, Kind};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.10 domain-separation tags (ASCII ‖ trailing `0x00`; `sign_domain` prepends them).
pub const DENIABLE_PREKEYS_DS: &[u8] = b"DMTAP-v0/deniable-prekeys\x00";
pub const DENIABLE_SPK_DS: &[u8] = b"DMTAP-v0/deniable-spk\x00";

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

// --- DeniablePrekeyBundle (§18.4.8) --------------------------------------------------------

/// The published X3DH/PQXDH prekeys for the deniable mode (spec §5.2.1, §18.4.8). Two signatures:
/// `spk_sig` (key 4) over the raw signed prekey, and `sig` (key 10) over the whole bundle — both
/// by an `IK`-authorized device key (the reference uses `ik` itself as that key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniablePrekeyBundle {
    pub suite: Suite,             // key 1 — 0x01 X3DH or 0x02 PQXDH
    pub ik: Vec<u8>,              // key 2 — the identity these prekeys belong to
    pub spk: Vec<u8>,             // key 3 — signed prekey (X25519 DH public)
    pub spk_sig: Vec<u8>,         // key 4 — device-key sig over `spk` (DS `DMTAP-v0/deniable-spk`)
    pub opks: Vec<Vec<u8>>,       // key 5 — one-time prekeys; MAY be empty
    pub last_kem: Option<Vec<u8>>, // key 6 — (PQ) last-resort ML-KEM enc key
    pub okems: Option<Vec<Vec<u8>>>, // key 7 — (PQ) one-time ML-KEM enc keys
    pub version: u64,             // key 8 — monotonic; reject older-or-equal
    pub ts: TimestampMs,          // key 9
    pub sig: Vec<u8>,             // key 10 — §18.9.10, over det_cbor(bundle ∖ {10})
}

impl DeniablePrekeyBundle {
    /// Integer-keyed canonical map (§18.4.8). `include_sig=false` omits key 10 for the §18.9.10
    /// signing body (which still covers `spk_sig`, key 4).
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::Bytes(self.spk.clone())),
            (4, Cv::Bytes(self.spk_sig.clone())),
            (5, Cv::Array(self.opks.iter().map(|o| Cv::Bytes(o.clone())).collect())),
        ];
        if let Some(k) = &self.last_kem {
            m.push((6, Cv::Bytes(k.clone())));
        }
        if let Some(ks) = &self.okems {
            m.push((7, Cv::Array(ks.iter().map(|k| Cv::Bytes(k.clone())).collect())));
        }
        m.push((8, Cv::U64(self.version)));
        m.push((9, Cv::U64(self.ts)));
        if include_sig {
            m.push((10, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.10 signing body for `sig`: deterministic CBOR of the bundle with `sig` omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a bundle (§18.4.8), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let ik = as_bytes(f.req(2)?)?;
        let spk = as_bytes(f.req(3)?)?;
        let spk_sig = as_bytes(f.req(4)?)?;
        let opks = as_array(f.req(5)?)?
            .into_iter()
            .map(as_bytes)
            .collect::<Result<_, _>>()?;
        let last_kem = f.take(6).map(as_bytes).transpose()?;
        let okems = match f.take(7) {
            Some(c) => Some(as_array(c)?.into_iter().map(as_bytes).collect::<Result<_, _>>()?),
            None => None,
        };
        let version = as_u64(f.req(8)?)?;
        let ts = as_u64(f.req(9)?)?;
        let sig = as_bytes(f.req(10)?)?;
        f.deny_unknown()?;
        Ok(DeniablePrekeyBundle {
            suite, ik, spk, spk_sig, opks, last_kem, okems, version, ts, sig,
        })
    }

    /// Publish (sign) a classical bundle: the device key signs `spk` (`spk_sig`) and then the whole
    /// body (`sig`) per §18.9.10. `ik` is set from the signer (an `IK` is `IK`-authorized).
    pub fn issue(
        device: &IdentityKey,
        spk: Vec<u8>,
        opks: Vec<Vec<u8>>,
        version: u64,
        ts: TimestampMs,
    ) -> DeniablePrekeyBundle {
        let spk_sig = device.sign_domain(DENIABLE_SPK_DS, &spk);
        let mut b = DeniablePrekeyBundle {
            suite: Suite::Classical,
            ik: device.public(),
            spk,
            spk_sig,
            opks,
            last_kem: None,
            okems: None,
            version,
            ts,
            sig: Vec::new(),
        };
        b.sig = device.sign_domain(DENIABLE_PREKEYS_DS, &b.signing_body());
        b
    }

    /// Verify both signatures under `ik` (§18.9.10): the bundle `sig` and the `spk_sig` over `spk`.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.ik, DENIABLE_SPK_DS, &self.spk, &self.spk_sig)?;
        verify_domain(&self.ik, DENIABLE_PREKEYS_DS, &self.signing_body(), &self.sig)
    }
}

// --- DeniableFrame = DeniableInit / DeniableMessage (§18.3.9) ------------------------------

/// A subsequent Double-Ratchet message (§18.3.9, discriminator `2`). Carries **no signature** —
/// the AEAD tag on `ct` is the shared-key MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniableMessage {
    pub dh: Vec<u8>, // key 1 — sender's current ratchet X25519 public key
    pub pn: u32,     // key 2 — messages in the previous sending chain
    pub n: u32,      // key 3 — message number in the current sending chain
    pub ct: Vec<u8>, // key 4 — AEAD ciphertext of the DeniablePayload
}

impl DeniableMessage {
    /// Integer-keyed canonical map with the discriminator (§18.3.9, key 0 = 2).
    fn to_cv(&self) -> Cv {
        Cv::Map(vec![
            (0, Cv::U64(2)),
            (1, Cv::Bytes(self.dh.clone())),
            (2, Cv::U64(self.pn as u64)),
            (3, Cv::U64(self.n as u64)),
            (4, Cv::Bytes(self.ct.clone())),
        ])
    }

    /// The body (without the discriminator) — used when embedded as `DeniableInit.msg` (key 8).
    fn from_fields(f: &mut Fields) -> Result<Self, CborError> {
        let dh = as_bytes(f.req(1)?)?;
        let pn = as_u32(f.req(2)?)?;
        let n = as_u32(f.req(3)?)?;
        let ct = as_bytes(f.req(4)?)?;
        Ok(DeniableMessage { dh, pn, n, ct })
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let disc = as_u64(f.req(0)?)?;
        if disc != 2 {
            return Err(CborError::UnknownDiscriminant(disc));
        }
        let out = Self::from_fields(&mut f)?;
        f.deny_unknown()?;
        Ok(out)
    }
}

/// The X3DH/PQXDH first message (§18.3.9, discriminator `1`). Carries **no signature**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniableInit {
    pub suite: Suite,                // key 1 — 0x01 X3DH / 0x02 PQXDH
    pub ik_a: Vec<u8>,               // key 2 — initiator IK
    pub ek_a: Vec<u8>,               // key 3 — initiator ephemeral X25519 public
    pub spk_ref: ContentId,          // key 4 — content-addr of the responder signed prekey consumed
    pub opk_ref: Option<ContentId>,  // key 5 — content-addr of the one-time prekey consumed
    pub kem_ct: Option<Vec<u8>>,     // key 6 — (PQ) KEM ciphertext, iff suite = 0x02
    pub kem_ref: Option<ContentId>,  // key 7 — (PQ) content-addr of the one-time KEM prekey
    pub msg: DeniableMessage,        // key 8 — the first Double-Ratchet message (embedded)
}

impl DeniableInit {
    /// Integer-keyed canonical map with the discriminator (§18.3.9, key 0 = 1).
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (0u64, Cv::U64(1)),
            (1, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Bytes(self.ik_a.clone())),
            (3, Cv::Bytes(self.ek_a.clone())),
            (4, Cv::Bytes(self.spk_ref.as_bytes().to_vec())),
        ];
        if let Some(r) = &self.opk_ref {
            m.push((5, Cv::Bytes(r.as_bytes().to_vec())));
        }
        if let Some(c) = &self.kem_ct {
            m.push((6, Cv::Bytes(c.clone())));
        }
        if let Some(r) = &self.kem_ref {
            m.push((7, Cv::Bytes(r.as_bytes().to_vec())));
        }
        m.push((8, self.msg.to_cv()));
        Cv::Map(m)
    }

    fn from_fields(f: &mut Fields) -> Result<Self, CborError> {
        let suite = suite_from_cv(f.req(1)?)?;
        let ik_a = as_bytes(f.req(2)?)?;
        let ek_a = as_bytes(f.req(3)?)?;
        let spk_ref = ContentId(as_bytes(f.req(4)?)?);
        let opk_ref = f.take(5).map(as_bytes).transpose()?.map(ContentId);
        let kem_ct = f.take(6).map(as_bytes).transpose()?;
        let kem_ref = f.take(7).map(as_bytes).transpose()?.map(ContentId);
        let msg = DeniableMessage::from_cv(f.req(8)?)?;
        Ok(DeniableInit { suite, ik_a, ek_a, spk_ref, opk_ref, kem_ct, kem_ref, msg })
    }
}

/// The deniable transport frame (§18.3.9) — a tagged choice on key `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniableFrame {
    Init(DeniableInit),
    Message(DeniableMessage),
}

impl DeniableFrame {
    fn to_cv(&self) -> Cv {
        match self {
            DeniableFrame::Init(i) => i.to_cv(),
            DeniableFrame::Message(m) => m.to_cv(),
        }
    }

    /// The exact wire bytes of this frame (carried as `Envelope.ciphertext` of a `kind=0x0b` MOTE).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a frame (§18.3.9), dispatching on key `0`; fails closed on an unknown discriminator.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let disc = as_u64(f.req(0)?)?;
        let out = match disc {
            1 => DeniableFrame::Init(DeniableInit::from_fields(&mut f)?),
            2 => DeniableFrame::Message(DeniableMessage::from_fields(&mut f)?),
            other => return Err(CborError::UnknownDiscriminant(other)),
        };
        f.deny_unknown()?;
        Ok(out)
    }
}

// --- DeniablePayload (§18.3.10) ------------------------------------------------------------

/// The plaintext sealed into a [`DeniableMessage::ct`] (§18.3.10) — the structural twin of
/// [`crate::mote::Payload`] with the identity signature **removed** (key 2 carries the real content
/// `kind` instead). Authentication is the ratchet MAC, not a signature; a decoder MUST reject any
/// smuggled signature field (`ERR_DENIABLE_SIGNATURE_PRESENT`, §18.3.10). This decoder fails closed
/// on **any** unrecognized key, so a smuggled signature is rejected regardless of the key it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniablePayload {
    pub from: Vec<u8>,             // key 1 — sender IK (bound by X3DH, NOT a signature)
    pub kind: Kind,               // key 2 — the real content kind (§2.3)
    pub headers: Headers,         // key 3
    pub body: Vec<u8>,            // key 4
    pub refs: Vec<ContentId>,     // key 5 — MAY be empty
    pub attach: Vec<Attachment>,  // key 6 — MAY be empty
    pub expires: Option<TimestampMs>, // key 7
}

impl DeniablePayload {
    /// Integer-keyed canonical map (§18.3.10). No signature field ever.
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Bytes(self.from.clone())),
            (2, Cv::U64(self.kind.as_u8() as u64)),
            (3, self.headers.to_cv()),
            (4, Cv::Bytes(self.body.clone())),
            (5, Cv::Array(self.refs.iter().map(|r| Cv::Bytes(r.as_bytes().to_vec())).collect())),
            (6, Cv::Array(self.attach.iter().map(Attachment::to_cv).collect())),
        ];
        if let Some(e) = self.expires {
            m.push((7, Cv::U64(e)));
        }
        Cv::Map(m)
    }

    /// The exact plaintext bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv())
    }

    /// Decode a deniable payload (§18.3.10), failing closed on any violation. Any key beyond the
    /// recognized `1..=7` (e.g. a smuggled signature) is rejected via `deny_unknown` — the
    /// concrete manifestation of `ERR_DENIABLE_SIGNATURE_PRESENT`.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let from = as_bytes(f.req(1)?)?;
        let kind = Kind::from_u8(as_u8(f.req(2)?)?).ok_or(CborError::UnknownDiscriminant(0))?;
        let headers = Headers::from_cv(f.req(3)?)?;
        let body = as_bytes(f.req(4)?)?;
        let refs = as_array(f.req(5)?)?
            .into_iter()
            .map(|c| as_bytes(c).map(ContentId))
            .collect::<Result<_, _>>()?;
        let attach = as_array(f.req(6)?)?
            .into_iter()
            .map(Attachment::from_cv)
            .collect::<Result<_, _>>()?;
        let expires = f.take(7).map(as_u64).transpose()?;
        f.deny_unknown()?;
        Ok(DeniablePayload { from, kind, headers, body, refs, attach, expires })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[test]
    fn prekey_bundle_signs_verifies_and_round_trips() {
        let b = DeniablePrekeyBundle::issue(
            &key(0x11),
            vec![0xab; 32],
            vec![vec![1u8; 32], vec![2u8; 32]],
            3,
            1_700_000_000_000,
        );
        assert!(b.verify().is_ok());
        let bytes = b.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "bundle is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite)");
        let back = DeniablePrekeyBundle::from_det_cbor(&bytes).unwrap();
        assert_eq!(b, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_bundle_fails_signature() {
        let mut b = DeniablePrekeyBundle::issue(&key(0x11), vec![0xab; 32], vec![], 1, 1);
        b.spk[0] ^= 0xff; // invalidates both spk_sig and sig
        assert_eq!(b.verify(), Err(IdentityError::BadSignature));
    }

    fn sample_message() -> DeniableMessage {
        DeniableMessage { dh: vec![0x09; 32], pn: 0, n: 5, ct: vec![0xde, 0xad, 0xbe, 0xef] }
    }

    #[test]
    fn deniable_message_frame_round_trips() {
        let frame = DeniableFrame::Message(sample_message());
        let bytes = frame.det_cbor();
        // First map key is the discriminator (integer 0), value 2.
        assert_eq!(bytes[0] & 0xe0, 0xa0);
        assert_eq!(bytes[1], 0x00, "first key is the discriminator 0");
        assert_eq!(bytes[2], 0x02, "DeniableMessage discriminator = 2");
        assert_eq!(DeniableFrame::from_det_cbor(&bytes).unwrap(), frame);
    }

    #[test]
    fn deniable_init_frame_round_trips_with_embedded_message() {
        let init = DeniableInit {
            suite: Suite::Classical,
            ik_a: key(0x11).public(),
            ek_a: vec![0x33; 32],
            spk_ref: ContentId::of(b"responder-spk"),
            opk_ref: Some(ContentId::of(b"responder-opk")),
            kem_ct: None,
            kem_ref: None,
            msg: sample_message(),
        };
        let frame = DeniableFrame::Init(init);
        let bytes = frame.det_cbor();
        assert_eq!(bytes[1], 0x00, "first key is the discriminator 0");
        assert_eq!(bytes[2], 0x01, "DeniableInit discriminator = 1");
        assert_eq!(DeniableFrame::from_det_cbor(&bytes).unwrap(), frame);
    }

    #[test]
    fn deniable_payload_round_trips_and_rejects_smuggled_signature() {
        let p = DeniablePayload {
            from: key(0x11).public(),
            kind: Kind::Chat,
            headers: Headers { subject: Some("hi".into()), ..Default::default() },
            body: b"deniable hello".to_vec(),
            refs: vec![],
            attach: vec![],
            expires: None,
        };
        let bytes = p.det_cbor();
        assert_eq!(DeniablePayload::from_det_cbor(&bytes).unwrap(), p);

        // A DeniablePayload MUST NOT carry a signature — smuggle one under an extra key and it
        // MUST be rejected (ERR_DENIABLE_SIGNATURE_PRESENT, §18.3.10).
        let mut m = match cbor::decode(&bytes).unwrap() {
            Cv::Map(m) => m,
            _ => unreachable!(),
        };
        m.push((8, Cv::Bytes(vec![0u8; 64]))); // a stray "signature"
        let leaky = cbor::encode(&Cv::Map(m));
        assert_eq!(DeniablePayload::from_det_cbor(&leaky), Err(CborError::UnknownKey(8)));
    }
}
