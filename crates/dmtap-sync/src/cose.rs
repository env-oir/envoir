//! Per-op authenticity: the RFC 9052 `COSE_Sign1` envelope frozen by `SYNC.md` §4.1 (`SYNC-OP-02`).
//!
//! This is the whole difference between §5.6's single-owner device cluster and the substrate's
//! multi-author sync: §5.6 ops ride **unsigned** inside an MLS group, so authenticity is ambient
//! group membership; here **the operation itself is the unit of authenticity**, so two products
//! built by different parties can converge on a shared namespace with no shared secret.
//!
//! The wire object is the four-element array `[protected, unprotected, payload, signature]`,
//! itself deterministic CBOR:
//!
//! * `protected` = `bstr(det_cbor({1: alg = -8 EdDSA, 4: kid = hlc.author}))`. `kid` lives in the
//!   **integrity-covered** header on purpose: the asserted signer key is folded into the
//!   signature, so a key substitution is a *verification failure*, never a silent
//!   mis-attribution.
//! * `unprotected` = the empty map `0xa0`. Nothing that matters travels outside the signature.
//! * `payload` = `bstr(det_cbor(SyncOp))`, always inline, never detached.
//! * `signature` = `Ed25519(sk_author, det_cbor(Sig_structure))` over the RFC 9052 §4.4
//!   `["Signature1", protected, external_aad, payload]` with **`external_aad` = the DS-tag
//!   `DMTAP-SYNC-v0/op` ‖ `0x00`**.
//!
//! Carrying the DS-tag in `external_aad` is the RFC-9052-idiomatic realization of §18.1.6's
//! `preimage = DS-tag ‖ body`: the tag is bound into the signature yet **never transmitted**, so a
//! `COSE_Sign1` minted for any other DMTAP object can never verify as a `SyncOp` — and there is no
//! discriminator flag on the wire for a peer to flip. A flipped payload byte, a substituted `kid`,
//! or any other `external_aad` is `ERR_SYNC_OP_SIG_INVALID` (`0x0A02`).

use crate::detcbor::{decode, encode, SVal};
use crate::error::SyncError;
use crate::wire::{SyncOp, DS_OP};
use dmtap_core::identity::{verify_domain, IdentityKey};

/// COSE header label `1` — `alg`.
pub const HDR_ALG: u64 = 1;
/// COSE header label `4` — `kid`.
pub const HDR_KID: u64 = 4;
/// COSE algorithm `-8` — EdDSA (suite `0x01`, Ed25519).
pub const ALG_EDDSA: i64 = -8;

/// The `external_aad` every `SyncOp` signature binds: `DMTAP-SYNC-v0/op ‖ 0x00` (§4.1).
pub fn op_external_aad() -> Vec<u8> {
    let mut v = DS_OP.to_vec();
    v.push(0x00);
    v
}

/// The protected header **bstr contents** for `author`: `det_cbor({1: -8, 4: author})`.
pub fn protected_header(author: &[u8]) -> Vec<u8> {
    encode(&SVal::Map(vec![
        (HDR_ALG, SVal::int(ALG_EDDSA)),
        (HDR_KID, SVal::Bytes(author.to_vec())),
    ]))
}

/// The RFC 9052 §4.4 signable preimage: `det_cbor(["Signature1", protected, external_aad, payload])`.
pub fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    encode(&SVal::Array(vec![
        SVal::Text("Signature1".into()),
        SVal::Bytes(protected.to_vec()),
        SVal::Bytes(external_aad.to_vec()),
        SVal::Bytes(payload.to_vec()),
    ]))
}

/// A decoded `COSE_Sign1` (§4.1) in its four wire parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1 {
    /// The protected-header bstr **contents** (already unwrapped from the bstr).
    pub protected: Vec<u8>,
    /// The payload bstr contents — `det_cbor(SyncOp)`.
    pub payload: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Encode to the canonical four-element wire array.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&SVal::Array(vec![
            SVal::Bytes(self.protected.clone()),
            SVal::Map(Vec::new()), // unprotected: the empty map 0xa0
            SVal::Bytes(self.payload.clone()),
            SVal::Bytes(self.signature.clone()),
        ]))
    }

    /// Decode the wire array, failing closed (`0x0A02`) on any shape other than the frozen one —
    /// including a non-empty unprotected header (nothing is permitted outside the signature) and a
    /// detached (`nil`) payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SyncError> {
        let cv = decode(bytes).map_err(|_| SyncError::OpSigInvalid)?;
        let items = match cv {
            SVal::Array(a) if a.len() == 4 => a,
            _ => return Err(SyncError::OpSigInvalid),
        };
        let protected = match &items[0] {
            SVal::Bytes(b) => b.clone(),
            _ => return Err(SyncError::OpSigInvalid),
        };
        match &items[1] {
            SVal::Map(m) if m.is_empty() => {}
            _ => return Err(SyncError::OpSigInvalid),
        }
        let payload = match &items[2] {
            SVal::Bytes(b) => b.clone(),
            _ => return Err(SyncError::OpSigInvalid),
        };
        let signature = match &items[3] {
            SVal::Bytes(b) => b.clone(),
            _ => return Err(SyncError::OpSigInvalid),
        };
        Ok(CoseSign1 { protected, payload, signature })
    }

    /// The `kid` (asserted signer key) and `alg` from the protected header.
    pub fn header(&self) -> Result<(i64, Vec<u8>), SyncError> {
        let cv = decode(&self.protected).map_err(|_| SyncError::OpSigInvalid)?;
        let entries = match cv {
            SVal::Map(m) => m,
            _ => return Err(SyncError::OpSigInvalid),
        };
        // Exactly {1: alg, 4: kid} — no other protected-header labels are emitted or accepted.
        if entries.len() != 2 {
            return Err(SyncError::OpSigInvalid);
        }
        let mut alg = None;
        let mut kid = None;
        for (k, v) in entries {
            match k {
                HDR_ALG => alg = v.as_int(),
                HDR_KID => kid = v.as_bytes().map(<[u8]>::to_vec),
                _ => return Err(SyncError::OpSigInvalid),
            }
        }
        match (alg, kid) {
            (Some(a), Some(k)) => Ok((a, k)),
            _ => Err(SyncError::OpSigInvalid),
        }
    }

    /// The signable preimage this envelope commits to.
    pub fn signable(&self) -> Vec<u8> {
        sig_structure(&self.protected, &op_external_aad(), &self.payload)
    }
}

/// Sign `op` under `sk` (whose public half MUST be `op.hlc.author`), producing the frozen
/// `COSE_Sign1` envelope (§4.1).
pub fn sign_op(sk: &IdentityKey, op: &SyncOp) -> Result<CoseSign1, SyncError> {
    let author = sk.public();
    if author != op.hlc.author {
        // The signer must be the op's own HLC author: attribution is the signature, not a claim.
        return Err(SyncError::OpSigInvalid);
    }
    let protected = protected_header(&author);
    let payload = op.det_cbor();
    let preimage = sig_structure(&protected, &op_external_aad(), &payload);
    // The DS-tag rides in `external_aad` inside the Sig_structure, so the raw Ed25519 message is
    // the Sig_structure itself — no second, competing domain prefix.
    let signature = sk.sign_domain(&[], &preimage);
    Ok(CoseSign1 { protected, payload, signature })
}

/// Verify a `COSE_Sign1` and return the authentic [`SyncOp`] it carries (§4.1).
///
/// Fails closed with `0x0A02` on: a malformed envelope, an algorithm other than EdDSA, a `kid`
/// that is not the payload's own `hlc.author` (substitution), a payload that is not a canonical
/// `SyncOp`, or a signature that does not verify over the exact `Sig_structure` — which includes
/// any envelope signed with a different `external_aad` (a different DMTAP object type).
pub fn verify_op(cose: &CoseSign1) -> Result<SyncOp, SyncError> {
    let (alg, kid) = cose.header()?;
    if alg != ALG_EDDSA {
        // Suite 0x01 is EdDSA; an unknown alg is never guessed at.
        return Err(SyncError::UnsupportedVersion);
    }
    let op = SyncOp::from_det_cbor(&cose.payload).map_err(|_| SyncError::OpSigInvalid)?;
    if kid != op.hlc.author {
        return Err(SyncError::OpSigInvalid);
    }
    // Re-encoding MUST reproduce the payload byte-for-byte: a signature over non-canonical bytes
    // must never be laundered into an op that re-encodes differently on another replica.
    if op.det_cbor() != cose.payload {
        return Err(SyncError::OpInvalid);
    }
    verify_domain(&kid, &[], &cose.signable(), &cose.signature)
        .map_err(|_| SyncError::OpSigInvalid)?;
    Ok(op)
}

/// Verify raw wire bytes (decode + [`verify_op`]).
pub fn verify_op_bytes(bytes: &[u8]) -> Result<SyncOp, SyncError> {
    verify_op(&CoseSign1::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detcbor::SVal;
    use crate::wire::{Hlc, OP_LWW_SET};

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn op_for(sk: &IdentityKey) -> SyncOp {
        SyncOp {
            kind: OP_LWW_SET,
            ns: String::new(),
            target: "a".into(),
            field: Some("x".into()),
            value: Some(SVal::Text("v".into())),
            hlc: Hlc { wall: 1_700_000_100_000, counter: 0, author: sk.public() },
            observed: None,
            reference: None,
        }
    }

    #[test]
    fn round_trip_verifies() {
        let sk = key(0xcc);
        let cose = sign_op(&sk, &op_for(&sk)).unwrap();
        let bytes = cose.to_bytes();
        assert_eq!(CoseSign1::from_bytes(&bytes).unwrap(), cose);
        assert_eq!(verify_op_bytes(&bytes).unwrap(), op_for(&sk));
    }

    #[test]
    fn flipped_payload_byte_fails_closed() {
        let sk = key(0xcc);
        let mut cose = sign_op(&sk, &op_for(&sk)).unwrap();
        let last = cose.payload.len() - 1;
        cose.payload[last] ^= 0x01;
        assert_eq!(verify_op(&cose), Err(SyncError::OpSigInvalid));
    }

    #[test]
    fn substituted_kid_fails_closed() {
        // Reuse a valid signature under a DIFFERENT kid: because kid is integrity-covered, this
        // is a verification failure, never a silent mis-attribution to the substituted key.
        let sk = key(0xcc);
        let other = key(0xdd);
        let mut cose = sign_op(&sk, &op_for(&sk)).unwrap();
        cose.protected = protected_header(&other.public());
        assert_eq!(verify_op(&cose), Err(SyncError::OpSigInvalid));
    }

    #[test]
    fn swapped_external_aad_fails_closed() {
        // Domain separation: a signature minted over ANY other external_aad (i.e. any other DMTAP
        // object's DS-tag) must not verify as a SyncOp.
        let sk = key(0xcc);
        let op = op_for(&sk);
        let protected = protected_header(&sk.public());
        let payload = op.det_cbor();
        let foreign_aad = b"DMTAP-SYNC-v0/snapshot\x00";
        let preimage = sig_structure(&protected, foreign_aad, &payload);
        let signature = sk.sign_domain(&[], &preimage);
        let cose = CoseSign1 { protected, payload, signature };
        assert_eq!(verify_op(&cose), Err(SyncError::OpSigInvalid));
    }

    #[test]
    fn non_empty_unprotected_header_is_refused() {
        let sk = key(0xcc);
        let cose = sign_op(&sk, &op_for(&sk)).unwrap();
        let bytes = encode(&SVal::Array(vec![
            SVal::Bytes(cose.protected.clone()),
            SVal::Map(vec![(1, SVal::Uint(1))]),
            SVal::Bytes(cose.payload.clone()),
            SVal::Bytes(cose.signature.clone()),
        ]));
        assert_eq!(verify_op_bytes(&bytes), Err(SyncError::OpSigInvalid));
    }

    #[test]
    fn signing_under_a_key_that_is_not_the_hlc_author_is_refused() {
        let sk = key(0xcc);
        let other = key(0xdd);
        assert_eq!(sign_op(&other, &op_for(&sk)), Err(SyncError::OpSigInvalid));
    }
}
