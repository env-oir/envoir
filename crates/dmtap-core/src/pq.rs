//! Suite `0x02` — the post-quantum **hybrid** — spec §1.1, §1.3, §16.7, §18.1.6, §18.2.
//!
//! Suite `0x02` was previously spec-reserved only; this module makes it **real on the wire** with
//! genuine post-quantum crypto (no placeholders):
//!
//! - **KEM (confidentiality).** [`HybridSeal`] seals the [`crate::mote::Payload`] with **X-Wing**
//!   (`draft-connolly-cfrg-xwing-kem`, draft 06 — X25519 ⊕ ML-KEM-768), whose SHA3-256 combiner is
//!   IND-CCA-secure if **either** the X25519 or the ML-KEM-768 share is unbroken (§1.3). X-Wing is
//!   a single monolithic KEM, so there is no "classical-only" establishment inside `0x02` to strip
//!   (§1.3). The 32-byte X-Wing shared secret is expanded via HKDF-SHA256 into a ChaCha20-Poly1305
//!   content key (matching suite `0x01`'s AEAD, §18.1.4). Real crate: [`x_wing`].
//! - **Signatures (authenticity).** [`HybridSigningKey`] signs with **both** Ed25519 **and**
//!   ML-DSA-65 (FIPS 204). [`verify_hybrid_domain`] requires **every** component to verify
//!   (AND-composition, §1.3), so a forgery needs breaking *both* and an intra-suite strip of the PQ
//!   half is rejected fail-closed with [`HybridError::HybridSuiteIncomplete`]
//!   (`ERR_HYBRID_SUITE_INCOMPLETE`, §21.4 `0x0210`). Real crate: [`ml_dsa`].
//!
//! ## Crate-maturity honesty
//! `x-wing` 0.1.0 and `ml-dsa` 0.1.1 are young pure-Rust RustCrypto(-adjacent) crates that track
//! the finalized standards (FIPS 203/204) and the X-Wing draft. They implement the **real**
//! algorithms — this is not a mock — but they are pre-1.0 and not yet independently audited to the
//! bar of `ed25519-dalek`. They are the closest audited-ish Rust options to the suite the spec
//! names (§16.7). The wire framing, length governance (§18.2), and the no-strip AND/combiner
//! invariants (§1.3) are enforced here regardless of the underlying crate version.
//!
//! ## Fixed component lengths (spec §18.2, `suite = 0x02`)
//! `ik-pub` = 32 B (Ed25519) ‖ 1952 B (ML-DSA-65) = 1984 B; `sig-val` = 64 B ‖ 3309 B = 3373 B;
//! X-Wing encapsulation key = 1216 B; X-Wing ciphertext = 1120 B; content key = 32 B.

use chacha20poly1305::{
    aead::{Aead, Payload as AeadPayload},
    ChaCha20Poly1305, Key as AeadKey, KeyInit, Nonce,
};
use hkdf::Hkdf;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedVerifyingKey, Generate, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use sha2::Sha256;
use x_wing::{
    kem::{Decapsulate, Encapsulate, KeyExport},
    Ciphertext as XWingCiphertext, DecapsulationKey, EncapsulationKey, Kem, XWingKem,
};

use crate::identity::{verify_domain, IdentityKey};
use crate::mote::{MoteError, PayloadSeal};

// --- Fixed component lengths (§18.2, suite 0x02) -------------------------------------------

/// Ed25519 public-key length (bytes).
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length (bytes).
pub const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-65 verifying-key length (bytes, FIPS 204).
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length (bytes, FIPS 204).
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Hybrid `ik-pub` length: `Ed25519 ‖ ML-DSA-65` (§18.2).
pub const HYBRID_PK_LEN: usize = ED25519_PK_LEN + MLDSA65_PK_LEN; // 1984
/// Hybrid `sig-val` length: `Ed25519_sig ‖ ML-DSA-65_sig` (§18.1.6, §18.2).
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN; // 3373
/// X-Wing encapsulation (public) key length (bytes).
pub const XWING_EK_LEN: usize = 1216;
/// X-Wing decapsulation (secret) key length (bytes).
pub const XWING_DK_LEN: usize = 32;
/// X-Wing ciphertext (encapsulated key) length (bytes).
pub const XWING_CT_LEN: usize = 1120;

/// HKDF-SHA256 `info` binding the X-Wing shared secret to a suite-`0x02` MOTE content key.
const HYBRID_AEAD_INFO: &[u8] = b"dmtap-mote-payload-v0/suite-0x02/x-wing-hkdf-chacha20poly1305";
/// Single-shot AEAD nonce. Safe as a constant: each seal derives a **fresh** key from a fresh
/// X-Wing encapsulation (unique shared secret), so no (key, nonce) pair is ever reused.
const HYBRID_AEAD_NONCE: [u8; 12] = [0u8; 12];

// --- Hybrid-suite verification error (ERR_HYBRID_SUITE_INCOMPLETE, §21.4 0x0210) -----------

/// A suite-`0x02` **intra-suite strip / incomplete-hybrid** rejection (`ERR_HYBRID_SUITE_INCOMPLETE`,
/// §21.4 `0x0210`).
///
/// Kept as its own type (like [`crate::suite::SuiteRatchetError`]) so it carries the normative wire
/// code without disturbing [`MoteError`]. A hybrid verifier MUST require **every** component
/// signature (AND-composition, §1.3); a `0x02` object that validates on only one component — because
/// the PQ half is missing, stripped, or fails — MUST be rejected here, never accepted on the
/// classical half.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HybridError {
    /// A component key/signature is the wrong length (missing/stripped) or fails to verify, so the
    /// hybrid AND-composition does not hold. Fail-closed, never accepted on a single component.
    #[error(
        "hybrid suite (0x02) object is incomplete — a component signature/key is missing, stripped, \
         or failed to verify; both Ed25519 AND ML-DSA-65 MUST verify \
         (ERR_HYBRID_SUITE_INCOMPLETE, §21.4 0x0210)"
    )]
    HybridSuiteIncomplete,
}

impl HybridError {
    /// The normative DMTAP wire error code (§21.4).
    pub fn code(&self) -> u16 {
        match self {
            HybridError::HybridSuiteIncomplete => 0x0210,
        }
    }
}

// --- Hybrid KEM keypair + sealer (X-Wing) --------------------------------------------------

/// An **X-Wing** hybrid KEM keypair (X25519 ⊕ ML-KEM-768) — the suite-`0x02` analogue of
/// [`crate::mote::SealKeypair`]. The recipient advertises [`public`](Self::public) (1216 B) via a
/// KeyPackage; the payload is sealed to it and opened with [`secret`](Self::secret) (32 B).
pub struct HybridKemKeypair {
    dk: [u8; XWING_DK_LEN],
    ek: Vec<u8>,
}

impl HybridKemKeypair {
    /// Generate a fresh X-Wing keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let (dk, ek) = XWingKem::generate_keypair();
        let ek_bytes = KeyExport::to_bytes(&ek);
        HybridKemKeypair { dk: *dk.as_bytes(), ek: ek_bytes.as_slice().to_vec() }
    }

    /// The 1216-byte X-Wing encapsulation (public) key.
    pub fn public(&self) -> &[u8] {
        &self.ek
    }

    /// The 32-byte X-Wing decapsulation (secret) key.
    pub fn secret(&self) -> &[u8; XWING_DK_LEN] {
        &self.dk
    }
}

/// The suite-`0x02` payload sealer: **X-Wing** KEM → HKDF-SHA256 → ChaCha20-Poly1305 AEAD.
///
/// Wire format of the sealed blob mirrors [`crate::mote::Hpke`]: `[u16 enc_len][X-Wing ct][AEAD ct]`
/// where `enc_len == 1120`. A caller passes this as the `sealer` to
/// [`crate::mote::build_mote_hybrid`] / [`crate::mote::validate`] for a `0x02` MOTE.
pub struct HybridSeal;

fn derive_aead_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(HYBRID_AEAD_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

impl PayloadSeal for HybridSeal {
    fn seal(&self, recipient_pub: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, MoteError> {
        let ek = EncapsulationKey::try_from(recipient_pub).map_err(|_| MoteError::BadKey)?;
        // X-Wing encapsulation: fresh shared secret + ciphertext (getrandom-backed).
        let (ct, ss) = ek.encapsulate();
        let key = derive_aead_key(ss.as_slice());
        let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&key));
        let nonce = Nonce::from_slice(&HYBRID_AEAD_NONCE);
        let sealed = cipher
            .encrypt(nonce, AeadPayload { msg: plaintext, aad })
            .map_err(|_| MoteError::SealFailed)?;

        let ct_bytes: &[u8] = ct.as_ref();
        debug_assert_eq!(ct_bytes.len(), XWING_CT_LEN);
        let mut out = Vec::with_capacity(2 + ct_bytes.len() + sealed.len());
        out.extend_from_slice(&(ct_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(ct_bytes);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn open(&self, recipient_secret: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, MoteError> {
        if sealed.len() < 2 {
            return Err(MoteError::DecryptFailed);
        }
        let enc_len = u16::from_be_bytes([sealed[0], sealed[1]]) as usize;
        if enc_len != XWING_CT_LEN || sealed.len() < 2 + enc_len {
            return Err(MoteError::DecryptFailed);
        }
        let ct_bytes = &sealed[2..2 + enc_len];
        let ct_body = &sealed[2 + enc_len..];

        let sk: [u8; XWING_DK_LEN] =
            recipient_secret.try_into().map_err(|_| MoteError::BadKey)?;
        let dk = DecapsulationKey::from(sk);
        let ct = XWingCiphertext::try_from(ct_bytes).map_err(|_| MoteError::DecryptFailed)?;
        let ss = Decapsulate::decapsulate(&dk, &ct);
        let key = derive_aead_key(ss.as_slice());
        let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&key));
        let nonce = Nonce::from_slice(&HYBRID_AEAD_NONCE);
        cipher
            .decrypt(nonce, AeadPayload { msg: ct_body, aad })
            .map_err(|_| MoteError::DecryptFailed)
    }
}

// --- Hybrid signing key (Ed25519 + ML-DSA-65) ----------------------------------------------

/// A suite-`0x02` **hybrid signing key**: an Ed25519 [`IdentityKey`] **and** an ML-DSA-65
/// signing key. Its [`public`](Self::public) is `Ed25519_pk ‖ ML-DSA-65_pk` (1984 B) and
/// [`sign_domain`](Self::sign_domain) produces `Ed25519_sig ‖ ML-DSA-65_sig` (3373 B); both
/// components sign the **same** domain-separated preimage `domain ‖ msg` used by suite `0x01`
/// ([`IdentityKey::sign_domain`]), so verification is symmetric. A `0x02` signature is unforgeable
/// unless **both** primitives are broken (§1.3).
pub struct HybridSigningKey {
    ed: IdentityKey,
    mldsa: MlDsaSigningKey<MlDsa65>,
}

impl HybridSigningKey {
    /// Generate a fresh hybrid signing key (both halves from the OS CSPRNG).
    pub fn generate() -> Self {
        HybridSigningKey { ed: IdentityKey::generate(), mldsa: MlDsaSigningKey::<MlDsa65>::generate() }
    }

    /// Build from an existing Ed25519 [`IdentityKey`] plus a fresh ML-DSA-65 half (useful when the
    /// classical identity already exists and is migrating to the hybrid suite).
    pub fn from_ed25519(ed: IdentityKey) -> Self {
        HybridSigningKey { ed, mldsa: MlDsaSigningKey::<MlDsa65>::generate() }
    }

    /// The hybrid public key `Ed25519_pk(32) ‖ ML-DSA-65_pk(1952)` = 1984 B (§18.2).
    pub fn public(&self) -> Vec<u8> {
        let mut v = self.ed.public();
        v.extend_from_slice(self.mldsa.verifying_key().encode().as_ref());
        v
    }

    /// Sign `domain ‖ msg` with **both** halves, returning `Ed25519_sig(64) ‖ ML-DSA-65_sig(3309)`
    /// = 3373 B (§18.1.6). ML-DSA signing here is the deterministic FIPS-204 variant.
    pub fn sign_domain(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut out = self.ed.sign_domain(domain, msg);
        debug_assert_eq!(out.len(), ED25519_SIG_LEN);
        let mut preimage = Vec::with_capacity(domain.len() + msg.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(msg);
        let sig: MlDsaSignature<MlDsa65> = self.mldsa.sign(&preimage);
        out.extend_from_slice(sig.encode().as_ref());
        out
    }
}

// --- Hybrid verification (AND-composition; no intra-suite strip, §1.3) ---------------------

/// Verify a suite-`0x02` hybrid signature over the domain-separated preimage `domain ‖ msg`.
///
/// `pk` MUST be `Ed25519_pk(32) ‖ ML-DSA-65_pk(1952)` and `sig` MUST be
/// `Ed25519_sig(64) ‖ ML-DSA-65_sig(3309)`. **Both** components MUST verify (AND-composition,
/// §1.3, §10.7.1). Any of — a wrong-length key/signature (a stripped component), or a component
/// that fails to verify (tamper) — is a fail-closed [`HybridError::HybridSuiteIncomplete`]
/// (`0x0210`): the hybrid is **never** accepted on the classical half alone. This is what makes a
/// forgery require breaking both primitives and blocks a silent strip-the-PQ-half downgrade.
pub fn verify_hybrid_domain(
    pk: &[u8],
    domain: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), HybridError> {
    // A wrong overall length means a component key or signature was dropped/stripped (§18.2).
    if pk.len() != HYBRID_PK_LEN || sig.len() != HYBRID_SIG_LEN {
        return Err(HybridError::HybridSuiteIncomplete);
    }
    let (ed_pk, mldsa_pk) = pk.split_at(ED25519_PK_LEN);
    let (ed_sig, mldsa_sig) = sig.split_at(ED25519_SIG_LEN);

    // AND-composition: require BOTH. We evaluate both components (no short-circuit) and reject
    // unless each independently verifies — a failure of either half is an incomplete/stripped
    // hybrid, mapped to the same 0x0210 (never downgraded to the surviving component's assurance).
    let ed_ok = verify_domain(ed_pk, domain, msg, ed_sig).is_ok();
    let mldsa_ok = verify_mldsa65(mldsa_pk, domain, msg, mldsa_sig);
    if ed_ok && mldsa_ok {
        Ok(())
    } else {
        Err(HybridError::HybridSuiteIncomplete)
    }
}

/// Verify the ML-DSA-65 half over `domain ‖ msg`. Returns `false` on any malformed key/signature or
/// a bad signature (fail closed) — the caller folds this into the AND-composition.
fn verify_mldsa65(pk: &[u8], domain: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc_vk);
    let Ok(signature) = MlDsaSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let mut preimage = Vec::with_capacity(domain.len() + msg.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(msg);
    vk.verify(&preimage, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DS: &[u8] = b"DMTAP-v0/test\x00";

    #[test]
    fn component_lengths_match_spec_18_2() {
        assert_eq!(HYBRID_PK_LEN, 1984);
        assert_eq!(HYBRID_SIG_LEN, 3373);
        let k = HybridSigningKey::generate();
        assert_eq!(k.public().len(), HYBRID_PK_LEN);
        assert_eq!(k.sign_domain(DS, b"m").len(), HYBRID_SIG_LEN);
        let kem = HybridKemKeypair::generate();
        assert_eq!(kem.public().len(), XWING_EK_LEN);
        assert_eq!(kem.secret().len(), XWING_DK_LEN);
    }

    #[test]
    fn xwing_seal_open_roundtrips() {
        let kem = HybridKemKeypair::generate();
        let aad = b"envelope-header";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let sealed = HybridSeal.seal(kem.public(), aad, pt).unwrap();
        // [u16 ct_len][1120 ct][aead ct incl. 16-byte tag]
        assert_eq!(u16::from_be_bytes([sealed[0], sealed[1]]) as usize, XWING_CT_LEN);
        let opened = HybridSeal.open(kem.secret(), aad, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn xwing_wrong_recipient_or_aad_fails_closed() {
        let kem = HybridKemKeypair::generate();
        let other = HybridKemKeypair::generate();
        let sealed = HybridSeal.seal(kem.public(), b"aad", b"secret").unwrap();
        // Wrong decapsulation key → AEAD authentication fails.
        assert_eq!(HybridSeal.open(other.secret(), b"aad", &sealed), Err(MoteError::DecryptFailed));
        // Tampered AAD → fails.
        assert_eq!(HybridSeal.open(kem.secret(), b"other-aad", &sealed), Err(MoteError::DecryptFailed));
        // Flipping a ciphertext byte → fails.
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(HybridSeal.open(kem.secret(), b"aad", &bad), Err(MoteError::DecryptFailed));
    }

    #[test]
    fn hybrid_signature_verifies() {
        let k = HybridSigningKey::generate();
        let pk = k.public();
        let sig = k.sign_domain(DS, b"payload");
        assert!(verify_hybrid_domain(&pk, DS, b"payload", &sig).is_ok());
        // Wrong message fails.
        assert_eq!(
            verify_hybrid_domain(&pk, DS, b"other", &sig),
            Err(HybridError::HybridSuiteIncomplete)
        );
    }

    #[test]
    fn stripping_the_pq_half_is_rejected_0x0210() {
        // The core no-strip invariant (§1.3): drop the ML-DSA half, keep the valid Ed25519 half.
        let k = HybridSigningKey::generate();
        let pk = k.public();
        let sig = k.sign_domain(DS, b"m");
        let ed_only_sig = &sig[..ED25519_SIG_LEN];
        let err = verify_hybrid_domain(&pk, DS, b"m", ed_only_sig).unwrap_err();
        assert_eq!(err, HybridError::HybridSuiteIncomplete);
        assert_eq!(err.code(), 0x0210);
        // Also: a hybrid-length signature whose PQ half is zeroed (present but invalid) → 0x0210.
        let mut zeroed = sig.clone();
        for b in &mut zeroed[ED25519_SIG_LEN..] {
            *b = 0;
        }
        assert_eq!(
            verify_hybrid_domain(&pk, DS, b"m", &zeroed).unwrap_err().code(),
            0x0210
        );
    }

    #[test]
    fn stripping_the_classical_half_is_rejected_0x0210() {
        // Symmetric: tampering the Ed25519 half while the ML-DSA half is valid must also fail.
        let k = HybridSigningKey::generate();
        let pk = k.public();
        let mut sig = k.sign_domain(DS, b"m");
        sig[0] ^= 0x01; // corrupt the Ed25519 component
        assert_eq!(
            verify_hybrid_domain(&pk, DS, b"m", &sig).unwrap_err().code(),
            0x0210
        );
    }

    #[test]
    fn cross_key_forgery_needs_both_halves() {
        // A signature from key A must not verify under key B (neither half matches).
        let a = HybridSigningKey::generate();
        let b = HybridSigningKey::generate();
        let sig = a.sign_domain(DS, b"m");
        assert_eq!(
            verify_hybrid_domain(&b.public(), DS, b"m", &sig).unwrap_err(),
            HybridError::HybridSuiteIncomplete
        );
        // Splicing A's valid Ed25519 half onto B's identity (PQ half from B is absent/mismatched)
        // is exactly the strip attack the AND-composition blocks.
        let mut spliced = a.sign_domain(DS, b"m");
        let b_sig = b.sign_domain(DS, b"m");
        spliced[ED25519_SIG_LEN..].copy_from_slice(&b_sig[ED25519_SIG_LEN..]);
        // Under A's key the ML-DSA half (B's) fails; under B's key the Ed25519 half (A's) fails.
        assert!(verify_hybrid_domain(&a.public(), DS, b"m", &spliced).is_err());
        assert!(verify_hybrid_domain(&b.public(), DS, b"m", &spliced).is_err());
    }
}
