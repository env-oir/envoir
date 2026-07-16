//! The primitive layer shared by X3DH and the Double Ratchet (spec §5.2.1(a)/(b)).
//!
//! Everything here is deliberately the *same* primitive family `dmtap-core` already uses —
//! X25519 (RFC 7748), HKDF-SHA256, and a ChaCha20-Poly1305 AEAD — so the deniable mode adds no
//! new cryptographic assumptions. Authentication is the AEAD tag under a per-message key: a
//! **shared-key MAC** either party can compute, which is exactly the property that makes the
//! transcript repudiable (§5.2.1(e)).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::DeniableError;

// --- domain-separated KDF labels (§18.9.10-style separation; each string is distinct) ---------
const X3DH_INFO: &[u8] = b"DMTAP-v0/deniable-x3dh";
const RK_INFO: &[u8] = b"DMTAP-v0/deniable-ratchet-root";
const CK_NEXT_INFO: &[u8] = b"DMTAP-v0/deniable-ratchet-chain";
const CK_MK_INFO: &[u8] = b"DMTAP-v0/deniable-ratchet-msg";
const MSG_KEY_INFO: &[u8] = b"DMTAP-v0/deniable-msg-key";

/// The X3DH "curve prefix" byte string (Signal X3DH §2.2): 32 `0xFF` bytes prepended to the DH
/// concatenation, domain-separating the X25519 key material from any raw hash input.
const X3DH_F: [u8; 32] = [0xFF; 32];

// --- X25519 helpers ---------------------------------------------------------------------------

/// A raw X25519 public key on the wire.
pub type Pub = [u8; 32];

/// Generate a fresh X25519 keypair from the OS CSPRNG; returns `(secret, public_bytes)`.
pub fn gen_keypair() -> (StaticSecret, Pub) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

/// The public half of an X25519 secret, as wire bytes.
pub fn public_of(secret: &StaticSecret) -> Pub {
    PublicKey::from(secret).to_bytes()
}

/// One Diffie–Hellman: `DH(secret, peer_public)`.
pub fn dh(secret: &StaticSecret, peer: &Pub) -> [u8; 32] {
    secret.diffie_hellman(&PublicKey::from(*peer)).to_bytes()
}

/// Parse a 32-byte X25519 public key, failing closed on the wrong length.
pub fn parse_pub(bytes: &[u8]) -> Result<Pub, DeniableError> {
    bytes.try_into().map_err(|_| DeniableError::BadKeyLength)
}

// --- HKDF-SHA256 ------------------------------------------------------------------------------

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length is within the SHA-256 limit");
}

fn split64(buf: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&buf[..32]);
    b.copy_from_slice(&buf[32..]);
    (a, b)
}

/// The X3DH root secret (§5.2.1(a)): `SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4])`. The DH ordering is
/// pinned by the caller (initiator/responder produce the same list in the same order).
pub fn x3dh_root(dhs: &[[u8; 32]]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + dhs.len() * 32);
    ikm.extend_from_slice(&X3DH_F);
    for d in dhs {
        ikm.extend_from_slice(d);
    }
    let mut sk = [0u8; 32];
    hkdf(&[0u8; 32], &ikm, X3DH_INFO, &mut sk);
    sk
}

/// Root KDF (Double Ratchet §3.3): `(RK', CK) = HKDF(salt=RK, ikm=DH_out)`.
pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    hkdf(rk, dh_out, RK_INFO, &mut out);
    split64(out)
}

/// Symmetric-chain KDF (Double Ratchet §3.4): from chain key `ck`, derive the next chain key and
/// this step's message key. One-way: given `ck'` you cannot recover `ck` or the earlier `mk`
/// (this is the forward-secrecy ratchet).
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut next = [0u8; 32];
    let mut mk = [0u8; 32];
    hkdf(ck, &[], CK_NEXT_INFO, &mut next);
    hkdf(ck, &[], CK_MK_INFO, &mut mk);
    (next, mk)
}

// --- AEAD (the shared-key MAC) ----------------------------------------------------------------

/// Seal `pt` under per-message key `mk` with associated data `ad`. The Poly1305 tag *is* the
/// shared-key MAC (§5.2.1): no signature is ever produced.
pub fn aead_seal(mk: &[u8; 32], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut kn = [0u8; 44]; // 32-byte key ‖ 12-byte nonce, both derived from the unique mk
    hkdf(mk, &[], MSG_KEY_INFO, &mut kn);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kn[..32]));
    cipher
        .encrypt(Nonce::from_slice(&kn[32..]), AeadPayload { msg: pt, aad: ad })
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-range inputs")
}

/// Open `ct` under per-message key `mk` with associated data `ad`. A wrong key, tampered
/// ciphertext, or tampered `ad` fails the tag ⇒ [`DeniableError::MacFailed`].
pub fn aead_open(mk: &[u8; 32], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, DeniableError> {
    let mut kn = [0u8; 44];
    hkdf(mk, &[], MSG_KEY_INFO, &mut kn);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kn[..32]));
    cipher
        .decrypt(Nonce::from_slice(&kn[32..]), AeadPayload { msg: ct, aad: ad })
        .map_err(|_| DeniableError::MacFailed)
}
