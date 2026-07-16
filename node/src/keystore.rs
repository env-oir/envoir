//! Durable keystore — the node's identity persisted to disk (spec §1.2, §1.4).
//!
//! `init` generates the §1.2 root identity (Ed25519 `IK`) and the §5.3 X25519 sealing keypair and
//! writes them here so a restarting daemon reloads the **same** identity — the address peers pinned
//! (§3.4) and the sealing key correspondents seal to (§5.3) survive a restart. Without this a
//! restarted node would mint a new identity every boot and become unreachable at its published name.
//!
//! ## What is persisted
//! - the 32-byte Ed25519 identity **seed** (reconstructs `IK` via [`IdentityKey::from_seed`]);
//! - the 32-byte X25519 sealing **secret** (the HPKE open key) and its derived **public**;
//! - the public identity key (convenience/verification), plus the operator's naming pointers
//!   (`names`, `kt` anchors, `keypkgs` locator) needed to (re)render the node's `_dmtap` record.
//!
//! ## Encryption at rest (spec §1.4)
//! The **secret** material (seed ‖ sealing secret) is either:
//! - **encrypted** — ChaCha20-Poly1305 under an Argon2id-derived key when a passphrase is supplied
//!   ([`Keystore::save`] with `Some(passphrase)`); or
//! - **plaintext-for-dev** — written verbatim with a clearly-marked `"encryption": "none"` and a
//!   `0600` file mode, for local development where no passphrase is set. This mode is explicit in the
//!   file and logged by the daemon, never a silent default that looks encrypted.
//!
//! The **public** fields are always stored in the clear. All byte fields use unpadded base64url
//! (RFC 4648 §5, spec §3.2/§3.9.1) via [`dmtap_naming::base64url`], the same encoding the `_dmtap`
//! DNS record uses — so the keystore is inspectable and consistent with the wire encoding.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use dmtap_core::identity::IdentityKey;
use dmtap_core::mote::SealKeypair;
use dmtap_naming::base64url;

/// Current on-disk keystore schema version.
const KEYSTORE_VERSION: u32 = 1;
/// The `encryption` tag for the plaintext-for-dev mode (spec §1.4 — clearly marked, not silent).
const ENC_NONE: &str = "none";
/// The `encryption` tag for passphrase-sealed keystores.
const ENC_AEAD: &str = "argon2id-chacha20poly1305";
/// KDF salt length (bytes).
const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305 nonce length (bytes).
const NONCE_LEN: usize = 12;
/// The plaintext secret blob is the identity seed followed by the sealing secret.
const SECRET_LEN: usize = 64;

/// Something went wrong reading, writing, or decrypting the keystore.
#[derive(Debug)]
pub enum KeystoreError {
    /// Underlying filesystem I/O failed.
    Io(std::io::Error),
    /// The keystore JSON was malformed / truncated.
    Serde(String),
    /// A base64url field failed to decode, or a decoded field had the wrong length.
    Encoding(&'static str),
    /// The OS CSPRNG failed to produce key material / salt / nonce.
    Rng(&'static str),
    /// The keystore is encrypted but no passphrase was supplied (or vice-versa).
    Passphrase(&'static str),
    /// AEAD decryption failed — wrong passphrase or a tampered keystore (fail closed).
    Decrypt,
    /// A structurally-valid keystore held an impossible/unsupported value.
    Corrupt(&'static str),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::Io(e) => write!(f, "keystore I/O error: {e}"),
            KeystoreError::Serde(e) => write!(f, "keystore JSON error: {e}"),
            KeystoreError::Encoding(w) => write!(f, "keystore encoding error: {w}"),
            KeystoreError::Rng(w) => write!(f, "keystore RNG error: {w}"),
            KeystoreError::Passphrase(w) => write!(f, "keystore passphrase error: {w}"),
            KeystoreError::Decrypt => {
                f.write_str("keystore decryption failed (wrong passphrase or tampered file)")
            }
            KeystoreError::Corrupt(w) => write!(f, "corrupt keystore: {w}"),
        }
    }
}
impl std::error::Error for KeystoreError {}
impl From<std::io::Error> for KeystoreError {
    fn from(e: std::io::Error) -> Self {
        KeystoreError::Io(e)
    }
}

/// A node's identity, loaded into memory. Secret fields are wiped on drop ([`Zeroize`]).
pub struct Keystore {
    /// The 32-byte Ed25519 identity seed (reconstructs `IK`).
    ik_seed: [u8; 32],
    /// The 32-byte X25519 sealing secret (the HPKE open key).
    seal_secret: [u8; 32],
    /// The X25519 sealing public key (advertised via KeyPackages, §5.3).
    pub seal_public: [u8; 32],
    /// The Ed25519 identity public key — this node's DMTAP address (§1.2).
    pub ik_public: Vec<u8>,
    /// When this identity was generated (ms since epoch).
    pub created_ms: u64,
    /// The names this identity claims (its `_dmtap` `names`, §3.2).
    pub names: Vec<String>,
    /// The KT log anchor URL(s) the operator publishes (§3.5.2).
    pub kt_anchors: Vec<String>,
    /// The KeyPackage bundle locator the operator publishes (§5.3, §18.4.3).
    pub keypkgs_loc: String,
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.ik_seed.zeroize();
        self.seal_secret.zeroize();
    }
}

impl Keystore {
    /// Generate a fresh identity: a random Ed25519 seed + a fresh X25519 sealing keypair, tagged with
    /// the operator's naming pointers. In-memory only — call [`save`](Self::save) to persist it.
    pub fn generate(
        created_ms: u64,
        names: Vec<String>,
        kt_anchors: Vec<String>,
        keypkgs_loc: impl Into<String>,
    ) -> Result<Self, KeystoreError> {
        let mut ik_seed = [0u8; 32];
        getrandom::getrandom(&mut ik_seed).map_err(|_| KeystoreError::Rng("identity seed"))?;
        let ik = IdentityKey::from_seed(&ik_seed);
        let seal = SealKeypair::generate();
        Ok(Keystore {
            ik_seed,
            seal_secret: *seal.secret(),
            seal_public: *seal.public(),
            ik_public: ik.public(),
            created_ms,
            names,
            kt_anchors,
            keypkgs_loc: keypkgs_loc.into(),
        })
    }

    /// Reconstruct this node's [`IdentityKey`] from the persisted seed (§1.2).
    pub fn identity_key(&self) -> IdentityKey {
        IdentityKey::from_seed(&self.ik_seed)
    }

    /// The raw sealing secret bytes (the HPKE open key) — used to rebuild a [`Node`](crate::node::Node)
    /// via [`with_journal_bytes`](crate::node::Node::with_journal_bytes).
    pub fn seal_secret(&self) -> [u8; 32] {
        self.seal_secret
    }

    /// Whether a keystore file already exists at `path`.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Persist this keystore to `path`, atomically (temp-file + rename), mode `0600`. If `passphrase`
    /// is `Some`, the secret material is sealed with ChaCha20-Poly1305 under an Argon2id-derived key;
    /// if `None`, it is written in the clearly-marked plaintext-for-dev mode (spec §1.4).
    pub fn save(&self, path: &Path, passphrase: Option<&str>) -> Result<(), KeystoreError> {
        let mut secret = [0u8; SECRET_LEN];
        secret[..32].copy_from_slice(&self.ik_seed);
        secret[32..].copy_from_slice(&self.seal_secret);

        let file = match passphrase {
            Some(pw) if !pw.is_empty() => {
                let mut salt = [0u8; SALT_LEN];
                let mut nonce = [0u8; NONCE_LEN];
                getrandom::getrandom(&mut salt).map_err(|_| KeystoreError::Rng("kdf salt"))?;
                getrandom::getrandom(&mut nonce).map_err(|_| KeystoreError::Rng("aead nonce"))?;
                let key = derive_key(pw, &salt)?;
                let ct = aead_seal(&key, &nonce, &secret)?;
                KeystoreFile {
                    version: KEYSTORE_VERSION,
                    encryption: ENC_AEAD.into(),
                    created_ms: self.created_ms,
                    ik_public: base64url::encode(&self.ik_public),
                    seal_public: base64url::encode(&self.seal_public),
                    names: self.names.clone(),
                    kt_anchors: self.kt_anchors.clone(),
                    keypkgs_loc: self.keypkgs_loc.clone(),
                    ik_seed: None,
                    seal_secret: None,
                    kdf_salt: Some(base64url::encode(&salt)),
                    aead_nonce: Some(base64url::encode(&nonce)),
                    secret_ciphertext: Some(base64url::encode(&ct)),
                }
            }
            _ => KeystoreFile {
                version: KEYSTORE_VERSION,
                encryption: ENC_NONE.into(),
                created_ms: self.created_ms,
                ik_public: base64url::encode(&self.ik_public),
                seal_public: base64url::encode(&self.seal_public),
                names: self.names.clone(),
                kt_anchors: self.kt_anchors.clone(),
                keypkgs_loc: self.keypkgs_loc.clone(),
                ik_seed: Some(base64url::encode(&self.ik_seed)),
                seal_secret: Some(base64url::encode(&self.seal_secret)),
                kdf_salt: None,
                aead_nonce: None,
                secret_ciphertext: None,
            },
        };
        secret.zeroize();

        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| KeystoreError::Serde(e.to_string()))?;
        write_atomic_0600(path, &bytes)?;
        Ok(())
    }

    /// Load and decrypt a keystore from `path`. `passphrase` is required iff the file is encrypted;
    /// a mismatch (encrypted file + no passphrase, or plaintext file + a passphrase) is a typed error
    /// rather than a silent fallback. AEAD failure (wrong passphrase / tamper) fails closed.
    pub fn load(path: &Path, passphrase: Option<&str>) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)?;
        let file: KeystoreFile =
            serde_json::from_slice(&bytes).map_err(|e| KeystoreError::Serde(e.to_string()))?;
        if file.version != KEYSTORE_VERSION {
            return Err(KeystoreError::Corrupt("unsupported keystore version"));
        }

        let (ik_seed, seal_secret) = match file.encryption.as_str() {
            ENC_NONE => {
                let seed = decode_32(file.ik_seed.as_deref(), "ik_seed")?;
                let sseal = decode_32(file.seal_secret.as_deref(), "seal_secret")?;
                (seed, sseal)
            }
            ENC_AEAD => {
                let pw = match passphrase {
                    Some(pw) if !pw.is_empty() => pw,
                    _ => {
                        return Err(KeystoreError::Passphrase(
                            "keystore is encrypted; a passphrase is required",
                        ))
                    }
                };
                let salt = decode_field(file.kdf_salt.as_deref(), "kdf_salt")?;
                let nonce = decode_field(file.aead_nonce.as_deref(), "aead_nonce")?;
                let ct = decode_field(file.secret_ciphertext.as_deref(), "secret_ciphertext")?;
                if nonce.len() != NONCE_LEN {
                    return Err(KeystoreError::Encoding("aead_nonce wrong length"));
                }
                let key = derive_key(pw, &salt)?;
                let mut secret = aead_open(&key, &nonce, &ct)?;
                if secret.len() != SECRET_LEN {
                    secret.zeroize();
                    return Err(KeystoreError::Corrupt("decrypted secret has wrong length"));
                }
                let mut seed = [0u8; 32];
                let mut sseal = [0u8; 32];
                seed.copy_from_slice(&secret[..32]);
                sseal.copy_from_slice(&secret[32..]);
                secret.zeroize();
                (seed, sseal)
            }
            _ => return Err(KeystoreError::Corrupt("unknown encryption mode")),
        };

        // Rederive the public halves and cross-check them against the stored (public) fields, so a
        // corrupted/mismatched keystore is refused rather than silently serving a wrong address.
        let ik = IdentityKey::from_seed(&ik_seed);
        let ik_public = ik.public();
        let stored_ik = decode_field(Some(&file.ik_public), "ik_public")?;
        if stored_ik != ik_public {
            return Err(KeystoreError::Corrupt("identity public key does not match seed"));
        }
        let seal_public = decode_32(Some(&file.seal_public), "seal_public")?;

        Ok(Keystore {
            ik_seed,
            seal_secret,
            seal_public,
            ik_public,
            created_ms: file.created_ms,
            names: file.names,
            kt_anchors: file.kt_anchors,
            keypkgs_loc: file.keypkgs_loc,
        })
    }
}

/// The on-disk JSON shape. Secret fields are `Option` so the same struct serializes either mode; a
/// field absent for the active mode is skipped (`skip_serializing_if`).
#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    encryption: String,
    created_ms: u64,
    ik_public: String,
    seal_public: String,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    kt_anchors: Vec<String>,
    #[serde(default)]
    keypkgs_loc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ik_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aead_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_ciphertext: Option<String>,
}

/// Derive a 32-byte AEAD key from `passphrase` + `salt` with Argon2id (default params).
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], KeystoreError> {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| KeystoreError::Corrupt("argon2 key derivation failed"))?;
    Ok(key)
}

/// ChaCha20-Poly1305 seal.
fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], pt: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), pt)
        .map_err(|_| KeystoreError::Corrupt("aead seal failed"))
}

/// ChaCha20-Poly1305 open (fails closed on a bad tag).
fn aead_open(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct).map_err(|_| KeystoreError::Decrypt)
}

/// Decode a required base64url field.
fn decode_field(field: Option<&str>, what: &'static str) -> Result<Vec<u8>, KeystoreError> {
    let s = field.ok_or(KeystoreError::Corrupt(what))?;
    base64url::decode(s).ok_or(KeystoreError::Encoding(what))
}

/// Decode a required base64url field that must be exactly 32 bytes.
fn decode_32(field: Option<&str>, what: &'static str) -> Result<[u8; 32], KeystoreError> {
    let v = decode_field(field, what)?;
    v.as_slice().try_into().map_err(|_| KeystoreError::Encoding(what))
}

/// Write `bytes` to `path` atomically (sibling `*.tmp` + rename), with mode `0600` on unix so the
/// secret material is not world-readable.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), KeystoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp: PathBuf = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("envoir-keystore-{}-{}-{}.json", std::process::id(), tag, n))
    }

    #[test]
    fn plaintext_keystore_round_trips() {
        let path = tmp_path("plain");
        let ks = Keystore::generate(
            1_700_000_000_000,
            vec!["alice@example.com".into()],
            vec!["https://kt.example/log".into()],
            "/mesh/kp/alice",
        )
        .unwrap();
        let ik_pub = ks.ik_public.clone();
        let seal_pub = ks.seal_public;
        let seed = ks.ik_seed;
        let sseal = ks.seal_secret;
        ks.save(&path, None).unwrap();

        // Public fields are stored in the clear as base64url; secrets are present but plaintext-marked.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"encryption\": \"none\""));

        let loaded = Keystore::load(&path, None).unwrap();
        assert_eq!(loaded.ik_public, ik_pub);
        assert_eq!(loaded.seal_public, seal_pub);
        assert_eq!(loaded.ik_seed, seed, "identity seed round-trips");
        assert_eq!(loaded.seal_secret, sseal, "sealing secret round-trips");
        assert_eq!(loaded.names, vec!["alice@example.com".to_string()]);
        // The reconstructed identity key produces the same address.
        assert_eq!(loaded.identity_key().public(), ik_pub);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_keystore_round_trips_and_rejects_wrong_passphrase() {
        let path = tmp_path("enc");
        let ks = Keystore::generate(1_700_000_000_000, vec![], vec![], "/kp").unwrap();
        let seed = ks.ik_seed;
        let sseal = ks.seal_secret;
        ks.save(&path, Some("correct horse battery staple")).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("argon2id-chacha20poly1305"));
        // No plaintext secret leaks into the encrypted file.
        assert!(!raw.contains("ik_seed"));
        assert!(!raw.contains("seal_secret\""));

        // Right passphrase decrypts to the same secrets.
        let loaded = Keystore::load(&path, Some("correct horse battery staple")).unwrap();
        assert_eq!(loaded.ik_seed, seed);
        assert_eq!(loaded.seal_secret, sseal);

        // Wrong passphrase fails closed (AEAD tag mismatch).
        assert!(matches!(
            Keystore::load(&path, Some("wrong")),
            Err(KeystoreError::Decrypt)
        ));
        // Missing passphrase on an encrypted keystore is a typed error, not a silent plaintext read.
        assert!(matches!(
            Keystore::load(&path, None),
            Err(KeystoreError::Passphrase(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keystore_keys_are_base64url_encoded() {
        let path = tmp_path("b64");
        let ks = Keystore::generate(1, vec![], vec![], "/kp").unwrap();
        let ik_pub = ks.ik_public.clone();
        ks.save(&path, None).unwrap();
        let file: KeystoreFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // Round-trips through the same strict unpadded-base64url codec the `_dmtap` record uses.
        assert!(!file.ik_public.contains('='), "no base64 padding");
        assert!(!file.ik_public.contains('+') && !file.ik_public.contains('/'), "url-safe alphabet");
        assert_eq!(base64url::decode(&file.ik_public).unwrap(), ik_pub);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_is_refused() {
        let path = tmp_path("tamper");
        let ks = Keystore::generate(1, vec![], vec![], "/kp").unwrap();
        ks.save(&path, Some("pw")).unwrap();
        let mut file: KeystoreFile =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // Flip a byte in the ciphertext → AEAD open must fail closed.
        let mut ct = base64url::decode(file.secret_ciphertext.as_ref().unwrap()).unwrap();
        ct[0] ^= 0xff;
        file.secret_ciphertext = Some(base64url::encode(&ct));
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(Keystore::load(&path, Some("pw")), Err(KeystoreError::Decrypt)));
        let _ = std::fs::remove_file(&path);
    }
}
