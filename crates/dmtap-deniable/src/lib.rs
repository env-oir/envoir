//! DMTAP optional **deniable 1:1 mode** — spec §5.2.1.
//!
//! A separate pairwise channel (never MLS) whose authentication is a **shared-key MAC**, so
//! *either* party could have produced any transcript ⇒ neither can prove the other authored a
//! message. It reuses the proven Signal design rather than inventing cryptography:
//!
//! - **[`initiate`] / [`DeniableResponder::accept`]** — X3DH (§5.2.1(a)) over a dedicated,
//!   `IK`-certified long-term X25519 **`idk`** (the Ed25519 `IK` only certifies `idk`, never does
//!   DH). Root: `SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4])`, with `AD = IK_A ‖ IK_B`.
//! - **[`DeniableSession`]** — the Double Ratchet (§5.2.1(b)): symmetric chains + a DH ratchet,
//!   per-message forward secrecy, every message authenticated by the AEAD tag (no signature).
//! - **Replay defense** (§5.2.1) — the responder prefers a one-time prekey and keeps a replay
//!   cache of consumed last-resort initiator ephemerals.
//!
//! The wire objects (`DeniablePrekeyBundle`, `DeniableInit`, `DeniableMessage`, `DeniablePayload`)
//! live in [`dmtap_core::deniable`]; this crate is the *session* implementation over them. Only
//! the classical suite (`0x01`, X3DH) is implemented — PQXDH (`0x02`, ML-KEM) fails closed, exactly
//! as `dmtap-core` fails closed on the PQ identity suite.

mod crypto;
mod ratchet;
mod session;

pub use ratchet::{DoubleRatchet, Header};
pub use session::{initiate, DeniableIdentity, DeniableResponder, DeniableSession};

/// Errors from the deniable session layer. Variant names track the spec's `ERR_DENIABLE_*` set.
#[derive(Debug, thiserror::Error)]
pub enum DeniableError {
    /// `ERR_DENIABLE_X3DH_FAILED` (`0x040C`) — a referenced one-time prekey was already spent, the
    /// signed-prekey reference did not match, or a last-resort init arrived while an opk was free.
    #[error("X3DH handshake failed (consumed/absent prekey or last-resort-while-opk-available)")]
    X3dhFailed,
    /// `ERR_DENIABLE_X3DH_FAILED` (`0x040C`), replay branch — a repeated last-resort initiator
    /// ephemeral was seen in the replay cache.
    #[error("replayed last-resort DeniableInit rejected")]
    ReplayRejected,
    /// The `idk`/`idk_a` certification (or a bundle signature) failed to verify under the IK.
    #[error("idk certification / prekey-bundle signature verification failed")]
    BadCertification,
    /// The shared-key MAC (AEAD tag) did not verify — tampered ciphertext/header, or a wrong key.
    #[error("message authentication (AEAD tag / shared-key MAC) failed")]
    MacFailed,
    /// A receiving chain could not produce the requested key (e.g. an old, already-ratcheted-past
    /// message — the forward-secrecy failure).
    #[error("ratchet decryption failed (no key for this message)")]
    DecryptFailed,
    /// The message claimed to skip more than the bounded number of in-chain keys.
    #[error("too many skipped message keys")]
    TooManySkipped,
    /// A key or reference had the wrong length.
    #[error("key or reference had the wrong length")]
    BadKeyLength,
    /// A suite this implementation does not implement (only classical `0x01` is implemented).
    #[error("suite {0:#04x} is not implemented by the deniable session layer (fail closed)")]
    UnsupportedSuite(u8),
    /// A decoded `DeniablePayload`/wire object was malformed (incl. a smuggled signature).
    #[error("canonical CBOR decode failed: {0}")]
    BadEncoding(#[from] dmtap_core::cbor::CborError),
}

#[cfg(test)]
mod tests;
