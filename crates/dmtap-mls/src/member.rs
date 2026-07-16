//! A [`Member`] — one MLS **leaf**: a device's key material + storage provider (spec §5.6).
//!
//! In DMTAP, **each of an owner's devices is its own MLS leaf** (§5.6): the multi-device cluster
//! is just a group whose members are the owner's devices. A `Member` bundles everything one leaf
//! needs — an `openmls` crypto/storage provider, its Ed25519 signature keypair, and a basic
//! credential naming `owner ‖ "#" ‖ label` — and can either **create** a new group or **join** an
//! existing one from a Welcome, in both cases consuming itself into a live [`Session`].

use openmls::prelude::{
    tls_codec::*, BasicCredential, CredentialWithKey, KeyPackage, MlsGroup, MlsGroupCreateConfig,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
    StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::error::MlsError;
use crate::session::Session;
use crate::DMTAP_MLS_CIPHERSUITE;

/// The byte that separates an owner id from a device label inside a leaf credential's identity
/// (`owner ‖ SEP ‖ label`). `#` never appears in a raw identity key, so [`Member::owner`] can
/// recover the owner id unambiguously.
const LABEL_SEP: u8 = b'#';

/// One MLS leaf: a single device belonging to some owner (spec §5.6). Holds the device's own
/// `openmls` provider (crypto + in-memory storage), its signing keypair, and its credential.
pub struct Member {
    /// Owner identity bytes (in DMTAP, the owner's `IK` public key) — shared across the owner's
    /// devices, so a group's roster can be grouped back to owners (§5.6).
    owner: Vec<u8>,
    /// Human device label ("phone", "home-box", …), unique within the owner's cluster.
    label: String,
    /// This device's `openmls` provider: RustCrypto primitives + an in-memory keystore/storage.
    provider: OpenMlsRustCrypto,
    /// This device's Ed25519 signature keypair (its MLS leaf signing key).
    signer: SignatureKeyPair,
    /// The credential (identity + signature public key) this leaf presents in the tree.
    credential: CredentialWithKey,
}

impl Member {
    /// Provision a fresh leaf for `owner`'s device `label`: generate an Ed25519 signature keypair
    /// (stored in the device's keystore) and a basic credential naming `owner ‖ "#" ‖ label`.
    pub fn new(owner: impl Into<Vec<u8>>, label: impl Into<String>) -> Result<Self, MlsError> {
        let owner = owner.into();
        let label = label.into();
        let provider = OpenMlsRustCrypto::default();

        let signer = SignatureKeyPair::new(DMTAP_MLS_CIPHERSUITE.signature_algorithm())
            .map_err(|e| MlsError::KeyMaterial(e.to_string()))?;
        signer
            .store(provider.storage())
            .map_err(|e| MlsError::KeyMaterial(e.to_string()))?;

        let mut identity = owner.clone();
        identity.push(LABEL_SEP);
        identity.extend_from_slice(label.as_bytes());
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Member { owner, label, provider, signer, credential })
    }

    /// The owner identity bytes this device belongs to (§5.6). Two `Member`s with the same owner
    /// are two devices of one identity.
    pub fn owner(&self) -> &[u8] {
        &self.owner
    }

    /// This device's label within the owner's cluster.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The full leaf identity as it appears in the roster: `owner ‖ "#" ‖ label`.
    pub fn leaf_identity(&self) -> Vec<u8> {
        self.credential.credential.serialized_content().to_vec()
    }

    /// Recover the owner id from a roster leaf identity (`owner ‖ "#" ‖ label`) — the inverse of
    /// how [`Member::new`] composes it. Lets a caller (or a test) confirm that two leaves are two
    /// devices of the **same** owner (§5.6).
    pub fn owner_of_identity(identity: &[u8]) -> &[u8] {
        match identity.iter().rposition(|&b| b == LABEL_SEP) {
            Some(i) => &identity[..i],
            None => identity,
        }
    }

    /// Publish a signed **KeyPackage** for this device (spec §5.3 async initiation): MLS's prekey
    /// — the leaf's identity/signature key + HPKE init key — serialized for the mesh so an
    /// initiator can **Add** this device while it is offline. Returns the TLS wire bytes.
    pub fn publish_key_package(&self) -> Result<Vec<u8>, MlsError> {
        let bundle = KeyPackage::builder()
            .build(
                DMTAP_MLS_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|e| MlsError::KeyMaterial(e.to_string()))?;
        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(|e| MlsError::Codec(e.to_string()))
    }

    /// Create a **new MLS group** with this device as the founding (and initial-committer, §5.1)
    /// leaf, over `group_id`. Consumes the `Member` into a live [`Session`].
    pub fn create_group(self, group_id: &[u8]) -> Result<Session, MlsError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(DMTAP_MLS_CIPHERSUITE)
            // Ship the ratchet tree inside the Welcome so an added member can join without a
            // separately-distributed tree (§5.3 — the KeyPackage/Welcome carry what's needed).
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            openmls::prelude::GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|e| MlsError::Group(e.to_string()))?;
        Ok(Session::new(self, group))
    }

    /// **Join** an existing group from a Welcome (spec §5.3): the added device bootstraps its full
    /// group state from the `welcome_bytes` produced by the Add Commit. The ratchet tree rides
    /// inside the Welcome (`use_ratchet_tree_extension`), so no separate tree is needed. Consumes
    /// the `Member` into a live [`Session`] already synced to the group's current epoch.
    pub fn join_from_welcome(self, welcome_bytes: &[u8]) -> Result<Session, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| MlsError::Codec(e.to_string()))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::UnexpectedContent),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MlsError::Group(e.to_string()))?;
        Ok(Session::new(self, group))
    }

    // --- accessors used by `Session` (crate-internal) --------------------------------------

    pub(crate) fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    pub(crate) fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }
}

/// Decode + **validate** a KeyPackage from its published TLS wire bytes (spec §5.3), returning the
/// verified [`KeyPackage`] ready to be handed to [`Session::add_member`](crate::Session::add_member).
/// Validation verifies the leaf-node signature, lifetime, and protocol version, so a forged or
/// malformed KeyPackage is rejected before it can be added to a group. Fails closed throughout.
pub(crate) fn decode_key_package(
    provider: &OpenMlsRustCrypto,
    bytes: &[u8],
) -> Result<KeyPackage, MlsError> {
    let msg =
        MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| MlsError::Codec(e.to_string()))?;
    let kp_in = match msg.extract() {
        MlsMessageBodyIn::KeyPackage(kp) => kp,
        _ => return Err(MlsError::UnexpectedContent),
    };
    kp_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::KeyMaterial(e.to_string()))
}
