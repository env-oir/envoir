//! Organization directory objects — spec §3.10.3, §18.4.7.
//!
//! A [`DomainDirectory`] is the signed, versioned, KT-logged enumeration of a domain's member and
//! group bindings (the org directory / GAL), signed by the **domain authority**. It is a
//! convenience **index**: each [`DirEntry`]'s `name → ik` MUST still verify forward via DNS + KT
//! before use (§3.9.4), so the directory can enumerate but never *forge* a binding.
//!
//! Integer-keyed canonical CBOR (§18.1.2); signing follows the general rule §18.9.3
//! (`Sign(sk, DS-tag ‖ 0x00 ‖ det_cbor(object ∖ {9}))`, DS-tag `DMTAP-v0/domain-directory`).

use crate::cbor::{self, as_array, as_bytes, as_text, as_u64, as_u8, CborError, Cv, Fields};
use crate::id::ContentId;
use crate::identity::{verify_domain, IdentityError, IdentityKey};
use crate::suite::Suite;
use crate::TimestampMs;

/// §18.9.3 domain-separation tag (ASCII ‖ trailing `0x00`; `sign_domain` prepends it).
pub const DOMAIN_DIRECTORY_DS: &[u8] = b"DMTAP-v0/domain-directory\x00";

fn suite_from_cv(cv: Cv) -> Result<Suite, CborError> {
    let b = as_u8(cv)?;
    Suite::from_u8(b).ok_or(CborError::UnknownSuite(b))
}

/// Directory membership visibility (§18.4.7 `dir-visibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// `"public"` — world-listable.
    Public,
    /// `"members-only"` — entries served only to authenticated members.
    MembersOnly,
}

impl Visibility {
    fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::MembersOnly => "members-only",
        }
    }
    fn from_str(s: &str) -> Result<Self, CborError> {
        match s {
            "public" => Ok(Visibility::Public),
            "members-only" => Ok(Visibility::MembersOnly),
            _ => Err(CborError::TypeMismatch),
        }
    }
}

/// Member key-custody model (§18.4.7 `member-custody`). An `"org-managed"` entry MUST be rendered
/// as such; presenting one as sovereign fails closed (`ERR_ORG_MANAGED_UNDISCLOSED`, §3.10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// `"sovereign"` — member holds their own key; the org cannot access it.
    Sovereign,
    /// `"org-managed"` — org holds/escrows the key (a disclosed limit).
    OrgManaged,
}

impl Custody {
    fn as_str(self) -> &'static str {
        match self {
            Custody::Sovereign => "sovereign",
            Custody::OrgManaged => "org-managed",
        }
    }
    fn from_str(s: &str) -> Result<Self, CborError> {
        match s {
            "sovereign" => Ok(Custody::Sovereign),
            "org-managed" => Ok(Custody::OrgManaged),
            _ => Err(CborError::TypeMismatch),
        }
    }
}

/// One directory entry — a member or group binding (§18.4.7 `DirEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,               // key 1 — "alice@abc.com" (or a group name)
    pub ik: Vec<u8>,                // key 2 — member/group identity key
    pub id: ContentId,              // key 3 — content addr of the member's current Identity
    pub custody: Custody,           // key 4
    pub roles: Option<Vec<String>>, // key 5 — informative org roles (OPTIONAL)
    pub added: TimestampMs,         // key 6
}

impl DirEntry {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::Text(self.name.clone())),
            (2, Cv::Bytes(self.ik.clone())),
            (3, Cv::Bytes(self.id.as_bytes().to_vec())),
            (4, Cv::Text(self.custody.as_str().into())),
        ];
        if let Some(r) = &self.roles {
            m.push((5, Cv::Array(r.iter().map(|x| Cv::Text(x.clone())).collect())));
        }
        m.push((6, Cv::U64(self.added)));
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cv)?;
        let name = as_text(f.req(1)?)?;
        let ik = as_bytes(f.req(2)?)?;
        let id = ContentId(as_bytes(f.req(3)?)?);
        let custody = Custody::from_str(&as_text(f.req(4)?)?)?;
        let roles = match f.take(5) {
            Some(c) => Some(as_array(c)?.into_iter().map(as_text).collect::<Result<_, _>>()?),
            None => None,
        };
        let added = as_u64(f.req(6)?)?;
        f.deny_unknown()?;
        Ok(DirEntry { name, ik, id, custody, roles, added })
    }
}

/// The signed, versioned org directory (spec §3.10.3, §18.4.7), signed by the domain authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDirectory {
    pub suite: Suite,           // key 1
    pub domain: String,         // key 2 — "abc.com"
    pub authority: Vec<u8>,     // key 3 — domain authority IK (threshold-held)
    pub version: u64,           // key 4 — monotonic; reject ≤ last pinned
    pub visibility: Visibility, // key 5
    pub entries: Vec<DirEntry>, // key 6 — MAY be empty
    pub prev: Option<ContentId>, // key 7 — hash chain (KT-logged)
    pub ts: TimestampMs,        // key 8
    pub sig: Vec<u8>,           // key 9 — §18.9.3
}

impl DomainDirectory {
    /// Integer-keyed canonical map (§18.4.7). `include_sig=false` omits key 9 for the §18.9.3
    /// signing body.
    fn to_cv(&self, include_sig: bool) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.suite.as_u8() as u64)),
            (2, Cv::Text(self.domain.clone())),
            (3, Cv::Bytes(self.authority.clone())),
            (4, Cv::U64(self.version)),
            (5, Cv::Text(self.visibility.as_str().into())),
            (6, Cv::Array(self.entries.iter().map(DirEntry::to_cv).collect())),
        ];
        if let Some(p) = &self.prev {
            m.push((7, Cv::Bytes(p.as_bytes().to_vec())));
        }
        m.push((8, Cv::U64(self.ts)));
        if include_sig {
            m.push((9, Cv::Bytes(self.sig.clone())));
        }
        Cv::Map(m)
    }

    /// The exact wire bytes: §18-canonical integer-keyed CBOR.
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(true))
    }

    /// The §18.9.3 signing body: deterministic CBOR of the directory with `sig` (key 9) omitted.
    pub fn signing_body(&self) -> Vec<u8> {
        cbor::encode(&self.to_cv(false))
    }

    /// Decode a directory (§18.4.7), failing closed on any violation.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let suite = suite_from_cv(f.req(1)?)?;
        let domain = as_text(f.req(2)?)?;
        let authority = as_bytes(f.req(3)?)?;
        let version = as_u64(f.req(4)?)?;
        let visibility = Visibility::from_str(&as_text(f.req(5)?)?)?;
        let entries: Vec<DirEntry> = as_array(f.req(6)?)?
            .into_iter()
            .map(DirEntry::from_cv)
            .collect::<Result<_, _>>()?;
        let prev = f.take(7).map(as_bytes).transpose()?.map(ContentId);
        let ts = as_u64(f.req(8)?)?;
        let sig = as_bytes(f.req(9)?)?;
        f.deny_unknown()?;
        Ok(DomainDirectory { suite, domain, authority, version, visibility, entries, prev, ts, sig })
    }

    /// Sign a directory with the authority `IK` (§18.9.3); `authority` is set from the signer.
    pub fn issue(
        authority: &IdentityKey,
        domain: impl Into<String>,
        version: u64,
        visibility: Visibility,
        entries: Vec<DirEntry>,
        prev: Option<ContentId>,
        ts: TimestampMs,
    ) -> DomainDirectory {
        let mut d = DomainDirectory {
            suite: Suite::Classical,
            domain: domain.into(),
            authority: authority.public(),
            version,
            visibility,
            entries,
            prev,
            ts,
            sig: Vec::new(),
        };
        d.sig = authority.sign_domain(DOMAIN_DIRECTORY_DS, &d.signing_body());
        d
    }

    /// Verify the domain-authority signature (§18.9.3). The caller MUST additionally verify each
    /// entry's forward `name → ik` binding (the directory indexes, it does not attest).
    pub fn verify(&self) -> Result<(), IdentityError> {
        if !self.suite.is_supported() {
            return Err(IdentityError::UnsupportedSuite(self.suite.as_u8()));
        }
        verify_domain(&self.authority, DOMAIN_DIRECTORY_DS, &self.signing_body(), &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn entry(name: &str, seed: u8, custody: Custody, roles: Option<Vec<String>>) -> DirEntry {
        DirEntry {
            name: name.into(),
            ik: key(seed).public(),
            id: ContentId::of(name.as_bytes()),
            custody,
            roles,
            added: 1_700_000_000_000,
        }
    }

    #[test]
    fn directory_signs_verifies_and_round_trips() {
        let dir = DomainDirectory::issue(
            &key(0x11),
            "abc.com",
            7,
            Visibility::Public,
            vec![
                entry("alice@abc.com", 0x22, Custody::Sovereign, Some(vec!["admin".into()])),
                entry("bob@abc.com", 0x33, Custody::OrgManaged, None),
            ],
            None,
            1_700_000_000_000,
        );
        assert!(dir.verify().is_ok());
        let bytes = dir.det_cbor();
        assert_eq!(bytes[0] & 0xe0, 0xa0, "directory is a CBOR map");
        assert_eq!(bytes[1], 0x01, "first key is integer 1 (suite), not a text key");
        let back = DomainDirectory::from_det_cbor(&bytes).unwrap();
        assert_eq!(dir, back);
        assert_eq!(bytes, back.det_cbor());
        assert!(back.verify().is_ok());
    }

    #[test]
    fn tampered_directory_fails_signature() {
        let mut dir = DomainDirectory::issue(
            &key(0x11),
            "abc.com",
            1,
            Visibility::MembersOnly,
            vec![],
            None,
            1,
        );
        dir.entries.push(entry("evil@abc.com", 0x44, Custody::Sovereign, None));
        assert_eq!(dir.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn unknown_visibility_and_custody_fail_closed() {
        assert!(Visibility::from_str("world").is_err());
        assert!(Custody::from_str("hosted").is_err());
    }
}
