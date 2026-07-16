//! Error type for the DMTAP MLS layer.
//!
//! openmls has a rich, deeply-typed error hierarchy; this crate collapses it to a small,
//! DMTAP-shaped enum so callers (the node) get one uniform error while still preserving the
//! underlying diagnostic string. Failures are surfaced, never swallowed (fail-closed).

/// A failure in an MLS group operation (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsError {
    /// Generating a signature keypair / credential / KeyPackage failed.
    KeyMaterial(String),
    /// Creating, joining, or mutating (Add/Remove/Commit) a group failed.
    Group(String),
    /// TLS wire (de)serialization of an MLS message / KeyPackage / Welcome failed.
    Codec(String),
    /// Processing an inbound MLS message failed (bad epoch, wrong group, decrypt failure —
    /// the fail-closed outcome a removed member hits when it can no longer read the group).
    Process(String),
    /// A message that was expected to be an MLS **application** message was some other content
    /// (a handshake/commit/proposal), or vice-versa.
    UnexpectedContent,
    /// An operation referenced a member/leaf that is not in the group.
    UnknownMember,
    /// A Commit this device authored and submitted to the committer was **superseded**: a
    /// different member's Commit, built from the same base epoch, was ordered ahead of it and
    /// already advanced the epoch by the time this device tried to merge its own pending Commit.
    /// `openmls` treats merging a no-longer-pending commit as a silent no-op success, so
    /// [`Session::advance`](crate::Session::advance) detects this and reports it explicitly rather
    /// than claiming the (actually-discarded) change went through — the caller must re-derive and
    /// resubmit its change against the new epoch (spec §5.1: the committer gives a total order, but
    /// two racing proposers off the same epoch is a real possibility on a leaderless mesh).
    StaleCommit,
}

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsError::KeyMaterial(e) => write!(f, "MLS key material error: {e}"),
            MlsError::Group(e) => write!(f, "MLS group error: {e}"),
            MlsError::Codec(e) => write!(f, "MLS codec error: {e}"),
            MlsError::Process(e) => write!(f, "MLS message processing error: {e}"),
            MlsError::UnexpectedContent => f.write_str("unexpected MLS message content"),
            MlsError::UnknownMember => f.write_str("member/leaf is not in the group"),
            MlsError::StaleCommit => f.write_str(
                "this device's own pending commit was superseded by a concurrently-ordered \
                 commit from the same base epoch; re-derive and resubmit against the new epoch",
            ),
        }
    }
}

impl std::error::Error for MlsError {}
