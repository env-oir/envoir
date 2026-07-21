//! Gateway authorization seam — decide whether a sender may use *this* gateway for legacy
//! egress, and record accountability. Self-host default ([`OpenGatewayAuthz`]) allows all
//! (you are your own gateway).
//!
//! This ties to the fairness/accountability model (spec §7.7, §9): a gateway attributes abuse
//! to an anonymous-but-accountable credential (ARC token / postage / attested operator identity
//! and measured reputation) rather than an IP, which is what makes a shared or open gateway
//! economically viable. The seam lets an operator plug in quota + accountability checks;
//! self-host imposes none.

use crate::AccountId;

/// The credential a sender presents to a gateway (spec §9). Kept abstract here: the seam only
/// needs to know *which accountable token* to attribute and rate-limit, never the sender's
/// identity (sealed sender is preserved).
#[derive(Debug, Clone)]
pub struct SendCredential {
    /// The billing account, when the operator hosts the sender (None for anonymous ARC-token
    /// senders whose accountability is the token itself).
    pub account: Option<AccountId>,
    /// An opaque anonymous-rate-limited-credential (ARC) token id, if presented (spec §9.3).
    pub token: Option<String>,
    /// Postage voucher amount attached, if any (spec §9.5).
    pub postage: u64,
    /// Proof-of-work bits attached, if any (spec §9.4).
    pub pow_bits: u32,
}

impl SendCredential {
    /// A credential carrying nothing but an account (used by self-host / hosted senders).
    pub fn none(account: impl Into<AccountId>) -> Self {
        SendCredential {
            account: Some(account.into()),
            token: None,
            postage: 0,
            pow_bits: 0,
        }
    }
}

/// The gateway's decision for a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDecision {
    Allow,
    /// Rejected; `reason` is safe to surface (e.g. "insufficient postage", "rate limited").
    Deny { reason: String },
}

/// Legacy-egress authorization. Implemented by an operator; the OSS gateway calls it before
/// bridging a MOTE to SMTP.
pub trait GatewayAuthz: Send + Sync {
    fn authorize(&self, cred: &SendCredential) -> GatewayDecision;
}

/// Self-host default: open. You run your own gateway, so every send from you is allowed. This
/// is the "self-host backstop" that makes gateway access a right, not a grant (spec §7.7).
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenGatewayAuthz;

impl GatewayAuthz for OpenGatewayAuthz {
    fn authorize(&self, _cred: &SendCredential) -> GatewayDecision {
        GatewayDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_gateway_allows_all() {
        assert_eq!(
            OpenGatewayAuthz.authorize(&SendCredential::none("me")),
            GatewayDecision::Allow
        );
    }
}
