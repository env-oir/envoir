//! # dmtap-seam — the DMTAP operator seam
//!
//! Envoir does not run a business: nobody charges anyone from inside this repository, and there
//! is no control plane. This crate exists so an **operator** — anyone who runs a node or gateway
//! for other people — can add quotas, usage accounting, and authorization **without forking or
//! patching the protocol**. A self-hoster running only their own node never touches any of this;
//! the defaults make the OSS fully functional standing alone.
//!
//! The seam is a small set of traits the OSS calls at well-defined points:
//!
//! - [`Metering`] — emit usage events at the real cost centers (legacy egress, hosted storage,
//!   relay bandwidth, message counts).
//! - [`Provisioning`] — create/suspend accounts and `@`-addresses (onboarding tiers A/B/C).
//! - [`Policy`] — quotas & entitlements (storage caps, send caps, rate limits).
//! - [`GatewayAuthz`] — authorize legacy egress with per-identity accountability.
//! - [`BillingSink`] — hand accumulated usage to a billing system, if one is attached. TODO(patala):
//!   "Patala" is a separate, not-yet-ready billing system expected to implement this eventually;
//!   see `billing_export` module docs. This crate computes no price and renders no invoice.
//! - [`postage::PostageProvider`] — OPTIONAL prepaid anti-spam credit (spec §9.5): a sender tops
//!   up a balance once, through whatever payment provider an operator chooses (never named here —
//!   see the `postage` module docs), and [`postage::PostageGatedAuthz`] draws it down per gateway
//!   send. Off by default; composes with [`GatewayAuthz`] without needing a place in [`Seam`].
//!
//! An operator who wants a working reference implementation of usage tracking (a bounded,
//! idempotent ingest queue), a flat-quota [`Policy`], the fail-closed [`GatewayAuthz`] reference
//! logic, and the gateway domain's DNS record-set builder does not need to write it from scratch —
//! see the sibling `dmtap-operator` crate, which implements these traits against no billing logic
//! at all.
//!
//! ## The self-host-default philosophy
//!
//! Every seam trait ships a **self-host default** that is unlimited / no-op ([`NullMetering`],
//! [`SelfHostProvisioning`], [`UnlimitedPolicy`], [`OpenGatewayAuthz`], [`NullBillingSink`]). So
//! the OSS is a **fully functional, unrestricted product on its own** — you can self-host and owe
//! nothing to anyone, nothing is gated. A third-party operator supplies real implementations to
//! add quotas, usage accounting, and (if they choose) billing **without forking or patching the
//! protocol**.
//!
//! ## The inviolable rule
//!
//! **Privacy, cryptography, metadata-privacy, and recovery are NEVER behind this seam.** The
//! seam meters and gates *operations* (hosting, storage, legacy egress) and *organizational*
//! concerns (accounts, quotas) — never protection. There is no seam hook that can disable
//! encryption, weaken the mixnet, or lock a user out of their own keys. See `CONTRACT.md`.
//!
//! **Native node-to-node delivery has no operator on the path, so there is nothing to meter or
//! bill.** Metering only ever applies to operator-*provided* services — legacy egress through
//! someone's gateway, storage on someone's hosted node, bytes through someone's relay. A
//! self-hosting user with no legacy correspondents and no hosted operator is never metered and
//! never billed by anyone, full stop.
//!
//! ## In-process and out-of-process
//!
//! An operator embeds this crate and uses the default impls, the `dmtap-operator` reference
//! impls, or their own. A remote/out-of-process operator implements the **same contract** over
//! HTTP/events; see `CONTRACT.md`. The OSS treats an unreachable operator by **failing open to
//! the self-host defaults** for functionality (never breaking mail) while **failing closed for
//! [`GatewayAuthz`]** (unattributable legacy egress is exactly the open-relay failure mode
//! accountability exists to prevent — see `CONTRACT.md` §12.2 and `dmtap-operator::authz`).

pub mod billing_export;
pub mod metering;
pub mod postage;
pub mod provisioning;
pub mod policy;
pub mod gateway_authz;

pub use billing_export::{BillingSink, NullBillingSink, UsageTotal};
pub use postage::{
    Money, NullPostage, NullReminders, PostageBalance, PostageGatedAuthz, PostageProvider,
    PostageReminder, PostageReminderSink, ReminderKind, SpendResult, TopUpRequest, TopUpResult,
};
pub use metering::{Metering, NullMetering, UsageEvent, UsageKind};
pub use provisioning::{
    Account, AddressTier, ProvisionRequest, ProvisionResult, Provisioning, SelfHostProvisioning,
};
pub use policy::{Policy, PolicyDecision, Quota, UnlimitedPolicy};
pub use gateway_authz::{GatewayAuthz, GatewayDecision, OpenGatewayAuthz, SendCredential};

/// An opaque account/tenant identifier at the seam boundary.
/// Self-host uses a single fixed id ([`SELF_HOST_ACCOUNT`]).
pub type AccountId = String;

/// The account id used in self-host mode (one local owner, no tenancy).
pub const SELF_HOST_ACCOUNT: &str = "self-host";

/// Milliseconds since the Unix epoch, passed explicitly (the OSS never assumes the operator's
/// clock). Callers supply the timestamp so this crate needs no clock dependency.
pub type TimestampMs = u64;

/// A bundle of the five seam implementations an operator provides. Self-host constructs this
/// with all defaults via [`Seam::self_host`].
pub struct Seam {
    pub metering: Box<dyn Metering>,
    pub provisioning: Box<dyn Provisioning>,
    pub policy: Box<dyn Policy>,
    pub gateway_authz: Box<dyn GatewayAuthz>,
    /// TODO(patala): no billing system attached by default — see `billing_export` module docs.
    pub billing: Box<dyn BillingSink>,
}

impl Seam {
    /// The fully-functional, unlimited, no-billing self-host configuration.
    pub fn self_host() -> Self {
        Seam {
            metering: Box::new(NullMetering),
            provisioning: Box::new(SelfHostProvisioning),
            policy: Box::new(UnlimitedPolicy),
            gateway_authz: Box::new(OpenGatewayAuthz),
            billing: Box::new(NullBillingSink),
        }
    }
}

impl Default for Seam {
    fn default() -> Self {
        Seam::self_host()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_host_seam_is_fully_functional_and_unmetered() {
        let seam = Seam::self_host();
        // metering is a no-op
        seam.metering.record(UsageEvent {
            account: SELF_HOST_ACCOUNT.into(),
            kind: UsageKind::MessagesSent,
            amount: 1,
            ts_ms: 0,
        });
        // policy allows everything
        assert!(matches!(
            seam.policy
                .check(&SELF_HOST_ACCOUNT.to_string(), &Quota::StorageBytes(u64::MAX)),
            PolicyDecision::Allow
        ));
        // gateway authorizes everything
        assert!(matches!(
            seam.gateway_authz
                .authorize(&SendCredential::none(SELF_HOST_ACCOUNT)),
            GatewayDecision::Allow
        ));
        // no billing system is attached; exporting a total is a no-op, not an error
        seam.billing.export(UsageTotal {
            account: SELF_HOST_ACCOUNT.into(),
            kind: UsageKind::StorageBytes,
            amount: 0,
        });
    }
}
