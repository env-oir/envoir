//! Billing export seam — the neutral boundary a future billing system attaches to.
//!
//! Envoir does not charge anyone: it ships no price book, no invoice type, no proration, no
//! payment-processor integration, and no multi-tenant superadmin-as-a-business surface. That is
//! deliberate — nobody runs Envoir as a business from inside this repository.
//!
//! But a third-party operator MAY legitimately charge for the *operations* they provide (hosted
//! storage, legacy-email egress, relay bandwidth) to the people whose nodes they run. Envoir's job
//! is to hand that operator accurate, deduplicated usage — never to decide what it costs. That is
//! what [`BillingSink`] is: accumulated per-account usage in, nothing prescribed out.
//!
//! TODO(patala): "Patala" is a separate, not-yet-ready billing system being built outside this
//! repository. It is expected to implement [`BillingSink`] once it exists. Until then — and for
//! any operator who never wants one — [`NullBillingSink`] is the only implementation, exactly like
//! the self-host default for every other seam capability: usage is still tracked
//! ([`crate::Metering`]) and quota-enforced ([`crate::Policy`]) with no billing system attached at
//! all; it is simply never exported anywhere.
//!
//! This module encodes no prices, no currency, no plan, and no invoice — and never will. If a
//! change to this file would require deciding what something costs, it belongs in Patala, not here.

use crate::metering::UsageKind;
use crate::AccountId;

/// Accumulated usage for one account and one metered dimension, over whatever window the
/// accumulating operator chooses (this crate does not define billing periods). A pure count —
/// never a price, a currency, or a plan. What the receiving billing system does with it is
/// entirely its own concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageTotal {
    pub account: AccountId,
    pub kind: UsageKind,
    /// The accumulated amount in the kind's natural unit (bytes, or a count).
    pub amount: u64,
}

/// TODO(patala): the boundary a billing system implements once one exists. Receives accumulated
/// usage; decides nothing about privacy, protocol behavior, or whether the account keeps working —
/// [`crate::Policy`] and [`crate::GatewayAuthz`] already own those decisions, before and
/// independently of any billing system being attached.
pub trait BillingSink: Send + Sync {
    /// Hand one accumulated total to the billing system. Fire-and-forget from the OSS's point of
    /// view: nothing here can feed back into a protocol/privacy decision (see the crate's
    /// inviolable rule).
    fn export(&self, total: UsageTotal);
}

/// No billing system attached (the default, and the only implementation this crate ships). Usage
/// has already been tracked and quota-checked before this runs; dropping it here means it is never
/// billed by anyone — never that it went untracked or unenforced.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullBillingSink;

impl BillingSink for NullBillingSink {
    fn export(&self, _total: UsageTotal) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_billing_sink_is_noop() {
        NullBillingSink.export(UsageTotal {
            account: "self-host".into(),
            kind: UsageKind::StorageBytes,
            amount: 12345,
        });
    }
}
