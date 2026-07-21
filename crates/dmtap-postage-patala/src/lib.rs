//! # dmtap-postage-patala
//!
//! An OPTIONAL, isolated reference implementation of
//! [`dmtap_seam::postage::PostageProvider`] (spec §9.5) backed by
//! [`patala`](../../../patala/PATALA.md) — a separate, sibling, non-custodial payment-rail
//! substrate. This crate exists to prove the seam is usable end-to-end with a real payment rail;
//! it is **never** a dependency of `dmtap-seam` itself, and an operator who wants a different
//! provider (Stripe, M-Pesa, their own ledger) writes their own small `PostageProvider` impl and
//! never looks at this crate at all — see `dmtap_seam::postage` module docs.
//!
//! ## Non-custodial, by construction
//!
//! This adapter never holds a sender's funds and never signs a payment on a sender's behalf.
//! Patala's rails are non-custodial (a `NonCustodialFinal` rail like `patala-stellar` settles
//! wallet-to-wallet); this crate only ever **verifies** a payment the sender's own wallet already
//! made, then credits a local prepaid ledger it owns. Custody, if any exists at all, is entirely
//! the payment provider's concern (`PATALA.md` §1), never this crate's.
//!
//! ## Two-phase top-up (why [`PatalaPostage::top_up`] never itself credits anything)
//!
//! [`dmtap_seam::postage::PostageProvider::top_up`] is a **synchronous** seam call. Patala's
//! `PaymentRail` is `async`, and — more importantly — a non-custodial rail requires the *sender's
//! own* signer to submit the payment; this adapter has no access to that key and must not invent
//! one. So the two halves are split, honestly, into:
//!
//! 1. [`PatalaPostage::top_up`] (sync, the `PostageProvider` method): returns a **payment
//!    intent** — pay [`PatalaPostage::destination`] this amount, with `reference` as the
//!    correlation key — as [`dmtap_seam::postage::TopUpResult::Pending`]. It credits nothing.
//! 2. [`PatalaPostage::credit_from_receipt`] (async, an inherent method — NOT part of the seam
//!    trait): the gateway calls this once it has a [`patala_core::Receipt`] for that payment
//!    (however it obtained one — the sender submitted it, or the operator's own infrastructure
//!    observed the chain). This is the ONLY place this crate trusts a payment happened: it calls
//!    [`patala_core::PaymentRail::verify`] and credits the local ledger **only** on a verified,
//!    currency-matching, not-already-credited receipt (idempotent on `reference`).
//!
//! [`PatalaPostage::spend`]/[`balance`] then operate purely on the local ledger — exactly the
//! "prepaid, not per-message" rule from the seam's own docs: no further patala/network calls on
//! the hot send path.
//!
//! ## UNVERIFIED AGAINST LIVE STELLAR
//!
//! **This crate has not been run against a live Stellar network (testnet or mainnet) from this
//! environment.** All tests here run fully offline against [`patala_core::MockRail`]; a real
//! top-up flow additionally depends on `patala-stellar`'s own live path, which that crate's own
//! README already discloses as unverified against live Horizon. Treat the end-to-end real-money
//! path as **UNVERIFIED** until someone runs it against a real (or at least testnet) Stellar
//! network and confirms it. See this crate's `README.md`.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use patala_core::{PayRequest, PaymentRail, Receipt};

use dmtap_seam::postage::{
    Money, PostageBalance, PostageProvider, SpendResult, TopUpRequest, TopUpResult,
};
use dmtap_seam::AccountId;

/// Everything that can go wrong crediting a receipt. Every variant is a refusal: none of them
/// ever results in a balance being credited.
#[derive(Debug, thiserror::Error)]
pub enum PostagePatalaError {
    /// The receipt's currency does not match this provider's configured currency.
    #[error("receipt currency {receipt} does not match this postage provider's currency {expected}")]
    CurrencyMismatch { receipt: String, expected: String },
    /// [`PaymentRail::verify`] itself failed (an operational failure to even check — RPC down,
    /// etc. — never implies the receipt is valid; see that method's own fail-closed contract).
    #[error("payment rail verification failed: {0}")]
    Rail(String),
    /// [`PaymentRail::verify`] returned `Ok(false)`: the receipt does not hold up.
    #[error("receipt did not verify")]
    NotVerified,
}

/// A [`PostageProvider`] backed by ANY `patala_core::PaymentRail` (a generic Stellar/Solana/mock
/// rail, or your own) — see the module docs for why crediting is split into
/// [`PatalaPostage::top_up`] (sync, always just an intent) and
/// [`PatalaPostage::credit_from_receipt`] (async, the only place a payment is trusted).
///
/// Like every `dmtap-seam` implementor, this struct owns its own storage: a plain in-memory
/// `Mutex<HashMap<...>>` ledger here, for reference — a real operator deployment would likely
/// back this with a database instead, which is exactly why `dmtap-seam` never prescribes storage.
pub struct PatalaPostage<R: PaymentRail> {
    rail: R,
    /// The operator's own receiving address/account senders pay into to top up. Opaque to this
    /// crate beyond carrying it through to the sender as part of the payment intent.
    destination: String,
    currency: String,
    ledger: Mutex<HashMap<AccountId, u64>>,
    /// Dedup: a receipt reference already credited is never credited twice, even if presented
    /// again (e.g. a retried gateway call).
    credited_references: Mutex<HashSet<String>>,
}

impl<R: PaymentRail> PatalaPostage<R> {
    /// Wrap `rail` (any `patala_core::PaymentRail` — real or [`patala_core::MockRail`] for
    /// tests/offline use) as a `PostageProvider`. `destination` is the operator's own receiving
    /// address/account; `currency` is the asset/ISO code this provider tracks balances in (must
    /// match what `rail` actually settles, e.g. `"USDC"` for `patala-stellar`).
    pub fn new(rail: R, destination: impl Into<String>, currency: impl Into<String>) -> Self {
        PatalaPostage {
            rail,
            destination: destination.into(),
            currency: currency.into(),
            ledger: Mutex::new(HashMap::new()),
            credited_references: Mutex::new(HashSet::new()),
        }
    }

    /// The address/account senders should pay to top up (surfaced to a client alongside the
    /// [`TopUpResult::Pending`] intent).
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The currency/asset code this provider tracks balances in.
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// The real credit path (see module docs). Verifies `receipt` against the configured
    /// `patala_core::PaymentRail` and, only on success, credits `account`'s prepaid balance by
    /// `receipt.amount_minor`. Idempotent on `receipt.reference`: a receipt whose reference has
    /// already been credited is accepted (returns the current balance) without crediting again —
    /// so a gateway may safely retry this call.
    pub async fn credit_from_receipt(
        &self,
        account: &AccountId,
        receipt: Receipt,
    ) -> Result<TopUpResult, PostagePatalaError> {
        if receipt.currency != self.currency {
            return Err(PostagePatalaError::CurrencyMismatch {
                receipt: receipt.currency.clone(),
                expected: self.currency.clone(),
            });
        }

        // Idempotency check BEFORE re-verifying: a repeated call with an already-credited
        // reference just reports the current balance, never re-credits.
        if self.credited_references.lock().unwrap().contains(&receipt.reference) {
            let balance = self.ledger.lock().unwrap().get(account).copied().unwrap_or(0);
            return Ok(TopUpResult::Credited {
                new_balance: Money::new(balance, self.currency.clone()),
                reference: receipt.reference,
            });
        }

        // The ONLY place this crate trusts a payment happened. Fail closed per
        // `PaymentRail::verify`'s own contract: `Err` is an operational failure to check (never
        // "valid"), `Ok(false)` is a receipt that does not hold up.
        let verified = self
            .rail
            .verify(&receipt)
            .await
            .map_err(|e| PostagePatalaError::Rail(e.to_string()))?;
        if !verified {
            return Err(PostagePatalaError::NotVerified);
        }

        let new_balance = {
            let mut ledger = self.ledger.lock().unwrap();
            let entry = ledger.entry(account.clone()).or_insert(0);
            *entry = entry.saturating_add(receipt.amount_minor);
            *entry
        };
        self.credited_references.lock().unwrap().insert(receipt.reference.clone());

        Ok(TopUpResult::Credited {
            new_balance: Money::new(new_balance, self.currency.clone()),
            reference: receipt.reference,
        })
    }

    /// Build the [`patala_core::PayRequest`] a sender's own wallet would submit to top up
    /// `account` by `amount_minor` — a convenience for constructing the intent this crate's
    /// `top_up` describes; never submitted or signed by this crate itself.
    pub fn top_up_pay_request(&self, amount_minor: u64, reference: impl Into<String>) -> PayRequest {
        PayRequest {
            amount_minor,
            currency: self.currency.clone(),
            destination: self.destination.clone(),
            reference: reference.into(),
        }
    }
}

/// A [`PatalaPostage`] wired to `patala-stellar`'s real rail — the one reference rail this crate
/// ships (Stellar: ~$0.0001/tx fees suit prepaid micropayment top-ups, 3-5s finality, Ed25519
/// StrKey so the operator's receiving identity key doubles as its wallet with no separate mapping
/// table; see `patala-stellar`'s own docs and `PATALA.md` §6).
pub type StellarPostage = PatalaPostage<patala_stellar::StellarRail>;

impl StellarPostage {
    /// Construct a postage provider that verifies USDC-on-Stellar top-ups against `horizon_url`,
    /// tracking balances for `usdc_issuer` on `network`, with senders paying into `destination`
    /// (a StrKey Stellar address, `G...`). Verify-only (no signer attached) — this crate never
    /// signs a payment on a sender's behalf; see the module docs' non-custodial section.
    ///
    /// **UNVERIFIED AGAINST LIVE STELLAR** — see this crate's `README.md`. Every test here runs
    /// against `patala_core::MockRail`, never this constructor's real `HorizonRpc`.
    pub fn stellar(
        network: patala_stellar::Network,
        usdc_issuer: impl Into<String>,
        base_fee_stroops: u32,
        horizon_url: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        let cfg = patala_stellar::StellarConfig {
            network,
            usdc_issuer: usdc_issuer.into(),
            base_fee_stroops,
        };
        let rpc: std::sync::Arc<dyn patala_stellar::rpc::StellarRpc> =
            std::sync::Arc::new(patala_stellar::rpc::HorizonRpc::new(horizon_url));
        let rail = patala_stellar::StellarRail::new(cfg, rpc);
        PatalaPostage::new(rail, destination, "USDC")
    }
}

impl<R: PaymentRail> PostageProvider for PatalaPostage<R> {
    /// Always an intent, never a credit (see module docs' two-phase top-up section) — this
    /// adapter has no sender key to sign a non-custodial payment with, so the honest synchronous
    /// answer is "here is where and how much to pay"; [`Self::credit_from_receipt`] is where a
    /// completed payment actually lands.
    fn top_up(&self, req: TopUpRequest) -> TopUpResult {
        if req.amount.currency != self.currency {
            return TopUpResult::Failed {
                reason: format!(
                    "this postage provider tracks {}, not {}",
                    self.currency, req.amount.currency
                ),
            };
        }
        TopUpResult::Pending { reference: req.reference }
    }

    fn balance(&self, account: &AccountId) -> Option<PostageBalance> {
        self.ledger.lock().unwrap().get(account).map(|&minor_units| PostageBalance {
            account: account.clone(),
            balance: Money::new(minor_units, self.currency.clone()),
        })
    }

    fn spend(&self, account: &AccountId, amount_minor_units: u64) -> SpendResult {
        let mut ledger = self.ledger.lock().unwrap();
        let balance = ledger.entry(account.clone()).or_insert(0);
        if *balance < amount_minor_units {
            SpendResult::Insufficient {
                balance_minor_units: *balance,
                required_minor_units: amount_minor_units,
            }
        } else {
            *balance -= amount_minor_units;
            SpendResult::Spent { remaining_minor_units: *balance }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmtap_seam::gateway_authz::{GatewayAuthz, GatewayDecision, SendCredential};
    use dmtap_seam::postage::PostageGatedAuthz;
    use patala_core::{Error as PatalaError, MockRail, RailClass};

    fn mock_rail() -> MockRail {
        MockRail::new("mock-postage-rail", RailClass::NonCustodialFinal, vec!["USDC".to_string()])
    }

    #[tokio::test]
    async fn top_up_is_always_a_pending_intent_never_a_credit() {
        let provider = PatalaPostage::new(mock_rail(), "operator-address", "USDC");
        let result = provider.top_up(TopUpRequest {
            account: "acct".into(),
            amount: Money::new(500, "USDC"),
            reference: "ref-1".into(),
        });
        assert_eq!(result, TopUpResult::Pending { reference: "ref-1".into() });
        // Nothing was credited by the sync call alone.
        assert_eq!(provider.balance(&"acct".to_string()), None);
    }

    #[tokio::test]
    async fn top_up_rejects_a_currency_this_provider_does_not_track() {
        let provider = PatalaPostage::new(mock_rail(), "operator-address", "USDC");
        let result = provider.top_up(TopUpRequest {
            account: "acct".into(),
            amount: Money::new(500, "EUR"),
            reference: "ref-1".into(),
        });
        assert!(matches!(result, TopUpResult::Failed { .. }));
    }

    #[tokio::test]
    async fn credit_from_receipt_verifies_before_crediting() {
        let rail = mock_rail();
        let account: AccountId = "acct".into();
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.expect("mock charge always succeeds");

        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        let result = provider.credit_from_receipt(&account, receipt).await.expect("verifies");
        assert!(matches!(result, TopUpResult::Credited { .. }));
        assert_eq!(provider.balance(&account).unwrap().balance.minor_units, 1_000);
    }

    #[tokio::test]
    async fn credit_from_receipt_rejects_a_tampered_receipt() {
        let rail = mock_rail();
        let account: AccountId = "acct".into();
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let mut receipt = rail.charge(&req).await.expect("mock charge always succeeds");
        receipt.amount_minor = 999_999; // tamper with the amount after the fact

        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        let err = provider.credit_from_receipt(&account, receipt).await.unwrap_err();
        assert!(matches!(err, PostagePatalaError::NotVerified));
        assert_eq!(provider.balance(&account), None, "a rejected receipt credits nothing");
    }

    #[tokio::test]
    async fn credit_from_receipt_rejects_currency_mismatch() {
        let rail = mock_rail();
        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        let receipt = Receipt {
            rail_id: "mock-postage-rail".into(),
            amount_minor: 1_000,
            currency: "EUR".into(), // provider tracks USDC
            reference: "ref-1".into(),
            proof: vec![],
            settled_at_unix: 0,
        };
        let err = provider
            .credit_from_receipt(&"acct".to_string(), receipt)
            .await
            .unwrap_err();
        assert!(matches!(err, PostagePatalaError::CurrencyMismatch { .. }));
    }

    #[tokio::test]
    async fn credit_from_receipt_is_idempotent_on_reference() {
        let rail = mock_rail();
        let account: AccountId = "acct".into();
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.expect("mock charge always succeeds");

        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        provider.credit_from_receipt(&account, receipt.clone()).await.unwrap();
        // Presenting the exact same receipt again must not double-credit.
        provider.credit_from_receipt(&account, receipt).await.unwrap();
        assert_eq!(provider.balance(&account).unwrap().balance.minor_units, 1_000);
    }

    #[tokio::test]
    async fn spend_and_insufficient_after_credit() {
        let rail = mock_rail();
        let account: AccountId = "acct".into();
        let req = PayRequest {
            amount_minor: 100,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();
        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        provider.credit_from_receipt(&account, receipt).await.unwrap();

        assert_eq!(provider.spend(&account, 40), SpendResult::Spent { remaining_minor_units: 60 });
        assert_eq!(
            provider.spend(&account, 1_000),
            SpendResult::Insufficient { balance_minor_units: 60, required_minor_units: 1_000 }
        );
    }

    #[tokio::test]
    async fn composes_with_gateway_authz_exactly_like_any_other_provider() {
        // Proves this real, patala-backed provider is a drop-in for the generic seam wiring —
        // no patala-specific code needed in `dmtap_seam::postage` itself.
        let rail = mock_rail();
        let account: AccountId = "acct".into();
        let req = PayRequest {
            amount_minor: 200,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();
        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        provider.credit_from_receipt(&account, receipt).await.unwrap();

        let authz = PostageGatedAuthz::new(dmtap_seam::gateway_authz::OpenGatewayAuthz, provider, 50, 10, "USDC");
        assert_eq!(authz.authorize(&SendCredential::none("acct")), GatewayDecision::Allow);
    }

    #[tokio::test]
    async fn rail_operational_failure_surfaces_as_rail_error_not_a_false_verify() {
        // A rail configured to fail its own calls must surface as a `Rail` error, never be
        // silently treated as a verified/unverified receipt either way.
        struct AlwaysErrorsOnVerify(MockRail);

        #[async_trait::async_trait]
        impl PaymentRail for AlwaysErrorsOnVerify {
            fn id(&self) -> &str {
                self.0.id()
            }
            fn capabilities(&self) -> &patala_core::RailCapabilities {
                self.0.capabilities()
            }
            async fn quote(&self, req: &PayRequest) -> patala_core::Result<patala_core::Quote> {
                self.0.quote(req).await
            }
            async fn charge(&self, req: &PayRequest) -> patala_core::Result<Receipt> {
                self.0.charge(req).await
            }
            async fn verify(&self, _receipt: &Receipt) -> patala_core::Result<bool> {
                Err(PatalaError::Rail("rpc unreachable".into()))
            }
        }

        let inner = mock_rail();
        let req = PayRequest {
            amount_minor: 100,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = inner.charge(&req).await.unwrap();
        let rail = AlwaysErrorsOnVerify(mock_rail());
        let provider = PatalaPostage::new(rail, "operator-address", "USDC");
        let err = provider
            .credit_from_receipt(&"acct".to_string(), receipt)
            .await
            .unwrap_err();
        assert!(matches!(err, PostagePatalaError::Rail(_)));
    }
}
