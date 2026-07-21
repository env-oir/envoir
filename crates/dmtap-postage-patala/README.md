# dmtap-postage-patala

An OPTIONAL, isolated reference implementation of `dmtap-seam`'s `postage::PostageProvider`
(spec §9.5), backed by [`patala`](../../../patala/PATALA.md) — a separate, sibling, non-custodial
payment-rail substrate (`patala-core` + `patala-stellar`).

**This is ONE possible payment provider, never a hard dependency.** `dmtap-seam::postage` names
no provider anywhere in its trait — see that module's docs. An operator who wants Stripe, M-Pesa,
or their own ledger instead writes their own small `PostageProvider` implementation and never
depends on this crate, `patala-core`, or `patala-stellar` at all. `dmtap-seam` itself has zero
dependencies (`cargo tree -p dmtap-seam` is empty) and this crate is deliberately excluded from
the envoir workspace's `default-members` (see the root `Cargo.toml`), so plain
`cargo build`/`cargo test` at the workspace root never pulls patala in.

## What's real here, and what isn't

- **Real:** the split between a synchronous top-up *intent* (`PatalaPostage::top_up`, part of the
  `PostageProvider` trait) and the async, verify-then-credit path
  (`PatalaPostage::credit_from_receipt`) that calls `patala_core::PaymentRail::verify` before ever
  touching the local prepaid ledger. Real, offline-tested logic: currency mismatch, tampered
  receipts, and idempotent re-crediting are all covered against `patala_core::MockRail`.
  `spend`/`balance` are a real, tested in-memory ledger.
- **Non-custodial by construction:** this crate never holds a sender's funds and never signs a
  payment on a sender's behalf — it only ever *verifies* a receipt for a payment the sender's own
  wallet already made. See the crate's module docs for why `top_up` can therefore never itself
  credit anything.
- **UNVERIFIED AGAINST LIVE STELLAR:** `StellarPostage::stellar` wires this crate to
  `patala-stellar`'s real `HorizonRpc` client. **Nobody has run this constructor's real path
  against a live Stellar network (testnet or mainnet) from this environment.** Every test in this
  crate exercises `credit_from_receipt`/`top_up`/`spend`/`balance` against
  `patala_core::MockRail`, which is deterministic and offline by design — it proves this crate's
  own verify-then-credit logic is correct, not that a real Stellar payment has ever settled through
  it. `patala-stellar`'s own `README.md` discloses the same residual for its rail. Treat the
  real-money top-up path as unverified until someone runs it against Stellar testnet (or mainnet)
  and confirms it.

## Using it

```rust,ignore
use dmtap_postage_patala::StellarPostage;
use patala_stellar::Network;

let provider = StellarPostage::stellar(
    Network::Testnet,
    "GISSUERADDRESS...",      // the USDC issuer this operator trusts
    100,                       // base fee, stroops
    "https://horizon-testnet.stellar.org",
    "GOPERATORADDRESS...",    // where senders pay to top up
);

// Sync: hand back a payment intent (destination + amount + reference).
let intent = provider.top_up(dmtap_seam::postage::TopUpRequest { /* ... */ });

// Async, once the gateway has a receipt for the sender's own on-chain payment:
// provider.credit_from_receipt(&account, receipt).await?;

// Wire into gateway_authz exactly like any other PostageProvider:
let authz = dmtap_seam::postage::PostageGatedAuthz::new(
    my_inner_authz, provider, /* cost_per_send */ 100, /* low balance threshold */ 500, "USDC",
);
```

Any other rail works identically — `PatalaPostage<R>` is generic over `patala_core::PaymentRail`,
so a `patala_core::MockRail` (for tests) or a future patala rail both plug in without a single
line of `dmtap-seam` or `dmtap-postage-patala` needing to change.
