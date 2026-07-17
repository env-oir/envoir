//! Legacy-gateway **random-mode alias store** — the stateful `GatewayAliasMap` (spec §7.10.2,
//! §7.10.3, §18.3.12).
//!
//! This is the **third**, distinct native↔legacy address-mapping concern in the gateway, and the
//! only **stateful** one. It must not be confused with the two stateless / self-describing forms:
//!
//! - [`crate::forwarded_addr`] — the **encoded** alias `local.native_domain@gateway` (§7.10.2): a
//!   pure, reversible codec. The alias *is* the mapping; you **decode** the native address straight
//!   out of the local-part, no table involved. It **reveals the native domain** to the legacy
//!   recipient.
//! - [`crate::authz::AliasAllocator`] / [`crate::authz::key_derived_localpart`] — DMTAP-native
//!   vanity / key-derived local-parts *on the gateway's own domain*.
//!
//! The **random** form is different in kind (§7.10.2 table): a `<rand>@gateway.domain` local-part is
//! an **opaque, high-entropy token with no recoverable native address** — you **cannot** derive the
//! target from it (unlike the encoded form), you must **look it up** in a per-alias table row. This
//! is the "Hide-My-Email"-style alias: it **hides** the native address from the legacy recipient, at
//! the cost of gateway-held state and the availability of that mapping. A row MAY be scoped to a
//! single `correspondent` and MAY be **burnable** (a per-sender throwaway, §7.10.2).
//!
//! # Row lifecycle & the fail-closed resolve (§7.10.3)
//!
//! A row is in exactly one state at a given `now`:
//!
//! - **active** — present, not past its TTL, not burned → [`GatewayAliasMap::resolve`] returns the
//!   bound [`AliasTarget`].
//! - **missing** — no row for the token (never minted, or a token an attacker guessed).
//! - **expired** — present but `now` is at/after the row's absolute expiry (TTL elapsed).
//! - **burned** — explicitly revoked ([`GatewayAliasMap::burn`]) or one-time-consumed (a
//!   `one_time` row is burned on its first successful resolve).
//!
//! Resolving a **missing / expired / burned** alias **fails closed** with
//! [`GatewayAliasError::Unmapped`] — `ERR_GATEWAY_ALIAS_UNMAPPED` (`0x0605`), disposition
//! **RETURN_SENDER_SMTP** `550 5.1.1` ("no such user", identical to the §21.9 non-existent-recipient
//! reply, since the bridge owns no identity to defer to). The gateway **MUST NOT** guess a native
//! address for a token it cannot resolve (§7.10.3).
//!
//! # Unguessability
//!
//! The token is drawn from the **OS CSPRNG** ([`getrandom`]): [`TOKEN_ENTROPY_BYTES`] = 16 bytes =
//! **128 bits** of entropy, RFC 4648 base32-lowercased (`a–z2–7`) into a dot-free, RFC 5321-valid
//! local-part. 128 bits makes the token computationally unguessable — an attacker cannot forge a
//! live alias, so the only way a token resolves is if the gateway itself minted it (and it is still
//! live). The alphabet is **dot-free**, so a random token can never be mistaken for the dotted
//! [`crate::forwarded_addr`] encoding. Minting loops on the (astronomically unlikely) collision so a
//! new mint never silently overwrites a live row.

use std::collections::HashMap;

/// Number of CSPRNG bytes behind each random alias token. 16 bytes = **128 bits** of entropy — a
/// token an attacker cannot feasibly guess or forge, so a resolvable token is one the gateway
/// actually minted (see the module-level *Unguessability* note).
pub const TOKEN_ENTROPY_BYTES: usize = 16;

/// RFC 4648 base32 lowercase alphabet (`a–z2–7`) — every character is a valid, **dot-free** RFC 5321
/// dot-atom byte, so the token is a legal `<rand>` local-part that cannot be confused with the dotted
/// [`crate::forwarded_addr`] encoding. Kept self-contained (the [`crate::authz`] equivalent is
/// private) so this module depends only on `dmtap-core` and crate-internal types.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes as lowercase base32 (RFC 4648, no padding).
fn base32_lower(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut bits = 0u32;
    let mut nbits = 0u32;
    for &b in input {
        bits = (bits << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(BASE32_LOWER[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(BASE32_LOWER[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// The real destination a random alias forwards to — the **native anchor** the bridge re-routes to
/// (§7.10.4: "the native address is the anchor"). An alias is a rotatable pointer at one of these; it
/// is **never** an identity of its own (§7.10.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasTarget {
    /// A native DMTAP address `local@domain` (the reply-path anchor a legacy reply is mapped back
    /// to, §7.10.3), e.g. `imran` + `mydomain.com`.
    Native {
        /// The native local-part.
        local: String,
        /// The native domain (publishes a `_dmtap` record, no legacy MX).
        domain: String,
    },
    /// A raw DMTAP identity public key — the mesh key the converted MOTE is ultimately sealed to
    /// and delivered at (§7.10.3).
    Identity(Vec<u8>),
}

/// Why resolving a random alias failed. The sole variant is the normative fail-closed refusal an
/// unmapped / expired / burned lookup produces; it maps to the spec's error registry (§21, §19.3.1),
/// consistent with [`crate::provenance::ProvenanceError`]'s `code()` mapping.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GatewayAliasError {
    /// `ERR_GATEWAY_ALIAS_UNMAPPED` (`0x0605`): the random alias has **no live row** — it is
    /// missing, its TTL has expired, or it was burned/one-time-consumed. Disposition
    /// **RETURN_SENDER_SMTP** `550 5.1.1` ("no such user", §7.10.3 / §21.9). The gateway MUST NOT
    /// guess a native address for it.
    #[error("gateway alias unmapped (ERR_GATEWAY_ALIAS_UNMAPPED, 0x0605)")]
    Unmapped,
}

impl GatewayAliasError {
    /// The spec's numeric error code (§21) for wire/telemetry reporting.
    pub fn code(&self) -> u16 {
        match self {
            GatewayAliasError::Unmapped => 0x0605,
        }
    }

    /// The RETURN_SENDER_SMTP reply the gateway MX returns for this error (§7.10.3): a `550` with
    /// the `5.1.1` "no such user" enhanced status, identical to the §21.9 non-existent-recipient
    /// reply.
    pub const SMTP_CODE: u16 = 550;
    /// The enhanced status code accompanying [`Self::SMTP_CODE`] (RFC 3463 `5.1.1`).
    pub const SMTP_ENHANCED_STATUS: &'static str = "5.1.1";
}

/// One stored random-alias mapping: the bound [`AliasTarget`], its optional single-correspondent
/// scope, its absolute TTL, and its burned state. Kept private — the row's state is only ever
/// observed through [`GatewayAliasMap::resolve`]'s fail-closed verdict.
#[derive(Debug, Clone)]
struct AliasRow {
    /// The native anchor this alias forwards to.
    target: AliasTarget,
    /// Optional single-correspondent scope (§7.10.2): the one legacy sender allowed to use this
    /// alias. `None` = any correspondent. (Enforcement of the scope is the caller's; the row records
    /// the binding.)
    correspondent: Option<String>,
    /// Absolute expiry in ms since the epoch (`None` = no TTL, never expires by time). A resolve at
    /// `now >= expires_at_ms` is [`GatewayAliasError::Unmapped`].
    expires_at_ms: Option<u64>,
    /// Whether this alias is burned on its first successful resolve (a per-sender throwaway,
    /// §7.10.2).
    one_time: bool,
    /// Set once the row is explicitly revoked or one-time-consumed. A burned row always resolves
    /// to [`GatewayAliasError::Unmapped`].
    burned: bool,
}

impl AliasRow {
    /// Whether the row is expired at `now` (TTL elapsed). No TTL ⇒ never expires by time.
    fn is_expired(&self, now_ms: u64) -> bool {
        matches!(self.expires_at_ms, Some(exp) if now_ms >= exp)
    }
}

/// The stateful random-mode alias store (spec §18.3.12): opaque token → native anchor, with a
/// per-alias TTL, optional single-correspondent scope, and explicit / one-time burn.
///
/// Minting draws a **128-bit CSPRNG** token ([`TOKEN_ENTROPY_BYTES`]) so the alias is non-reversible
/// and unguessable — unlike [`crate::forwarded_addr`] you cannot derive the target from the token,
/// you resolve it here. Every resolve **fails closed** ([`GatewayAliasError::Unmapped`], `0x0605`)
/// for a missing / expired / burned row.
#[derive(Debug, Default, Clone)]
pub struct GatewayAliasMap {
    /// token local-part → its row.
    rows: HashMap<String, AliasRow>,
}

impl GatewayAliasMap {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint an **always-live** (no-TTL, any-correspondent, non-one-time) random alias bound to
    /// `target`, returning the opaque token local-part. The token is a fresh 128-bit CSPRNG draw;
    /// minting retries on the (astronomically unlikely) collision so it never overwrites a live row.
    pub fn mint(&mut self, target: AliasTarget) -> String {
        self.mint_row(target, None, None, false, 0)
    }

    /// Mint a random alias with an optional single-`correspondent` scope, an optional `ttl_ms`
    /// (relative to `now_ms`, after which the alias is [`GatewayAliasError::Unmapped`]), and a
    /// `one_time` flag (burn on first successful resolve). Returns the opaque token local-part.
    pub fn mint_with(
        &mut self,
        target: AliasTarget,
        correspondent: Option<String>,
        ttl_ms: Option<u64>,
        one_time: bool,
        now_ms: u64,
    ) -> String {
        self.mint_row(target, correspondent, ttl_ms, one_time, now_ms)
    }

    /// Shared minting core: draw a fresh unguessable token, compute the absolute expiry, and insert
    /// the row. Loops until the drawn token is unused so a mint never clobbers an existing row.
    fn mint_row(
        &mut self,
        target: AliasTarget,
        correspondent: Option<String>,
        ttl_ms: Option<u64>,
        one_time: bool,
        now_ms: u64,
    ) -> String {
        // Absolute expiry = now + ttl, saturating so a huge TTL never wraps to an early expiry.
        let expires_at_ms = ttl_ms.map(|ttl| now_ms.saturating_add(ttl));
        let row = AliasRow { target, correspondent, expires_at_ms, one_time, burned: false };

        loop {
            let token = random_alias_token();
            // Fail-closed against the (negligible) chance of a collision with a live token: never
            // overwrite an existing mapping.
            if !self.rows.contains_key(&token) {
                self.rows.insert(token.clone(), row);
                return token;
            }
        }
    }

    /// Resolve a random `alias` at `now_ms` to its bound [`AliasTarget`].
    ///
    /// Fails closed with [`GatewayAliasError::Unmapped`] (`0x0605`) if the row is **missing**,
    /// **expired** (TTL elapsed), or **burned** (explicitly revoked or already one-time-consumed).
    /// A successful resolve of a `one_time` row **burns** it, so a second resolve of the same
    /// one-time token is `Unmapped`.
    pub fn resolve(
        &mut self,
        alias: &str,
        now_ms: u64,
    ) -> Result<AliasTarget, GatewayAliasError> {
        let row = self.rows.get_mut(alias).ok_or(GatewayAliasError::Unmapped)?;
        if row.burned || row.is_expired(now_ms) {
            return Err(GatewayAliasError::Unmapped);
        }
        let target = row.target.clone();
        if row.one_time {
            // One-time-consumed ⇒ burn on first successful resolve (§7.10.2 burnable).
            row.burned = true;
        }
        Ok(target)
    }

    /// The single-`correspondent` scope a live alias was minted with, if any (`None` when the alias
    /// is unscoped, missing, expired, or burned). Lets a caller enforce §7.10.2's per-correspondent
    /// binding without exposing the target.
    pub fn correspondent_of(&self, alias: &str, now_ms: u64) -> Option<&str> {
        let row = self.rows.get(alias)?;
        if row.burned || row.is_expired(now_ms) {
            return None;
        }
        row.correspondent.as_deref()
    }

    /// Explicitly **burn** (revoke) an alias so every future resolve is [`GatewayAliasError::Unmapped`]
    /// (§7.10.4: rotatable / burnable with no effect on the native anchor). Returns `true` if a row
    /// existed to burn (idempotent: burning an already-burned row still returns `true`), `false` if
    /// the token was never minted.
    pub fn burn(&mut self, alias: &str) -> bool {
        match self.rows.get_mut(alias) {
            Some(row) => {
                row.burned = true;
                true
            }
            None => false,
        }
    }

    /// The number of stored rows (including expired/burned ones still occupying a slot).
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the store holds no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Draw a fresh opaque random alias local-part: [`TOKEN_ENTROPY_BYTES`] (128 bits) from the OS
/// CSPRNG, base32-lowercased into a dot-free, RFC 5321-valid `<rand>` local-part (§7.10.2). This is
/// the non-reversible, unguessable token — there is no target packed into it.
pub fn random_alias_token() -> String {
    let mut raw = [0u8; TOKEN_ENTROPY_BYTES];
    getrandom::getrandom(&mut raw).expect("OS CSPRNG unavailable");
    base32_lower(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(local: &str, domain: &str) -> AliasTarget {
        AliasTarget::Native { local: local.to_string(), domain: domain.to_string() }
    }

    #[test]
    fn mint_then_resolve_roundtrips() {
        let mut map = GatewayAliasMap::new();
        let target = native("imran", "mydomain.com");
        let alias = map.mint(target.clone());

        // A live row resolves to exactly the bound target.
        assert_eq!(map.resolve(&alias, 0), Ok(target.clone()));
        // Re-resolving a non-one-time live alias keeps working.
        assert_eq!(map.resolve(&alias, 1_000), Ok(target));
    }

    #[test]
    fn identity_target_roundtrips() {
        let mut map = GatewayAliasMap::new();
        let target = AliasTarget::Identity(vec![1, 2, 3, 4, 5]);
        let alias = map.mint(target.clone());
        assert_eq!(map.resolve(&alias, 0), Ok(target));
    }

    #[test]
    fn missing_row_fails_closed_0x0605() {
        let mut map = GatewayAliasMap::new();
        // A token that was never minted must not resolve.
        let err = map.resolve("neverminted2345", 0).unwrap_err();
        assert_eq!(err, GatewayAliasError::Unmapped);
        assert_eq!(err.code(), 0x0605);
        // Even after a real mint, an unrelated guessed token still fails closed.
        let _live = map.mint(native("a", "b.com"));
        assert_eq!(map.resolve("someothertoken", 0), Err(GatewayAliasError::Unmapped));
    }

    #[test]
    fn expired_row_fails_closed_0x0605() {
        let mut map = GatewayAliasMap::new();
        let target = native("imran", "mydomain.com");
        // TTL of 1000ms from now=0 ⇒ expires at 1000.
        let alias = map.mint_with(target.clone(), None, Some(1_000), false, 0);

        // Live strictly before expiry.
        assert_eq!(map.resolve(&alias, 999), Ok(target));
        // At the expiry instant and after, fails closed with 0x0605.
        let at = map.resolve(&alias, 1_000).unwrap_err();
        assert_eq!(at, GatewayAliasError::Unmapped);
        assert_eq!(at.code(), 0x0605);
        assert_eq!(map.resolve(&alias, 10_000), Err(GatewayAliasError::Unmapped));
    }

    #[test]
    fn burned_row_fails_closed_0x0605() {
        let mut map = GatewayAliasMap::new();
        let alias = map.mint(native("imran", "mydomain.com"));

        // Live until explicitly revoked.
        assert!(map.resolve(&alias, 0).is_ok());
        assert!(map.burn(&alias), "burn of a minted alias reports it existed");
        let err = map.resolve(&alias, 1).unwrap_err();
        assert_eq!(err, GatewayAliasError::Unmapped);
        assert_eq!(err.code(), 0x0605);

        // Burning a token that was never minted reports no row.
        assert!(!map.burn("nosuchtoken2345"));
    }

    #[test]
    fn one_time_alias_burns_on_first_resolve() {
        let mut map = GatewayAliasMap::new();
        let target = native("throwaway", "mydomain.com");
        let alias = map.mint_with(target.clone(), None, None, true, 0);

        // First resolve succeeds and consumes (burns) the alias.
        assert_eq!(map.resolve(&alias, 0), Ok(target));
        // Second resolve of the one-time-consumed alias fails closed.
        assert_eq!(map.resolve(&alias, 0), Err(GatewayAliasError::Unmapped));
    }

    #[test]
    fn two_mints_yield_distinct_unguessable_tokens() {
        let mut map = GatewayAliasMap::new();
        let a = map.mint(native("a", "x.com"));
        let b = map.mint(native("b", "y.com"));
        assert_ne!(a, b, "two mints must not collide");

        // Each token carries the full 128-bit entropy: 16 bytes base32 = 26 chars, dot-free, and a
        // legal RFC 5321 dot-atom local-part (no confusion with the dotted forwarded encoding).
        for token in [&a, &b] {
            // 16 bytes = 128 bits, base32 (5 bits/char, no padding) ⇒ ceil(128/5) = 26 chars.
            assert_eq!(token.len(), (TOKEN_ENTROPY_BYTES * 8).div_ceil(5));
            assert!(!token.contains('.'), "random token must be dot-free");
            assert!(
                token.bytes().all(|c| BASE32_LOWER.contains(&c)),
                "token {token:?} must be base32-lowercase"
            );
        }
    }

    #[test]
    fn many_mints_are_all_distinct() {
        // A sharper unguessability/uniqueness check: a batch of mints yields no duplicate token.
        let mut map = GatewayAliasMap::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let t = map.mint(native("u", "example.com"));
            assert!(seen.insert(t), "CSPRNG minted a duplicate token");
        }
        assert_eq!(map.len(), 2_000);
    }

    #[test]
    fn correspondent_scope_is_recorded_and_hidden_when_dead() {
        let mut map = GatewayAliasMap::new();
        let alias =
            map.mint_with(native("imran", "mydomain.com"), Some("bob@gmail.com".into()), None, false, 0);
        assert_eq!(map.correspondent_of(&alias, 0), Some("bob@gmail.com"));
        // Once burned, the scope is no longer surfaced (row is dead).
        map.burn(&alias);
        assert_eq!(map.correspondent_of(&alias, 0), None);
    }

    #[test]
    fn saturating_ttl_never_wraps_to_early_expiry() {
        let mut map = GatewayAliasMap::new();
        let target = native("imran", "mydomain.com");
        // A near-max TTL from a large now must not wrap around to an already-expired instant: the
        // absolute expiry saturates at u64::MAX rather than overflowing back to a small value, so a
        // resolve at `now` (before that saturated expiry) is still live.
        let now = u64::MAX - 1;
        let alias = map.mint_with(target.clone(), None, Some(u64::MAX), false, now);
        assert_eq!(map.resolve(&alias, now), Ok(target));
    }

    #[test]
    fn unmapped_error_reports_return_sender_smtp_reply() {
        assert_eq!(GatewayAliasError::SMTP_CODE, 550);
        assert_eq!(GatewayAliasError::SMTP_ENHANCED_STATUS, "5.1.1");
    }
}
