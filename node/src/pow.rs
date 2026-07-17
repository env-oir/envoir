//! Bounded memory-hard PoW verification (spec §9.4, §16.5).
//!
//! A cold sender with no token issuer MAY attach a **memory-hard proof-of-work** (Argon2id) to clear
//! the anti-abuse gate (§9.4). Verifying it is **symmetric-cost**: checking a solution costs the
//! recipient roughly what producing it cost the sender. Because the cold-sender gate runs *before*
//! any per-source cap can apply (§2.7 step 6 precedes identity), a flood of **bogus** PoW attachments
//! is itself a memory/CPU **DoS** — the attacker forces expensive verifications for free.
//!
//! The recipient therefore MUST **bound the number of memory-hard verifications per time window, per
//! delivering connection/relay** (§16.5). Past the budget a cold MOTE is **deferred to the requests
//! area WITHOUT verifying** its PoW ([`PowCheck::OverBudget`]) — never unbounded memory-hard work on
//! unauthenticated input, and never fail *open* by accepting it. This is one more reason PoW is the
//! rate-capped last resort: the ARC-token / postage paths verify with a cheap signature check and
//! impose no symmetric-cost DoS surface, so they are always preferred (§9.3, §9.5).
//!
//! [`PowGate`] wires the two halves together: a per-connection [`PowVerifyBudget`] gate in front of a
//! [`MemoryHardVerifier`] whose invocation count is observable, so a caller can prove that
//! over-budget MOTEs were deferred **without** the Argon2id verifier ever running.

use std::collections::HashMap;

use dmtap_core::mote::PowSolution;
use dmtap_core::TimestampMs;

/// Default verification budget window (§16.5): one second.
pub const POW_VERIFY_WINDOW_MS: u64 = 1_000;
/// Default verifications allowed per window per delivering connection (§16.5: "a few / s / source",
/// operator-tunable). Beyond this a cold PoW MOTE is deferred without being verified.
pub const POW_VERIFY_MAX_PER_WINDOW: u32 = 4;
/// The largest Argon2id memory cost (KiB) the recipient will ever spend on an **unauthenticated**
/// cold PoW. A solution demanding more is rejected *without* running Argon2id — refusing to let an
/// attacker force an arbitrarily expensive single verification (the same symmetric-cost DoS, §9.4).
pub const POW_MAX_MEM_KIB: u32 = 256 * 1024; // 256 MiB
/// Cap on distinct connections tracked by the budget, so the gate's own bookkeeping is bounded.
pub const POW_MAX_TRACKED_CONNS: usize = 100_000;

/// The disposition of one cold-sender PoW check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowCheck {
    /// Within budget and the Argon2id solution verified — the sender cleared the gate.
    Verified,
    /// Within budget but the Argon2id solution did **not** verify — an under-proven cold sender.
    Failed,
    /// The per-connection window budget is exhausted — defer WITHOUT verifying (§16.5).
    OverBudget,
}

/// A per-connection, per-window count of memory-hard verifications performed (§16.5). Keyed on the
/// **delivering connection/relay** (the transport return path), never the attacker-controlled
/// envelope contents.
pub struct PowVerifyBudget {
    window_ms: u64,
    max_per_window: u32,
    max_conns: usize,
    conns: HashMap<Vec<u8>, WindowCount>,
}

struct WindowCount {
    window_start: TimestampMs,
    count: u32,
}

impl PowVerifyBudget {
    /// The production budget ([`POW_VERIFY_WINDOW_MS`] / [`POW_VERIFY_MAX_PER_WINDOW`]).
    pub fn new() -> Self {
        Self::with_bounds(POW_VERIFY_WINDOW_MS, POW_VERIFY_MAX_PER_WINDOW)
    }

    /// An explicit budget (tests exercise tiny windows/caps).
    pub fn with_bounds(window_ms: u64, max_per_window: u32) -> Self {
        PowVerifyBudget {
            window_ms,
            max_per_window,
            max_conns: POW_MAX_TRACKED_CONNS,
            conns: HashMap::new(),
        }
    }

    /// Try to reserve one verification slot for `conn` at `now`. Returns `true` if within the
    /// per-connection window budget (and records the spend), `false` if the budget is exhausted (the
    /// caller MUST then defer without verifying, §16.5).
    pub fn allow(&mut self, conn: &[u8], now: TimestampMs) -> bool {
        // Bound the bookkeeping: if we are tracking too many connections, drop the whole table (a
        // fresh window for everyone). Fail-safe — it only ever *resets* budgets, never raises them
        // mid-window for a specific attacker (the flood is still capped by the fresh window).
        if self.conns.len() >= self.max_conns && !self.conns.contains_key(conn) {
            self.conns.clear();
        }
        let w = self
            .conns
            .entry(conn.to_vec())
            .or_insert(WindowCount { window_start: now, count: 0 });
        if now.saturating_sub(w.window_start) >= self.window_ms {
            w.window_start = now;
            w.count = 0;
        }
        if w.count >= self.max_per_window {
            return false;
        }
        w.count += 1;
        true
    }

    /// Drop connection entries whose window has fully elapsed at `now`, bounding memory over time.
    pub fn prune(&mut self, now: TimestampMs) {
        let window = self.window_ms;
        self.conns.retain(|_, w| now.saturating_sub(w.window_start) < window);
    }
}

impl Default for PowVerifyBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// The memory-hard verifier — the symmetric-cost half the budget exists to bound (§9.4). Its
/// [`invocations`](Self::invocations) counter makes it observable that over-budget MOTEs are deferred
/// **without** it ever running.
pub struct MemoryHardVerifier {
    max_mem_kib: u32,
    invocations: u64,
}

impl MemoryHardVerifier {
    pub fn new() -> Self {
        MemoryHardVerifier { max_mem_kib: POW_MAX_MEM_KIB, invocations: 0 }
    }

    /// How many times the memory-hard Argon2id verification actually ran. A param-ceiling rejection
    /// (below) is a cheap pre-check and does **not** count — it never spends memory-hard work.
    pub fn invocations(&self) -> u64 {
        self.invocations
    }

    /// Verify a cold-sender PoW `sol` against the §16.5 puzzle scope `id ‖ recipient ‖ epoch_nonce`
    /// (memory-hard, symmetric-cost, §9.4). Refuses — *without* running Argon2id — a non-Argon2id
    /// algorithm or params above [`POW_MAX_MEM_KIB`] (refusing to let an attacker force an
    /// arbitrarily expensive single verification). Every actual Argon2id run increments
    /// [`invocations`](Self::invocations).
    pub fn verify(&mut self, id: &[u8], recipient: &[u8], sol: &PowSolution) -> bool {
        if sol.algo != "argon2id" {
            return false;
        }
        let [m_kib, t_iters, p_lanes] = sol.params;
        if m_kib == 0 || t_iters == 0 || p_lanes == 0 || m_kib > self.max_mem_kib {
            return false;
        }
        let params = match argon2::Params::new(m_kib, t_iters, p_lanes, Some(32)) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // This is the memory-hard step the budget bounds — count it.
        self.invocations += 1;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        // Puzzle preimage = id ‖ recipient ‖ solution (the sender's found nonce); salt = epoch nonce
        // (§16.5 "fresh epoch nonce to prevent precompute"), stretched to Argon2's minimum length.
        let mut preimage = Vec::with_capacity(id.len() + recipient.len() + sol.solution.len());
        preimage.extend_from_slice(id);
        preimage.extend_from_slice(recipient);
        preimage.extend_from_slice(&sol.solution);
        let salt = salt_from(&sol.epoch_nonce);
        let mut out = [0u8; 32];
        if argon.hash_password_into(&preimage, &salt, &mut out).is_err() {
            return false;
        }
        leading_zero_bits(&out) >= sol.difficulty as u32
    }
}

impl Default for MemoryHardVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// A per-connection budget gate in front of the memory-hard verifier (§9.4, §16.5). The node calls
/// [`check`](Self::check) for every cold-sender PoW MOTE; the verifier runs **only** within budget.
pub struct PowGate {
    budget: PowVerifyBudget,
    verifier: MemoryHardVerifier,
}

impl PowGate {
    pub fn new() -> Self {
        PowGate { budget: PowVerifyBudget::new(), verifier: MemoryHardVerifier::new() }
    }

    /// Reconfigure the per-connection verification budget (operator-tunable, §16.5).
    pub fn set_budget(&mut self, window_ms: u64, max_per_window: u32) {
        self.budget = PowVerifyBudget::with_bounds(window_ms, max_per_window);
    }

    /// Gate then (only within budget) verify a cold PoW `sol` delivered over connection `conn` at
    /// `now`. Over budget ⇒ [`PowCheck::OverBudget`] with the verifier **untouched** (§16.5).
    pub fn check(
        &mut self,
        conn: &[u8],
        id: &[u8],
        recipient: &[u8],
        sol: &PowSolution,
        now: TimestampMs,
    ) -> PowCheck {
        if !self.budget.allow(conn, now) {
            return PowCheck::OverBudget;
        }
        if self.verifier.verify(id, recipient, sol) {
            PowCheck::Verified
        } else {
            PowCheck::Failed
        }
    }

    /// Total memory-hard verifications performed — observable proof the budget held (§16.5).
    pub fn verifications(&self) -> u64 {
        self.verifier.invocations()
    }

    /// Prune the budget's per-connection bookkeeping at `now`.
    pub fn prune(&mut self, now: TimestampMs) {
        self.budget.prune(now);
    }
}

impl Default for PowGate {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed-length Argon2id salt from the (possibly short) epoch nonce — BLAKE3 to 16 bytes, ≥ the
/// Argon2 minimum, so any nonce length is accepted deterministically.
fn salt_from(epoch_nonce: &[u8]) -> [u8; 16] {
    let cid = dmtap_core::id::ContentId::of(epoch_nonce);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&cid.0[1..17]);
    salt
}

/// Count leading zero bits of a digest (the PoW difficulty measure, §9.4).
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &b in bytes {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sol() -> PowSolution {
        // Tiny, fast Argon2id params so the verifier runs quickly; the solution is bogus (it will not
        // meet difficulty), which is exactly the flood case — the point under test is the BUDGET, not
        // whether any particular solution is valid.
        PowSolution {
            algo: "argon2id".into(),
            params: [8, 1, 1],
            epoch_nonce: b"epoch-nonce".to_vec(),
            solution: b"bogus".to_vec(),
            difficulty: 8,
        }
    }

    #[test]
    fn budget_bounds_verifications_per_window_per_conn() {
        let mut gate = PowGate::new();
        gate.set_budget(1_000, 2);
        let s = sol();
        // First two from the same connection are verified (within budget) — Argon2id runs.
        assert!(matches!(gate.check(b"relayA", b"id1", b"me", &s, 1_000), PowCheck::Failed));
        assert!(matches!(gate.check(b"relayA", b"id2", b"me", &s, 1_000), PowCheck::Failed));
        assert_eq!(gate.verifications(), 2);
        // The next two are OVER budget — deferred WITHOUT running Argon2id (counter unchanged).
        assert_eq!(gate.check(b"relayA", b"id3", b"me", &s, 1_000), PowCheck::OverBudget);
        assert_eq!(gate.check(b"relayA", b"id4", b"me", &s, 1_000), PowCheck::OverBudget);
        assert_eq!(gate.verifications(), 2, "over-budget MOTEs never invoked the verifier");
    }

    #[test]
    fn budget_is_per_connection() {
        let mut gate = PowGate::new();
        gate.set_budget(1_000, 1);
        let s = sol();
        assert!(matches!(gate.check(b"relayA", b"i", b"me", &s, 0), PowCheck::Failed));
        // A DIFFERENT delivering connection has its own budget.
        assert!(matches!(gate.check(b"relayB", b"i", b"me", &s, 0), PowCheck::Failed));
        // relayA is now over budget in the same window.
        assert_eq!(gate.check(b"relayA", b"i", b"me", &s, 0), PowCheck::OverBudget);
    }

    #[test]
    fn budget_refills_after_the_window() {
        let mut b = PowVerifyBudget::with_bounds(1_000, 1);
        assert!(b.allow(b"c", 0));
        assert!(!b.allow(b"c", 500), "still in the window");
        assert!(b.allow(b"c", 1_000), "window elapsed ⇒ fresh budget");
    }

    #[test]
    fn over_ceiling_params_are_refused_without_running_argon2id() {
        let mut v = MemoryHardVerifier::new();
        let mut s = sol();
        s.params = [POW_MAX_MEM_KIB + 1, 1, 1]; // demands more memory than we will ever spend
        assert!(!v.verify(b"id", b"me", &s));
        assert_eq!(v.invocations(), 0, "the ceiling pre-check spent no memory-hard work");
    }

    #[test]
    fn a_correct_solution_verifies() {
        // Mine a real solution at a trivial difficulty so the happy path (Verified) is covered.
        let mut v = MemoryHardVerifier::new();
        let id = b"content-id";
        let me = b"recipient";
        let epoch_nonce = b"epoch".to_vec();
        let params = [8u32, 1, 1];
        let difficulty = 4u8;
        let mut nonce: u32 = 0;
        let solved = loop {
            let mut trial = sol();
            trial.params = params;
            trial.epoch_nonce = epoch_nonce.clone();
            trial.solution = nonce.to_be_bytes().to_vec();
            trial.difficulty = difficulty;
            if v.verify(id, me, &trial) {
                break trial;
            }
            nonce += 1;
            assert!(nonce < 100_000, "should find a difficulty-4 solution quickly");
        };
        // Re-verify the mined solution cleanly.
        let mut v2 = MemoryHardVerifier::new();
        assert!(v2.verify(id, me, &solved));
        assert_eq!(v2.invocations(), 1);
    }
}
