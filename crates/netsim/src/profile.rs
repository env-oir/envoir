//! The two normative mixing profiles (DMTAP spec `../dmtap/04-transport.md` §4.4.10 table,
//! pinned parameters `../dmtap/16-parameters.md` §16.3). This module only carries the
//! numbers; it does not implement the mechanisms.

/// Loop-loss detection threshold: a node infers an active drop/delay attack when the
/// fraction of its own loop-cover packets that fail to return exceeds this bound
/// (§4.4.7, §16.3: "> 20% loss (sliding window)").
pub const LOOP_LOSS_THRESHOLD: f64 = 0.20;

/// Which mixing profile a message/session negotiated (§4.4.10, capability-negotiated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// §4.4.10 default: 3 hops, exp(mean 5s)/hop, Poisson cover mean 30s, G=2 guards / 30d,
    /// 3 disjoint operators.
    Standard,
    /// §4.4.10 high-risk lever: 5 hops, exp(mean 30s)/hop, constant-rate cover mean 5s,
    /// G=3 guards / 7d, 5 disjoint operators.
    HighSecurity,
}

impl Profile {
    /// Path length ν (§4.4.3, §4.4.10).
    pub fn hops(self) -> usize {
        match self {
            Profile::Standard => 3,
            Profile::HighSecurity => 5,
        }
    }

    /// Per-hop Poisson mixing delay mean, in seconds (§4.4.5, §4.4.10).
    pub fn per_hop_mean_delay_s(self) -> f64 {
        match self {
            Profile::Standard => 5.0,
            Profile::HighSecurity => 30.0,
        }
    }

    /// Loop-cover Poisson rate mean, in seconds/loop (λ_loop, §4.4.7, §4.4.10).
    pub fn loop_mean_interval_s(self) -> f64 {
        match self {
            Profile::Standard => 30.0,
            Profile::HighSecurity => 5.0,
        }
    }

    /// Drop-cover Poisson rate mean, in seconds/packet (§4.4.5). v0 pins the same default
    /// mean as the loop stream; High-security's is "constant-rate" but we still drive it
    /// from a Poisson process here (constant-*rate*, not constant-*interval* — see the
    /// abstraction note in the crate-level docs).
    pub fn drop_cover_mean_interval_s(self) -> f64 {
        self.loop_mean_interval_s()
    }

    /// Pinned entry-guard set size G (§4.4.8, §4.4.10).
    pub fn guard_count(self) -> usize {
        match self {
            Profile::Standard => 2,
            Profile::HighSecurity => 3,
        }
    }

    /// Mean of the total end-to-end mixing delay: sum of `hops` iid Exponential(mean)
    /// random variables is Gamma(shape = hops, scale = mean); its mean is `hops * mean`.
    pub fn total_delay_mean_s(self) -> f64 {
        self.hops() as f64 * self.per_hop_mean_delay_s()
    }

    /// Std-dev of the total end-to-end mixing delay: Var[Exp(mean)] = mean^2, and variances
    /// of independent hops add, so std = sqrt(hops) * mean.
    pub fn total_delay_std_s(self) -> f64 {
        (self.hops() as f64).sqrt() * self.per_hop_mean_delay_s()
    }

    pub fn name(self) -> &'static str {
        match self {
            Profile::Standard => "Standard(3-hop)",
            Profile::HighSecurity => "HighSecurity(5-hop)",
        }
    }
}
