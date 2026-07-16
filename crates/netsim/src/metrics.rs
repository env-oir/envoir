//! The two adversary models and the metrics they produce.
//!
//! (a) **Global passive adversary** (`passive_correlation_attack`): observes every entry and
//! exit event in the network (it is "global") but cannot read payloads and cannot drop/delay
//! anything. Its only lever is timing correlation over the candidate exit events within the
//! plausible delay window of a target message — UNLESS it also happens to control (log at)
//! both the entry and exit mix of a given path, in which case it needs no timing guess at all
//! (the disclosed "colluding first-and-last mixes" residual, §4.4.11/§6.6 item 1).
//!
//! (b) **Global active adversary** (`loop_loss_detection`): additionally drops a fraction of
//! packets that pass through the mixes it controls (`SimConfig::active_drop_rate`). It cannot
//! tell a loop-cover packet from a real one (they are byte-indistinguishable, §4.4.5), so
//! dropping "just the real traffic" is not an available strategy in this model — exactly the
//! point of loop cover as a detector (§4.4.7).

use crate::profile::{Profile, LOOP_LOSS_THRESHOLD};
use crate::sim::SimOutput;
use std::collections::HashMap;

pub struct CorrelationResult {
    /// Real messages that actually arrived (excludes ones the active adversary dropped).
    pub n_total: usize,
    /// Of those, how many fell entirely outside the adversary's timing window (no candidate
    /// exit event at all) — counted as a failed guess, tallied separately as a sanity check.
    pub n_no_signal: usize,
    /// Of those, how many were broken via entry+exit mix collusion rather than timing.
    pub n_collusion: usize,
    /// successes / n_total.
    pub success_rate: f64,
    /// Mean size of the adversary's per-message candidate set (larger = more cover/ambiguity).
    pub avg_anonymity_set: f64,
    /// Mean log2(candidate-set size) — Shannon entropy under a uniform-over-candidates model.
    pub avg_entropy_bits: f64,
    /// What a uniform random guess among all other clients would score — the "chance" floor.
    pub chance_rate: f64,
}

pub fn passive_correlation_attack(output: &SimOutput, profile: Profile) -> CorrelationResult {
    let mean = profile.total_delay_mean_s();
    let std = profile.total_delay_std_s();
    let lo_off = (mean - 3.0 * std).max(0.0);
    let hi_off = mean + 3.0 * std;

    let mut total = 0usize;
    let mut no_signal = 0usize;
    let mut collusion = 0usize;
    let mut successes = 0usize;
    let mut size_sum = 0f64;
    let mut entropy_sum = 0f64;
    let mut size_n = 0usize;

    let n_clients = output.clients.len();

    for m in &output.real_messages {
        if m.exit_time.is_none() {
            continue; // actively dropped -- excluded from the passive-correlation stat
        }
        total += 1;

        // Colluding entry+exit mix: the adversary directly observed both ends of this exact
        // path and needs no timing inference (§4.4.11's disclosed residual).
        if m.entry_compromised && m.exit_compromised {
            collusion += 1;
            successes += 1;
            size_sum += 1.0;
            size_n += 1;
            continue;
        }

        let window_lo = m.entry_time + lo_off;
        let window_hi = m.entry_time + hi_off;
        let start = output
            .exit_events
            .partition_point(|e| e.time < window_lo);
        let end = output.exit_events.partition_point(|e| e.time <= window_hi);
        let candidates = &output.exit_events[start..end];

        if candidates.is_empty() {
            // Window heuristic missed even the true delivery (a Gamma-tail outlier); the
            // adversary has nothing to guess from, which we count as a failed correlation.
            no_signal += 1;
            continue;
        }

        size_sum += candidates.len() as f64;
        entropy_sum += (candidates.len() as f64).log2();
        size_n += 1;

        let target = m.entry_time + mean;
        let guess_client = candidates
            .iter()
            .min_by(|a, b| {
                let da = (a.time - target).abs();
                let db = (b.time - target).abs();
                da.partial_cmp(&db).unwrap()
            })
            .map(|e| e.client);

        if guess_client == Some(m.receiver) {
            successes += 1;
        }
    }

    CorrelationResult {
        n_total: total,
        n_no_signal: no_signal,
        n_collusion: collusion,
        success_rate: successes as f64 / total.max(1) as f64,
        avg_anonymity_set: size_sum / size_n.max(1) as f64,
        avg_entropy_bits: entropy_sum / size_n.max(1) as f64,
        chance_rate: 1.0 / n_clients.saturating_sub(1).max(1) as f64,
    }
}

pub struct DetectionResult {
    /// Clients that emitted at least one loop-cover packet.
    pub n_clients: usize,
    /// Clients whose loop-return loss fraction exceeded the §16.3 threshold.
    pub clients_flagged: usize,
    /// clients_flagged / n_clients — i.e. the fraction of nodes that would raise
    /// `ERR_MIX_ACTIVE_ATTACK_SUSPECTED` / `HALT_ALERT` and fail closed (§4.4.7).
    pub detection_rate: f64,
    pub avg_loop_loss_fraction: f64,
}

/// Loop-cover active-attack detector (§4.4.7): per client, the fraction of its own loops that
/// failed to return; a node infers an attack when that exceeds `LOOP_LOSS_THRESHOLD`.
pub fn loop_loss_detection(output: &SimOutput) -> DetectionResult {
    let mut sent: HashMap<usize, usize> = HashMap::new();
    let mut lost: HashMap<usize, usize> = HashMap::new();
    for rec in &output.loop_records {
        *sent.entry(rec.client).or_insert(0) += 1;
        if !rec.delivered {
            *lost.entry(rec.client).or_insert(0) += 1;
        }
    }

    let mut flagged = 0usize;
    let mut loss_frac_sum = 0f64;
    let mut n = 0usize;
    for client in &output.clients {
        let s = *sent.get(&client.id).unwrap_or(&0);
        if s == 0 {
            continue;
        }
        let l = *lost.get(&client.id).unwrap_or(&0);
        let frac = l as f64 / s as f64;
        loss_frac_sum += frac;
        n += 1;
        if frac > LOOP_LOSS_THRESHOLD {
            flagged += 1;
        }
    }

    DetectionResult {
        n_clients: n,
        clients_flagged: flagged,
        detection_rate: flagged as f64 / n.max(1) as f64,
        avg_loop_loss_fraction: loss_frac_sum / n.max(1) as f64,
    }
}

/// Fraction of clients with *at least one* compromised pinned guard — the empirical
/// counterpart of the closed-form bound `1 - (1-f)^G` from §4.4.8 ("persistently on a known
/// [bad] guard").
pub fn any_guard_compromised_fraction(output: &SimOutput) -> f64 {
    let n = output.clients.len();
    if n == 0 {
        return 0.0;
    }
    let exposed = output
        .clients
        .iter()
        .filter(|c| c.any_guard_compromised(&output.fleet))
        .count();
    exposed as f64 / n as f64
}

/// Fraction of clients whose *entire* pinned guard set is compromised (the stronger,
/// always-exposed case; not the quantity `guard_exposure_bound` predicts).
pub fn fully_exposed_client_fraction(output: &SimOutput) -> f64 {
    let n = output.clients.len();
    if n == 0 {
        return 0.0;
    }
    let exposed = output
        .clients
        .iter()
        .filter(|c| c.fully_exposed(&output.fleet))
        .count();
    exposed as f64 / n as f64
}

/// Closed-form §4.4.8 bound: probability a client is "persistently on a known [bad] guard" —
/// i.e. at least one of its G pinned guards is adversary-controlled — when a fraction `f` of
/// the entry layer is compromised. The complement, `(1-f)^G`, is "persistently clear".
pub fn guard_exposure_bound(f_compromised: f64, guard_count: usize) -> f64 {
    1.0 - (1.0 - f_compromised).powi(guard_count as i32)
}
