//! The event generator: deterministic (seeded), analytic Poisson-process traffic generation
//! plus per-packet Gamma-distributed (sum-of-exponential-hops) delay realization.
//!
//! ABSTRACTION: this is NOT a queueing/network discrete-event simulator — there is no
//! per-mix buffer contention modeled, no bandwidth limit, no bounded replay cache, no epoch
//! rotation. Each packet's path and per-hop delays are drawn independently of every other
//! packet, exactly as the Poisson-mixing *mechanism* prescribes (§4.4.6: "a packet's output
//! time is independent of its input time given the exponential hold" — independence is the
//! point, not a simplification of it). What IS modeled faithfully: stratified per-layer path
//! draws, pinned entry guards, fresh-path-per-packet (incl. cover), Poisson real/loop/drop
//! traffic, per-hop exponential mixing delay, and an adversary that can (a) passively log
//! traffic at compromised mixes and (b) actively drop a fraction of what passes through them.

use crate::client::{build_clients, Client};
use crate::path::select_path;
use crate::profile::Profile;
use crate::topology::{Fleet, MixId};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rand_distr::{Distribution, Exp, Poisson};

pub struct SimConfig {
    pub profile: Profile,
    pub n_clients: usize,
    pub mixes_per_layer: usize,
    /// Simulated wall-clock duration, in seconds.
    pub duration_s: f64,
    /// Real-message Poisson rate per client, in messages/second.
    pub honest_rate_per_client_hz: f64,
    /// Scales the profile's default loop/drop-cover mean interval: `<1.0` = more frequent
    /// (stronger) cover, `1.0` = spec default, `>1.0` = less frequent (weaker) cover.
    pub cover_multiplier: f64,
    /// Fraction of mixes, in every layer, under adversary control (§4.4.11).
    pub f_compromised: f64,
    /// Fraction of packets a compromised mix actively drops when it handles one (0.0 = the
    /// adversary is purely passive/logging; §4.4.6/§6.1 active-adversary capability).
    pub active_drop_rate: f64,
    pub seed: u64,
}

/// A real (non-cover) message's fate, as observed by a global omniscient recorder (used by
/// the adversary-analysis functions in `metrics`, which are only allowed to see what the
/// modeled adversary is entitled to see).
pub struct RealMessageRecord {
    pub sender: usize,
    pub receiver: usize,
    pub entry_time: f64,
    /// `None` if actively dropped en route.
    pub exit_time: Option<f64>,
    pub entry_compromised: bool,
    pub exit_compromised: bool,
}

/// One client loop-cover packet's fate (§4.4.7 — the active-attack detector).
pub struct LoopRecord {
    pub client: usize,
    pub entry_time: f64,
    pub delivered: bool,
}

/// A delivery event a global passive observer sees on the exit side: either a real message
/// arriving at its receiver, or a loop-cover packet returning to its own sender. This is the
/// adversary's full "who received something, when" candidate pool.
pub struct ExitEvent {
    pub time: f64,
    pub client: usize,
}

pub struct SimOutput {
    pub fleet: Fleet,
    pub clients: Vec<Client>,
    pub real_messages: Vec<RealMessageRecord>,
    /// Sorted ascending by `time`.
    pub exit_events: Vec<ExitEvent>,
    pub loop_records: Vec<LoopRecord>,
}

/// Realize a homogeneous Poisson process over `[0, duration_s)` at rate `rate_hz`: draw the
/// count from `Poisson(rate_hz * duration_s)`, then place that many iid Uniform(0, duration_s)
/// arrival times (the standard equivalence for a homogeneous Poisson process) and sort them.
fn poisson_process_times(rng: &mut ChaCha8Rng, rate_hz: f64, duration_s: f64) -> Vec<f64> {
    if rate_hz <= 0.0 || duration_s <= 0.0 {
        return Vec::new();
    }
    let lambda = rate_hz * duration_s;
    let poisson = Poisson::new(lambda).expect("finite, non-negative Poisson rate");
    let n = poisson.sample(rng).round().max(0.0) as usize;
    let mut times: Vec<f64> = (0..n).map(|_| rng.gen::<f64>() * duration_s).collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times
}

/// Walk a packet through its path: at each hop, if the mix is compromised and the active
/// adversary is dropping, the packet may be silently discarded (mirrors `DROP_SILENT`
/// semantics, e.g. `ERR_MIX_REPLAY_DETECTED`/tagging-check drops, §4.4.6); otherwise the hop
/// adds an independent Exponential(mean = `per_hop_mean_delay_s`) mixing delay (§4.4.6
/// Poisson mixing). Returns the exit time, or `None` if dropped en route.
fn traverse_path(
    fleet: &Fleet,
    path: &[MixId],
    entry_time: f64,
    per_hop_mean_delay_s: f64,
    active_drop_rate: f64,
    rng: &mut ChaCha8Rng,
) -> Option<f64> {
    let hop_delay = Exp::new(1.0 / per_hop_mean_delay_s).expect("positive mean delay");
    let mut t = entry_time;
    for &hop in path {
        if active_drop_rate > 0.0 && fleet.is_compromised(hop) && rng.gen::<f64>() < active_drop_rate
        {
            return None;
        }
        let delay: f64 = hop_delay.sample(rng);
        t += delay;
    }
    Some(t)
}

pub fn run(config: &SimConfig) -> SimOutput {
    assert!(config.n_clients >= 2, "need at least 2 clients");
    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);

    let fleet = Fleet::build(
        config.profile.hops(),
        config.mixes_per_layer,
        config.f_compromised,
        &mut rng,
    );
    let clients = build_clients(
        config.n_clients,
        &fleet,
        config.profile.guard_count(),
        &mut rng,
    );

    let mut real_messages = Vec::new();
    let mut exit_events = Vec::new();
    let mut loop_records = Vec::new();

    let loop_rate_hz = 1.0 / (config.profile.loop_mean_interval_s() * config.cover_multiplier);
    let drop_cover_rate_hz =
        1.0 / (config.profile.drop_cover_mean_interval_s() * config.cover_multiplier);
    let per_hop_mean = config.profile.per_hop_mean_delay_s();

    for client in &clients {
        // --- Real (honest) traffic: Poisson-arriving messages to a uniformly random peer. ---
        let msg_times = poisson_process_times(&mut rng, config.honest_rate_per_client_hz, config.duration_s);
        for entry_time in msg_times {
            let receiver = loop {
                let r = rng.gen_range(0..config.n_clients);
                if r != client.id {
                    break r;
                }
            };
            let path = select_path(client, &fleet, &mut rng);
            let entry_compromised = fleet.is_compromised(path[0]);
            let exit_compromised = fleet.is_compromised(*path.last().expect("non-empty path"));
            let exit_time = traverse_path(
                &fleet,
                &path,
                entry_time,
                per_hop_mean,
                config.active_drop_rate,
                &mut rng,
            );
            if let Some(t) = exit_time {
                exit_events.push(ExitEvent { time: t, client: receiver });
            }
            real_messages.push(RealMessageRecord {
                sender: client.id,
                receiver,
                entry_time,
                exit_time,
                entry_compromised,
                exit_compromised,
            });
        }

        // --- Loop cover (§4.4.5/§4.4.7): a full-path packet back to the sender via SURB. ---
        let loop_times = poisson_process_times(&mut rng, loop_rate_hz, config.duration_s);
        for entry_time in loop_times {
            let path = select_path(client, &fleet, &mut rng);
            let exit_time = traverse_path(
                &fleet,
                &path,
                entry_time,
                per_hop_mean,
                config.active_drop_rate,
                &mut rng,
            );
            if let Some(t) = exit_time {
                exit_events.push(ExitEvent { time: t, client: client.id });
            }
            loop_records.push(LoopRecord {
                client: client.id,
                entry_time,
                delivered: exit_time.is_some(),
            });
        }

        // --- Drop cover (§4.4.5): addressed to a random mix that discards it at the last
        // hop by design, so it never produces an exit event. It still consumes RNG draws for
        // its arrival times (entry-link cover mass), which is all this model needs from it —
        // see the crate-level abstraction note on why exit-side (not entry-side) traffic is
        // what drives this simulator's passive-correlation candidate pool.
        let _drop_cover_times =
            poisson_process_times(&mut rng, drop_cover_rate_hz, config.duration_s);
    }

    exit_events.sort_by(|a, b| a.time.partial_cmp(&b.time).unwrap());

    SimOutput {
        fleet,
        clients,
        real_messages,
        exit_events,
        loop_records,
    }
}
