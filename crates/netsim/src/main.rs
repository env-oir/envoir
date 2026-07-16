//! `netsim-report` — runs the full parameter sweep and prints the measured tables.
//! Everything here is deterministic given the fixed seeds; re-running reproduces byte-
//! identical numbers.

use netsim::metrics::{
    any_guard_compromised_fraction, guard_exposure_bound, loop_loss_detection,
    passive_correlation_attack,
};
use netsim::sim::{self, SimConfig};
use netsim::Profile;

const N_CLIENTS: usize = 50;
const MIXES_PER_LAYER: usize = 12;
const DURATION_S: f64 = 4.0 * 3600.0; // 4 simulated hours
const SEED: u64 = 42;

fn base_config(profile: Profile) -> SimConfig {
    SimConfig {
        profile,
        n_clients: N_CLIENTS,
        mixes_per_layer: MIXES_PER_LAYER,
        duration_s: DURATION_S,
        honest_rate_per_client_hz: 1.0 / 900.0, // 1 msg/15min/client
        cover_multiplier: 1.0,
        f_compromised: 0.0,
        active_drop_rate: 0.0,
        seed: SEED,
    }
}

fn experiment_a_passive_vs_volume_and_cover() {
    println!("\n=== (A) Passive correlation vs honest volume & cover-traffic rate ===");
    println!("(f=0 compromised mixes; pure global-passive timing-correlation adversary)\n");
    println!(
        "{:<18} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "profile", "honest/hr", "cover×", "n_msgs", "success%", "chance%", "entropy(b)"
    );

    for profile in [Profile::Standard, Profile::HighSecurity] {
        for honest_per_hour in [4.0, 12.0] {
            for cover_multiplier in [8.0, 1.0, 0.25] {
                let mut cfg = base_config(profile);
                cfg.honest_rate_per_client_hz = honest_per_hour / 3600.0;
                cfg.cover_multiplier = cover_multiplier;
                let out = sim::run(&cfg);
                let r = passive_correlation_attack(&out, profile);
                println!(
                    "{:<18} {:>10.1} {:>10.2} {:>10} {:>9.2}% {:>9.2}% {:>10.2}",
                    profile.name(),
                    honest_per_hour,
                    cover_multiplier,
                    r.n_total,
                    r.success_rate * 100.0,
                    r.chance_rate * 100.0,
                    r.avg_entropy_bits
                );
            }
        }
    }
}

fn experiment_b_active_drop_detection() {
    println!("\n=== (B) Active-drop detection via loop cover (loss threshold = 20%) ===\n");
    println!(
        "{:<18} {:>6} {:>10} {:>12} {:>14} {:>14}",
        "profile", "f", "drop_rate", "avg_loss%", "flagged/total", "detect%"
    );

    for profile in [Profile::Standard, Profile::HighSecurity] {
        for f in [0.1, 0.3, 0.5] {
            for drop_rate in [0.0, 0.1, 0.3, 0.6, 1.0] {
                let mut cfg = base_config(profile);
                cfg.f_compromised = f;
                cfg.active_drop_rate = drop_rate;
                let out = sim::run(&cfg);
                let d = loop_loss_detection(&out);
                println!(
                    "{:<18} {:>6.2} {:>10.2} {:>11.2}% {:>7}/{:<6} {:>13.1}%",
                    profile.name(),
                    f,
                    drop_rate,
                    d.avg_loop_loss_fraction * 100.0,
                    d.clients_flagged,
                    d.n_clients,
                    d.detection_rate * 100.0
                );
            }
        }
    }
}

fn experiment_c_anonymity_vs_compromised_fraction() {
    println!("\n=== (C) Anonymity set / correlation vs fraction of compromised mixes f ===");
    println!("(active_drop_rate=0 -- passive-logging colluding mixes only)\n");
    println!(
        "{:<18} {:>6} {:>10} {:>10} {:>12} {:>14} {:>16}",
        "profile", "f", "success%", "entropy(b)", "collusion%", "guard-exp%(sim)", "guard-exp%(formula)"
    );

    for profile in [Profile::Standard, Profile::HighSecurity] {
        for f in [0.0, 0.05, 0.1, 0.2, 0.3, 0.5] {
            let mut cfg = base_config(profile);
            cfg.f_compromised = f;
            let out = sim::run(&cfg);
            let r = passive_correlation_attack(&out, profile);
            let exposed_sim = any_guard_compromised_fraction(&out);
            let exposed_formula = guard_exposure_bound(f, profile.guard_count());
            println!(
                "{:<18} {:>6.2} {:>9.2}% {:>10.2} {:>11.2}% {:>15.2}% {:>19.2}%",
                profile.name(),
                f,
                r.success_rate * 100.0,
                r.avg_entropy_bits,
                (r.n_collusion as f64 / r.n_total.max(1) as f64) * 100.0,
                exposed_sim * 100.0,
                exposed_formula * 100.0
            );
        }
    }
}

fn main() {
    println!("netsim -- DMTAP mixnet anonymity simulator (seed={SEED}, {N_CLIENTS} clients, {MIXES_PER_LAYER} mixes/layer, {DURATION_S}s horizon)");
    experiment_a_passive_vs_volume_and_cover();
    experiment_b_active_drop_detection();
    experiment_c_anonymity_vs_compromised_fraction();
}
