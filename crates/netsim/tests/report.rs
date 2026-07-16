//! Deterministic qualitative-claims report/test for the netsim mixnet anonymity simulator.
//!
//! Everything here uses a fixed seed (no wall-clock, no thread RNG) so a re-run reproduces
//! byte-identical numbers. Run `cargo test -p netsim -- --nocapture` to see the printed
//! summary table alongside the assertions.
//!
//! This asserts the three qualitative claims the task set out to (empirically) demonstrate:
//!   (i)   cover traffic + Poisson mixing drive passive correlation toward chance as
//!         cover-rate/volume grows;
//!   (ii)  loop-cover detects active packet-dropping once it crosses the §16.3 20%-loss
//!         threshold, and does NOT false-positive when there is no attack;
//!   (iii) the anonymity set shrinks (correlation success rises, entropy falls) as the
//!         fraction of compromised mixes `f` grows, via the disclosed entry+exit-collusion
//!         residual (§4.4.11) -- and this is NOT fixed by adding hops (Standard vs
//!         High-security both degrade with f, since collusion depends on the entry/exit
//!         mixes only, not path length).

use netsim::metrics::{
    any_guard_compromised_fraction, guard_exposure_bound, loop_loss_detection,
    passive_correlation_attack,
};
use netsim::sim::{self, SimConfig};
use netsim::Profile;

const SEED: u64 = 7;
const N_CLIENTS: usize = 40;
const MIXES_PER_LAYER: usize = 10;
const DURATION_S: f64 = 2.0 * 3600.0; // 2 simulated hours -- kept small so `cargo test` is fast

fn base_config(profile: Profile) -> SimConfig {
    SimConfig {
        profile,
        n_clients: N_CLIENTS,
        mixes_per_layer: MIXES_PER_LAYER,
        duration_s: DURATION_S,
        honest_rate_per_client_hz: 6.0 / 3600.0, // 6 msgs/hr/client
        cover_multiplier: 1.0,
        f_compromised: 0.0,
        active_drop_rate: 0.0,
        seed: SEED,
    }
}

#[test]
fn passive_correlation_converges_toward_chance_as_cover_and_volume_grow() {
    // Weak cover (long mean interval between loops) vs. spec-default vs. strengthened cover,
    // all with zero compromised mixes -- pure global-passive timing-correlation adversary.
    let mut weak = base_config(Profile::Standard);
    weak.cover_multiplier = 8.0; // 8x the mean interval => far fewer loops => weak cover
    let weak_out = sim::run(&weak);
    let weak_r = passive_correlation_attack(&weak_out, Profile::Standard);

    let default_cfg = base_config(Profile::Standard); // cover_multiplier = 1.0 (spec default)
    let default_out = sim::run(&default_cfg);
    let default_r = passive_correlation_attack(&default_out, Profile::Standard);

    let mut strong = base_config(Profile::Standard);
    strong.cover_multiplier = 0.2; // 5x more frequent loops => strong cover
    let strong_out = sim::run(&strong);
    let strong_r = passive_correlation_attack(&strong_out, Profile::Standard);

    println!(
        "\n[passive vs cover] weak={:.4} default={:.4} strong={:.4} chance={:.4}",
        weak_r.success_rate, default_r.success_rate, strong_r.success_rate, strong_r.chance_rate
    );
    println!(
        "[passive vs cover] entropy(bits) weak={:.2} default={:.2} strong={:.2}",
        weak_r.avg_entropy_bits, default_r.avg_entropy_bits, strong_r.avg_entropy_bits
    );

    // Claim (i): stronger cover monotonically pushes correlation success DOWN...
    assert!(
        weak_r.success_rate > default_r.success_rate,
        "weak cover ({:.4}) should correlate better than default cover ({:.4})",
        weak_r.success_rate,
        default_r.success_rate
    );
    assert!(
        default_r.success_rate > strong_r.success_rate,
        "default cover ({:.4}) should correlate better than strong cover ({:.4})",
        default_r.success_rate,
        strong_r.success_rate
    );
    // ...and toward the chance floor (1/(n_clients-1)) -- "toward", not exactly at, chance.
    assert!(
        strong_r.success_rate < 3.0 * strong_r.chance_rate,
        "strong-cover success rate {:.4} should approach the chance floor {:.4}",
        strong_r.success_rate,
        strong_r.chance_rate
    );
    // ...and anonymity-set entropy rises as cover strengthens.
    assert!(weak_r.avg_entropy_bits < default_r.avg_entropy_bits);
    assert!(default_r.avg_entropy_bits < strong_r.avg_entropy_bits);

    // Also verify honest TRAFFIC VOLUME alone (holding cover fixed) pushes toward chance:
    // more real messages in flight means more confusable candidate exit events too.
    let mut low_volume = base_config(Profile::Standard);
    low_volume.honest_rate_per_client_hz = 1.0 / 3600.0; // 1 msg/hr/client
    let low_out = sim::run(&low_volume);
    let low_r = passive_correlation_attack(&low_out, Profile::Standard);

    let mut high_volume = base_config(Profile::Standard);
    high_volume.honest_rate_per_client_hz = 30.0 / 3600.0; // 30 msgs/hr/client
    let high_out = sim::run(&high_volume);
    let high_r = passive_correlation_attack(&high_out, Profile::Standard);

    println!(
        "[passive vs volume] low_volume={:.4} high_volume={:.4}",
        low_r.success_rate, high_r.success_rate
    );
    assert!(
        high_r.success_rate < low_r.success_rate,
        "higher honest traffic volume ({:.4}) should correlate worse than low volume ({:.4})",
        high_r.success_rate,
        low_r.success_rate
    );
}

#[test]
fn high_security_profile_resists_passive_correlation_at_least_as_well_as_standard() {
    // Same cover/volume settings, only the profile (3-hop vs 5-hop, delay/cover params) differs.
    let standard_out = sim::run(&base_config(Profile::Standard));
    let standard_r = passive_correlation_attack(&standard_out, Profile::Standard);

    let hs_out = sim::run(&base_config(Profile::HighSecurity));
    let hs_r = passive_correlation_attack(&hs_out, Profile::HighSecurity);

    println!(
        "\n[3-hop vs 5-hop] standard success={:.4} entropy={:.2} | high-security success={:.4} entropy={:.2}",
        standard_r.success_rate, standard_r.avg_entropy_bits, hs_r.success_rate, hs_r.avg_entropy_bits
    );

    assert!(
        hs_r.success_rate <= standard_r.success_rate + 1e-9,
        "5-hop High-security ({:.4}) should not correlate worse than 3-hop Standard ({:.4})",
        hs_r.success_rate,
        standard_r.success_rate
    );
    assert!(
        hs_r.avg_entropy_bits > standard_r.avg_entropy_bits,
        "5-hop High-security should have a strictly larger anonymity set (more, longer, \
         higher-variance hops widen the timing window) than 3-hop Standard"
    );
}

#[test]
fn active_drop_detected_above_threshold_no_false_positive_below() {
    // A meaningfully-compromised fleet (f=0.4) that is NOT dropping anything: the loop-cover
    // detector must not false-positive.
    let mut no_attack = base_config(Profile::Standard);
    no_attack.f_compromised = 0.4;
    no_attack.active_drop_rate = 0.0;
    let no_attack_out = sim::run(&no_attack);
    let no_attack_d = loop_loss_detection(&no_attack_out);

    // The same compromised fraction, now actively dropping every packet it can see.
    let mut full_attack = base_config(Profile::Standard);
    full_attack.f_compromised = 0.4;
    full_attack.active_drop_rate = 1.0;
    let full_attack_out = sim::run(&full_attack);
    let full_attack_d = loop_loss_detection(&full_attack_out);

    println!(
        "\n[active-drop] f=0.4 no-drop: avg_loss={:.3} detect_rate={:.3} | full-drop: avg_loss={:.3} detect_rate={:.3}",
        no_attack_d.avg_loop_loss_fraction,
        no_attack_d.detection_rate,
        full_attack_d.avg_loop_loss_fraction,
        full_attack_d.detection_rate
    );

    assert_eq!(
        no_attack_d.detection_rate, 0.0,
        "no packets are ever dropped absent an active adversary -- zero false positives"
    );
    assert!(
        full_attack_d.detection_rate > 0.9,
        "nearly every client should detect the attack once compromised mixes drop \
         everything they see: got {:.3}",
        full_attack_d.detection_rate
    );
    assert!(full_attack_d.avg_loop_loss_fraction > no_attack_d.avg_loop_loss_fraction);

    // Sweep drop_rate to show the crossing behavior: low sub-threshold dropping stays mostly
    // undetected, higher dropping reliably crosses the 20% loss threshold (§16.3).
    let mut low_drop = base_config(Profile::Standard);
    low_drop.f_compromised = 0.4;
    low_drop.active_drop_rate = 0.05; // small, sub-threshold nudge
    let low_drop_out = sim::run(&low_drop);
    let low_drop_d = loop_loss_detection(&low_drop_out);

    let mut high_drop = base_config(Profile::Standard);
    high_drop.f_compromised = 0.4;
    high_drop.active_drop_rate = 0.5;
    let high_drop_out = sim::run(&high_drop);
    let high_drop_d = loop_loss_detection(&high_drop_out);

    println!(
        "[active-drop sweep] drop_rate=0.05 detect_rate={:.3} | drop_rate=0.5 detect_rate={:.3}",
        low_drop_d.detection_rate, high_drop_d.detection_rate
    );
    assert!(
        high_drop_d.detection_rate > low_drop_d.detection_rate,
        "detection rate must rise as active drop aggressiveness rises"
    );
}

#[test]
fn anonymity_set_shrinks_and_correlation_rises_as_compromised_fraction_grows() {
    for profile in [Profile::Standard, Profile::HighSecurity] {
        let mut clean = base_config(profile);
        clean.f_compromised = 0.0;
        let clean_out = sim::run(&clean);
        let clean_r = passive_correlation_attack(&clean_out, profile);

        let mut compromised = base_config(profile);
        compromised.f_compromised = 0.5;
        let compromised_out = sim::run(&compromised);
        let compromised_r = passive_correlation_attack(&compromised_out, profile);

        println!(
            "\n[{}] f=0.0 success={:.4} entropy={:.2} collusion={} | f=0.5 success={:.4} entropy={:.2} collusion={}",
            profile.name(),
            clean_r.success_rate,
            clean_r.avg_entropy_bits,
            clean_r.n_collusion,
            compromised_r.success_rate,
            compromised_r.avg_entropy_bits,
            compromised_r.n_collusion
        );

        assert_eq!(
            clean_r.n_collusion, 0,
            "with f=0 there are no compromised mixes to collude, so zero deterministic breaks"
        );
        assert!(
            compromised_r.n_collusion > 0,
            "with f=0.5 some paths should have both entry and exit mix compromised"
        );
        assert!(
            compromised_r.success_rate > clean_r.success_rate,
            "[{}] correlation success should rise as f grows: f=0 -> {:.4}, f=0.5 -> {:.4}",
            profile.name(),
            clean_r.success_rate,
            compromised_r.success_rate
        );
        assert!(
            compromised_r.avg_entropy_bits < clean_r.avg_entropy_bits,
            "[{}] anonymity-set entropy should fall as f grows: f=0 -> {:.2}, f=0.5 -> {:.2}",
            profile.name(),
            clean_r.avg_entropy_bits,
            compromised_r.avg_entropy_bits
        );

        // The empirical "at least one pinned guard compromised" fraction should track the
        // closed-form §4.4.8 bound `1-(1-f)^G` reasonably at f=0.5 (finite per-layer
        // population effects matter more at small f -- see crate docs / final report).
        let sim_exposed = any_guard_compromised_fraction(&compromised_out);
        let formula_exposed = guard_exposure_bound(0.5, profile.guard_count());
        println!(
            "[{}] guard-exposure f=0.5: sim={:.3} formula={:.3}",
            profile.name(),
            sim_exposed,
            formula_exposed
        );
        assert!(
            (sim_exposed - formula_exposed).abs() < 0.30,
            "[{}] empirical guard exposure {:.3} should be within 0.30 of the closed-form bound {:.3}",
            profile.name(),
            sim_exposed,
            formula_exposed
        );
    }
}
