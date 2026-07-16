//! Clients and pinned entry guards (§4.4.8: a sender does NOT choose a fresh entry mix per
//! packet — it pins a small, rotating guard set of size G and reuses it across packets).

use crate::topology::{Fleet, MixId};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

pub struct Client {
    pub id: usize,
    /// The pinned entry-guard set (size = `Profile::guard_count()`), drawn once from the
    /// entry layer and reused for the whole simulated run.
    ///
    /// ABSTRACTION NOTE: real DMTAP rotates guards every `guard_rotation_period` (30d
    /// Standard / 7d High-security, §16.3). Our simulated runs are far shorter than that, so
    /// "drawn once, held for the run" is a faithful model of the pinned-guard *mechanism*
    /// without needing to simulate calendar-scale rotation.
    pub guards: Vec<MixId>,
}

impl Client {
    /// True iff *at least one* pinned guard in this client's set is adversary-controlled —
    /// the "persistently on a known [bad] guard" case §4.4.8 bounds at probability
    /// `1 - (1-f)^G` (the complement of "persistently clear", probability `(1-f)^G`).
    pub fn any_guard_compromised(&self, fleet: &Fleet) -> bool {
        self.guards.iter().any(|&g| fleet.is_compromised(g))
    }

    /// True iff *every* pinned guard in this client's set is adversary-controlled — the
    /// strictly stronger case where the entry hop is compromised on 100% of this client's
    /// packets/loops, not merely "sometimes" (not the quantity §4.4.8's formula bounds).
    pub fn fully_exposed(&self, fleet: &Fleet) -> bool {
        self.guards.iter().all(|&g| fleet.is_compromised(g))
    }
}

pub fn build_clients(
    n: usize,
    fleet: &Fleet,
    guard_count: usize,
    rng: &mut ChaCha8Rng,
) -> Vec<Client> {
    let entry_layer = &fleet.layer_ids[0];
    assert!(
        entry_layer.len() >= guard_count,
        "entry layer must have at least G mixes to draw a guard set"
    );
    (0..n)
        .map(|id| {
            let guards: Vec<MixId> = entry_layer
                .choose_multiple(rng, guard_count)
                .copied()
                .collect();
            Client { id, guards }
        })
        .collect()
}
