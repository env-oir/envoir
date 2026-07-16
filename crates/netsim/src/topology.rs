//! Stratified mix-fleet model (§4.4.3: three — or five, High-security — layers, entry/
//! middle.../exit; §4.4.8: operator diversity; §4.4.11: an adversary-controlled fraction of
//! the fleet).
//!
//! ABSTRACTION NOTE: real DMTAP requires path hops to cross **distinct attested operators**
//! (§4.4.8), which exists to stop one adversary self-claiming many operators. Here every mix
//! already has a distinct `MixId`, and a path is drawn one mix per *layer* — layers are
//! disjoint id sets, so hop-distinctness is automatic and the operator-diversity constraint
//! is trivially satisfied by construction. What we DO model explicitly is the thing the
//! operator-diversity rule is trying to bound: the **fraction `f` of the fleet an adversary
//! controls**, spread deterministically and evenly across every layer (the worst case for the
//! defender — an adversary that concentrated in one layer alone could never see both path ends).

use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

pub type MixId = usize;

#[derive(Debug, Clone)]
pub struct MixNode {
    pub id: MixId,
    pub layer: usize,
    /// True if this mix is under adversary control (logs everything it peels; see
    /// `sim::SimConfig::active_drop_rate` for whether it also drops/delays).
    pub compromised: bool,
}

#[derive(Debug, Clone)]
pub struct Fleet {
    pub hops: usize,
    /// Flat, `MixId`-indexed storage.
    pub nodes: Vec<MixNode>,
    /// `layer_ids[l]` = the `MixId`s belonging to layer `l` (0 = entry, `hops-1` = exit).
    pub layer_ids: Vec<Vec<MixId>>,
}

impl Fleet {
    /// Build a stratified fleet: `per_layer` mixes in each of `hops` layers. Exactly
    /// `round(f_compromised * per_layer)` mixes in *each* layer are marked compromised
    /// (an exact achieved fraction, not sampling noise), with *which* mixes shuffled under
    /// `rng` so the compromised set isn't trivially the first N ids.
    pub fn build(hops: usize, per_layer: usize, f_compromised: f64, rng: &mut ChaCha8Rng) -> Fleet {
        assert!(per_layer > 0, "each layer needs at least one mix");
        let n_bad = ((f_compromised * per_layer as f64).round() as usize).min(per_layer);

        let mut nodes = Vec::with_capacity(hops * per_layer);
        let mut layer_ids = Vec::with_capacity(hops);
        let mut next_id: MixId = 0;

        for layer in 0..hops {
            let mut flags = vec![false; per_layer];
            for slot in flags.iter_mut().take(n_bad) {
                *slot = true;
            }
            flags.shuffle(rng);

            let mut ids = Vec::with_capacity(per_layer);
            for compromised in flags {
                let id = next_id;
                next_id += 1;
                nodes.push(MixNode {
                    id,
                    layer,
                    compromised,
                });
                ids.push(id);
            }
            layer_ids.push(ids);
        }

        Fleet {
            hops,
            nodes,
            layer_ids,
        }
    }

    pub fn node(&self, id: MixId) -> &MixNode {
        &self.nodes[id]
    }

    pub fn is_compromised(&self, id: MixId) -> bool {
        self.nodes[id].compromised
    }

    /// Achieved compromised fraction, averaged over the whole fleet (should equal the
    /// requested `f_compromised` up to per-layer rounding).
    pub fn achieved_compromised_fraction(&self) -> f64 {
        let bad = self.nodes.iter().filter(|n| n.compromised).count();
        bad as f64 / self.nodes.len() as f64
    }
}
