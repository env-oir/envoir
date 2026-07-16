//! Path selection: one mix drawn uniformly at random per stratified layer, entry hop drawn
//! from the client's pinned guard set (§4.4.3, §4.4.8). "Fresh path per packet" (§4.4.3)
//! applies to every packet including cover packets (§4.4.5) — callers draw a fresh path for
//! every real, loop, and drop-cover packet.

use crate::client::Client;
use crate::topology::{Fleet, MixId};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

/// Draw a fresh `fleet.hops`-length path: `path[0]` is one of the client's pinned guards,
/// `path[1..]` is one mix drawn uniformly from each subsequent layer.
pub fn select_path(client: &Client, fleet: &Fleet, rng: &mut ChaCha8Rng) -> Vec<MixId> {
    let mut path = Vec::with_capacity(fleet.hops);
    let entry = *client
        .guards
        .choose(rng)
        .expect("client must have at least one pinned guard");
    path.push(entry);
    for layer in 1..fleet.hops {
        let ids = &fleet.layer_ids[layer];
        let pick = *ids.choose(rng).expect("layer must have at least one mix");
        path.push(pick);
    }
    path
}
