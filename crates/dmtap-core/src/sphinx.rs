//! Sphinx packet & framing byte layouts — spec §4.4.1, §18.5.4.
//!
//! Unlike every other DMTAP wire object, Sphinx is a **fixed-length binary** format, **not**
//! deterministic CBOR: it is on the mixnet wire and MUST be constant-length at every hop so a
//! 3-hop and a 5-hop cell are byte-identical (padding hides path length and payload length). This
//! module pins the DMTAP-specific field layouts §18.5.4 requires:
//!
//! - [`SphinxCell`] — the constant `32 + 240 + 16 + 2048 = 2336`-byte on-wire cell (`α ‖ β ‖ γ ‖ δ`).
//! - [`RoutingCommand`] — the per-hop, fixed 48-byte routing/delay command carried inside `β`.
//! - [`Surb`] — the 352-byte Single-Use Reply Block (`first_hop ‖ header ‖ key_seed`).
//! - [`SphinxFragmentHeader`] — the fixed 16-byte header at the front of each cell's `δ` plaintext.
//!
//! All multi-byte integers are **big-endian** (§18.1.3). The cryptographic construction (`α`
//! re-randomization, `β` onion, `γ` MAC, `δ` LIONESS PRP) is per §4.4.1 and is NOT modeled here —
//! these are the byte layouts only. Sphinx carries **no DMTAP `sig-val`** (§18.9.14); integrity is
//! the per-hop MAC / wide-block PRP.

/// Length constants from §18.5.4 (all fixed).
pub const ALPHA_LEN: usize = 32;
pub const BETA_LEN: usize = 240; // r_max(5) · 48
pub const GAMMA_LEN: usize = 16;
pub const DELTA_LEN: usize = 2048;
/// Total on-wire cell length — identical for every cell of every profile (§18.5.4).
pub const CELL_LEN: usize = ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN; // 2336
/// Max per-hop routing commands packed into `β` (`r_max`).
pub const R_MAX: usize = 5;
/// Fixed size of one `RoutingCommand` block inside `β`.
pub const ROUTING_COMMAND_LEN: usize = 48;
/// Pre-built Sphinx header length inside a SURB (`α ‖ β ‖ γ`).
pub const SURB_HEADER_LEN: usize = ALPHA_LEN + BETA_LEN + GAMMA_LEN; // 288
/// Total SURB length (`first_hop ‖ header ‖ key_seed`).
pub const SURB_LEN: usize = 32 + SURB_HEADER_LEN + 32; // 352
/// Fixed `SphinxFragmentHeader` length at the front of each cell's `δ` plaintext.
pub const FRAGMENT_HEADER_LEN: usize = 16;
/// Fragment-data bytes per cell after the fragment header (`2048 − 16`).
pub const FRAGMENT_DATA_LEN: usize = DELTA_LEN - FRAGMENT_HEADER_LEN; // 2032

/// Errors from parsing a fixed-length Sphinx layout (fail closed, §18.5.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SphinxError {
    #[error("wrong length for {what}: expected {expected}, got {got}")]
    WrongLength { what: &'static str, expected: usize, got: usize },
    #[error("unknown RoutingCommand.cmd {0:#04x} (§18.5.4; ERR_MIX_PACKET_MALFORMED 0x0307)")]
    UnknownCommand(u8),
    #[error("reserved bytes must be zero (§18.5.4; ERR_MIX_PACKET_MALFORMED 0x0307)")]
    ReservedNonZero,
}

fn fixed<'a>(bytes: &'a [u8], what: &'static str, expected: usize) -> Result<&'a [u8], SphinxError> {
    if bytes.len() == expected {
        Ok(bytes)
    } else {
        Err(SphinxError::WrongLength { what, expected, got: bytes.len() })
    }
}

/// The per-hop routing command (§18.5.4), a fixed 48-byte block inside `β`. Each hop peels exactly
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingCommand {
    /// `0x00` forward-to-mix; `0x01` deliver-to-recipient (exit); `0x02` SURB-reply hop.
    pub cmd: u8,
    /// bit0 = last-hop; all other bits reserved and MUST be 0.
    pub flags: u8,
    /// Poisson-sampled hop delay in milliseconds (§16.3), big-endian on the wire.
    pub delay_ms: u32,
    /// Next node's routing id (32 B); all-zero for `cmd = 0x01` (deliver-to-recipient).
    pub next_hop: [u8; 32],
}

impl RoutingCommand {
    /// Serialize to the fixed 48-byte layout (offsets per §18.5.4). `reserved` (10 B) is zero.
    pub fn to_bytes(&self) -> [u8; ROUTING_COMMAND_LEN] {
        let mut out = [0u8; ROUTING_COMMAND_LEN];
        out[0] = self.cmd;
        out[1] = self.flags;
        out[2..6].copy_from_slice(&self.delay_ms.to_be_bytes());
        out[6..38].copy_from_slice(&self.next_hop);
        // out[38..48] reserved — already zero.
        out
    }

    /// Parse the fixed 48-byte layout, failing closed on an unknown `cmd` or non-zero reserved
    /// bytes (§18.5.4, `ERR_MIX_PACKET_MALFORMED`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphinxError> {
        let b = fixed(bytes, "RoutingCommand", ROUTING_COMMAND_LEN)?;
        let cmd = b[0];
        if cmd > 0x02 {
            return Err(SphinxError::UnknownCommand(cmd));
        }
        let flags = b[1];
        // other flag bits are reserved and MUST be 0 (bit0 = last-hop).
        if flags & !0x01 != 0 {
            return Err(SphinxError::ReservedNonZero);
        }
        let delay_ms = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&b[6..38]);
        // `cmd = 0x01` (deliver-to-recipient / exit) has no next node: `next_hop` MUST be all-zero
        // (§18.5.4). A non-zero next_hop here is a canonical-encoding gap — reject it fail-closed so
        // there is exactly one valid on-wire encoding of an exit command.
        if cmd == 0x01 && next_hop.iter().any(|&x| x != 0) {
            return Err(SphinxError::ReservedNonZero);
        }
        if b[38..48].iter().any(|&x| x != 0) {
            return Err(SphinxError::ReservedNonZero);
        }
        Ok(RoutingCommand { cmd, flags, delay_ms, next_hop })
    }
}

/// A Single-Use Reply Block (§18.5.4). The replier treats it as opaque: sets `δ` to its reply,
/// wraps under `key_seed`, prepends `header`, sends to `first_hop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surb {
    pub first_hop: [u8; 32],
    /// Pre-built return-path Sphinx header `(α ‖ β ‖ γ)`, opaque to the replier (288 B).
    pub header: Vec<u8>,
    pub key_seed: [u8; 32],
}

impl Surb {
    /// Serialize to the fixed 352-byte layout (§18.5.4).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SURB_LEN);
        out.extend_from_slice(&self.first_hop);
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.key_seed);
        debug_assert_eq!(out.len(), SURB_LEN);
        out
    }

    /// Parse the fixed 352-byte layout (with a 288-byte `header`), failing closed on length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphinxError> {
        let b = fixed(bytes, "Surb", SURB_LEN)?;
        let mut first_hop = [0u8; 32];
        first_hop.copy_from_slice(&b[0..32]);
        let header = b[32..32 + SURB_HEADER_LEN].to_vec();
        let mut key_seed = [0u8; 32];
        key_seed.copy_from_slice(&b[32 + SURB_HEADER_LEN..SURB_LEN]);
        Ok(Surb { first_hop, header, key_seed })
    }
}

/// The fixed 16-byte fragment header at the front of each cell's `δ` plaintext (§18.5.4). A MOTE
/// is padded to a bucket rung and split into `frag_count` cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphinxFragmentHeader {
    /// Random per-MOTE id linking this MOTE's fragments (fresh per MOTE; unlinkable to identity).
    pub msg_id: [u8; 8],
    /// 0-based fragment number, big-endian.
    pub frag_index: u16,
    /// Total fragments for this MOTE (∈ {1,4,16,32}, the ladder), big-endian.
    pub frag_count: u16,
    /// True `Envelope` length before bucket padding, big-endian.
    pub total_len: u32,
}

impl SphinxFragmentHeader {
    /// Serialize to the fixed 16-byte layout (offsets per §18.5.4).
    pub fn to_bytes(&self) -> [u8; FRAGMENT_HEADER_LEN] {
        let mut out = [0u8; FRAGMENT_HEADER_LEN];
        out[0..8].copy_from_slice(&self.msg_id);
        out[8..10].copy_from_slice(&self.frag_index.to_be_bytes());
        out[10..12].copy_from_slice(&self.frag_count.to_be_bytes());
        out[12..16].copy_from_slice(&self.total_len.to_be_bytes());
        out
    }

    /// Parse the fixed 16-byte layout, failing closed on length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphinxError> {
        let b = fixed(bytes, "SphinxFragmentHeader", FRAGMENT_HEADER_LEN)?;
        let mut msg_id = [0u8; 8];
        msg_id.copy_from_slice(&b[0..8]);
        Ok(SphinxFragmentHeader {
            msg_id,
            frag_index: u16::from_be_bytes([b[8], b[9]]),
            frag_count: u16::from_be_bytes([b[10], b[11]]),
            total_len: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        })
    }
}

/// The constant-length Sphinx cell (§18.5.4): `α ‖ β ‖ γ ‖ δ` = `32 + 240 + 16 + 2048 = 2336`
/// bytes, identical for every cell of every profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphinxCell {
    /// Header group element (X25519 point, v0), re-randomized per hop.
    pub alpha: [u8; ALPHA_LEN],
    /// The routing onion: `r_max = 5` per-hop `RoutingCommand` blocks, zero-padded.
    pub beta: Vec<u8>,
    /// Poly1305 header MAC over `β` for this hop.
    pub gamma: [u8; GAMMA_LEN],
    /// The constant-length payload cell (LIONESS-permuted per hop).
    pub delta: Vec<u8>,
}

impl SphinxCell {
    /// Serialize to the fixed 2336-byte on-wire layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CELL_LEN);
        out.extend_from_slice(&self.alpha);
        out.extend_from_slice(&self.beta);
        out.extend_from_slice(&self.gamma);
        out.extend_from_slice(&self.delta);
        debug_assert_eq!(out.len(), CELL_LEN);
        out
    }

    /// Parse the fixed 2336-byte layout, failing closed on any length mismatch (a cell off the
    /// constant-length invariant is `ERR_MIX_PACKET_MALFORMED`, §18.5.4).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SphinxError> {
        let b = fixed(bytes, "SphinxCell", CELL_LEN)?;
        let mut alpha = [0u8; ALPHA_LEN];
        alpha.copy_from_slice(&b[0..ALPHA_LEN]);
        let beta = b[ALPHA_LEN..ALPHA_LEN + BETA_LEN].to_vec();
        let mut gamma = [0u8; GAMMA_LEN];
        gamma.copy_from_slice(&b[ALPHA_LEN + BETA_LEN..ALPHA_LEN + BETA_LEN + GAMMA_LEN]);
        let delta = b[ALPHA_LEN + BETA_LEN + GAMMA_LEN..CELL_LEN].to_vec();
        Ok(SphinxCell { alpha, beta, gamma, delta })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(CELL_LEN, 2336);
        assert_eq!(BETA_LEN, R_MAX * ROUTING_COMMAND_LEN);
        assert_eq!(SURB_HEADER_LEN, 288);
        assert_eq!(SURB_LEN, 352);
        assert_eq!(FRAGMENT_DATA_LEN, 2032);
    }

    #[test]
    fn routing_command_round_trips_and_validates() {
        let rc = RoutingCommand { cmd: 0x00, flags: 0x01, delay_ms: 1234, next_hop: [0xab; 32] };
        let bytes = rc.to_bytes();
        assert_eq!(bytes.len(), ROUTING_COMMAND_LEN);
        assert_eq!(RoutingCommand::from_bytes(&bytes).unwrap(), rc);
    }

    #[test]
    fn routing_command_rejects_unknown_cmd_and_reserved() {
        let mut bytes = RoutingCommand { cmd: 0x01, flags: 0, delay_ms: 0, next_hop: [0; 32] }.to_bytes();
        bytes[0] = 0x03; // unknown command
        assert_eq!(RoutingCommand::from_bytes(&bytes), Err(SphinxError::UnknownCommand(0x03)));
        let mut bytes2 = RoutingCommand { cmd: 0x02, flags: 0, delay_ms: 0, next_hop: [0; 32] }.to_bytes();
        bytes2[40] = 0xff; // reserved byte non-zero
        assert_eq!(RoutingCommand::from_bytes(&bytes2), Err(SphinxError::ReservedNonZero));
        let mut bytes3 = RoutingCommand { cmd: 0x00, flags: 0, delay_ms: 0, next_hop: [0; 32] }.to_bytes();
        bytes3[1] = 0x02; // reserved flag bit set
        assert_eq!(RoutingCommand::from_bytes(&bytes3), Err(SphinxError::ReservedNonZero));
    }

    #[test]
    fn deliver_command_requires_zero_next_hop() {
        // A `cmd = 0x01` (exit) command has no next node — a non-zero next_hop is a canonical
        // encoding gap and must be rejected fail-closed. Build a wire form directly (the
        // constructor path would honor whatever bytes we hand it), then flip a next_hop byte.
        let mut bytes = RoutingCommand { cmd: 0x01, flags: 0x01, delay_ms: 0, next_hop: [0; 32] }.to_bytes();
        bytes[6] = 0x01; // first next_hop byte non-zero
        assert_eq!(RoutingCommand::from_bytes(&bytes), Err(SphinxError::ReservedNonZero));
        // The all-zero next_hop exit command still round-trips.
        let ok = RoutingCommand { cmd: 0x01, flags: 0x01, delay_ms: 0, next_hop: [0; 32] };
        assert_eq!(RoutingCommand::from_bytes(&ok.to_bytes()).unwrap(), ok);
    }

    #[test]
    fn surb_round_trips() {
        let s = Surb { first_hop: [0x11; 32], header: vec![0x22; SURB_HEADER_LEN], key_seed: [0x33; 32] };
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), SURB_LEN);
        assert_eq!(Surb::from_bytes(&bytes).unwrap(), s);
    }

    #[test]
    fn fragment_header_round_trips() {
        let h = SphinxFragmentHeader { msg_id: [1, 2, 3, 4, 5, 6, 7, 8], frag_index: 3, frag_count: 16, total_len: 40000 };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), FRAGMENT_HEADER_LEN);
        assert_eq!(SphinxFragmentHeader::from_bytes(&bytes).unwrap(), h);
    }

    #[test]
    fn cell_round_trips_and_rejects_wrong_length() {
        let c = SphinxCell {
            alpha: [0x01; ALPHA_LEN],
            beta: vec![0x02; BETA_LEN],
            gamma: [0x03; GAMMA_LEN],
            delta: vec![0x04; DELTA_LEN],
        };
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), CELL_LEN);
        assert_eq!(SphinxCell::from_bytes(&bytes).unwrap(), c);
        assert!(matches!(
            SphinxCell::from_bytes(&bytes[..CELL_LEN - 1]),
            Err(SphinxError::WrongLength { .. })
        ));
    }
}
