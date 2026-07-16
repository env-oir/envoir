//! Daemon configuration (spec §0.2) — data dir, bind addresses, passphrase, naming pointers.
//!
//! Every knob has an environment variable and a sane default, so the node runs with zero flags in
//! development yet is fully configurable in a container (the deploy gap the scaffold surfaced: the
//! §8 servers were hardcoded to `127.0.0.1`, unreachable through a Docker port-map — the bind host
//! is now [`mail_host`](NodeConfig::mail_host) / [`node_bind`](NodeConfig::node_bind), defaulting to
//! `0.0.0.0`).
//!
//! | env var                | field           | default            |
//! |------------------------|-----------------|--------------------|
//! | `ENVOIR_DATA_DIR`      | `data_dir`      | `./envoir-data`    |
//! | `ENVOIR_NODE_BIND`     | `node_bind`     | `0.0.0.0:4600`     |
//! | `ENVOIR_MAIL_HOST`     | `mail_host`     | `0.0.0.0`          |
//! | `ENVOIR_IMAP_PORT`     | `imap_port`     | `1143`             |
//! | `ENVOIR_POP3_PORT`     | `pop3_port`     | `1110`             |
//! | `ENVOIR_SMTP_PORT`     | `smtp_port`     | `1587`             |
//! | `ENVOIR_MAIL`          | `mail_enabled`  | `true`             |
//! | `ENVOIR_PASSPHRASE`    | `passphrase`    | *(none ⇒ dev mode)*|
//! | `ENVOIR_NAMES`         | `names`         | *(empty)*          |
//! | `ENVOIR_KT_ANCHORS`    | `kt_anchors`    | `https://kt.invalid/log` (placeholder) |
//! | `ENVOIR_KEYPKGS_LOC`   | `keypkgs_loc`   | `/mesh/kp/self`    |
//! | `ENVOIR_TICK_SECS`     | `tick_secs`     | `15`               |

use std::path::PathBuf;
use std::time::Duration;

/// The default TCP port the node's mesh transport binds (`ENVOIR_NODE_BIND`).
const DEFAULT_NODE_BIND: &str = "0.0.0.0:4600";
/// The default interface the §8 client servers bind — `0.0.0.0` so a container port-map reaches them.
const DEFAULT_MAIL_HOST: &str = "0.0.0.0";
/// A clearly-invalid placeholder KT anchor: a parseable `_dmtap` record needs a non-empty `kt=`, but
/// the real log URL is operator config — this default makes the shape valid while flagging "replace me".
const PLACEHOLDER_KT: &str = "https://kt.invalid/log";

/// Fully-resolved daemon configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory holding the keystore + journal (created on demand).
    pub data_dir: PathBuf,
    /// `host:port` the mesh transport listener binds (the reachable node address).
    pub node_bind: String,
    /// Interface the §8 client servers bind (IMAP/POP3/SMTP-submission).
    pub mail_host: String,
    pub imap_port: u16,
    pub pop3_port: u16,
    pub smtp_port: u16,
    /// Whether to start the §8 client servers at all.
    pub mail_enabled: bool,
    /// Keystore passphrase; `None` ⇒ plaintext-for-dev keystore (spec §1.4).
    pub passphrase: Option<String>,
    /// The names this identity claims (its `_dmtap` `names`, §3.2).
    pub names: Vec<String>,
    /// The KT log anchor URL(s) the operator publishes (§3.5.2).
    pub kt_anchors: Vec<String>,
    /// The KeyPackage bundle locator the operator publishes (§5.3).
    pub keypkgs_loc: String,
    /// How often the daemon fires its retry/poll/deadline tick.
    pub tick: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            data_dir: PathBuf::from("./envoir-data"),
            node_bind: DEFAULT_NODE_BIND.to_string(),
            mail_host: DEFAULT_MAIL_HOST.to_string(),
            imap_port: 1143,
            pop3_port: 1110,
            smtp_port: 1587,
            mail_enabled: true,
            passphrase: None,
            names: Vec::new(),
            kt_anchors: vec![PLACEHOLDER_KT.to_string()],
            keypkgs_loc: "/mesh/kp/self".to_string(),
            tick: Duration::from_secs(15),
        }
    }
}

impl NodeConfig {
    /// Build a config from the environment, falling back to [`Default`] for anything unset. Invalid
    /// numeric values fall back to the default (a bad `ENVOIR_IMAP_PORT` does not crash the daemon).
    pub fn from_env() -> Self {
        let mut c = NodeConfig::default();
        if let Ok(v) = std::env::var("ENVOIR_DATA_DIR") {
            if !v.is_empty() {
                c.data_dir = PathBuf::from(v);
            }
        }
        if let Ok(v) = std::env::var("ENVOIR_NODE_BIND") {
            if !v.is_empty() {
                c.node_bind = v;
            }
        }
        if let Ok(v) = std::env::var("ENVOIR_MAIL_HOST") {
            if !v.is_empty() {
                c.mail_host = v;
            }
        }
        c.imap_port = env_u16("ENVOIR_IMAP_PORT", c.imap_port);
        c.pop3_port = env_u16("ENVOIR_POP3_PORT", c.pop3_port);
        c.smtp_port = env_u16("ENVOIR_SMTP_PORT", c.smtp_port);
        if let Ok(v) = std::env::var("ENVOIR_MAIL") {
            c.mail_enabled = !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no");
        }
        c.passphrase = std::env::var("ENVOIR_PASSPHRASE").ok().filter(|s| !s.is_empty());
        if let Ok(v) = std::env::var("ENVOIR_NAMES") {
            c.names = split_csv(&v);
        }
        if let Ok(v) = std::env::var("ENVOIR_KT_ANCHORS") {
            let anchors = split_csv(&v);
            if !anchors.is_empty() {
                c.kt_anchors = anchors;
            }
        }
        if let Ok(v) = std::env::var("ENVOIR_KEYPKGS_LOC") {
            if !v.is_empty() {
                c.keypkgs_loc = v;
            }
        }
        if let Some(secs) = std::env::var("ENVOIR_TICK_SECS").ok().and_then(|v| v.parse::<u64>().ok())
        {
            c.tick = Duration::from_secs(secs.max(1));
        }
        c
    }

    /// The keystore path within the data dir.
    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.json")
    }

    /// The durable outbound-journal path within the data dir (spec §19.3.3).
    pub fn journal_path(&self) -> PathBuf {
        self.data_dir.join("journal.json")
    }
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key).ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(default)
}

fn split_csv(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bind_all_interfaces_not_loopback() {
        let c = NodeConfig::default();
        // The Docker-reachability fix: never default to 127.0.0.1.
        assert!(c.node_bind.starts_with("0.0.0.0"));
        assert_eq!(c.mail_host, "0.0.0.0");
        assert_eq!(c.keystore_path(), PathBuf::from("./envoir-data/keystore.json"));
        assert_eq!(c.journal_path(), PathBuf::from("./envoir-data/journal.json"));
    }

    #[test]
    fn csv_parsing_trims_and_drops_empties() {
        assert_eq!(split_csv("a, b ,,c"), vec!["a", "b", "c"]);
        assert!(split_csv("  ,  ").is_empty());
    }
}
