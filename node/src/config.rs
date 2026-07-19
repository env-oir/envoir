//! Daemon configuration (spec §0.2) — data dir, bind addresses, passphrase, naming pointers.
//!
//! The node is **native-only** (spec §8.5): it serves the libp2p mesh, JMAP (§8.1, the node's
//! native and only client surface), and the optional Envoir Send API (§13.5.1). The legacy
//! IMAP/POP3/SMTP-submission surfaces live **only on the separate gateway**, so the node no longer
//! carries any of their bind config.
//!
//! Every knob has an environment variable and a sane default, so the node runs with zero flags in
//! development yet is fully configurable in a container (the bind host is [`node_bind`](NodeConfig::node_bind),
//! defaulting to `0.0.0.0` so a Docker port-map can reach the mesh listener).
//!
//! | env var                | field           | default            |
//! |------------------------|-----------------|--------------------|
//! | `ENVOIR_DATA_DIR`      | `data_dir`      | `./envoir-data`    |
//! | `ENVOIR_NODE_BIND`     | `node_bind`     | `0.0.0.0:4600`     |
//! | `ENVOIR_PASSPHRASE`    | `passphrase`    | *(none ⇒ dev mode)*|
//! | `ENVOIR_NAMES`         | `names`         | *(empty)*          |
//! | `ENVOIR_KT_ANCHORS`    | `kt_anchors`    | `https://kt.invalid/log` (placeholder) |
//! | `ENVOIR_KEYPKGS_LOC`   | `keypkgs_loc`   | `/mesh/kp/self`    |
//! | `ENVOIR_TICK_SECS`     | `tick_secs`     | `15`               |
//! | `ENVOIR_SUPERVISED`    | `supervised`    | `false` (`1` ⇒ stdin EOF is a shutdown signal — for a supervising desktop shell) |
//! | `ENVOIR_SEND_API`      | `send_api_enabled` | `false` (opt-in) |
//! | `ENVOIR_SEND_API_BIND` | `send_api_bind` | `0.0.0.0:4610`     |
//! | `ENVOIR_SEND_ADMIN_TOKEN` | `send_admin_token` | *(none ⇒ key-management disabled)* |
//! | `ENVOIR_JMAP`          | `jmap_enabled`  | `false` (opt-in)   |
//! | `ENVOIR_JMAP_BIND`     | `jmap_bind`     | `127.0.0.1:4700` (localhost — off-localhost requires TLS) |
//! | `ENVOIR_JMAP_APP_PASSWORDS` | `jmap_app_passwords` | *(empty ⇒ no client can authenticate, fail-closed)* |
//! | `ENVOIR_JMAP_ACCOUNT`  | `jmap_account`  | *(first name, else base64url(ik))* |
//! | `ENVOIR_JMAP_BASE_URL` | `jmap_base_url` | *(derived from `jmap_bind`)* |
//! | `ENVOIR_PUB_SERVE`     | `pub_serve_enabled` | `false` (opt-in — the operator is choosing to make public objects readable by anyone, §22.6.1) |
//! | `ENVOIR_PUB_BIND`      | `pub_bind`      | `0.0.0.0:4680` (public surface — unlike JMAP, meant to be reachable off-box) |

use std::path::PathBuf;
use std::time::Duration;

/// The default TCP port the node's mesh transport binds (`ENVOIR_NODE_BIND`).
const DEFAULT_NODE_BIND: &str = "0.0.0.0:4600";
/// A clearly-invalid placeholder KT anchor: a parseable `_dmtap` record needs a non-empty `kt=`, but
/// the real log URL is operator config — this default makes the shape valid while flagging "replace me".
const PLACEHOLDER_KT: &str = "https://kt.invalid/log";
/// The default bind for the Envoir Send HTTP API (`ENVOIR_SEND_API_BIND`) — off unless enabled.
const DEFAULT_SEND_API_BIND: &str = "0.0.0.0:4610";
/// The default bind for the node-native JMAP listener (`ENVOIR_JMAP_BIND`). **Loopback** by default:
/// JMAP terminates TLS on the node (spec §8.2), and this listener speaks plain HTTP, so a native
/// client on the same machine (a Tauri app) reaches it over `127.0.0.1`; any off-localhost bind
/// requires a TLS front (enforced fail-closed in the daemon).
const DEFAULT_JMAP_BIND: &str = "127.0.0.1:4700";
/// The default bind for the DMTAP-PUB gateway (`ENVOIR_PUB_BIND`, spec §22.5/§22.6). Unlike JMAP,
/// this surface is **meant** to be reached by other peers off-box (public reads are anonymous —
/// §22.5.1), so it defaults to all-interfaces like the mesh/Send-API binds, not loopback.
const DEFAULT_PUB_BIND: &str = "0.0.0.0:4680";

/// Fully-resolved daemon configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory holding the keystore + journal (created on demand).
    pub data_dir: PathBuf,
    /// `host:port` the mesh transport listener binds (the reachable node address).
    pub node_bind: String,
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
    /// Supervised mode (`ENVOIR_SUPERVISED=1`): the daemon treats **stdin EOF as a shutdown
    /// signal**. Set by a supervisor (the desktop shell) that spawns the node as a sidecar and holds
    /// its stdin pipe — if the supervisor dies abnormally the OS closes the pipe and the daemon
    /// self-terminates instead of orphaning ([`crate::daemon::shutdown_signal_supervised`]). Off by
    /// default: an interactive `envoir-node run` must NOT exit just because stdin is closed or
    /// redirected from `/dev/null`.
    pub supervised: bool,
    /// Whether to expose the Envoir Send HTTP API (spec §13.5.1). **Off by default** — it is a
    /// privileged programmatic send surface, opt-in via `ENVOIR_SEND_API`.
    pub send_api_enabled: bool,
    /// `host:port` the Envoir Send HTTP listener binds when [`send_api_enabled`](Self::send_api_enabled).
    pub send_api_bind: String,
    /// The admin bearer token guarding the key-management routes (`/v1/keys*`). `None` ⇒ key
    /// management is **disabled** (fail-closed): only `/v1/send` is served, so a misconfigured
    /// deployment can never mint/rotate/revoke keys without an explicitly-set secret.
    pub send_admin_token: Option<String>,
    /// Whether to serve the node-native JMAP listener (spec §8.1 — the node's native, and only,
    /// client-sync surface). **Off by default** — opt-in via `ENVOIR_JMAP`.
    pub jmap_enabled: bool,
    /// `host:port` the JMAP listener binds when [`jmap_enabled`](Self::jmap_enabled). Defaults to
    /// loopback; an off-localhost bind requires a TLS front (enforced fail-closed in the daemon).
    pub jmap_bind: String,
    /// App-passwords (spec §8.2) that authenticate a JMAP client, as `(username, secret)` pairs. An
    /// **empty** list means no client can authenticate (fail-closed). Parsed from
    /// `ENVOIR_JMAP_APP_PASSWORDS` as a comma-separated list of `user:secret` (a bare `secret`
    /// binds to the account username).
    pub jmap_app_passwords: Vec<(String, String)>,
    /// The JMAP `accountId`/`username` this node presents. `None` ⇒ derived (first name, else the
    /// base64url of the identity key).
    pub jmap_account: Option<String>,
    /// The externally-reachable base URL advertised in the JMAP Session resource (its `apiUrl` /
    /// `downloadUrl` / … are built from it). `None` ⇒ derived from [`jmap_bind`](Self::jmap_bind).
    pub jmap_base_url: Option<String>,
    /// Whether to serve the DMTAP-PUB gateway (spec §22.5/§22.6) — the node's optional public-object
    /// HTTP surface (feed head/range, announce, manifest, chunk). **Off by default**: a node that
    /// never advertises `pub-1` is never expected to serve public objects (§22.6.1), and public
    /// objects are not blind — the operator can read what it serves — so this is an explicit opt-in
    /// via `ENVOIR_PUB_SERVE`.
    pub pub_serve_enabled: bool,
    /// `host:port` the DMTAP-PUB listener binds when [`pub_serve_enabled`](Self::pub_serve_enabled).
    /// Unlike JMAP this surface is meant to be reachable off-box (reads are anonymous, §22.5.1), so
    /// it defaults to all-interfaces rather than loopback.
    pub pub_bind: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            data_dir: PathBuf::from("./envoir-data"),
            node_bind: DEFAULT_NODE_BIND.to_string(),
            passphrase: None,
            names: Vec::new(),
            kt_anchors: vec![PLACEHOLDER_KT.to_string()],
            keypkgs_loc: "/mesh/kp/self".to_string(),
            tick: Duration::from_secs(15),
            supervised: false,
            send_api_enabled: false,
            send_api_bind: DEFAULT_SEND_API_BIND.to_string(),
            send_admin_token: None,
            jmap_enabled: false,
            jmap_bind: DEFAULT_JMAP_BIND.to_string(),
            jmap_app_passwords: Vec::new(),
            jmap_account: None,
            jmap_base_url: None,
            pub_serve_enabled: false,
            pub_bind: DEFAULT_PUB_BIND.to_string(),
        }
    }
}

impl NodeConfig {
    /// Build a config from the environment, falling back to [`Default`] for anything unset. Invalid
    /// numeric values fall back to the default (a bad `ENVOIR_TICK_SECS` does not crash the daemon).
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
        if let Ok(v) = std::env::var("ENVOIR_SUPERVISED") {
            c.supervised = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ENVOIR_SEND_API") {
            c.send_api_enabled = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ENVOIR_SEND_API_BIND") {
            if !v.is_empty() {
                c.send_api_bind = v;
            }
        }
        c.send_admin_token = std::env::var("ENVOIR_SEND_ADMIN_TOKEN").ok().filter(|s| !s.is_empty());
        if let Ok(v) = std::env::var("ENVOIR_JMAP") {
            c.jmap_enabled = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ENVOIR_JMAP_BIND") {
            if !v.is_empty() {
                c.jmap_bind = v;
            }
        }
        if let Ok(v) = std::env::var("ENVOIR_JMAP_APP_PASSWORDS") {
            c.jmap_app_passwords = parse_app_passwords(&v);
        }
        c.jmap_account = std::env::var("ENVOIR_JMAP_ACCOUNT").ok().filter(|s| !s.is_empty());
        c.jmap_base_url = std::env::var("ENVOIR_JMAP_BASE_URL").ok().filter(|s| !s.is_empty());
        if let Ok(v) = std::env::var("ENVOIR_PUB_SERVE") {
            c.pub_serve_enabled = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ENVOIR_PUB_BIND") {
            if !v.is_empty() {
                c.pub_bind = v;
            }
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

    /// Whether the JMAP bind host is a loopback address (`127.0.0.0/8`, `::1`, `localhost`). Only a
    /// loopback bind is served over plain HTTP; an off-localhost bind requires a TLS front and is
    /// refused fail-closed by the daemon (JMAP terminates TLS on the node, spec §8.2).
    pub fn jmap_bind_is_loopback(&self) -> bool {
        host_is_loopback(&self.jmap_bind)
    }

    /// The resolved JMAP `accountId`/`username` for this node: the configured account, else the
    /// first claimed name, else the base64url of the identity public key (`ik_public`).
    pub fn jmap_account_id(&self, ik_public: &[u8]) -> String {
        if let Some(a) = self.jmap_account.as_ref().filter(|s| !s.is_empty()) {
            return a.clone();
        }
        if let Some(n) = self.names.first().filter(|s| !s.is_empty()) {
            return n.clone();
        }
        dmtap_naming::base64url::encode(ik_public)
    }

    /// The resolved JMAP Session base URL: the configured value, else `http://<jmap_bind>` (plain
    /// HTTP is only ever used on loopback; an off-localhost deployment sets the TLS front's URL).
    pub fn jmap_base_url_resolved(&self) -> String {
        self.jmap_base_url.clone().unwrap_or_else(|| format!("http://{}", self.jmap_bind))
    }

    /// The JMAP app-passwords with any bare-secret entry's username resolved to `account_id`.
    pub fn jmap_app_passwords_resolved(&self, account_id: &str) -> Vec<(String, String)> {
        self.jmap_app_passwords
            .iter()
            .map(|(u, s)| {
                let user = if u.is_empty() { account_id.to_string() } else { u.clone() };
                (user, s.clone())
            })
            .collect()
    }
}

/// Parse `ENVOIR_JMAP_APP_PASSWORDS`: a comma-separated list of `user:secret` (a bare `secret` has
/// an empty username, later resolved to the account id). Empty entries are dropped.
fn parse_app_passwords(v: &str) -> Vec<(String, String)> {
    v.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| match e.split_once(':') {
            Some((u, s)) => (u.trim().to_string(), s.to_string()),
            None => (String::new(), e.to_string()),
        })
        .filter(|(_, s)| !s.is_empty())
        .collect()
}

/// Whether `bind` names a loopback interface. Accepts `host:port` (`127.0.0.1:4700`,
/// `[::1]:4700`, `localhost:4700`) and a bare host/IP (`::1`, `127.0.0.1`, `localhost`).
fn host_is_loopback(bind: &str) -> bool {
    // A full socket address (handles `127.0.0.1:80` and the bracketed `[::1]:80`).
    if let Ok(sa) = bind.parse::<std::net::SocketAddr>() {
        return sa.ip().is_loopback();
    }
    // A bare IP literal (`::1`, `127.0.0.1`).
    if let Ok(ip) = bind.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // A `host:port` (or bare host) with a non-IP host — only `localhost` is loopback.
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    host.eq_ignore_ascii_case("localhost")
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
        assert_eq!(c.keystore_path(), PathBuf::from("./envoir-data/keystore.json"));
        assert_eq!(c.journal_path(), PathBuf::from("./envoir-data/journal.json"));
    }

    #[test]
    fn supervised_mode_is_off_by_default() {
        // An interactive `envoir-node run` must not exit on a closed/redirected stdin; only an
        // explicit ENVOIR_SUPERVISED=1 (the desktop shell's sidecar spawn) opts into EOF-shutdown.
        assert!(!NodeConfig::default().supervised);
    }

    #[test]
    fn send_api_is_off_by_default_and_management_disabled() {
        let c = NodeConfig::default();
        // The Envoir Send API is a privileged programmatic surface — opt-in only.
        assert!(!c.send_api_enabled);
        // With no admin token, key management is fail-closed (disabled).
        assert!(c.send_admin_token.is_none());
        assert_eq!(c.send_api_bind, "0.0.0.0:4610");
    }

    #[test]
    fn csv_parsing_trims_and_drops_empties() {
        assert_eq!(split_csv("a, b ,,c"), vec!["a", "b", "c"]);
        assert!(split_csv("  ,  ").is_empty());
    }

    #[test]
    fn pub_serve_is_off_by_default_and_binds_all_interfaces() {
        let c = NodeConfig::default();
        // The DMTAP-PUB gateway is opt-in (§22.6.1: a node never advertising `pub-1` is never
        // expected to serve public objects) — and unlike JMAP its default bind is NOT loopback,
        // since the surface is meant to be reachable off-box (anonymous reads, §22.5.1).
        assert!(!c.pub_serve_enabled);
        assert_eq!(c.pub_bind, "0.0.0.0:4680");
    }

    #[test]
    fn jmap_is_off_by_default_and_binds_loopback() {
        let c = NodeConfig::default();
        // The JMAP surface is opt-in, and its default bind is loopback (no cleartext off-host).
        assert!(!c.jmap_enabled);
        assert_eq!(c.jmap_bind, "127.0.0.1:4700");
        assert!(c.jmap_bind_is_loopback());
        // No app-passwords by default ⇒ no client can authenticate (fail-closed).
        assert!(c.jmap_app_passwords.is_empty());
    }

    #[test]
    fn loopback_detection() {
        assert!(host_is_loopback("127.0.0.1:4700"));
        assert!(host_is_loopback("127.5.5.5:80"));
        assert!(host_is_loopback("localhost:4700"));
        assert!(host_is_loopback("[::1]:4700"));
        assert!(host_is_loopback("::1"));
        assert!(!host_is_loopback("0.0.0.0:4700"));
        assert!(!host_is_loopback("192.168.1.9:4700"));
        assert!(!host_is_loopback("example.com:4700"));
    }

    #[test]
    fn app_password_parsing() {
        // `user:secret`, bare `secret` (empty user), trims and drops empties.
        let p = parse_app_passwords("alice@dmtap.local:s3cret, plainsecret ,, :dangling");
        assert_eq!(
            p,
            vec![
                ("alice@dmtap.local".to_string(), "s3cret".to_string()),
                (String::new(), "plainsecret".to_string()),
                (String::new(), "dangling".to_string()),
            ]
        );
        // A bare secret resolves its username to the account id.
        let c = NodeConfig { jmap_app_passwords: p, ..NodeConfig::default() };
        let resolved = c.jmap_app_passwords_resolved("bob@dmtap.local");
        assert_eq!(resolved[1], ("bob@dmtap.local".to_string(), "plainsecret".to_string()));
        assert_eq!(resolved[0].0, "alice@dmtap.local");
    }

    #[test]
    fn jmap_account_and_base_url_resolution() {
        let mut c = NodeConfig::default();
        // No name, no account ⇒ base64url(ik).
        let ik = vec![1u8, 2, 3, 4];
        assert_eq!(c.jmap_account_id(&ik), dmtap_naming::base64url::encode(&ik));
        // A claimed name is used when no explicit account.
        c.names = vec!["me@dmtap.local".to_string()];
        assert_eq!(c.jmap_account_id(&ik), "me@dmtap.local");
        // An explicit account wins.
        c.jmap_account = Some("primary@dmtap.local".to_string());
        assert_eq!(c.jmap_account_id(&ik), "primary@dmtap.local");
        // Base URL derives from the bind unless set.
        assert_eq!(c.jmap_base_url_resolved(), "http://127.0.0.1:4700");
        c.jmap_base_url = Some("https://mail.example".to_string());
        assert_eq!(c.jmap_base_url_resolved(), "https://mail.example");
    }
}
