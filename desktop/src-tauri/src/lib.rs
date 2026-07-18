//! Envoir desktop — sidecar lifecycle + REAL-mode wiring.
//!
//! This Tauri v2 app bundles the Envoir static client (the `client/` frontend) and runs the real
//! `envoir-node` binary as a **managed sidecar**, so the whole node runs on the user's own machine.
//! The webview client then talks to it in REAL mode over the node's loopback JMAP surface
//! (spec §8.1), exactly as if the user had started `envoir-node run` by hand.
//!
//! ## What `run()` does
//! 1. Resolves a per-user app-data dir and a `node/` data dir under it.
//! 2. On first run, generates a random app-password (persisted, so the client keeps working across
//!    restarts) and — if there is no keystore yet — runs `envoir-node init` once to mint the
//!    identity keystore.
//! 3. Spawns `envoir-node run` as a Tauri sidecar with the node's real environment (loopback binds,
//!    JMAP on, the generated app-password, the Send API on), draining its stdout/stderr to the log.
//! 4. Creates the main window with an initialization script that injects `window.__ENVOIR_NODE__`
//!    — the exact shape `client/js/store.js::resolveNodeConfig()` reads — so `js/net/sync.js`
//!    auto-connects in REAL mode with no user configuration.
//! 5. Kills the sidecar on app exit (`RunEvent::Exit`).
//!
//! The node's JMAP listener is loopback-bound and app-password gated; a small CORS allowance on that
//! listener (see `node/src/jmap_api.rs`) lets the `tauri://` webview origin reach it. CORS is not the
//! security boundary there — the app-password is.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// The loopback host:port the node's JMAP listener binds (spec §8.2 — plain HTTP only on loopback).
const JMAP_BIND: &str = "127.0.0.1:4700";
/// The base URL the client uses to reach the node's JMAP surface.
const JMAP_BASE_URL: &str = "http://127.0.0.1:4700";
/// The loopback host:port for the node's mesh transport (kept local for a desktop install).
const NODE_BIND: &str = "127.0.0.1:4600";
/// The loopback host:port for the node's Envoir Send API (spec §13.5.1).
const SEND_API_BIND: &str = "127.0.0.1:4610";
/// The JMAP app-password username. Must match the `username` injected into the webview and the
/// left side of `ENVOIR_JMAP_APP_PASSWORDS` (`<username>:<secret>`).
const APP_USER: &str = "envoir";
/// The sidecar program name passed to `ShellExt::sidecar`. `tauri-build` copies the configured
/// externalBin (`binaries/envoir-node-<target-triple>`, see `tauri.conf.json`) next to the app
/// executable with the triple stripped, so at runtime it is resolved by this **base name**.
const SIDECAR: &str = "envoir-node";

/// Holds the running sidecar child so it can be killed on exit.
#[derive(Default)]
struct NodeProcess(Mutex<Option<CommandChild>>);

/// Entry point invoked from `main.rs`.
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(NodeProcess::default())
        .setup(|app| {
            let handle = app.handle().clone();
            if let Err(e) = start_node_and_window(&handle) {
                // Fail loudly: without the node the client would silently fall back to SIMULATION.
                eprintln!("envoir-desktop: fatal — could not start the local node: {e}");
                return Err(e);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the Envoir desktop app");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            // Kill the managed node so it never outlives the app (no orphaned loopback listener).
            if let Some(child) = app_handle
                .state::<NodeProcess>()
                .0
                .lock()
                .expect("node process lock poisoned")
                .take()
            {
                let _ = child.kill();
            }
        }
    });
}

/// Resolve the data dir, ensure the identity keystore, spawn the node, and build the main window
/// with the injected REAL-mode config. Any failure is fatal (see `run()`).
fn start_node_and_window(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let app_data = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data)?;
    let node_dir = app_data.join("node");
    std::fs::create_dir_all(&node_dir)?;

    // A stable per-install app-password + Send admin token (generated once, then reused).
    let app_password = load_or_create_secret(&app_data.join("app-password"))?;
    let send_admin_token = load_or_create_secret(&app_data.join("send-admin-token"))?;
    let env = node_env(&node_dir, &app_password, &send_admin_token);

    // First run: mint the identity keystore if absent. `envoir-node init` is idempotent (it refuses
    // to overwrite an existing keystore without ENVOIR_FORCE_INIT), so guarding on the file is just
    // to avoid a needless process spawn.
    let keystore = node_dir.join("keystore.json");
    if !keystore.exists() {
        run_node_init(app, &env)?;
    }

    // Spawn the long-lived daemon and keep the child so we can kill it on exit.
    let child = spawn_node_run(app, &env)?;
    app.state::<NodeProcess>()
        .0
        .lock()
        .expect("node process lock poisoned")
        .replace(child);

    // Inject the node config the client reads (store.js::resolveNodeConfig). The exact shape:
    // { enabled, baseUrl, username, appPassword }. serde_json renders a valid JS object literal
    // (and escapes the secret safely).
    let node_cfg = serde_json::json!({
        "enabled": true,
        "baseUrl": JMAP_BASE_URL,
        "username": APP_USER,
        "appPassword": app_password,
    });
    let init_script = format!("window.__ENVOIR_NODE__ = {node_cfg};");

    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Envoir")
        .inner_size(1240.0, 840.0)
        .min_inner_size(880.0, 600.0)
        .initialization_script(&init_script)
        .build()?;

    Ok(())
}

/// The node's real runtime environment (spec `dmtap::config`): loopback binds, JMAP + Send API on,
/// the generated app-password, and the app-data node dir. Loopback-only — nothing is exposed off the
/// machine.
fn node_env(node_dir: &Path, app_password: &str, send_admin_token: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("ENVOIR_DATA_DIR".into(), node_dir.to_string_lossy().into_owned());
    env.insert("ENVOIR_NODE_BIND".into(), NODE_BIND.into());
    // Native JMAP client surface (spec §8.1) — the client's only sync path.
    env.insert("ENVOIR_JMAP".into(), "1".into());
    env.insert("ENVOIR_JMAP_BIND".into(), JMAP_BIND.into());
    env.insert("ENVOIR_JMAP_APP_PASSWORDS".into(), format!("{APP_USER}:{app_password}"));
    // Envoir Send API (spec §13.5.1) — enabled on loopback, with key-management unlocked by a
    // generated admin token (fail-closed without one).
    env.insert("ENVOIR_SEND_API".into(), "1".into());
    env.insert("ENVOIR_SEND_API_BIND".into(), SEND_API_BIND.into());
    env.insert("ENVOIR_SEND_ADMIN_TOKEN".into(), send_admin_token.into());
    env
}

/// Run `envoir-node init` once and wait for it to finish, draining its output to the log.
fn run_node_init(
    app: &tauri::AppHandle,
    env: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cmd = app.shell().sidecar(SIDECAR)?.args(["init"]).envs(env.clone());
    let (mut rx, _child) = cmd.spawn()?;
    // Block until the init process terminates (setup() is synchronous; this is a one-shot).
    tauri::async_runtime::block_on(async {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                    log_node("init", &line);
                }
                CommandEvent::Terminated(_) => break,
                _ => {}
            }
        }
    });
    Ok(())
}

/// Spawn `envoir-node run` as the managed daemon, draining stdout/stderr to the log on a task.
fn spawn_node_run(
    app: &tauri::AppHandle,
    env: &HashMap<String, String>,
) -> Result<CommandChild, Box<dyn std::error::Error>> {
    let cmd = app.shell().sidecar(SIDECAR)?.args(["run"]).envs(env.clone());
    let (mut rx, child) = cmd.spawn()?;
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => log_node("run", &line),
                CommandEvent::Terminated(payload) => {
                    eprintln!("[envoir-node/run] terminated: {payload:?}");
                    break;
                }
                _ => {}
            }
        }
    });
    Ok(child)
}

/// Log one line of node output (bytes → lossy UTF-8).
fn log_node(phase: &str, line: &[u8]) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end();
    if !text.is_empty() {
        eprintln!("[envoir-node/{phase}] {text}");
    }
}

/// Load a persisted secret from `path`, or generate a fresh 32-byte CSPRNG secret (base64url,
/// unpadded), persist it (0600 on unix), and return it. Reused across restarts so the client's
/// injected credentials stay stable.
fn load_or_create_secret(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let secret = random_secret();
    std::fs::write(path, &secret)?;
    restrict_permissions(path);
    Ok(secret)
}

/// 32 random bytes from the OS CSPRNG, base64url-encoded without padding (URL/JS/Basic-auth safe).
fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    base64url_nopad(&bytes)
}

/// Minimal unpadded base64url encoder (RFC 4648 §5) — avoids pulling in a base64 crate for one call.
fn base64url_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Best-effort tighten of a secret file to owner-only (0600) on unix; a no-op elsewhere.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_vectors() {
        // RFC 4648 test vectors, unpadded base64url.
        assert_eq!(base64url_nopad(b""), "");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(b"foob"), "Zm9vYg");
        assert_eq!(base64url_nopad(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_nopad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn random_secret_is_urlsafe_and_long() {
        let s = random_secret();
        // 32 bytes → 43 unpadded base64url chars.
        assert_eq!(s.len(), 43);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // Two draws differ (CSPRNG, not a constant).
        assert_ne!(s, random_secret());
    }

    #[test]
    fn node_env_has_loopback_binds_and_app_password() {
        let env = node_env(Path::new("/tmp/nd"), "sekret", "admintok");
        assert_eq!(env["ENVOIR_JMAP"], "1");
        assert_eq!(env["ENVOIR_JMAP_BIND"], "127.0.0.1:4700");
        assert_eq!(env["ENVOIR_JMAP_APP_PASSWORDS"], "envoir:sekret");
        assert_eq!(env["ENVOIR_DATA_DIR"], "/tmp/nd");
        assert_eq!(env["ENVOIR_SEND_API"], "1");
        assert_eq!(env["ENVOIR_SEND_ADMIN_TOKEN"], "admintok");
        // Every bind is loopback — nothing exposed off the machine.
        assert!(env["ENVOIR_NODE_BIND"].starts_with("127.0.0.1"));
        assert!(env["ENVOIR_SEND_API_BIND"].starts_with("127.0.0.1"));
    }
}
