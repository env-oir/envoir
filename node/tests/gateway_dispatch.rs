//! Proves the `envoir-node gateway` / `--gateway` privilege-separation seam actually launches the
//! dedicated `envoir-gateway` binary in a separate process, rather than merging gateway logic
//! into the identity-holding node process. See `node/src/main.rs`'s `run_gateway_mode` for the
//! mechanism and its `TODO(privsep)`.

use std::path::PathBuf;
use std::process::Command;

/// The `envoir-gateway` binary cargo builds alongside `envoir-node` in the same target directory
/// (both are workspace members with their own `[[bin]]`; `cargo build --workspace` — required
/// before `cargo test --workspace` can pass — produces both before either binary's tests run).
fn gateway_bin() -> PathBuf {
    let node_bin = PathBuf::from(env!("CARGO_BIN_EXE_envoir-node"));
    let name = if cfg!(windows) { "envoir-gateway.exe" } else { "envoir-gateway" };
    node_bin.with_file_name(name)
}

#[test]
fn gateway_subcommand_execs_the_dedicated_gateway_binary() {
    let gw = gateway_bin();
    assert!(
        gw.exists(),
        "expected envoir-gateway to be built alongside envoir-node at {} \
         (run `cargo build --workspace` first)",
        gw.display()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("version")
        .output()
        .expect("failed to run envoir-node gateway version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // envoir-gateway's own `version` command prints its own binary name + version — proving the
    // dispatch actually reached the gateway binary's own CLI, not a node-side stub.
    assert!(
        output.status.success() && stdout.contains("envoir-gateway"),
        "expected the gateway binary's own version output, got status {:?} stdout: {stdout:?} \
         stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dash_dash_gateway_flag_is_accepted_as_an_alias() {
    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("--gateway")
        .arg("version")
        .output()
        .expect("failed to run envoir-node --gateway version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success() && stdout.contains("envoir-gateway"), "got: {stdout:?}");
}

#[test]
fn gateway_dispatch_forwards_arguments_unchanged() {
    // `personal` with no config path argument is the gateway's own usage-error path — proving
    // argv[2..] reaches the gateway binary's own argument parser intact.
    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("personal")
        .output()
        .expect("failed to run envoir-node gateway personal");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("envoir-gateway personal <config.toml>"),
        "expected the gateway's own usage message, got stderr: {stderr:?}"
    );
}

#[test]
fn missing_gateway_binary_fails_closed_with_a_clear_error_and_nonzero_exit() {
    // ENVOIR_GATEWAY_BIN pointed at a path that does not exist must fail loudly and refuse to
    // fall through to any node-side behavior — never a silent no-op, never node identity code.
    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("version")
        .env("ENVOIR_GATEWAY_BIN", "/nonexistent/path/envoir-gateway-does-not-exist")
        .output()
        .expect("failed to run envoir-node gateway version");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gateway") && stderr.contains("ENVOIR_GATEWAY_BIN"),
        "expected a clear --gateway/ENVOIR_GATEWAY_BIN error, got stderr: {stderr:?}"
    );
}

#[test]
fn envoir_gateway_bin_override_is_honored() {
    let real_gateway = gateway_bin();
    assert!(real_gateway.exists(), "envoir-gateway must be built for this test — run `cargo build --workspace`");

    let output = Command::new(env!("CARGO_BIN_EXE_envoir-node"))
        .arg("gateway")
        .arg("version")
        .env("ENVOIR_GATEWAY_BIN", &real_gateway)
        .output()
        .expect("failed to run envoir-node gateway version with an explicit override");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success() && stdout.contains("envoir-gateway"), "got: {stdout:?}");
}
