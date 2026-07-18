# Envoir desktop

A Tauri v2 shell that bundles the Envoir static client (`../client`, served straight into the
webview — no build step) and runs the **real `envoir-node`** as a managed sidecar, so the whole
node lives on the user's machine. On launch it mints an identity keystore + app-password on first
run, starts the node with loopback binds (JMAP `:4700`, mesh `:4600`, Send API `:4610`), and
injects `window.__ENVOIR_NODE__` so the client auto-connects in REAL mode — no configuration.
See `src-tauri/src/lib.rs` for the full lifecycle.

This directory is its **own** cargo workspace, deliberately not a monorepo member: the heavy
Tauri/webview graph stays out of the monorepo build and `cargo test --workspace`.

## Build & run

```sh
# 1. Build the node from the monorepo and stage it as the sidecar
#    (binaries/envoir-node-<host-triple>, the Tauri externalBin convention):
./scripts/prepare-sidecar.sh

# 2. Dev-run or bundle (needs the tauri-cli, `cargo install tauri-cli`):
cd src-tauri
cargo tauri dev
cargo tauri build
```

The node's JMAP listener stays loopback-bound and app-password gated; the small CORS allowance on
it (`node/src/jmap_api.rs`) only lets the `tauri://` webview origin talk to loopback — the
app-password, not CORS, is the security boundary.
