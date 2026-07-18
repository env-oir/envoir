#!/bin/sh
# Build the real envoir-node from the monorepo and stage it as the Tauri sidecar.
#
# Tauri's externalBin convention wants `binaries/envoir-node-<target-triple>`; tauri-build then
# copies it next to the app executable with the triple stripped, and lib.rs resolves it by the
# base name "envoir-node". Run this before `cargo tauri dev` / `cargo tauri build`.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
triple=$(rustc --print host-tuple 2>/dev/null || rustc -vV | sed -n 's/^host: //p')

cargo build --release -p envoir-node --manifest-path "$repo_root/Cargo.toml"
mkdir -p "$repo_root/desktop/src-tauri/binaries"
cp "$repo_root/target/release/envoir-node" "$repo_root/desktop/src-tauri/binaries/envoir-node-$triple"
echo "staged desktop/src-tauri/binaries/envoir-node-$triple"
