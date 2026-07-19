#!/usr/bin/env bash
# Reproducible build of the WASM binding.
#
#   ./crates/dmtap-sync-wasm/build.sh          # both targets
#   ./crates/dmtap-sync-wasm/build.sh nodejs   # just the one the test suite loads
#
# Emits two packages from ONE compiled core:
#   pkg-node/    --target nodejs   — CommonJS, synchronous init; what `test/vectors.test.mjs` loads
#   pkg/         --target bundler  — ESM + `.d.ts`; the npm-consumable artifact for a web product
#
# Requires: rustup target add wasm32-unknown-unknown, and wasm-pack (https://rustwasm.github.io).
# wasm-pack fetches a `wasm-bindgen` CLI matching the version in Cargo.lock, so the JS glue and the
# compiled module can never drift apart.
set -euo pipefail

cd "$(dirname "$0")"

# --- Size profile (WASM-ONLY) -------------------------------------------------------------------
# Exported here rather than written into the workspace `[profile.release]` on purpose: these settings
# must shape the browser artifact WITHOUT touching how the node/gateway binaries are compiled.
#
#   opt-level=z     the whole win. `release` defaults to opt-level=3, which inlines and unrolls the
#                   BTreeMap/CRDT generics that dominate this module; `z` gives up that speed for a
#                   ~34% smaller download. Measured 600_776 -> 399_763 raw on its own.
#   lto=fat + cu=1  cross-crate dead-code elimination and no per-CGU duplication. Worth ~8 KB HERE
#                   (399_763 -> 391_657); on its own, without opt-level=z, worth ~nothing (600_005) —
#                   the reachable set is already minimal, so there is little left to strip.
#
# NOT set: panic=abort. wasm32-unknown-unknown already aborts on panic, so it changes no bytes
# (measured 391_899 WITH it vs 391_657 without) and would only add a divergence from native builds.
#
# Override any of these from the environment if you are bisecting a size or codegen question.
export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-z}"
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-fat}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"

targets=("${@:-nodejs bundler}")
# shellcheck disable=SC2206
targets=(${targets[*]})

for target in "${targets[@]}"; do
  case "$target" in
    nodejs) out=pkg-node ;;
    bundler) out=pkg ;;
    web) out=pkg-web ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
  esac
  echo "==> wasm-pack build --target $target --out-dir $out"
  wasm-pack build --release --target "$target" --out-dir "$out" --out-name dmtap_sync
  size=$(wc -c <"$out/dmtap_sync_bg.wasm" | tr -d ' ')
  gz=$(gzip -9 -c "$out/dmtap_sync_bg.wasm" | wc -c | tr -d ' ')
  printf '    %s: %s bytes raw, %s bytes gzipped\n' "$out/dmtap_sync_bg.wasm" "$size" "$gz"
done

cat <<'EOF'

Next: run the cross-surface conformance proof.

  cargo test -p dmtap-sync-wasm --test native_trace     # the native half
  node --test 'crates/dmtap-sync-wasm/test/*.test.mjs'  # the WASM half + the byte-for-byte diff
EOF
