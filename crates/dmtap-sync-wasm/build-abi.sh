#!/usr/bin/env bash
# Reproducible build of the RAW-ABI artifact — the module the Go binding embeds and runs under
# wazero. The sibling `build.sh` builds the wasm-bindgen artifact for the browser; this one builds
# the other surface of the same crate.
#
#   ./crates/dmtap-sync-wasm/build-abi.sh
#
# Output is written straight into the Go module, because that is the only consumer:
#
#   bindings/go/dmtap_sync_abi.wasm
#
# Requires: rustup target add wasm32-unknown-unknown. `wasm-opt` (from binaryen) is optional but
# roughly halves the artifact — the script uses wasm-pack's cached copy if one is present.
set -euo pipefail

cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
out="$root/bindings/go/dmtap_sync_abi.wasm"

# --- Size profile ------------------------------------------------------------------------------
# Same reasoning as build.sh: these shape the wasm artifact WITHOUT touching how the node/gateway
# binaries compile. opt-level=z is the dominant win on the BTreeMap/CRDT generics; lto=fat plus a
# single codegen unit strips the rest of the cross-crate dead code.
export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-z}"
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-fat}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"

# `getrandom` 0.3/0.4 select a custom backend through this cfg rather than a Cargo feature. It
# points them at `src/entropy.rs`, which FAILS rather than fabricating bytes — see that file for
# why that is the safe direction. 0.2 gets there through the `abi` feature instead.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg getrandom_backend=\"custom\""

echo "==> cargo build --no-default-features --features abi --target wasm32-unknown-unknown"
cargo build \
  --manifest-path Cargo.toml \
  --no-default-features --features abi \
  --release --target wasm32-unknown-unknown

built="$root/target/wasm32-unknown-unknown/release/dmtap_sync_wasm.wasm"

# --- wasm-opt (optional) -----------------------------------------------------------------------
# Roughly halves the module. wasm-pack applies the equivalent to the browser artifact, so without
# this step the two surfaces' sizes are not comparable and the Go artifact looks far worse than it
# is. Skipped, with a warning, when no binaryen is available — the unoptimized module is correct,
# just larger.
wasm_opt=""
if command -v wasm-opt >/dev/null 2>&1; then
  wasm_opt=$(command -v wasm-opt)
else
  cached=$(find "$HOME/Library/Caches/.wasm-pack" "$HOME/.cache/.wasm-pack" \
    -name wasm-opt -type f 2>/dev/null | head -n1 || true)
  [ -n "$cached" ] && wasm_opt="$cached"
fi

if [ -n "$wasm_opt" ]; then
  echo "==> $wasm_opt -Oz --strip-debug --strip-producers"
  "$wasm_opt" -Oz --strip-debug --strip-producers "$built" -o "$out"
else
  echo "WARNING: wasm-opt not found — embedding the unoptimized module (roughly 1.9x larger)." >&2
  cp "$built" "$out"
fi

size=$(wc -c <"$out" | tr -d ' ')
gz=$(gzip -9 -c "$out" | wc -c | tr -d ' ')
printf '    %s: %s bytes raw, %s bytes gzipped\n' "${out#"$root"/}" "$size" "$gz"

cat <<'EOF'

Next: run the three-surface conformance proof.

  cargo test -p dmtap-sync-wasm --test native_trace     # native Rust, records the trace
  node --test 'crates/dmtap-sync-wasm/test/*.test.mjs'  # the JS/WASM surface, diffed against it
  (cd bindings/go && go test ./...)                     # the Go surface, diffed against it too
EOF
