#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run the DMTAP formal (symbolic) models under ProVerif.
#
# If ProVerif is on PATH, uses it directly. Otherwise falls back to a
# throwaway Docker container (ocaml/opam) that installs ProVerif via opam.
#
# Usage:   ./run.sh            # run all models
#          ./run.sh <file.pv>  # run one model
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

MODELS=("deniable_1to1.pv" "deniable_1to1_deniability.pv" "dmtap_auth.pv")
if [ "$#" -ge 1 ]; then MODELS=("$@"); fi

run_native() {
  for m in "${MODELS[@]}"; do
    echo "======================================================================"
    echo "== proverif $m"
    echo "======================================================================"
    proverif "$m" || true
  done
}

run_docker() {
  echo "ProVerif not found on PATH -- running via Docker (ocaml/opam)."
  docker run --rm -v "$PWD":/work ocaml/opam:debian-12-ocaml-4.14 bash -c '
    set -e
    opam install -y proverif >/dev/null 2>&1
    eval $(opam env)
    cd /work
    for m in '"${MODELS[*]}"'; do
      echo "===================================================================="
      echo "== proverif $m"
      echo "===================================================================="
      proverif "$m" || true
    done
  '
}

if command -v proverif >/dev/null 2>&1; then
  run_native
elif command -v docker >/dev/null 2>&1; then
  run_docker
else
  echo "Neither proverif nor docker is available. Install ProVerif:"
  echo "  opam install proverif    (https://proverif.inria.fr/)"
  exit 1
fi
