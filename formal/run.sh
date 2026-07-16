#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run the DMTAP formal (symbolic) models under ProVerif.
#
# Resolution order:
#   1. `proverif` on PATH                       -> run natively.
#   2. local Docker image `proverif-local:2.05` -> run in it (fast; no install).
#   3. any other Docker                         -> throwaway ocaml/opam that
#                                                  installs ProVerif via opam.
#
# Usage:   ./run.sh            # run all models
#          ./run.sh <file.pv>  # run one model
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

MODELS=(
  "deniable_1to1.pv"
  "deniable_1to1_deniability.pv"
  "dmtap_auth.pv"
  "mls_group_keys.pv"
  "kt_append_only.pv"
  "mixnet_unlinkability.pv"
)
if [ "$#" -ge 1 ]; then MODELS=("$@"); fi

PVIMG="proverif-local:2.05"

run_native() {
  for m in "${MODELS[@]}"; do
    echo "======================================================================"
    echo "== proverif $m"
    echo "======================================================================"
    proverif "$m" || true
  done
}

run_docker_image() {
  echo "ProVerif not on PATH -- running via Docker image $PVIMG."
  for m in "${MODELS[@]}"; do
    echo "======================================================================"
    echo "== proverif $m"
    echo "======================================================================"
    docker run --rm -v "$PWD":/work -w /work "$PVIMG" proverif "$m" || true
  done
}

run_docker_opam() {
  echo "ProVerif not on PATH and $PVIMG absent -- falling back to ocaml/opam."
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
  if docker image inspect "$PVIMG" >/dev/null 2>&1; then
    run_docker_image
  else
    run_docker_opam
  fi
else
  echo "Neither proverif nor docker is available. Install ProVerif:"
  echo "  opam install proverif    (https://proverif.inria.fr/)"
  exit 1
fi
