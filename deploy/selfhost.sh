#!/usr/bin/env bash
# Envoir self-host — one-command bring-up wrapper around docker compose.
#
# What this does (nothing more): pick a docker compose invocation, make sure deploy/.env exists
# (copying deploy/.env.example on first run), build the two images from the real workspace, and
# start the stack in the background. It does not touch anything outside deploy/.
#
# Usage:
#   deploy/selfhost.sh up       # build + start (default)
#   deploy/selfhost.sh down     # stop + remove containers (keeps the node-data volume)
#   deploy/selfhost.sh logs     # follow logs from both services
#   deploy/selfhost.sh ps       # show status
#
# Read deploy/README.md first — several pieces of this stack are honestly-labelled demo/seam
# behavior (pre-alpha), not hardened self-host infrastructure.

set -euo pipefail

# Resolve paths relative to this script, not the caller's cwd.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed / not on PATH. See deploy/README.md prerequisites." >&2
    exit 1
fi

# Prefer the `docker compose` plugin (v2); fall back to the standalone `docker-compose` (v1).
if docker compose version >/dev/null 2>&1; then
    compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
    compose() { docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
else
    echo "error: neither 'docker compose' (plugin) nor 'docker-compose' (standalone) is available." >&2
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    echo "wrote $ENV_FILE from .env.example (defaults: gateway on localhost/2525, no TLS) — edit it, then re-run." >&2
fi

mkdir -p "$SCRIPT_DIR/certs"

cmd="${1:-up}"
case "$cmd" in
    up)
        compose build
        compose up -d
        echo
        echo "Started. Gateway inbound MX listening on \${GATEWAY_PORT:-2525} (host)."
        echo "Node's serve-mail demo is running but its ports are NOT reliably reachable via"
        echo "docker-compose port publishing — see deploy/README.md 'Testing the node demo servers'."
        echo
        echo "  $0 logs   # follow logs"
        echo "  $0 ps     # status"
        echo "  $0 down   # stop"
        ;;
    down)
        compose down
        ;;
    logs)
        compose logs -f
        ;;
    ps)
        compose ps
        ;;
    *)
        echo "usage: $0 {up|down|logs|ps}" >&2
        exit 1
        ;;
esac
