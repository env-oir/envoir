#!/usr/bin/env bash
# envoir-gateway — minimal personal (single-operator) bring-up.
#
#   ./setup.sh <your-domain> [--listen ADDR] [--selector NAME] [--dir PATH] [--run]
#
# What it does (idempotent — never overwrites an existing file):
#   1. writes  <dir>/personal.toml         from examples/personal.toml with your domain filled in
#   2. writes  <dir>/recipients.directory  from examples/recipients.directory (add your keys)
#   3. generates a DKIM ed25519 keypair    into <dir>/dkim/<selector>.key.pem  (needs openssl)
#   4. prints the exact DNS records to publish for your domain
#   5. with --run, launches the daemon (cargo run -p envoir-gateway -- personal <dir>/personal.toml)
#
# This is a REFERENCE bring-up. Read README.md for the honest caveats (public IP, port 25, DKIM
# private-key wiring, attestation-key persistence).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN=""
LISTEN="0.0.0.0:25"
SELECTOR="gw1"
OUT_DIR="."
RUN=0

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

[ $# -ge 1 ] || usage 2
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --listen)   LISTEN="$2"; shift 2 ;;
    --selector) SELECTOR="$2"; shift 2 ;;
    --dir)      OUT_DIR="$2"; shift 2 ;;
    --run)      RUN=1; shift ;;
    -*)         echo "setup: unknown flag $1" >&2; usage 2 ;;
    *)          if [ -z "$DOMAIN" ]; then DOMAIN="$1"; shift; else echo "setup: unexpected arg $1" >&2; usage 2; fi ;;
  esac
done
[ -n "$DOMAIN" ] || { echo "setup: <your-domain> is required" >&2; usage 2; }

mkdir -p "$OUT_DIR" "$OUT_DIR/dkim"
CONFIG="$OUT_DIR/personal.toml"
DIRECTORY="$OUT_DIR/recipients.directory"
DKIM_KEY="$OUT_DIR/dkim/$SELECTOR.key.pem"

# ── 1. config ────────────────────────────────────────────────────────────────────────────
if [ -f "$CONFIG" ]; then
  echo "setup: $CONFIG exists — leaving it untouched"
else
  sed -e "s|^domain = .*|domain = \"$DOMAIN\"|" \
      -e "s|^listen = .*|listen = \"$LISTEN\"|" \
      -e "s|^selector = .*|selector = \"$SELECTOR\"|" \
      -e "s|^directory = .*|directory = \"$DIRECTORY\"|" \
      "$SCRIPT_DIR/examples/personal.toml" > "$CONFIG"
  echo "setup: wrote $CONFIG (domain=$DOMAIN listen=$LISTEN selector=$SELECTOR)"
fi

# ── 2. recipient directory ───────────────────────────────────────────────────────────────
if [ -f "$DIRECTORY" ]; then
  echo "setup: $DIRECTORY exists — leaving it untouched"
else
  cp "$SCRIPT_DIR/examples/recipients.directory" "$DIRECTORY"
  echo "setup: wrote $DIRECTORY — ADD YOUR OWN identity line(s) (email + ik-b64 + seal-b64 from your node)"
fi

# ── 3. DKIM keypair ──────────────────────────────────────────────────────────────────────
DKIM_PUB_B64=""
if command -v openssl >/dev/null 2>&1; then
  if [ -f "$DKIM_KEY" ]; then
    echo "setup: $DKIM_KEY exists — reusing it"
  else
    openssl genpkey -algorithm ed25519 -out "$DKIM_KEY" 2>/dev/null
    chmod 600 "$DKIM_KEY"
    echo "setup: generated DKIM ed25519 private key at $DKIM_KEY (keep it secret)"
  fi
  # RFC 8463: the DKIM TXT publishes the raw 32-byte ed25519 public key, base64. The DER
  # SubjectPublicKeyInfo is 44 bytes; the last 32 are the raw key.
  DKIM_PUB_B64="$(openssl pkey -in "$DKIM_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')"
else
  echo "setup: openssl not found — skipping DKIM key generation (install openssl and re-run)"
fi

# ── 4. DNS records to publish ────────────────────────────────────────────────────────────
MX_HOST="mx.$DOMAIN"
cat <<EOF

────────────────────────────────────────────────────────────────────────────────
DNS records to publish for $DOMAIN
(the gateway does NOT publish these for you — add them at your DNS provider)
────────────────────────────────────────────────────────────────────────────────

# MX — route legacy inbound mail to this gateway (point $MX_HOST at THIS host's public IP)
$DOMAIN.                 IN  MX    10 $MX_HOST.
$MX_HOST.                IN  A     <this-gateway-public-IPv4>
# $MX_HOST.              IN  AAAA  <this-gateway-public-IPv6>   ; if you have one

# SPF — authorize this gateway's IP to send as $DOMAIN
$DOMAIN.                 IN  TXT   "v=spf1 a:$MX_HOST -all"

# DKIM — the selector "$SELECTOR" public key the gateway signs outbound with (RFC 8463 ed25519)
${SELECTOR}._domainkey.$DOMAIN.  IN  TXT  "v=DKIM1; k=ed25519; p=${DKIM_PUB_B64:-<run-with-openssl-to-fill>}"

# DMARC — start at p=none (monitor), tighten to quarantine/reject once aligned
_dmarc.$DOMAIN.          IN  TXT   "v=DMARC1; p=none; rua=mailto:postmaster@$DOMAIN"

# DMTAP _dmtap (spec §3.2) — the name→key pointer for EACH of your addresses. The ik/id/kt/
# keypkgs values are produced by YOUR envoir node (this gateway does not mint identities):
<base-local>._dmtap.$DOMAIN.  IN  TXT  "v=dmtap1; suite=1; ik=<base64url-IK>; id=<Identity-hash>; kt=<KT-log-URL>; keypkgs=<KeyPackage-locator>"
# _dmtap.$DOMAIN.        IN  SVCB  1 . ( ... )   ; optional service params / KT anchors

────────────────────────────────────────────────────────────────────────────────
Honest caveats (see README.md):
  * Inbound legacy mail needs a real public IPv4 and inbound TCP port 25 reachable.
    Many home/residential ISPs block inbound 25 — you need a VPS or a business line.
  * A brand-new sending IP has no reputation; warm it up before enforcing.
  * The DKIM private key above is generated for the DNS record; wiring it into the
    node-driven OUTBOUND signing leg is documented in the roadmap, not auto-wired here.
────────────────────────────────────────────────────────────────────────────────
EOF

# ── 5. run ───────────────────────────────────────────────────────────────────────────────
if [ "$RUN" -eq 1 ]; then
  echo "setup: launching the personal gateway (Ctrl-C to stop)…"
  exec cargo run --release -p envoir-gateway -- personal "$CONFIG"
else
  echo "setup: ready. Start it with:"
  echo "    cargo run -p envoir-gateway -- personal $CONFIG"
  echo "  or, after \`cargo build --release -p envoir-gateway\`:"
  echo "    ./target/release/envoir-gateway personal $CONFIG"
fi
