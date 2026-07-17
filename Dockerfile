# envoir-gateway — personal DMTAP <-> legacy SMTP bridge.
#
# NOTE ON BUILD CONTEXT: while the gateway lives in the envoir monorepo it depends on the
# sibling crates dmtap-core / dmtap-mail by PATH, so the Docker build context must be the
# REPO ROOT, not gateway/:
#
#     docker build -f gateway/Dockerfile -t envoir-gateway .
#
# (docker-compose.yml already sets `context: ..` so `docker compose up` does this for you.)
# Once the gateway is split into its own `envoir-gateway` repo (see SEPARATION.md), the path
# deps become a versioned crates.io / git dependency and the context collapses back to `.`.

# ---- builder ----------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder
WORKDIR /src
# Copy the whole workspace (path deps + Cargo.lock for a reproducible build).
COPY . .
RUN cargo build --release -p envoir-gateway --bin envoir-gateway

# ---- runtime ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# ca-certificates: for outbound SMTP-over-STARTTLS trust anchors (webpki uses the system roots).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. NOTE: binding port 25 as non-root needs either a published
# host port mapping (compose maps 25->2525) or `CAP_NET_BIND_SERVICE`. See README.
RUN useradd --system --home /gateway --shell /usr/sbin/nologin gateway
WORKDIR /gateway

COPY --from=builder /src/target/release/envoir-gateway /usr/local/bin/envoir-gateway
# Config + directory are mounted at runtime (see docker-compose.yml). /gateway/config is the
# expected mount point for personal.toml and recipients.directory.
USER gateway

# The daemon is stateless; it holds no queue and no mailbox — restart it freely.
ENTRYPOINT ["envoir-gateway"]
CMD ["personal", "/gateway/config/personal.toml"]
