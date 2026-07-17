# Gateway — intended for its own repo (`envoir-gateway`)

**Status: lives in the `envoir` monorepo for now, by design — but it is intended to be split
out into its own repository (`envoir-gateway`) once it earns it.** This note records that intent
and the discipline that keeps the future split a clean lift rather than an untangling.

## Why the gateway is the natural thing to separate

The gateway is the **legacy bridge** — the one component that touches the old world (SMTP / IMAP /
POP3 / DNS / DKIM / SPF / DMARC / spam-filtering). It is architecturally the odd one out:

- **Most exposed.** It accepts inbound SMTP from the entire public internet and performs outbound
  DNS/SMTP — by far the largest attack surface in the system (SSRF, spoofing, relay abuse). Keeping
  it in a separate repo lets its security review and release cadence be scoped independently.
- **Legacy-only dependencies.** It pulls in mail/DNS/TLS/anti-spam machinery that the native core
  (`dmtap-core`, `node`, `client`, mesh) does not need.
- **A different audience.** Its operators are mail-relay/infrastructure people, not end users or
  self-hosters — a distinct contributor and ops community.
- **Deprecatable by design.** The whole point of DMTAP is that the gateway is a *bridge you can walk
  away from* as the native mesh grows. Isolating "the bridge" from "the sovereign core" reflects that
  in the repo structure: native identity, delivery, files, chat, and verification never depend on it.

The **node** and **client** stay together (the client is the node's UI); they are the native pair.

## Why it is not split out *yet*

While `dmtap-core`'s public API is still moving fast, a monorepo's **atomic cross-component changes**
are worth more than the boundary. Splitting now would turn every core change that touches the gateway
into a cross-repo dance (edit core → bump the pin → fix the gateway). We split when the friction
flips the other way.

## Boundary discipline to maintain NOW (so the split stays a clean lift)

Keep the gateway loosely coupled so extracting it is a `git filter-repo` plus a dependency line:

- **Depend only on `dmtap-core`'s and `dmtap-mail`'s public API.** These are the gateway's only two
  sibling deps (mail = RFC 5322 parse/render + the SMTP-DATA↔MoteDraft translation); reach into no
  crate's internals. Both must be versioned/published before the split (see the runbook precondition).
- **No dependency on `node` / `dmtap-p2p`.** Mesh delivery is behind the `MeshDelivery` trait
  (`src/mesh.rs`) — the `dmtap-p2p`/node swarm is the drop-in *above* the gateway, never a build
  dependency of it (this also avoids the `dmtap-p2p → node` cycle).
- **Own wire objects via `dmtap-core`.** `GatewayAttestation` / `ProvenanceRecord` come from
  `dmtap-core`; the gateway consumes, it does not redefine.
- **Config/authz/quota/usage-tracking are self-contained** (`GatewayAuthz`, `GatewayMeter`); billing
  is an external concern (the private `envoir-cloud` layer reads the meter — never a build dep here).

If a change would make the gateway depend on `node`, on another crate's internals, or on the billing
layer, treat it as a smell and route it through `dmtap-core`'s public API or a trait seam instead.

## When to actually split it out

Move the gateway to `envoir-gateway` when **any** of these is true:

1. `dmtap-core`'s public API has stabilized (≈ post-1.0), so a git/published-crate dependency is
   low-churn.
2. A distinct gateway-operator community has formed with its own cadence.
3. The gateway's release/security cadence has clearly diverged from the native core.

## Extraction runbook (one mechanical operation)

When the trigger above fires, the split is a scripted lift — history-preserving, no untangling. The
gateway currently path-depends on **two** sibling crates: `dmtap-core` and `dmtap-mail`
(`gateway/Cargo.toml`). Both must be handled.

### Precondition (do this FIRST — it is what makes the split non-circular)

**`dmtap-core` and `dmtap-mail` must already be published or pinned as versioned crates before the
gateway leaves the monorepo.** If the gateway kept a *git* dependency on the monorepo while the
monorepo also contained the gateway, you would have a repo depending on the repo it was carved out of
— a circular, self-referential git dependency that breaks reproducible builds and history. So, in the
`envoir` monorepo, first:

1. Give `crates/dmtap-core` and `crates/dmtap-mail` a real, frozen `version` and publish them —
   either to crates.io (`cargo publish -p dmtap-core -p dmtap-mail`) or to a private registry, **or**
   tag the monorepo (`git tag dmtap-core-vX.Y.Z`) so the extracted gateway can pin a git `rev`/`tag`
   rather than a moving branch.
2. Confirm the gateway builds against those *versioned* deps in place (flip the two path deps to the
   published version locally and run `RUSTFLAGS="-D warnings" cargo test -p envoir-gateway`) **before**
   extracting. If it does not build against versioned deps, the boundary is not clean yet — fix that
   first; do not extract.

This precondition is exactly trigger (1) in "When to actually split it out": the split waits until a
git/published dependency on the core is low-churn.

### Step 1 — carve out `gateway/` with its history

Use `git filter-repo` (preferred; `git subtree split` is the fallback). From a **fresh clone** of the
monorepo (filter-repo rewrites history — never run it on your working clone):

```sh
git clone <envoir-monorepo-url> envoir-gateway && cd envoir-gateway
# Keep only the gateway subtree, rewriting it to the repo root and preserving its commit history:
git filter-repo --subdirectory-filter gateway
# (fallback without git-filter-repo:)
#   git subtree split -P gateway -b gateway-only && git checkout gateway-only
```

The result is a repo whose root is today's `gateway/` contents, with every commit that touched
`gateway/` preserved.

### Step 2 — rewrite the dependency lines

In the new repo's `Cargo.toml`, replace the two path deps with the versioned/pinned deps prepared in
the precondition:

```toml
# before (monorepo):
# dmtap-core = { path = "../crates/dmtap-core" }
# dmtap-mail = { path = "../crates/dmtap-mail" }

# after (published):
dmtap-core = "X.Y.Z"
dmtap-mail = "X.Y.Z"
# …or, if pinning to a monorepo tag instead of a registry:
# dmtap-core = { git = "https://…/envoir", tag = "dmtap-core-vX.Y.Z" }
# dmtap-mail = { git = "https://…/envoir", tag = "dmtap-core-vX.Y.Z" }
```

Then make it a standalone workspace: add a top-level `[workspace]` stanza (the extracted `Cargo.toml`
was a monorepo *member*), drop the monorepo-relative `workspace.metadata.dmtap.spec = "../dmtap/"`
note (or repoint the spec links), and regenerate the lockfile with `cargo generate-lockfile`.

### Step 3 — verify and cut over

```sh
RUSTFLAGS="-D warnings" cargo test   # all gateway tests, now against versioned deps
cargo build --release -p envoir-gateway --bin envoir-gateway
```

Then, in the monorepo, delete `gateway/` and remove `"gateway"` from the root `Cargo.toml`
`[workspace] members`. The `crates/dmtap-seam` / `envoir-cloud` billing seam is untouched — it never
build-depended on the gateway.

### What moves with it (everything under `gateway/`, nothing else)

- **Source**: all of `src/` (incl. `src/personal.rs`, `src/main.rs`, `src/authz.rs`, …) and their
  `#[cfg(test)]` unit tests.
- **Tests**: `tests/gateway.rs`, `tests/daemon.rs`, `tests/sockets.rs` (self-contained — they use only
  `envoir_gateway` + `dmtap-core`/`dmtap-mail` public API and in-process loopback servers, no monorepo
  siblings, so they move verbatim).
- **Ops & docs**: `README.md`, `SEPARATION.md`, `Dockerfile`, `docker-compose.yml`, `setup.sh`, and
  `examples/` (`personal.toml`, `recipients.directory`). Update the `Dockerfile`/`docker-compose.yml`
  build **context** from `..` (repo root, needed only for the path deps) back to `.` once the deps are
  versioned, and repoint the `../dmtap/…` spec links to the spec repo's URL.

Because the boundary discipline below has been maintained, steps 1–3 are the whole job: no code edits
beyond the dependency lines and the standalone-workspace boilerplate.

## Target long-term repository shape

```
dmtap           the protocol specification
envoir          native core: dmtap-core + crates + node + client + mesh + mail-engine
envoir-gateway  the legacy bridge (this component, once split out)
envoir-cloud    private, thin billing layer
```
