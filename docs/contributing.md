# Contributing

## The spec is authoritative

Independent implementations must be buildable from the DMTAP specification alone — the Rust
reference in this repository (`node/`, `gateway/`, `crates/*`) is a proof and a set of libraries,
**not** normative. Where the reference and the spec disagree, the spec governs, and the
discrepancy is a bug. The spec lives in the sibling
**[env-oir/dmtap](https://github.com/vul-os/dmtap)** repository; changes to protocol behavior
should generally start there, not in this repo's code.

## Before you start

- Read [architecture.md](architecture.md) and [protocol.md](protocol.md) for how the pieces fit
  together.
- Read [roadmap.md](roadmap.md) for what's implemented vs. stubbed today, so you don't duplicate
  work already tracked as deferred.
- Check the relevant crate's own doc comments and tests — most subsystems (`dmtap-mail`,
  `dmtap-deniable`, `dmtap-mls`, `envoir-gateway`) carry a detailed capability/status table in
  their module docs or README.

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
```

Some subsystems have their own extra checks:

```sh
cd formal && ./run.sh                                    # ProVerif symbolic models
cd fuzz   && cargo +nightly fuzz run envelope -- -max_total_time=5
cargo test -p dmtap-core                                  # conformance vectors + drift guard
```

See [getting-started.md](getting-started.md) for the full command reference.

## What a good change looks like

- **Grounded, not invented.** Every claim in this documentation set, and every behavior in the
  code, should trace back to a spec clause, a real test, or an explicit, disclosed limitation.
  Don't add capability claims (e.g. "audited," "post-quantum," "anonymous") that the spec or the
  implementation doesn't actually back up — this project's whole credibility rests on not
  overclaiming. See [privacy.md](privacy.md) and [security.md](security.md) for the tone to match.
- **Honest about what's stubbed.** If you're implementing a piece of a larger subsystem, say so
  in the module doc and in the relevant README, the way `node/README.md` and `gateway/README.md`
  already do — a `todo!()` with a spec-section pointer is more useful than a silently-incomplete
  happy path.
- **Fail closed, not open, on anything security-relevant.** DMTAP's whole downgrade-resistance
  model (spec §10.7) is "refuse or ask the user, never silently degrade" — new code should follow
  that pattern, and if you're touching anything covered by the
  [downgrade-tests](../crates/downgrade-tests) suite, add a case there.

## Security issues

Do **not** open a public issue for an unfixed vulnerability. Report it to `security@envoir.org`
(PGP key in the spec repo's `SECURITY.md`) or via the repository's private security-advisory
facility. See [security.md](security.md#reporting-a-vulnerability) for the disclosure process and
safe-harbour terms.

## License

Everything here — protocol, node, gateway, client, libraries — ships under the **MIT license**
([`LICENSE-MIT`](../LICENSE-MIT)). Apache-2.0 dual-licensing (for its explicit patent grant,
relevant to the anti-abuse token/postage mechanisms) is under consideration but not yet adopted;
contributions are accepted under MIT as it stands today.

## Governance

Standards-track intent is to pursue an IETF Internet-Draft for the DMTAP wire protocol, the way
JMAP and MLS did — neutral governance is what lets competing implementations adopt the protocol
without fearing capture by any one project, Envoir included. See the spec repo's `GOVERNANCE.md`
for who decides what.
