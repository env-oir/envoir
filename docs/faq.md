# FAQ

**Is this ready to use for real mail?**
No. This is a pre-alpha reference implementation — a demonstrable, honestly-labeled preview of the
protocol, not a production mail service. See [security.md](security.md#the-audit-gate) for the
audit gate that has to happen first.

**Is there a token or cryptocurrency?**
No. There is no cryptocurrency and no blockchain anywhere in this project. The *only* place DMTAP
admits anything chain-like is an optional, off-by-default self-sovereign naming backend for
un-loseable addresses — nothing else depends on it, and most deployments will just use ordinary
DNS. Anti-abuse for cold contact (stopping spam without a central filter, without deanonymizing
the sender) uses three separate things, none of which are a coin: anonymous **Privacy-Pass-style
rate-limit tokens** (ARC), a memory-hard **proof-of-work** fallback, and an optional **real-money
postage** stamp (a signed, prepaid credit voucher, not a cryptocurrency) that can also fund
gateway operators. See spec §9 and [protocol.md](protocol.md#anti-abuse-honestly).

**Why a key instead of a password?**
Because a password is bound to a provider's account system, and a key is yours. The account model
ties your identity to whoever runs the server; the key model means the server is just a courier.
See [features/identity.md](features/identity.md).

**What happens to my mail if my provider disappears?**
Your `name@domain` address stops resolving, but your **key** — the actual identity — is
unaffected. You publish a signed move record binding the same key to a new name, and existing
contacts (who route by key, not by name) follow you automatically. See spec §1.6 and
[features/identity.md](features/identity.md).

**Can I still talk to people on Gmail/Outlook?**
Yes, via the optional legacy gateway, which bridges DMTAP to ordinary SMTP. Mail through the
gateway is unavoidably plaintext on that leg (that's inherent to SMTP, not an Envoir shortcoming),
and the client marks it as **legacy-origin** so you always know which messages were end-to-end the
whole way. See [features/mail.md](features/mail.md) and
[features/transport-traceability.md](features/transport-traceability.md).

**Can I self-host?**
Yes, and it's not a crippled tier — self-hosting has every protocol feature, client, and privacy
guarantee a hosted operator would offer. The only thing you lose is convenience (someone else runs
the box and warms the IPs for legacy mail). See [features/self-hosting.md](features/self-hosting.md).

**Is my mail "anonymous"?**
Content and authenticity, yes, against essentially any adversary. Metadata (who talks to whom,
when) is strongly protected against a *global passive* observer, and meaningfully — but not
perfectly — hardened against a *global active* one. Read [privacy.md](privacy.md) for the honest,
quantified version of this answer; don't trust a shorter one, including this one.

**Is this audited?**
Not yet. Six machine-checked ProVerif models cover the deniable-1:1 handshake, DMTAP-Auth
sign-in, MLS group keys, key-transparency append-only logs, and mixnet unlinkability; every wire
decoder is fuzzed; a 104-case conformance suite exists (68 executing and passing today); and
`cargo test --workspace` runs 585 passing tests — but none of that substitutes for the independent
external audit the project treats as a hard gate before any production deployment. See
[security.md](security.md).

**What license is this under?**
MIT (see [`LICENSE-MIT`](../LICENSE-MIT)). Apache-2.0 dual-licensing (for its explicit patent
grant) is under consideration; the project ships as MIT today. See
[contributing.md](contributing.md).

**How is this different from Signal / Matrix / email?**
It's closer to "what if email's addressing model and Signal's cryptography had a P2P mixnet and
no central server" — one keypair for mail, chat, calendar, contacts, and files, with a
legacy-email bridge for day-one usefulness and a decentralized login (DMTAP-Auth) built on the
same key. See [architecture.md](architecture.md) and [protocol.md](protocol.md).

**What's real in the web client right now, versus simulated?**
Identity keygen/signing, safety-number derivation, and MOTE signing are real browser
cryptography. Network delivery (the mesh and mixnet) is an in-memory, clearly-labeled simulation —
a production client compiles the Rust protocol core to WASM and speaks to a real node over libp2p
instead. See the client's own real-vs-simulated table in [`client/README.md`](../client/README.md)
and [roadmap.md](roadmap.md).
