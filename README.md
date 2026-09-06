# Trahens

Trahens is a research protocol for privacy-oriented route discovery in
decentralized and path-aware networks. The repository develops a bounded,
executable control-plane core before attempting a complete routing architecture.

The description to prefer over shorter summaries is:

> **Trahens is a privacy-oriented rendezvous route-discovery and control-plane
> protocol, not a complete anonymous communication network.**

It is not a replacement for Tor, I2P, or a mixnet. Those systems assume an IP
substrate and a relay-discovery model and make anonymity claims Trahens does not
make. Trahens contributes bounded route discovery, hop-local state,
capability-based rendezvous, and explicit evidence boundaries.

## Status

The active specification is **Trahens Core v1.8**, registry **1.8.0**.
**v1.7, v1.6 and v1.5 are history.**

v1.8 replaces the pre-shared adjacent-link key and configured epoch with an
authenticated handshake. **B1.1** is a Noise `XXpsk0` exchange over X25519
between peers that pin each other's static key, with the profile set negotiated
inside the authenticated transcript. Every process session now derives its own
directional W2 keys and its own link epoch, so a node cannot restart into an
epoch it has already used: it no longer chooses one. Rekeys are a fresh
handshake chained through the previous session's export key; an initial
handshake keys the same modifier from the static-static value the manifest
already implies, so a first message from a sender without that identity is
refused before any Diffie-Hellman. The protocol
version byte becomes `3`, so v1.7 and v1.8 do not interoperate — and a v1.7 node
cannot bring a link up at all, because it has no handshake to offer.

v1.7 rebuilt the end-to-end route channel on a directional key schedule with
counter nonces and a per-direction replay window, closing an end-to-end `DATA`
replay an intermediate relay could otherwise mount, and signed the gateway offer
over a transcript binding the protocol version, suite, reply key, and parameter
digest. v1.8 keeps both unchanged.

v1.6 separated the suite-independent routing nonce from the suite-sized
eligibility field. This added 32 bytes to `DISCOVER`, so v1.5 and v1.6 do not
interoperate either; v1.7 and v1.8 keep that encoding unchanged. The v1.7, v1.6
and v1.5 registries, vectors, corpora, and generated Markdown remain only so
those historical profiles stay reproducible; no current binary speaks them.

The active profile stack is:

- **B1.1** — authenticated adjacent-link establishment with session-derived directional keys and epoch;
- **U1** — branch-local representation replacement and conditional passive unlinkability;
- **E1** — deterministic route lifecycle, event precedence, and cleanup;
- **R1** — generic rendezvous-gateway discovery with post-READY capability redemption;
- **M2** — canonical suite-agile logical messages;
- **W2** — fixed-size authenticated adjacent-link records and canonical fragmentation;
- **T1** — hop-local selective recovery, fresh retry ciphertexts, and fragment interleaving;
- **T2** — fixed or selectable quantized-adaptive scheduling, weighted fair service, and bounded overload behavior;
- **T3** — equal-budget multi-link classification and active probing analysis;
- **T4** — packet-event emulation with clocks, jitter, bottlenecks, churn, partial observation, and selective delay.

The mandatory interoperability path is B1.1 + U1 + E1 + R1 + M2 + W2 + T1 +
fixed T2/P1. Adaptive T2 and C1 eligibility are selectable experimental profiles
with their own narrower CI gates. T3 and T4 remain analysis profiles.

## Complete-system boundaries

Core v1.8 is not a complete endpoint-anonymity system.

### Private directory

R1 removes endpoint-specific selectors from mandatory route discovery, but an
authorized initiator still needs a private descriptor. D1 is currently a
non-normative strawman. Directory enumeration, lookup correlation, publication
timing, authorization, and directory-gateway collusion remain unresolved.

### Network bootstrap

Adjacent-link authentication is now inside the profile: peers establish their
link keys through the B1.1 handshake rather than being handed them. What the
prototype still receives from configuration is the peer list itself — addresses,
node IDs, and each peer's pinned static public key. It therefore demonstrates
**route bootstrap over a named peer set**, not autonomous network bootstrap.

The non-normative [`spec/network-bootstrap-b1.md`](spec/network-bootstrap-b1.md)
records the remaining stages, B1.2 onward: peer discovery, admission,
gateway-service advertisement, and directory-root discovery.

A prober holding no manifest identity learns nothing from a responder: under
`psk0` its first message does not decrypt, so no Diffie-Hellman is performed and
no reply is sent. What the registry limits still bound is an authenticated peer
misbehaving. A deployment that must accept handshakes from peers it has no
manifest entry for has no static-static value to key from, and needs B1.2's
cookie gate instead.

### Traffic analysis

Fixed-size records and local representation replacement do not establish
global traffic-flow unlinkability. Fixed T2 supports only a narrow conditional
slot-occupancy claim during an already established, non-overloaded schedule.
Adaptive T2 exposes public cadence changes and makes no activity-presence claim.

## Active discovery model

A destination creates a short-lived one-time capability, registers its
commitment at selected rendezvous gateways, and privately distributes a
descriptor to an authorized initiator.

A v1.8 `DISCOVER` contains:

- a suite-independent 32-byte routing nonce;
- a suite-sized eligibility field.

The routing nonce binds the returned candidate chain and derives per-offer
labels. Under mandatory R1 the eligibility field is another non-semantic nonce.
Under experimental C1 v2 it is a 128-byte rerandomizable capsule.

Every relay independently replaces the branch token, routing nonce,
transmission identifier, reply-key representation, padding, sequence, and link
ciphertext, and separately transforms the eligibility field according to the
selected suite.

Gateways return authenticated nested candidates. The initiator selects one
exact chain, sends `COMMIT`, receives `READY`, and only then presents the
one-time capability. The gateway atomically consumes the capability and begins
the destination-side rendezvous. Losing fan-out subtrees receive `CANCEL`;
failed commits receive `ABORT`; all terminal paths reclaim state locally.

## Current transport result

M2 separates semantic encoding from observable framing. W2 defines canonical
fragments. T1 carries fragments in 1,052-byte encrypted DATA records, returns
same-size encrypted selective ACKs, and retransmits only missing fragments with
fresh sequences, padding, tags, and ciphertext.

T2 exposes three release modes:

- **fixed** — one public rate class, with idle slots filled by CHAFF;
- **adaptive** — one class per epoch, moving by at most one adjacent class after authenticated negotiation and hysteresis;
- **work-conserving** — real cells only, retained as an efficiency and correlation baseline.

Queue admission, schedule-control reserve, retry work, rate transitions, and
overload cleanup are finite. New fragmented transmissions share service through
weighted deficit round robin.

## Cryptographic research status

- **R1 (`0x0101`)** is the mandatory eligibility suite and carries no endpoint-specific material in `DISCOVER`.
- **C1 v2 (`0x0003`)** is selectable only on the experimental profile. It is wired end to end and lets a recipient decide eligibility after relays rerandomize the capsule. Its algebraic ratio-tag negative control remains, and it must not be cited as evidence of endpoint anonymity.
- **C1 v1 (`0x0001`)** is retired and rejected.
- **Symbolic C2 (`0x0002`)** is an ideal research functionality, not a live network suite.
- **C2 k=2 audit (`0x7f02`)** is disabled and rejected by live decoders.

The reply path uses independent first-hop reply keys, multiplicative
`ristretto255` blinding, nested ChaCha20-Poly1305 encryption, Ed25519 gateway
authentication, and an Extract-then-Expand key schedule. Full reply-layer
unlinkability remains conditional on key privacy and independent review of the
complete multi-user composition.

## v1.8 P1 implementation

The registry in `spec/protocol-registry-v1.8.json` generates Python, Rust, and
Markdown constants. Independent generators produce canonical and noncanonical
M2 vectors and the binary corpus, and the B1.1 handshake vectors are
additionally cross-checked against an independent Noise implementation.

Three Rust executables use ordinary UDP:

```text
trahens-endpoint
trahens-relay
trahens-rendezvous
```

They implement the B1.1 link handshake, fixed 1,052-byte W2 records, bounded T1
recovery, selectable T2 scheduling, typed route state, atomic R1 redemption,
experimental C1 eligibility, and zeroizing secret wrappers.

The Linux namespace harness starts each process separately, builds veth
networks, applies `tc netem`, captures every link, and checks packet size,
cleanup, loss recovery, fan-out selection, fixed scheduling, adaptive
negotiation, and C1 eligibility. A separate multi-host harness exists for
future real-network evaluation.

## Evidence boundary

A passing harness demonstrates implementation coherence, tested
interoperability, and bounded failure behavior for the tested topology and
impairments. It does not prove anonymity, key privacy, directory privacy,
autonomous bootstrap, resistance to a global observer, or production security.

The highest-value remaining work is:

1. a second independent implementation;
2. independent cryptographic review of the reply path;
3. a concrete and reviewed D1 directory;
4. real multi-host measurement;
5. independent traffic-analysis evaluation;
6. B1.2 onward: identity, admission, and bounded peer discovery.

## Repository map

- `paper/legacy/` — preserved historical source material.
- `paper/rewrite/` — current standalone protocol paper.
- `docs/` — strategy, threat model, ADRs, reviews, implementation guidance, and evidence maps.
- `spec/` — active, historical, experimental, and future-profile specifications and vectors.
- `simulator/` — deterministic protocol and adversarial models.
- `implementation/` — Rust nodes, crates, conformance tests, fuzz targets, and Linux harnesses.
- `reports/` — reproducible experiment and conformance outputs.
- `tools/` — registry/vector generators, repository checks, audits, and experiment runners.

## Quick start

```bash
make test
make r1-vectors
make t1-vectors
make t2-vectors
make t3-vectors
make t4-vectors
make t1-compare
make t2-compare
make t3-compare
make t4-compare
make paper
make check
```

Start with:

1. [`FORDUMMY.md`](FORDUMMY.md)
2. [`spec/core-v1.8.md`](spec/core-v1.8.md)
3. [`spec/link-handshake-b1.md`](spec/link-handshake-b1.md)
4. [`spec/p1-prototype-profile-v1.8.md`](spec/p1-prototype-profile-v1.8.md)
5. [`spec/protocol-registry-v1.8.md`](spec/protocol-registry-v1.8.md)
6. [`docs/implementing-trahens-p1.md`](docs/implementing-trahens-p1.md)
7. [`docs/p1-acceptance-evidence.md`](docs/p1-acceptance-evidence.md)
8. [`docs/threat-model.md`](docs/threat-model.md)
9. [`spec/private-directory-d1.md`](spec/private-directory-d1.md)
10. [`spec/network-bootstrap-b1.md`](spec/network-bootstrap-b1.md)

## Development-record note

The version sequence and files under `docs/review-log/` are a compressed
internal reconstruction of design decisions and deterministic experiments.
They must not be cited as independent external review. See
`docs/development-record.md` and `docs/external-review-2026-07-30.md`.

## License

| Material | License |
|---|---|
| Source code — `implementation/`, `simulator/`, `tools/`, `formal/` | [Apache License 2.0](LICENSE) |
| Specifications, docs, and current paper — `spec/`, `docs/`, `paper/rewrite/` | [CC BY 4.0](LICENSE-CC-BY-4.0.txt) |

Apache-2.0 covers code and supplies an explicit patent grant for independent
implementers. CC BY 4.0 covers the written specifications and results.

`paper/legacy/` is excluded from both grants and remains confidential author
material. See [`NOTICE.md`](NOTICE.md).