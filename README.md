# Trahens

Trahens is a research protocol for privacy-enabled route discovery in decentralized and path-aware networks. The repository develops a bounded, executable control-plane core before attempting a complete routing architecture.

## Status

The active specification is **Trahens Core v1.0**, composed of:

- **U1** - branch-local representation replacement and conditional passive unlinkability;
- **E1** - deterministic event and route-state lifecycle;
- **R1** - generic rendezvous-gateway discovery with post-READY one-time capability redemption;
- **M2** - canonical suite-agile variable-length logical messages;
- **W2** - fixed-size authenticated adjacent-link cells with bounded reassembly.

Endpoint-specific material is absent from active `DISCOVER` messages. A destination issues a random, short-lived capability, registers its commitment at selected rendezvous gateways, and privately distributes a descriptor to an authorized initiator. Discovery returns authenticated gateway candidates. After `COMMIT` and `READY`, the initiator presents the capability through the active route; the gateway atomically consumes it and starts the local rendezvous procedure.

This removes the active protocol's dependency on an unresolved receiver-anonymous universal-rerandomization construction. It introduces an explicit directory-and-gateway trust boundary. The protocol does not yet specify private descriptor lookup, protection from colluding directory and gateway operators, traffic-flow unlinkability, or a production implementation.

## Cryptographic research status

Research-only providers remain executable and fail closed:

- **C1 (`0x0001`)** reproduces a persistent algebraic ratio tag and is a mandatory negative control.
- **Symbolic C2 (`0x0002`)** is an ideal functionality used only to test composition and failure placement.
- **C2 k=2 audit (`0x7f02`)** transcribes the cited CRYPTO 2021 construction and remains disabled after the literal finite-field reduction failed an exhaustive small-chain homomorphism check.

The reply path continues to use independent first-hop reply keys, additive `ristretto255` tweaks, nested ChaCha20-Poly1305 encryption, Ed25519 candidate authentication, and domain-separated HKDF-SHA-256. These retained components still require independent cryptographic review as a composition.

## Current result

Every forwarded branch receives a fresh adjacent capability, a tweaked reply public key, a replacement R1 service-query nonce, a new canonical M2 message, a fresh W2 message-local identifier, new padding, and new adjacent-link ciphertexts. `CANDIDATE` returns through nested authenticated reply layers. `COMMIT` reserves the selected tentative route, `READY` activates it, and every state has a finite local deadline.

M2 separates semantic encoding from observable framing. W2 fragments a message into 992-byte payload fragments, pads each cell plaintext to 1,024 bytes, and emits 1,052-byte adjacent-link records. Cell count and timing remain observable unless a later scheduling profile conceals them.

## Repository map

- `paper/legacy/` - preserved historical source material.
- `paper/rewrite/` - standalone current formal protocol paper.
- `docs/` - strategy, threat model, ADRs, citation audit, cryptographic reviews, and review logs.
- `spec/` - active and research specifications, invariants, transcripts, and vectors.
- `simulator/` - deterministic discovery and lifecycle models, codecs, providers, and adversarial experiments.
- `implementation/` - requirements for a future user-space overlay prototype.
- `reports/` - reproducible experiment and conformance outputs.
- `tools/` - repository checks, vector generators, exhaustive audits, and experiment runners.

## Quick start

```bash
make test
make r1-vectors
make r1-compare
make c2-k2-exhaustive
make fragmentation-compare
make paper
make check
```

Start with [`spec/core-v1.0.md`](spec/core-v1.0.md), [`spec/rendezvous-capability-r1.md`](spec/rendezvous-capability-r1.md), [`spec/eligibility-suite-interface-v1.md`](spec/eligibility-suite-interface-v1.md), [`spec/message-codec-m2.md`](spec/message-codec-m2.md), [`spec/wire-cell-w2.md`](spec/wire-cell-w2.md), [`spec/event-lifecycle-profile-e1.md`](spec/event-lifecycle-profile-e1.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/citation-audit.md`](docs/citation-audit.md).
