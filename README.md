# Trahens

Trahens is a research protocol for privacy-enabled route discovery in decentralized and path-aware networks. The repository develops a bounded, executable control-plane core before attempting a complete routing architecture.

## Status

The active specification is **Trahens Core v1.4**, composed of:

- **U1** - branch-local representation replacement and conditional passive unlinkability;
- **E1** - deterministic event and route-state lifecycle;
- **R1** - generic rendezvous-gateway discovery with post-READY one-time capability redemption;
- **M2** - canonical suite-agile variable-length logical messages;
- **W2** - canonical 992-byte fragmentation and fixed-size authenticated adjacent-link records;
- **T1** - hop-local selective recovery, fresh retry ciphertexts, and fragment interleaving;
- **T2** - fixed or quantized-adaptive schedule epochs, authenticated rate negotiation, weighted fair service, and bounded overload behavior;
- **T3** - equal-budget multi-link route classification, correlated background traffic, boundary-phase measurement, and active probing;
- **T4** - deterministic packet-event emulation with heterogeneous clocks, jitter, shared bottlenecks, route churn, partial observation, open-world classification, and bounded selective delay.

Endpoint-specific material is absent from active `DISCOVER` messages. A destination issues a random, short-lived capability, registers its commitment at selected rendezvous gateways, and privately distributes a descriptor to an authorized initiator. Discovery returns authenticated gateway candidates. After `COMMIT` and `READY`, the initiator presents the capability through the active route; the gateway atomically consumes it and starts the local rendezvous procedure.

This removes the active protocol's dependency on an unresolved receiver-anonymous universal-rerandomization construction. It introduces explicit directory, gateway, and adjacent-link scheduling trust boundaries. The protocol does not yet specify private descriptor lookup, protection from colluding directory and gateway operators, a global-observer traffic-flow theorem, production congestion control, or a production implementation.

## Current transport result

M2 separates semantic encoding from observable framing. W2 defines canonical fragments. T1 carries fragments in 1,052-byte encrypted DATA records, returns same-size encrypted selective ACKs, and retransmits only missing fragments with fresh sequences, padding, tags, and ciphertexts.

T2 adds three release modes:

- **fixed** - one public rate class for a declared interval, with idle slots filled by CHAFF;
- **adaptive** - one class per epoch, changing by at most one class after encrypted OFFER/ACCEPT negotiation and hysteresis;
- **work-conserving** - real cells only, retained as an efficiency and correlation baseline.

Weighted deficit round robin shares new-data service among backlogged link-local transmissions. Queue admission, schedule-control reserve, retry work, rate transitions, and overload cleanup are finite. Adaptive scheduling reduces reserved CHAFF, but public rate transitions reveal coarse queue activity and therefore carry no activity-presence privacy claim.

The deterministic T2 model shows the intended trade-off. Under the equal-overload workload, adaptive scheduling delivered all admitted work with a peak queue of 98 cells and 370 chaff cells, whereas the fixed low-rate profile dropped 15% of offered work and the fixed high-rate profile emitted 1,600 chaff cells. A simple rate-class distinguisher had no advantage against fixed-high active versus idle traces, but perfect advantage against the evaluated adaptive traces.

T3 removes total bandwidth as a trivial feature by assigning fixed, adaptive, and hybrid traces the same exact per-link super-epoch cell budget. It then evaluates four route labels over longer windows, independent and correlated background traffic, public transition phases, and a bounded active bandwidth probe. The fixed count trace is route-independent in this model. Adaptive traces remain strongly classifiable and probe-responsive. The hybrid profile uses a non-zero baseline, smoothing, independent decoy uplifts, and non-boundary transitions; it lowers the simple classifier and probe advantage but does not establish traffic-flow unlinkability. These are deterministic model results, not network benchmarks or anonymity proofs.

T4 converts those public schedules into timestamped cell events. It adds finite access and shared-bottleneck serialization, bounded propagation jitter, independent observer-clock skew/offset/noise/quantisation, partial link observation, route churn, disjoint open-world unknown routes, and a bounded selective-delay probe. Every compared trace retains the exact public-cell budget. The transparent classifier reports monitored recall and unknown false-positive rate separately; the transparent delay detector is treated as a falsification tool, not a security proof.

## Cryptographic research status

Research-only providers remain executable and fail closed:

- **C1 (`0x0001`)** reproduces a persistent algebraic ratio tag and is a mandatory negative control.
- **Symbolic C2 (`0x0002`)** is an ideal functionality used only to test composition and failure placement.
- **C2 k=2 audit (`0x7f02`)** transcribes the cited construction and remains disabled after the literal finite-field reduction failed exhaustive small-chain homomorphism checks.

The reply path continues to use independent first-hop reply keys, additive `ristretto255` tweaks, nested ChaCha20-Poly1305 encryption, Ed25519 candidate authentication, and domain-separated HKDF-SHA-256. These retained components still require independent cryptographic review as a composition.

## Repository map

- `paper/legacy/` - preserved historical source material.
- `paper/rewrite/` - standalone current formal protocol paper.
- `docs/` - strategy, threat model, ADRs, citation audit, cryptographic reviews, and review logs.
- `spec/` - active and research specifications, invariants, transcripts, and vectors.
- `simulator/` - deterministic discovery, lifecycle, transport, scheduling, and adversarial models.
- `implementation/` - requirements for a future user-space overlay prototype.
- `reports/` - reproducible experiment and conformance outputs.
- `tools/` - repository checks, vector generators, exhaustive audits, and experiment runners.

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

Start with [`spec/core-v1.4.md`](spec/core-v1.4.md), [`spec/rendezvous-capability-r1.md`](spec/rendezvous-capability-r1.md), [`spec/message-codec-m2.md`](spec/message-codec-m2.md), [`spec/wire-cell-w2.md`](spec/wire-cell-w2.md), [`spec/transport-profile-t1.md`](spec/transport-profile-t1.md), [`spec/transport-profile-t2.md`](spec/transport-profile-t2.md), [`spec/transport-profile-t3.md`](spec/transport-profile-t3.md), [`spec/transport-profile-t4.md`](spec/transport-profile-t4.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/citation-audit.md`](docs/citation-audit.md).
