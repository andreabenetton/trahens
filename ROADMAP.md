# Roadmap

| Revision | Purpose | Gate | State |
|---|---|---|---|
| v1.4.1 | independent review remediation | cryptographic construction and evidence boundaries corrected | Complete |
| v1.5 | P1 interoperable user-space prototype | Rust nodes, frozen registry/vectors, namespace faults, cleanup | Complete; every gate line executes in CI, see [`docs/p1-acceptance-evidence.md`](docs/p1-acceptance-evidence.md) |
| v1.6 | external cryptographic and protocol review | reply key privacy, commitment, state machines, wire and resource model reviewed independently | Planned |
| v1.7 | multi-host deployment | independently operated nodes interoperate across real networks | Planned |
| v1.8 | captured-traffic evaluation | performance and traffic-analysis experiments use real packet traces | Planned |
| v2.0 | reviewed stable protocol | wire protocol and security model survive implementation and independent review | Blocked on v1.6–v1.8 |

## v1.5 focus

The protocol is no longer extended primarily through simulator profiles. v1.5 freezes M2, W2, R1, T1, and fixed T2/P1 in one machine-readable registry, provides independent canonical and malformed vectors, and implements three separately started UDP processes in Rust. Linux namespaces replace simulated queues with kernel sockets, scheduling, MTU, loss, delay, jitter, duplication, and reordering.

The P1 acceptance checklist is normative in `spec/p1-prototype-profile-v1.5.md`. Source presence is not equivalent to passing the runtime gate: Rust compilation, 5% loss recovery, burst-loss failure, 12-relay establishment, packet-size capture, and state cleanup must execute successfully in CI or an equivalent Linux host.

Every one of those now executes. `docs/p1-acceptance-evidence.md` maps each gate line to the job or harness arm that runs it, and records the three gaps that remain open rather than claiming them as passed: off-route subtree cancellation under relay fan-out, adaptive T2 being codec-only, and C1 being a network-disabled library.

## Security work retained for v1.6

1. obtain an independent multi-user IK-CCA/key-privacy review of C1 v2 reply sealing and nested blinding composition;
2. review the recipient-bound commitment and failure/resource uniformity;
3. translate or extend the bounded R1/E1 models into an adversarial symbolic proof where appropriate;
4. review capability atomicity, replay/expiry, T1 recovery, and fixed-T2 claim boundaries;
5. decide whether C1 should be replaced with a standard anonymous public-key encryption construction;
6. keep post-quantum migration classified as a reply-path redesign, not a primitive substitution.

## Strategic scope

Trahens is evaluated as privacy-preserving route discovery for decentralized and path-aware networks such as mesh, delay-tolerant, and policy-aware fabrics. It is not positioned as a replacement for mature anonymity overlays that already assume an IP substrate and public relay directory.
