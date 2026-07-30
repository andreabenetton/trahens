# ADR 0037: Build the P1 user-space prototype over UDP

## Status

Accepted for v1.5.

## Context

The simulator has exhausted the highest-value design questions it can answer. It cannot expose real kernel queues, socket loss, scheduling, process cleanup, network-namespace behavior, packet captures, or independent decoder behavior. QUIC and TCP would replace parts of T1 and make a first prototype less representative.

## Decision

P1 consists of three Rust executables—`trahens-endpoint`, `trahens-relay`, and `trahens-rendezvous`—using ordinary UDP and typed event-driven state machines. M2, W2, R1, T1, and fixed T2 are mandatory. Adaptive T2 and T3/T4 remain analysis profiles.

The repository includes a Linux namespace harness with one namespace per process, veth links, configurable MTU, `tc netem`, fixed-size capture validation, 2-hop and 12-hop topologies, loss and burst-loss scenarios, replay/expiry checks, and cleanup assertions.

## Consequences

P1 prioritizes canonical interoperability and bounded failure over throughput. Production status remains blocked by external cryptographic review and independent implementation. Platforms without Linux namespaces may run unit/conformance tests but cannot satisfy the namespace acceptance gate.
