# ADR 0031: Add packet-level emulation and heterogeneous observer clocks

- Status: Accepted
- Date: 2026-07-30

## Context

T3 compares epoch-level public cell counts under equal bandwidth. That model cannot represent serialization, propagation jitter, shared bottleneck queues, independent observer clocks, timestamp quantisation, or packet-level inter-arrival features. A profile that appears indistinguishable in epoch counts may remain distinguishable in timestamp traces, while a classifier that assumes a perfect shared clock may overstate an attack.

## Decision

Introduce T4 as an evaluation-only profile layered over T2/T3. The deterministic reference emulator converts scheduled fixed-size cells into finite packet events. It models access-link serialization, optional shared bottlenecks, bounded propagation jitter, per-link affine clocks, measurement noise, and timestamp quantisation.

A target token is local to one hop. After arrival and relay processing, a continuing target cell is represented by a new local token. Route labels and token kinds are retained only for experiment measurement.

The emulator enforces the public cell budget online and reports queue, expiry, delay, budget, and cleanup failures. T4 introduces no wire-format change and no production privacy claim.

## Consequences

- Timestamp and correlation attacks can be tested without assuming a shared perfect clock.
- Shared-bottleneck and queue effects become explicit rather than hidden in abstract delay values.
- The model remains reproducible and small enough for CI.
- Results are still model results; validation against Shadow, ns-3, a user-space implementation, or deployment traces remains necessary.
