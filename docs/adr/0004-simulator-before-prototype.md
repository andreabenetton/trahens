# ADR-0004: Build a deterministic simulator before network code

- Status: Accepted
- Date: 2026-07-30

## Context

Flooding, degree obfuscation, route-state retention, and churn interact nonlinearly. Building a network implementation first would make protocol defects difficult to distinguish from transport and concurrency defects.

## Decision

A deterministic discrete-event simulator will be the first executable artifact. It will model topology, bounded discovery, duplicate suppression, relay state, expiration, churn, and malicious strategies. Experiments will record seeds and parameters.

## Consequences

- Design alternatives can be rejected cheaply.
- Simulator behavior must not be confused with real-network performance.
- The simulator becomes an executable reference for state transitions.

## Validation

Every resource or scalability claim in the paper must point to a reproducible simulator experiment or prototype result.
