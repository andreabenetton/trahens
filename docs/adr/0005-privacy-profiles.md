<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0005: Express traffic-analysis resistance as deployment profiles

- Status: Accepted
- Date: 2026-07-30

## Context

The legacy draft requires adjacent links to make control messages, data, and chaff indistinguishable and to maintain a constant rate. That requirement is too strong to hide inside a generic underlay assumption and too expensive for many deployments.

## Decision

Core defines routing correctness and message semantics. Separate privacy profiles define padding classes, batching delay, link scheduling, cover traffic, and the adversaries against which they are evaluated. Claims must name the profile that provides them.

## Consequences

- A baseline implementation can run without claiming global traffic-analysis resistance.
- Stronger privacy has explicit bandwidth and latency costs.
- Interoperability negotiation must avoid making rare profiles a fingerprint.

## Validation

Each privacy profile needs a measurable traffic-generation specification and a correlation experiment.
