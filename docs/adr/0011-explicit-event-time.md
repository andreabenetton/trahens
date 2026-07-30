<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0011: Define explicit event time and half-open state deadlines

- Status: Accepted
- Date: 2026-07-30

## Context

Core v0.3 named branch, tentative, and active lifetimes but did not define the result of a message arriving at the exact expiry or candidate-window boundary. Without deterministic precedence, independent implementations can disagree on whether state exists, whether a candidate is eligible, and whether cancellation or reverse propagation wins a race.

## Decision

Core v0.4 adopts lifecycle profile E1.

- State is valid on `[created, expiry)` and invalid at `expiry`.
- Equal-time events are ordered as expiry, cancellation, route control, candidate, discovery, candidate-window closure, then local workload generation.
- A candidate arriving exactly at a window deadline is eligible.
- A message arriving exactly at its required state deadline is rejected.
- Ring schedules and ring indexes remain initiator-local.

## Consequences

- lifecycle races have deterministic and testable outcomes;
- delayed messages cannot revive expired state;
- simulator results can be reproduced across implementations;
- event timing remains observable and therefore does not strengthen traffic-flow unlinkability;
- deployments with different internal schedulers must demonstrate externally equivalent results.
