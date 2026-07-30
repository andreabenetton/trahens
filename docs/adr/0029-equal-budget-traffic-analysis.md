# ADR-0029: Compare schedule policies under an equal public bandwidth budget

- Status: Accepted
- Date: 2026-07-30

## Context

T2 showed that adaptive schedules reveal activity, but its fixed and adaptive traces used different total CHAFF budgets. A classifier could therefore exploit total cell count rather than route-dependent shape.

## Decision

T3 comparisons use a finite super-epoch and require every profile to emit the same exact number of fixed-size records on each observed directed link. Fixed, adaptive, and hybrid allocations differ only in their within-window distribution.

## Consequences

Total bytes are removed as a trivial feature. Timing, boundary alignment, queueing, and cross-link correlation remain observable. The equalizer is an offline evaluation envelope and is not automatically a deployable online scheduler.
