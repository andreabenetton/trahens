# ADR 0028: Weighted DRR and atomic admission under overload

- Status: Accepted
- Date: 2026-07-30

## Context

Multiple route-control transmissions may share one scheduled link. FIFO service permits a large or malicious source to dominate slots, and partial fragment admission wastes bounded reassembly state.

## Decision

Use local weighted deficit round robin for new DATA after bounded ACK, SCHEDULE, and retransmission service. Reserve a complete first-send fragment set before admission when the canonical M2 size is known. At maximum rate, reject or expire work instead of silently increasing cadence.

## Consequences

Service is reproducibly fair for fixed-size cells and implementable with bounded per-class state. Weights are local policy and do not cross relays. Atomic admission may reject a large message even when a few slots remain.
