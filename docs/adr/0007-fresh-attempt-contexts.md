<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0007: Use a local logical discovery and fresh wire attempt IDs

- Status: Accepted
- Date: 2026-07-30

## Context

Expanding-ring discovery retries the same service request with progressively broader limits. Reusing one wire-visible discovery identifier would let every relay directly link all rings. A single identifier is convenient for deduplication and accounting, but cross-ring deduplication is not required for correctness because every ring is independently bounded.

Fresh identifiers do not by themselves make retries unlinkable. Relays and link observers may correlate attempts through timing, origin adjacency, service metadata, and overlapping relay sets.

## Decision

Separate two contexts:

1. a random `logical_discovery_id` stored only by the initiator for cumulative policy and accounting;
2. a fresh random 128-bit `attempt_id` transmitted for each ring and used only for attempt-local duplicate suppression.

Messages MUST NOT expose the logical discovery ID, previous attempt IDs, ring index, or retry count. Candidate identities are deduplicated locally by authenticated responder/service identity.

## Consequences

- Direct identifier correlation across rings is removed.
- Relays cannot suppress duplicate propagation across attempts.
- Cumulative budgets are enforced by the initiator and independently by each relay's peer/time/global limits.
- Timing and topology correlation remain and must be measured.
- Late candidates require attempt-specific state and cannot be confused with later rings.

## Validation

The deterministic simulator now reports:

- relays observing any attempt;
- relays observing multiple attempts;
- repeated relay observations;
- candidate repetition across attempts;
- cumulative transmission and state-allocation cost.
