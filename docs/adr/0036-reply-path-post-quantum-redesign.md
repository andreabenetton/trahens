# ADR 0036: Treat post-quantum migration as a reply-path redesign

## Status

Accepted as a planning constraint.

## Context

C1 reply keys are group elements and relays transform them by multiplication with a secret scalar. Correct reverse peeling relies on the matching scalar action on the initiator secret. This algebraic operation is intrinsic to a discrete-log group and has no direct drop-in lattice-KEM equivalent.

## Decision

Post-quantum support remains outside P1. Any future hybrid or post-quantum profile must redesign reply-key evolution and nested reverse delivery rather than substitute one KEM identifier. It must receive a new suite identifier, transcript domains, vectors, proof obligations, and resource analysis.

## Consequences

C1 v2 is explicitly classical. Implementers must not advertise algorithm agility as evidence that the reply path can be migrated by configuration alone.
