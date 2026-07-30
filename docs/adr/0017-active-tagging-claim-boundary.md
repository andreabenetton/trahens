<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0017: Close the active-unlinkability claim gate

- Status: Accepted
- Date: 2026-07-30

## Context

The C1 universal rerandomizable encryption capsule contains a consistency pair. Correct rerandomization changes its wire representation, but a compromised relay is not required to transform it honestly. Adjacent-link authentication prevents third-party modification on an edge; it does not prevent the relay itself from emitting a new valid ciphertext.

A malicious relay can replace the consistency pair `(U1,V1)` with `(c V1,V1)` for a chosen non-zero scalar `c`. An honest relay later scales both points during rerandomization, preserving the relation `U1 = c V1`. A colluding downstream relay can test that relation. The destination rejects the altered capsule unless `c` equals the destination eligibility secret.

## Decision

Treat the ratio relation as an executable active-tagging counterexample. Core v0.6, C1, and U1 MUST NOT claim active-adversary message unlinkability. The implementation normalizes endpoint rejection with other invalid-cryptographic outcomes and exposes no amplified diagnostic response.

## Consequences

- passive wire-image and conditional batch-local claims remain separately testable;
- active security is a blocked gate, not an assumed property;
- the reference model records tags created, downstream observations, endpoint rejection, route result, and cleanup;
- C1 must be revised or replaced before any active-adversary unlinkability claim;
- future proposals must be evaluated against selective failure and algebraic tagging, not only ciphertext equality.
