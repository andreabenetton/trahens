# Changelog

## Unreleased

### Core v0.3 and U1

- Removed the attempt-wide wire identifier from the active design.
- Replaced attempt-scoped forwarding with peer-bound branch-local contexts.
- Added independent branch tokens, candidate tokens, and direction-bound route capabilities.
- Added a blinded reply-key chain and nested candidate-return transcript.
- Added a rerandomizable eligibility-capsule requirement for the U1 profile.
- Separated wire-image, batch-local, and traffic-flow unlinkability claims.
- Added fixed record-class and mixing requirements for the conditional U1 claim.
- Added Core v0.3 messages, state machines, invariants, resource accounting, and cryptographic transcript drafts.
- Added ADR-0008 through ADR-0010 for unlinkable branch contexts, reply-key blinding, and eligibility rerandomization.
- Extended the simulator with branch-local discovery, context-amplification metrics, loop re-entry metrics, and mandatory budgets.
- Added a 100-run comparison of identifier-based and U1 branch-local discovery.
- Restored the paper as a formal LaTeX research draft with algorithms, assumptions, propositions, and measured results.

### Earlier repository baseline

- Imported the 2020 Trahens draft and rendered paper as immutable legacy material.
- Added a staged research and engineering strategy.
- Added Core v0.1 as the first scoped correctness baseline.
- Added Core v0.2 with expanding-ring discovery, local logical-discovery context, and fresh wire attempt identifiers.
- Added cumulative transmission and state-allocation budgets.
- Added relay resource-accounting rules and cross-attempt invariants.
- Added deterministic fixed-flood and expanding-ring simulations.
