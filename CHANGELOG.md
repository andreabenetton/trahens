# Changelog

## Core v0.6 - 2026-07-30

- Added W1: one 1,052-byte adjacent-link record with a 12-byte public header, 1,024-byte encrypted body, and 16-byte tag.
- Added exact DISCOVER, CANDIDATE, route-control, and CHAFF layouts.
- Integrated W1 and C1 cryptography into the E1 event lifecycle.
- Added exact nested candidate construction, responder verification, and COMMIT/READY proofs.
- Added adjacent-link tamper injection and exact wire-byte metrics.
- Added a reproducible persistent ratio-tag attack against the C1 URE consistency pair.
- Closed the active-adversary unlinkability claim gate and retained only explicitly scoped passive claims.
- Added eight tests, bringing the deterministic suite to 53 tests.
- Reworked the formal paper as a standalone current draft with clearer notation, exact wire formats, integrated algorithms, active-tagging analysis, five-line numbering, and no watermark.

## Core v0.5 - 2026-07-30

- Added the concrete C1 research cryptographic profile.
- Bound Core to canonical `ristretto255` point and scalar encodings.
- Added a GJJS-style 128-byte universally rerandomizable eligibility capsule.
- Required non-identity rerandomization coins so every valid outgoing capsule changes all four point encodings.
- Added the additively tweakable reply-key chain and the custom `TR-KEM-R255` KEM/AEAD wrapper.
- Added HKDF-SHA-256, ChaCha20-Poly1305, and Ed25519 transcript authentication.
- Added ordered CANDIDATE, COMMIT, and READY transcript definitions and generic `INVALID_CRYPTO` behavior.
- Added deterministic C1 vectors, a `libsodium`/`cryptography` reference implementation, and seven C1 tests.
- Increased the complete deterministic suite from 38 to 45 tests.
- Rewrote the formal paper as a 22-page Core v0.5 document with clearer notation, worked examples, claim boundaries, formal propositions, five-line numbering, and no watermark.

## Core v0.4 - 2026-07-30

- Added E1 event lifecycle with half-open deadlines and deterministic equal-time precedence.
- Added candidate windows and delayed candidates across initiator-local expanding rings.
- Added cancellation races and maximal off-route subtree cancellation.
- Added tentative CANDIDATE mappings, `PENDING_READY` COMMIT reservation, reverse READY activation, and ready-gated data-plane exposure.
- Added loss, exact duplication, reordering, forced fault injection, and deterministic cleanup.
- Added malicious fresh-branch generation and ingress-peer token buckets.
- Added 15 event-lifecycle tests, increasing the complete suite to 38 tests.
- Added the 100-run lifecycle comparison report.
- Updated the formal paper to Core v0.4 with five-line modulo numbering and no watermark.

## Core v0.3 and earlier

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
