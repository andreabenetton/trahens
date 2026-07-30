# Changelog

## Core v1.0 - 2026-07-30

- Adopted R1 rendezvous capabilities as the active eligibility profile and removed endpoint-specific material from operational DISCOVER messages.
- Added an eligibility-provider boundary with active R1, C1 negative control, symbolic C2 control, and a disabled C2 k=2 audit provider.
- Added one-time capability commitments, finite expiry, atomic redemption, wrong-gateway and replay rejection, and explicit directory/gateway trust boundaries.
- Changed the event model default to R1 and added deterministic cross-hop literal-tag replacement tests and tracked R1 conformance vectors.
- Added an exhaustive small Cunningham-chain checker for the literal C2 finite-field reduction.
- Added an author-query note and a source-based assessment of the ASIACRYPT 2022 updatable/randomizable PKE interface.
- Published active Core v1.0, R1, eligibility-interface, message, state-machine, invariant, and resource-accounting specifications.
- Rewrote the formal paper as one current protocol draft with point-of-use citations, clear R1 notation, line numbers every five lines, and no watermark.

## Core v0.9 - 2026-07-30

- Selected the exact `k`-linear construction in Wang et al., CRYPTO 2021, Section 6.3 and Figure 6, for a concrete C2 interoperability audit.
- Fixed the minimum admissible `k = 2` and a deterministic length-three Cunningham-chain conformance parameter set.
- Added canonical subgroup-checked public-key and 412-byte ciphertext encodings.
- Implemented deterministic key generation, encryption, decryption, wrong-recipient rejection, mutation rejection, and linear strand rerandomization outside the event simulator.
- Added a fail-closed full-rerandomization API after an exact counterexample showed that the literal finite-field map `u -> u mod q` is not a multiplicative homomorphism from `QR*_p` to `Z_q`.
- Reserved local suite `0x7f02` for audit artifacts only and prohibited it from M2/W2 network use.
- Added ten C2-K2 audit tests, including a minimal `q = 5`, `p = 11` homomorphism counterexample, and a deterministic JSON conformance report.
- Expanded the formal paper with point-of-use citations, a concrete-construction transcription section, exact encoding sizes, and an explicit interoperability limitation.
- Kept the symbolic C2 oracle as the only protocol-facing C2 backend and retained the production prohibition.

## Core v0.8 - 2026-07-30

- Selected C2, a receiver-anonymous rerandomizable RCCA eligibility contract, as the active-security target.
- Added formal C2-IND, C2-RA, C2-RR, C2-RCCA, C2-TAG, and C2-COMP games.
- Added an executable C2 ideal functionality for protocol composition and negative-path testing; explicitly prohibited production use.
- Retained C1 as the persistent-ratio-tag negative control and as the current reply/signature component set.
- Added M2 suite-agile logical messages with a canonical length-delimited eligibility capsule.
- Bound the cryptographic suite in every encrypted W2 fragment and rejected cross-suite reassembly or M2/W2 mismatch before semantic state allocation.
- Added deterministic symbolic C2 vectors and integrated active-security comparison scenarios.
- Expanded the conformance suite and repository checks for C2, M2, and suite mismatch.
- Revised the standalone formal paper to present one current protocol draft, including the C2 security contract, symbolic boundary, active games, and measured negative-control results.

## Core v0.7 - 2026-07-30

- Added M1 canonical variable-length logical messages with minimal varints and no semantic padding.
- Added W2 fixed-size 1,052-byte adjacent-link cells with a 32-byte encrypted fragment header and 992-byte fragment payload.
- Added canonical fragmentation for messages up to 16,384 bytes and at most 17 cells.
- Added bounded out-of-order reassembly, exact-duplicate idempotency, conflicting-duplicate invalidation, timeouts, concurrent-context limits, and aggregate reserved-byte limits.
- Prohibited branch, candidate, tentative, pending, or active route-state allocation before complete W2 reassembly and canonical M1 decoding.
- Integrated M1/W2 into the E1/C1 event model with cell-level loss, duplication, tampering, wire-byte, fragment, and reassembly metrics.
- Added a route-depth comparison showing that candidate messages may span multiple cells instead of failing at a single-record capacity limit.
- Added eight tests, bringing the deterministic suite to 61 tests.
- Reworked the formal paper to explain the separation between logical messages and fixed encrypted cells, bounded reassembly, fragment-count leakage, and the reliability cost of multi-cell candidates.

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
