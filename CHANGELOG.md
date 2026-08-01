# Changelog

## Registry 1.6.1 - 2026-08-01

- Added error identifier 14, `not_eligible`. A C1 gateway previously recorded
  both a malformed capsule and a well-formed one addressed elsewhere as
  `malformed`, so an operator could not tell a peer sending rubbish from C1
  working as intended. The eligibility interface splits the two questions:
  `Accept` is well-formedness, `IsEligible` is the recipient's decision. Both
  outcomes remain externally indistinguishable; only local counters differ.
- No wire encoding change. The conformance corpus is byte-identical and only
  the embedded registry version moved.

## Registry 1.6.0 - 2026-08-01

- **Wire change. v1.5 is superseded and is now history.** `DISCOVER` gained a
  suite-independent 32-byte `routing_nonce` alongside an `eligibility_field`
  the active suite sizes, so a v1.5 encoding does not decode under v1.6 and the
  two profiles do not interoperate.
- Before this, one 32-byte value was the eligibility field, the binding of each
  link in the returned candidate chain, and the key per-offer labels were
  derived from. Two of those three belong to route discovery, so every suite
  was forced to be 32 bytes. `docs/adr/0040-routing-nonce-split.md` records the
  decision, including that the candidate chain no longer covers the eligibility
  field and why that is defensible.
- Candidate layers do **not** grow: `RelayLayer` carries routing nonces at the
  same 32 bytes it previously carried discovery nonces.
- C1 v2 became selectable on an experimental profile and is wired end to end;
  adaptive T2 became selectable with `--schedule-profile`. Each has its own CI
  gate and neither may be cited as evidence for a mandatory gate line.
- `Discover.options` is renamed `depth`, which is what it always carried. No
  byte layout change.
- The v1.5 registry, vectors and corpus are retained and still regenerate from
  their own generators, so that profile stays reproducible. No binary here
  speaks it.

## Registry 1.5.2 - 2026-07-31

- Pinned `expiry_class` to `limits.expiry_class_p1`. The field had been parsed,
  bounded only away from zero, and then never read: deadlines come from the
  phase and the registry's per-class TTLs. Both codecs now reject any other
  value as malformed rather than accepting and ignoring it.
- Conformance corpus grew from 22 to 32 vectors, adding ten negatives for the
  new rule. A rule with no vector is one an implementer can miss.
- Regenerating found that `generate_t1_vectors.py` had been emitting a
  CANDIDATE with expiry class 3 — a published vector encoding a message no
  conforming node may send. Its digest changes; the fragment counts and lengths
  the T1 headers pin do not.

## Registry 1.5.1 - 2026-07-30

- Amended the frozen registry with constants that normative mandatory-limit
  lists already required but that had no registry entry: T1 RTO clamp bounds
  and initial value split (`t1_rto_min_ms`, `t1_rto_max_ms`), T1 ACK delay
  bound and pending-ACK cap, per-class E1 lifecycle deadlines (branch,
  offer, tentative, ready-hold, route-setup), the ADR-0013 ingress token
  bucket parameters, branch-context and candidate-response ceilings, R1
  registration bounds and endpoint-handle lifetime, and the fan-out class
  bound. No wire encoding changes; the conformance corpus is byte-identical
  and only the embedded registry version string moved to 1.5.1.

## Core v1.5 P1 prototype - 2026-07-30

- Froze M2, W2, R1, T1, and the fixed T2 P1 profile in one machine-readable registry, including stable message, suite, error, width, limit, byte-order, and protection-class assignments.
- Corrected the C1 v2 versioning mismatch, retired suite `0x0001`, assigned C1 v2 suite `0x0003`, and generated matching Python, Rust, and normative Markdown constants.
- Added recipient-bound reply-ciphertext commitment, construction-wide v2 domain separation, generic crypto failures, zeroization, replay windows, bounded reassembly, and pre-authentication allocation controls.
- Moved deterministic crypto helpers outside the installable package and added independent positive and negative M2 conformance vectors plus a binary mutation corpus.
- Added a Rust user-space workspace with endpoint, relay, and rendezvous executables over UDP, typed event-driven state machines, fixed-size W2 cells, T1 reliability, fixed T2 scheduling, and one-time R1 redemption.
- Added Linux namespace interoperability, impairment, capture, fixed-cell, metric, cleanup, direct two-process, two-relay loss, and twelve-relay CI gates.
- Added R1/E1 TLA+ specifications, bounded executable state exploration, entropy-based anonymity metrics, fuzz targets, cryptographic claim boundaries, post-quantum and deployment-scope ADRs, and review-remediation traceability.

## Core v1.4 - 2026-07-30

- Added T4 as a packet-level adversarial evaluation profile layered over T2/T3 without changing the wire format.
- Added deterministic per-cell events, finite access-link and shared-bottleneck serialization, propagation jitter, queue accounting, and exact online public-budget enforcement.
- Added independent affine observer clocks with skew, offset, noise, and timestamp quantisation.
- Added partial observation and route churn in which only newly generated target cells adopt the changed path.
- Added an open-world route classifier with disjoint monitored, unknown-calibration, and unknown-testing route sets and explicit monitored-TPR, unknown-FPR, precision, and macro-F1 metrics.
- Added a bounded selective-delay probe with steady present/absent workloads, route-churn conditions, and finite phase/lag search.
- Added deterministic T4 vectors, nine model tests, three tracked reports, two ADRs, and repository smoke/reproduction targets.
- Published Core v1.4, T4 evaluation, message, state-machine, invariant, resource-accounting, strategy, citation-audit, and formal-paper updates.

## Core v1.3 - 2026-07-30

- Added T3 as a multi-link traffic-analysis evaluation profile layered over T2 without changing the wire format.
- Added exact equal-bandwidth super-epoch comparison for fixed, adaptive, and hybrid schedules on every observed link.
- Added a four-class route model, independent and correlated background traffic, hop-delayed target signals, and observation windows from 32 to 256 epochs.
- Added a transparent nearest-centroid classifier using binned counts, first differences, boundary metadata, and lagged cross-link correlations.
- Added a bounded active bandwidth-probe experiment with trained present/absent detection and explicit TPR/FPR reporting.
- Added a hybrid evaluation policy with non-zero baseline, smoothed response, independent decoy uplifts, non-boundary transition phases, and exact budget compensation.
- Added deterministic T3 vectors, nine model tests, three tracked reports, and repository smoke/reproduction targets, bringing the complete suite to 117 tests.
- Published Core v1.3, T3 transport-analysis, message, state-machine, invariant, resource-accounting, and ADR updates.
- Expanded the formal paper with the T3 adversary, equal-budget methodology, classifiers, probing, results, and point-of-use citations to flow-correlation, routing, watermarking, and traffic-shaping research.

## Core v1.2 - 2026-07-30

- Added T2 fixed, quantized-adaptive, and work-conserving adjacent-link schedule modes.
- Added same-size encrypted SCHEDULE OFFER, ACCEPT, and REJECT frames with link-local negotiation identifiers.
- Added finite public rate menus, one-class boundary transitions, peer maximums, minimum hold time, and asymmetric queue-pressure hysteresis.
- Added weighted deficit round robin for admitted new DATA after bounded ACK, schedule-control, and retry reserves.
- Added atomic first-send queue reservation, finite queue residence, overload rejection, and fail-closed maximum-class behavior.
- Added deterministic independent and Gilbert-Elliott loss models, a rate-class activity distinguisher, Jain-normalized fairness, and two-link public-count correlation experiments.
- Added T2 codec/model tests and deterministic schedule-control vectors, bringing the complete suite to 108 tests.
- Published Core v1.2, T2 transport, message, state-machine, invariant, and resource-accounting specifications.
- Expanded the formal paper with T2 notation, negotiation and service algorithms, point-of-use citations, congestion/fairness measurements, adaptive leakage, burst-loss results, and multi-link correlation limits.

## Core v1.1 - 2026-07-30

- Added T1 hop-local reliability with encrypted cumulative selective ACK bitmaps, bounded RTO recovery, and finite retry exhaustion.
- Added exact fixed-size T1 DATA, ACK, and CHAFF frame encodings while retaining the 1,052-byte adjacent-link record.
- Required fresh public sequences, random padding, authentication tags, and ciphertexts for every retransmission.
- Added round-robin fragment interleaving and fixed-schedule or work-conserving release modes.
- Added an explicit fixed-schedule claim boundary: active and empty traffic have identical per-direction modeled slot traces only inside a pre-existing non-overflowing epoch.
- Added deterministic route-depth and 2%, 5%, and 10% cell-loss comparisons against unrecovered W2 delivery.
- Added T1 codec, recovery, cleanup, retry-exhaustion, deep-fragmentation, trace-equivalence tests, and tracked deterministic framing/retry vectors.
- Published Core v1.1, T1 transport, message, state-machine, invariant, and resource-accounting specifications.
- Expanded the formal paper with T1 notation, frame layouts, algorithms, security boundaries, citations, and measured bandwidth/reliability trade-offs.

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
