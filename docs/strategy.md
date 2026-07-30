# Improvement strategy

## Objective

Turn the protocol concept into a falsifiable research program and then into an interoperable experimental protocol. The project succeeds only if it states precisely:

- what information each participant learns;
- what an adversary can observe or modify;
- how much bandwidth, computation, relay state, and reassembly memory discovery consumes;
- which privacy properties survive each compromise and observation model;
- which components are core mechanisms and which are deployment profiles.

## Design principles

1. **Narrow before extending.** Solve bounded local discovery before global name resolution.
2. **Transform every cross-hop handle.** A privacy claim fails if any opaque field remains a stable equality token.
3. **Separate semantic encoding from observable framing.** Logical messages should be canonical and extensible; link cells should carry the privacy and scheduling properties.
4. **Separate security properties.** Wire-image unlinkability, batch-local matching resistance, traffic-flow unlinkability, lifecycle correctness, and reassembly safety are distinct.
5. **No implicit cryptography.** Every key, transcript, nonce, proof, error rule, and domain separator must be defined.
6. **Bound every resource.** Messages, cells, fragments, fan-out, branch contexts, candidates, lifetimes, queues, reassemblies, and cryptographic operations require explicit limits.
7. **Make claims executable.** Every security or scalability claim maps to a test, simulation, model, or proof obligation.
8. **Preserve evolution.** Version and suite negotiation must resist downgrade without becoming a fingerprinting oracle.
9. **Keep evidence immutable.** Improvements occur in versioned specifications and the standalone formal paper.

## Current architecture

Trahens Core v0.7 is a bounded discovery and ready-gated bidirectional route-establishment protocol. It excludes global directory resolution, incentives, inter-domain policy, and a replacement link stack.

U1 removes attempt-wide wire identifiers. Every outgoing branch replaces its capability, additively tweaks the reply public key, rerandomizes the hidden eligibility capsule, and reconstructs a fresh logical message.

E1 defines half-open state deadlines, deterministic equal-time precedence, candidate windows, delayed candidates across local rings, cancellation races, tentative reverse mappings, pending-ready reservation, reverse activation, loss, duplication, and deterministic cleanup.

C1 fixes the concrete classical operations. M1 defines canonical variable-length logical messages without semantic padding. W2 fragments each M1 message into fixed 1,052-byte adjacent-link cells, assigns a fresh link-local message identifier, authenticates each cell independently, and reassembles under strict byte, context, fragment, and time limits. The event model executes C1, M1, W2, and E1 together.

The active-tagging experiment found a persistent ratio relation in the C1 URE consistency pair. Active-adversary unlinkability is not claimed. This negative result remains a design gate: the eligibility construction must be replaced or strengthened before an active-security claim is reconsidered.

W2 closes exact cell-length classification but does not hide the number or timing of cells. A traffic scheduler must address fragment-count and burst-shape leakage separately.

## Workstreams

### A. Core semantics

Maintain the completed E1 baseline for DISCOVER, CANDIDATE, COMMIT, READY, ABORT, CANCEL, CLOSE, expiry, loss, delay, duplication, reordering, fragmentation, and cancellation. Extend only through versioned lifecycle profiles and conformance tests.

### B. Unlinkability and cryptography

Review and challenge the concrete C1 URE and reply KEM. Align the construction with an explicit security definition, replace the active-tag-vulnerable eligibility mechanism, expand malformed-input vectors, and run active-tagging and related-key experiments. Independent review remains a release gate.

### C. Message and cell interoperability

Specify M1 and W2 independently. Require canonical varints, deterministic fragmentation, exact header validation, bounded out-of-order reassembly, duplicate conflict rules, generic failure behavior, two independent codecs, fuzzing, and cross-language vectors.

### D. Resource and denial-of-service model

Because U1 removes attempt-wide duplicate suppression and W2 permits multi-cell messages, quantify branch-context amplification and fragment-spray pressure. Enforce per-link, per-peer, per-node, queue, time-window, logical-byte, cell, reassembly, and global limits before expensive operations.

### E. Simulation and measurement

Use deterministic models to compare discovery success, cumulative work, peak concurrent state, delayed-candidate behavior, route setup, fragmentation, cell loss, churn, and attacker strategies. Privacy experiments must report adversarial matching success rather than infer privacy from encryption alone.

### F. Overlay prototype

Begin with schema, codec, reassembly, and conformance work using C1 only as a research profile. After two independent M1/W2 codecs agree on vectors and negative inputs, implement the smallest user-space overlay over an existing authenticated transport. The prototype validates interoperability and state machines; it does not replace IP.

### G. Traffic-scheduling profiles

Specify cell interleaving, CHAFF, release cadence, fragment-count padding, overflow, fairness, and constant- or quantized-rate behavior separately from Core. Measure latency, loss exposure, and bandwidth cost against named correlation adversaries.

### H. Directory research

Treat long-range registration and resolution as a separate protocol. Compare rendezvous, capability-based introduction, private-query-compatible directories, replication, poisoning resistance, and selective-denial behavior. Repeated hashing is not accepted as query privacy.

## Iteration model

Each iteration contains:

1. a defect or research question;
2. a proposed change and explicit assumptions;
3. an ADR for architecture changes;
4. versioned specification updates;
5. executable tests, simulations, or proof obligations;
6. measured results and known counterexamples;
7. a decision to accept, revise, or revert.

An iteration is incomplete when it changes prose without changing a testable artifact.

## Phases and gates

### Phase 0 - Evidence baseline: complete

Legacy material is immutable, current material is versioned separately, and repository checks are reproducible.

### Phase 1 - Core correctness baseline: complete

Core v0.2 established the first coherent message taxonomy, lifecycle, state machines, and bounded expanding-ring policy.

### Phase 2 - U1 structural unlinkability: complete as a research design

Core v0.3 removed stable cross-hop handles and defined branch-local transformation, fixed observable classes, mixing, and a conditional challenge game. The simulator records the cost of losing attempt-wide deduplication.

Gate status: protocol structure accepted; cryptographic guarantee not approved.

### Phase 3 - Event-driven route lifecycle: complete as a deterministic model

Core v0.4 and E1 define event ordering, candidate windows, delayed candidates, tentative reverse state, pending-ready reservation, final READY gating, cancellation races, loss, exact duplication, fresh-branch attacks, and deterministic cleanup.

Gate status: modeled route-state transitions and races have bounded deterministic outcomes; network implementation remains unvalidated.

### Phase 4 - Cryptographic profile C1: concrete research baseline complete

Delivered:

- concrete URE and additive reply-key constructions;
- canonical `ristretto255` point/scalar rules and endpoint descriptors;
- KDF, AEAD, signature, and transcript domain separation;
- generic malformed-input behavior;
- deterministic vectors and executable reference code;
- positive and negative conformance tests.

Gate status: interoperability ambiguity is reduced, but the production-security gate is open. Independent proof review, active-tagging analysis, related-key analysis, side-channel review, and a post-quantum strategy remain required.

### Phase 5 - Integrated wire and active-security baseline: complete

Delivered:

- exact adjacent-link authentication and byte accounting;
- integrated C1 candidate, COMMIT, and READY processing in the E1 event model;
- adjacent-link tampering tests;
- a reproducible persistent-ratio-tag counterexample;
- explicit closure of the active-unlinkability claim gate.

### Phase 6 - M1/W2 message-cell separation: complete as a research baseline

Delivered:

- canonical variable-length M1 messages without semantic padding;
- fixed-size W2 encrypted cells and deterministic fragmentation;
- bounded out-of-order reassembly and conflict handling;
- integrated cell-level loss, duplication, tampering, and cleanup;
- route-depth and fragmentation measurements;
- explicit fragment-count leakage and reliability limits.

Gate status: the single-cell capacity limit is removed. Independent codec agreement, fuzzing, fragment-spray analysis, scheduler design, and active-security repair remain open.

### Phase 7 - Overlay interoperability prototype

Deliverables include two independent codecs, a conformance harness, fault injection, packet captures, and a controlled testbed.

Exit gate: independent nodes establish, activate, use, and expire routes consistently under adverse transport and fragment behavior.

### Phase 8 - Traffic privacy profiles

Deliverables include padded, mixed, interleaved, and scheduled-cell profiles with correlation experiments and quantified bandwidth/latency costs.

Exit gate: every traffic-analysis claim names its profile, adversary, topology, and measured success metric.

### Phase 9 - Long-range resolution

Deliverables include a separate directory threat model, ownership and freshness rules, replication model, private-query analysis, and poisoning/enumeration tests.

Exit gate: directory behavior does not silently invalidate Core privacy claims.

## Immediate backlog

1. Replace or redesign the C1 eligibility capsule against persistent algebraic tagging and selective failure.
2. State the exact active-security game and required proof obligations.
3. Define M1/W2 in a machine-readable schema and implement an independent codec.
4. Build malformed-message, malformed-cell, reassembly, and nested-candidate fuzzing corpora.
5. Model fragment sprays, overlapping message identifiers, timeout churn, and distributed reassembly exhaustion.
6. Define cell interleaving, fragment-count padding, release delay, and fairness profiles.
7. Measure admission fairness for legitimate discovery under adaptive branch and fragment attacks.
8. Define bounded retransmission without stable cross-hop identifiers.
9. Add transport churn and route-repair experiments.
10. Keep production claims blocked until independent cryptographic and implementation review.
