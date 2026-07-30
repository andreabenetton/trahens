# Improvement strategy

## Objective

Turn the protocol concept into a falsifiable research program and then into an interoperable experimental protocol. The project succeeds only if it states precisely:

- what information each participant learns;
- what an adversary can observe or modify;
- how much bandwidth, computation, and relay state discovery consumes;
- which privacy properties survive each compromise and observation model;
- which components are core mechanisms and which are deployment profiles.

## Design principles

1. **Narrow before extending.** Solve bounded local discovery before global name resolution.
2. **Transform every cross-hop handle.** A privacy claim fails if any opaque field remains a stable equality token.
3. **Separate security properties.** Wire-image unlinkability, batch-local matching resistance, traffic-flow unlinkability, and lifecycle correctness are distinct.
4. **No implicit cryptography.** Every key, transcript, nonce, proof, error rule, and domain separator must be defined.
5. **Bound every resource.** Messages, fan-out, branch contexts, candidate responses, lifetimes, queues, and cryptographic operations require explicit limits.
6. **Make claims executable.** Every security or scalability claim maps to a test, simulation, model, or proof obligation.
7. **Preserve evolution.** Version and suite negotiation must resist downgrade without becoming a fingerprinting oracle.
8. **Keep evidence immutable.** Improvements occur in versioned specifications and the standalone formal paper.

## Current architecture

Trahens Core v0.6 is a bounded discovery and ready-gated bidirectional route-establishment protocol. It excludes global directory resolution, incentives, inter-domain policy, and a replacement link stack.

U1 removes attempt-wide wire identifiers. Every outgoing branch replaces its capability, additively tweaks the reply public key, rerandomizes the hidden eligibility capsule, reconstructs the canonical body, pads it to one W1 record, and obtains fresh adjacent-link encryption.

E1 defines half-open state deadlines, deterministic equal-time precedence, candidate windows, delayed candidates across local rings, cancellation races, tentative reverse mappings, pending-ready reservation, reverse activation, loss, duplication, and deterministic cleanup.

C1 fixes the concrete classical operations. W1 fixes the adjacent-link record at 1,052 bytes and moves message type and protocol fields inside the encrypted 1,024-byte body. The event model executes C1, W1, and E1 together.

The active-tagging experiment found a persistent ratio relation in the C1 URE consistency pair. Active-adversary unlinkability is not claimed. This negative result is now a design gate: the eligibility construction must be replaced or strengthened before an active-security claim is reconsidered.

## Workstreams

### A. Core semantics

Maintain the completed E1 baseline for DISCOVER, CANDIDATE, COMMIT, READY, ABORT, CANCEL, CLOSE, expiry, loss, delay, duplication, reordering, and cancellation. Extend only through versioned lifecycle profiles and conformance tests.

### B. Unlinkability and cryptography

Review and challenge the concrete C1 URE and reply KEM. Align the construction with an explicit security definition, define depth-hiding candidate classes, expand malformed-input vectors, and run active-tagging and related-key experiments. Independent review remains a release gate.

### C. Resource and denial-of-service model

Because U1 removes attempt-wide duplicate suppression, quantify branch-context amplification and enforce per-link, per-peer, per-node, queue, time-window, and global limits before expensive operations.

### D. Simulation and measurement

Use deterministic models to compare discovery success, cumulative work, peak concurrent state, delayed-candidate behavior, route setup, churn, and attacker strategies. Privacy experiments must report adversarial matching success rather than infer privacy from encryption alone.

### E. Overlay prototype

Begin with schema, codec, and conformance work using C1 only as a research profile. After two independent codecs agree on vectors and negative inputs, implement the smallest user-space overlay over an existing authenticated transport. The prototype validates interoperability and state machines; it does not replace IP.

### F. Traffic-scheduling profiles

Specify batching, chaff, release cadence, overflow, and constant- or quantized-rate behavior separately from Core. Measure the latency and bandwidth cost against named correlation adversaries.

### G. Directory research

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

The original source and PDF are immutable, current material is versioned separately, and repository checks are reproducible.

### Phase 1 - Core correctness baseline: complete

Core v0.2 established the first coherent message taxonomy, lifecycle, state machines, and bounded expanding-ring policy.

### Phase 2 - U1 structural unlinkability: complete as a research design

Core v0.3 removes stable cross-hop handles and defines branch-local transformation, fixed record classes, mixing, and a conditional challenge game. The simulator records the cost of losing attempt-wide deduplication.

Gate status: protocol structure accepted; cryptographic guarantee not yet approved.

### Phase 3 - Event-driven route lifecycle: complete as a deterministic model

Core v0.4 and E1 define event ordering, candidate windows, delayed candidates, tentative reverse state, pending-ready reservation, final READY gating, cancellation races, loss, exact duplication, fresh-branch attacks, and deterministic cleanup.

Gate status: all modeled route-state transitions and races have bounded deterministic outcomes; network implementation remains unvalidated.

### Phase 4 - Cryptographic profile C1: concrete research baseline complete

Delivered:

- concrete GJJS-style URE and additive reply-key constructions;
- canonical `ristretto255` point/scalar rules and endpoint descriptors;
- KDF, AEAD, signature, and transcript domain separation;
- generic malformed-input behavior;
- deterministic vectors and executable reference code;
- positive and negative conformance tests.

Gate status: interoperability ambiguity is closed, but the production-security gate is open. Independent proof review, active-tagging analysis, related-key analysis, side-channel review, and a post-quantum strategy remain required.


### Phase 5 - W1 and integrated active-security analysis: complete as a research baseline

Delivered:

- one 1,052-byte W1 control record and exact message layouts;
- link authentication, canonical parsing, and exact byte accounting;
- integrated C1 candidate, COMMIT, and READY processing in the E1 event model;
- adjacent-link tampering tests;
- a reproducible persistent-ratio-tag counterexample;
- explicit closure of the active-unlinkability claim gate.

Gate status: codec interoperability can proceed, but active-security approval is blocked until the eligibility construction is replaced or proven against the identified attack class.

### Phase 6 - Overlay interoperability prototype

Deliverables include a canonical codec, conformance harness, fault injection, packet captures, and a controlled testbed.

Exit gate: independent nodes establish, activate, use, and expire routes consistently under adverse transport behavior.

### Phase 7 - Traffic privacy profiles

Deliverables include padded, mixed, and scheduled-link profiles with correlation experiments and quantified bandwidth/latency costs.

Exit gate: every traffic-analysis claim names its profile, adversary, topology, and measured success metric.

### Phase 8 - Long-range resolution

Deliverables include a separate directory threat model, ownership and freshness rules, replication model, private-query analysis, and poisoning/enumeration tests.

Exit gate: directory behavior does not silently invalidate Core privacy claims.

## Immediate backlog

1. Replace or redesign the C1 eligibility capsule against persistent algebraic tagging and selective failure.
2. State the exact active-security game and required proof obligations.
3. Implement W1 independently from a reviewed schema and cross-check canonical encodings.
4. Build a malformed-record and malformed-nested-candidate fuzzing corpus.
5. Extend the integrated model with batching, release delay, and two-relay correlation measurements.
6. Model distributed fresh-branch attackers, peer rotation, and candidate spam.
7. Measure admission fairness for legitimate discovery under adaptive attack.
8. Define bounded retransmission without cross-hop identifiers.
9. Add transport churn and route-repair experiments.
10. Keep production claims blocked until independent cryptographic and implementation review.
