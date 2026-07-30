# Improvement strategy

## Objective

Turn the 2020 concept into a falsifiable research program and then into an interoperable experimental protocol. The project succeeds only if it states precisely:

- what information each participant learns;
- what an adversary can observe or modify;
- how much bandwidth, computation, and relay state discovery consumes;
- which privacy properties survive each compromise and observation model;
- which components are core mechanisms and which are deployment profiles.

## Design principles

1. **Narrow before extending.** Solve bounded local discovery before global name resolution.
2. **Transform every cross-hop handle.** A privacy claim fails if any opaque field remains a stable equality token.
3. **Separate privacy properties.** Wire-image unlinkability, batch-local matching resistance, and traffic-flow unlinkability are distinct.
4. **No implicit cryptography.** Every key, transcript, nonce, proof, error rule, and domain separator must be defined.
5. **Bound every resource.** Messages, fan-out, branch contexts, candidate responses, lifetimes, queues, and cryptographic operations require explicit limits.
6. **Make claims executable.** Every security or scalability claim maps to a test, simulation, model, or proof obligation.
7. **Preserve evolution.** Version and suite negotiation must resist downgrade without becoming a fingerprinting oracle.
8. **Keep the legacy draft immutable.** Improvements occur in versioned specifications and the formal rewrite.

## Current architecture

Trahens Core v0.3 is a bounded discovery and opaque bidirectional route-establishment protocol. It excludes the legacy Beacon/Authority directory, economic incentives, inter-domain policy, and a replacement layer-2 stack.

The U1 profile removes attempt-wide wire identifiers. Every outgoing branch replaces its token and capabilities, blinds the reply public key, rerandomizes the hidden eligibility selector, reconstructs the canonical body, pads it to a fixed record class, and passes it through a mixing boundary. This restores the structure required for the original non-adjacent bit-pattern unlinkability objective.

The restoration is conditional rather than absolute. U1 assumes a secure rerandomizable-encryption primitive and reply-key construction, and its batch-local claim excludes precise timing, queue observation, and active modification. The repository therefore distinguishes a restored protocol objective from a completed cryptographic proof.

## Workstreams

### A. Core semantics

Complete the DISCOVER, CANDIDATE, COMMIT, READY, ABORT, CLOSE, expiry, and cleanup behavior under event time, loss, delay, duplication, and cancellation.

### B. Unlinkability and cryptography

Select and analyze the URE eligibility primitive and tweakable reply KEM. Define canonical transcripts, depth-hiding candidate capsules, malformed-ciphertext behavior, test vectors, and active-tagging experiments. Independent review is a release gate.

### C. Resource and denial-of-service model

Because U1 removes attempt-wide duplicate suppression, quantify branch-context amplification and enforce per-link, per-peer, per-node, queue, time-window, and global limits before expensive operations.

### D. Simulation and measurement

Use deterministic models to compare discovery success, cumulative work, peak concurrent state, delayed-candidate behavior, route setup, churn, and attacker strategies. Privacy experiments must report adversarial matching success rather than infer privacy from encryption alone.

### E. Overlay prototype

After the event model and first cryptographic profile stabilize, implement the smallest interoperable user-space overlay over an existing authenticated transport. The prototype validates encoding and state machines; it does not replace IP.

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

### Phase 3 - Event-driven route lifecycle: next

Deliverables:

- event queue and explicit clocks;
- candidate windows and late-candidate policy;
- tentative reverse state and candidate return;
- COMMIT/READY activation;
- expiry, cancellation, and deterministic cleanup;
- packet loss, delay, duplication, and reordering;
- malicious branch generation and token-bucket admission.

Exit gate: all route-state transitions and races produce deterministic, bounded outcomes.

### Phase 4 - Cryptographic profile v0.1

Deliverables:

- concrete URE and reply-KEM constructions;
- transcript definitions and domain separation;
- identity or credential binding;
- downgrade, replay, and malformed-ciphertext rules;
- canonical test vectors;
- active-tagging analysis;
- independent cryptographic review.

Exit gate: no security behavior depends on undefined generic primitives, and the U1 claim is either proved under stated assumptions or narrowed.

### Phase 5 - Overlay interoperability prototype

Deliverables include a canonical codec, conformance harness, fault injection, packet captures, and a controlled testbed.

Exit gate: independent nodes establish, activate, use, and expire routes consistently under adverse transport behavior.

### Phase 6 - Traffic privacy profiles

Deliverables include padded, mixed, and scheduled-link profiles with correlation experiments and quantified bandwidth/latency costs.

Exit gate: every traffic-analysis claim names its profile, adversary, topology, and measured success metric.

### Phase 7 - Long-range resolution

Deliverables include a separate directory threat model, ownership and freshness rules, replication model, private-query analysis, and poisoning/enumeration tests.

Exit gate: directory behavior does not silently invalidate Core privacy claims.

## Immediate backlog

1. Add event time and candidate-window configuration to the simulator.
2. Model delayed candidates from earlier rings and cancellation races.
3. Implement candidate reverse propagation and tentative relay state.
4. Implement COMMIT and READY propagation and route activation.
5. Add deterministic expiration and cleanup under lost final messages.
6. Add malicious fresh-branch floods, replay, candidate spam, and token buckets.
7. Measure peak concurrent state in addition to cumulative allocations.
8. Add the U1 two-relay matching harness and unchanged-field negative tests.
9. Select candidate URE and reply-KEM constructions for cryptographic review.
10. Produce canonical message and transcript test vectors before network I/O.
