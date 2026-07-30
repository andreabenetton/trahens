# Improvement strategy

## Objective

Turn the 2020 concept into a falsifiable research program and then into an interoperable experimental protocol. The project succeeds only if it can state precisely:

- what information each participant learns;
- what an adversary can observe or modify;
- how much bandwidth, computation, and relay state discovery consumes;
- which privacy properties survive realistic compromise and traffic observation;
- which components are essential and which are deployment profiles.

## Design principles

1. **Narrow before extending.** Solve bounded local discovery before global name resolution.
2. **Separate mechanism from privacy profile.** Core routing correctness must work without claiming that every deployment provides the same traffic-analysis resistance.
3. **No implicit cryptography.** Every key, transcript, nonce, signature, and validation rule must be defined.
4. **Bound every resource.** Messages, fan-out, state, retries, lifetimes, and cryptographic operations require explicit limits.
5. **Make claims executable.** Every security or scalability claim maps to a test, simulation, model, or proof obligation.
6. **Preserve protocol evolution.** Versioning and algorithm negotiation must resist downgrade and fingerprinting.
7. **Keep the legacy draft immutable.** Improvements happen in new specifications and paper revisions.

## Workstreams

### A. Protocol scope and semantics

Define Trahens Core as a bounded discovery and bidirectional route-state establishment protocol. Exclude the global directory, economic incentives, inter-domain policy, and a replacement layer-2 stack from Core v0.1.

### B. Security and privacy model

Create adversary classes rather than one ambiguous global adversary. Define confidentiality, authentication, route-position privacy, endpoint unlinkability, and availability separately. State where each property fails.

### C. Cryptographic redesign

Replace BIP32-derived routing keys and generic `E/S/V` notation with explicit, reviewed constructions. Bind every message to the protocol version, discovery instance, direction, hop context, and expiration. Add replay and downgrade defenses.

### D. Resource and denial-of-service model

Specify duplicate suppression, per-neighbor and per-origin budgets, state caps, cryptographic work limits, expiration, and overload behavior. A relay must reject work before expensive operations whenever possible.

### E. Simulation and measurement

Build a deterministic simulator before network code. Measure flood growth, route discovery probability, state occupancy, churn recovery, malicious fan-out, and the privacy/cost trade-off of cover traffic.

### F. Overlay prototype

Implement the smallest interoperable prototype over an existing transport. The prototype should validate state machines and encoding, not attempt to replace IP.

### G. Directory research

Treat beacon/authority resolution as a separate protocol. Compare multiple designs, including replicated rendezvous, private-information-retrieval-compatible directories, and capability-based introduction. Do not assume repeated hashing provides query privacy.

## Iteration model

Each iteration is a small, reviewable unit with:

1. a question or defect;
2. a proposed change;
3. an ADR when architecture changes;
4. specification updates;
5. tests or simulations;
6. measured results;
7. a decision to accept, revise, or revert.

An iteration is incomplete when it only changes prose without changing a testable artifact.

## Phases and gates

### Phase 0 - Repository and evidence baseline

Deliverables:

- immutable legacy source and PDF;
- baseline assessment;
- glossary and open questions;
- ADR process;
- reproducible repository checks.

Exit gate: the original design can be cited without being mistaken for the current specification.

### Phase 1 - Core v0.1 semantics

Deliverables:

- entities and trust boundaries;
- relay, initiator, and responder state machines;
- message taxonomy;
- route-state lifecycle;
- protocol invariants;
- explicit non-goals.

Exit gate: two implementers can independently describe the same state transitions and failure behavior.

### Phase 2 - Abuse-resistant discovery

Deliverables:

- discovery identifiers and duplicate suppression;
- hard fan-out and hop limits;
- per-link quotas;
- state and CPU budgets;
- replay and stale-message behavior;
- overload tests in the simulator.

Exit gate: every accepted input has a calculable upper bound on local work and retained state.

### Phase 3 - Cryptographic profile v0.1

Deliverables:

- concrete key establishment and signature profiles;
- transcript definitions and domain separation;
- identity-to-ephemeral-key binding;
- downgrade and replay resistance;
- test vectors;
- independent cryptographic review.

Exit gate: no security behavior depends on undefined generic cryptographic functions.

### Phase 4 - Deterministic simulator

Deliverables:

- reproducible topologies and events;
- honest and malicious relay strategies;
- metrics and experiment manifests;
- baseline results for scale, churn, and attack cases.

Exit gate: design choices can be compared quantitatively before network implementation.

### Phase 5 - Overlay interoperability prototype

Deliverables:

- canonical binary encoding;
- at least two independent node implementations or one implementation plus a conformance harness;
- interoperability tests;
- packet captures and failure injection;
- bounded local discovery on a controlled testbed.

Exit gate: nodes establish and expire routes consistently under packet loss, duplication, and reordering.

### Phase 6 - Privacy profiles

Deliverables:

- baseline encrypted-link profile;
- padded control-plane profile;
- constant-rate or scheduled-link profile;
- measured bandwidth and latency cost;
- adversarial correlation evaluation.

Exit gate: privacy claims name the exact deployment profile and measured adversary.

### Phase 7 - Long-range resolution

Deliverables:

- separate directory threat model;
- registration ownership and freshness rules;
- replication and consistency model;
- private-query analysis;
- resistance to enumeration, poisoning, and selective denial.

Exit gate: the directory does not silently invalidate the privacy properties of Core.

## Immediate backlog

1. Validate Core v0.1 state machines against the legacy algorithms.
2. Remove all normative dependence on obfuscated neighbor degree from Core.
3. Define a relay resource-accounting model.
4. Decide whether route labels are random capabilities or hashes of ephemeral keys.
5. Specify discovery deduplication and route-candidate diversity.
6. Model colluding adjacent relays and compromised responders.
7. Replace the original cryptographic derivation scheme.
8. Produce message test vectors before implementing network I/O.
