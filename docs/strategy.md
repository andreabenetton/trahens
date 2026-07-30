# Improvement strategy

## Objective

Turn Trahens into a falsifiable research protocol and then an interoperable experimental overlay. The project succeeds only when it states precisely what each participant learns, what an adversary can observe or modify, what resources each operation consumes, and which privacy property is supported under which profile.

## Design principles

1. **Narrow before extending.** Complete bounded local discovery before global resolution.
2. **Transform every cross-hop handle.** No opaque field is assumed unlinkable merely because it is encrypted.
3. **Separate semantic encoding from observable framing.** M2 describes messages; W2 describes cells.
4. **Separate adversaries and claims.** Cell equality, passive wire-image unlinkability, batch-local matching resistance, active tagging, traffic-flow unlinkability, lifecycle correctness, and resource safety are distinct.
5. **Use explicit cryptographic contracts.** Keys, algorithms, transcript domains, replay equivalence, errors, encodings, and proof obligations are normative.
6. **Keep counterexamples executable.** C1 remains in the suite because a future design must defeat the same ratio-tag experiment, not merely remove its description.
7. **Bound every resource.** Messages, cells, fragments, fan-out, state, queues, timers, and cryptographic work have hard limits.
8. **Make claims executable.** Every claim maps to a test, simulation, attack game, proof obligation, or independent implementation.
9. **Block deployment claims.** Symbolic models and reference implementations are not substitutes for cryptographic review, fuzzing, side-channel analysis, or operational measurement.

## Current architecture

Trahens Core v0.8 is a bounded route-discovery and ready-gated bidirectional route-establishment protocol. It excludes global directory resolution, incentives, inter-domain policy, and a replacement link stack.

U1 removes network-wide discovery handles. Each outgoing branch replaces its capability, tweaks the reply public key, rerandomizes the eligibility capsule, and reconstructs the message.

E1 defines half-open deadlines, deterministic event precedence, candidate windows, delayed candidates, cancellation races, tentative mappings, COMMIT, READY, loss, duplication, and cleanup.

C2 defines the active-security target for destination eligibility: public rerandomization without the recipient key, receiver anonymity, replayable chosen-ciphertext security, and resistance to persistent cross-hop tags. The repository currently provides an executable ideal functionality, not a concrete construction. C1 remains the negative-control eligibility backend and supplies the executable reply-key, nested-candidate, signature, KDF, AEAD, and transcript components.

M2 defines suite-agile canonical variable-length messages. W2 fragments them into fixed 1,052-byte adjacent-link cells and reassembles them under strict byte, context, fragment, suite, and time bounds. W2 equalizes individual cell length but does not hide cell count or timing.

## Current evidence

The integrated C1 experiment reproduces a persistent ratio relation across an honest rerandomizing relay. The separated colluder recognizes the relation and the destination rejects the capsule.

In the symbolic C2 experiment, an upstream marker mutation is not replay-equivalent. The first honest transformation rejects it and no transformed capsule reaches the downstream colluder. This confirms the intended state-machine location of validation and rerandomization, the generic failure path, and cleanup behavior. It does not demonstrate security of the concrete CRYPTO 2021 construction.

## Workstreams

### A. Concrete C2 cryptography

Select the exact anonymous rerandomizable RCCA construction and parameters. Define canonical key, ciphertext, proof, scalar, and group/ring encodings; exact `KeyGen`, `Enc`, `ReRand`, and `Dec`; malformed-input behavior; deterministic vectors; and side-channel requirements. Map the C2 games to the cited construction and assumptions. Obtain independent review.

### B. Suite and transcript composition

Ensure the M2 suite, W2 reassembly suite, endpoint descriptor, reply-key transcript, candidate transcript, COMMIT, and READY cannot be confused or downgraded. Keep eligibility, reply, signing, and adjacent-link keys domain-separated.

### C. Independent codec interoperability

Specify M2 and W2 in a machine-readable schema. Build a second independent implementation, cross-check canonical encodings and malformed inputs, and fuzz envelope, varint, fragmentation, reassembly, nested-candidate, and suite-mismatch paths.

### D. Resource and denial-of-service model

Measure branch amplification, fragment sprays, cryptographic-work exhaustion, distributed peer rotation, invalid C2 proof cost, and selective failure. Enforce pre-cryptographic peer and global limits and account for every rejected operation.

### E. Reliability profile

After concrete C2, define bounded recovery for multi-cell messages. Retransmission, acknowledgement, erasure coding, or repair must use fresh adjacent-link encryption, finite retry counts, bounded reassembly extension, and no stable cross-hop identifier.

### F. Traffic scheduling

Define fragment interleaving, CHAFF, release cadence, cell-count padding, fairness, and rate shaping separately from Core. Measure bandwidth, latency, loss exposure, and correlation advantage for named adversaries.

### G. Overlay prototype

Build the smallest user-space overlay over an existing authenticated transport only after C2 and two codec implementations satisfy their gates. The prototype validates interoperability and operational state behavior; it does not replace IP.

### H. Directory research

Treat registration and long-range resolution as a separate protocol with its own ownership, freshness, private-query, replication, poisoning, enumeration, and selective-denial analysis.

## Iteration model

Each revision contains:

1. a defect or research question;
2. explicit assumptions and proposed change;
3. one or more ADRs;
4. versioned specification changes;
5. executable tests, simulations, vectors, or proof obligations;
6. measured results and known counterexamples;
7. an accept, revise, or revert decision.

A revision is incomplete when it changes prose without changing a testable artifact.

## Phase gates

### Completed research baselines

- Core semantics and expanding-ring policy.
- U1 branch-local structural unlinkability.
- E1 event-driven route lifecycle.
- C1 executable reply/signature component baseline and negative-control eligibility attack.
- M2/W2 message-cell separation and bounded reassembly.
- C2 abstract games, suite integration, and executable ideal functionality.

### Current gate: concrete C2

Exit requires:

- exact construction and parameters;
- canonical encodings and deterministic vectors;
- positive, malformed, receiver-anonymity, RCCA, replay, and tag tests;
- no observable C1 ratio-tag analogue under the declared game;
- independent cryptographic review;
- paper claims aligned exactly with proved and measured properties.

### Subsequent gates

1. bounded reliability for fragmented messages;
2. independent codecs and fuzzing;
3. overlay interoperability under faults and churn;
4. traffic-privacy scheduling with measured correlation results;
5. separate long-range resolution.

## Immediate backlog

1. Implement the selected concrete C2 instantiation outside the simulator.
2. Replace the 640-byte planning budget with exact ciphertext and proof sizes.
3. Add C2 receiver-anonymity, RCCA, and tag-game harnesses against real bytes.
4. Add cross-suite downgrade and transcript-confusion tests.
5. Build a second M2/W2 codec and differential fuzzer.
6. Model invalid-C2 work exhaustion and distributed fragment sprays.
7. Define bounded reliability without stable cross-hop identifiers.
8. Define cell interleaving and fragment-count padding.
9. Keep production claims blocked until independent review and implementation audit.
