# Improvement strategy

## Objective

Develop Trahens as a falsifiable privacy-preserving route-discovery protocol and then as an interoperable experimental overlay. Every security claim must identify the adversary, observation boundary, required profile, retained leakage, and supporting test, proof obligation, or measurement.

## Active architecture

Core v1.3 binds U1, E1, R1, M2, W2, T1, T2, and the T3 analysis profile.

- U1 replaces branch-local capabilities and representations at each honest relay.
- E1 defines deterministic state transitions, half-open deadlines, candidate windows, COMMIT, READY, cancellation, and cleanup.
- R1 discovers generic rendezvous gateways and presents a one-time endpoint capability only after READY.
- M2 defines canonical variable-length logical messages.
- W2 defines canonical fragmentation and the fixed 1,052-byte adjacent-link record.
- T1 adds encrypted selective ACKs, bounded retries, fresh retry ciphertexts, and fragment interleaving.
- T2 defines fixed and quantized-adaptive epochs, encrypted schedule negotiation, weighted fair service, bounded queues, overload rejection, and explicit rate-trace leakage.
- T3 compares fixed, adaptive, and hybrid schedules under an exact equal bandwidth budget and attacks them with multi-link route classification and active probing.

R1 is Gate B of the cryptographic decision. The active protocol no longer depends on receiver-anonymous universal rerandomization. C1, symbolic C2, and the C2 k=2 transcription remain research providers and mandatory negative or composition controls.

## Design principles

1. **No endpoint selector in active discovery.** Raw capability, commitment, endpoint key, address, gateway pseudonym, and endpoint handle are prohibited from DISCOVER.
2. **Transform every branch-local handle.** Tokens, query nonces, reply keys, message identifiers, padding, and link ciphertexts are replaced for each child.
3. **Separate messages, recovery, and release.** M2 is semantic; W2 fragments; T1 repairs; T2 decides bounded service and public cadence.
4. **Separate route activation from rendezvous.** CANDIDATE is tentative, COMMIT reserves, READY activates, and only then may RENDEZVOUS_OPEN carry the capability.
5. **Make trust and observation boundaries explicit.** R1 requires a directory and gateways; T2 exposes public rate class and epoch boundaries.
6. **Keep counterexamples executable.** C1 and the C2 audit remain reproducible and fail closed.
7. **Bound every resource.** Cells, bytes, fragments, ACKs, retries, timers, schedule controls, CHAFF, queues, deficits, contexts, branches, registrations, and failed redemptions have finite limits.
8. **Normalize failure behavior.** Invalid capability, suite, message, cell, route, signature, reassembly, and schedule negotiation failures must not become detailed remote oracles.
9. **Do not turn adaptation into an anonymity claim.** Adaptive scheduling is an efficiency/congestion mechanism whose public class sequence is treated as leakage.
10. **Compare privacy policies at equal public cost.** A schedule comparison must equalize record length and total cell budget before attributing classifier performance to trace shape.
11. **Block production claims.** Reference code and deterministic simulations are not independent cryptographic, transport, or operational validation.

## Current evidence

R1 erases an upstream literal nonce marker at the first honest replacement. The correct capability redeems once, while replay, expiry, wrong gateway, all-zero input, and duplicate registration fail. The raw capability is absent from encoded DISCOVER bytes.

T1 recovers missing adjacent-link fragments with finite selective acknowledgements and retries. T2 demonstrates deterministic overload, weighted sharing, finite rate transitions, and the cost/leakage distinction between fixed, adaptive, and work-conserving release. Under the current equal-overload model, adaptive scheduling delivered all admitted work with substantially less CHAFF than fixed-high service, but its public rate sequence permitted perfect classification by the deliberately simple rate-presence observer. T3 then equalizes total public bandwidth and still finds route information in adaptive trace shape and active-probe response. The hybrid evaluation envelope reduces those signals through smoothing, decoy uplifts, and non-boundary transitions, but it is not a proof or a deployable scheduler.

The C1 negative control still carries a persistent algebraic ratio relation through an honest rerandomizing relay. The symbolic C2 control rejects a non-replay-equivalent mutation before an honest relay emits a child. The C2 k=2 audit reproduces executable source equations and demonstrates that the literal finite-field reduction is not multiplicative over tested small chains.

## Workstreams

### A. Private descriptor distribution

Specify authentication, private query, replication, rotation, revocation, enumeration resistance, and what the directory learns.

### B. Gateway trust reduction

Evaluate multiple gateways, short epochs, operator separation, threshold registration, auditable selective denial, and endpoint authentication limiting a stolen-capability race.

### C. Recovery and correlated loss

Extend T1 with adversarial ACK behavior, schedule-control loss, bounded redundancy, and queue-aware deadlines. Compare retransmission and erasure coding under correlated loss.

### D. Congestion and adaptive schedules

Complete T2 negotiation under loss, simultaneous offers, restart, and peer disagreement. Evaluate randomized or privacy-budgeted adaptation. Treat rate changes as observable until a formal privacy mechanism and classifier study justify a narrower claim.

### E. Multi-link traffic analysis

The deterministic equal-budget count baseline, route classifier, correlated-cross-traffic condition, boundary metric, and active probe are complete. Next, add packet-level timing, heterogeneous propagation delay and clocks, partial observation, route churn, open-world imbalance, shared bottlenecks, deployment-derived traces, and stronger learned classifiers.

### F. Independent interoperability

Implement M2/W2/T1/T2 independently, exchange conformance corpora, fuzz malformed inputs, and verify identical acceptance, rejection, recovery, and scheduling behavior.

### G. Retained cryptography

Review the additive reply-key transform, custom KEM, nested candidate chain, transcript binding, and failure timing. Preserve the C2 author query and exhaustive checker; reopen endpoint-specific eligibility only after independent review.

## Completion gates

### Gate R1-private

- descriptor queries have a specified privacy goal and adversary;
- descriptors are authenticated, finite, rotatable, and revocable;
- directory/gateway collusion leakage is quantified;
- abuse and replication limits are defined.

### Gate T2-transport

- recovery, queue, negotiation, and retry state are finite; **baseline passed**;
- rate transitions are quantized and boundary-aligned; **baseline passed**;
- fair service under sustained backlogs is measured; **baseline passed**;
- fixed and adaptive privacy claims are separated; **baseline passed**;
- schedule-control loss, conflict, restart, and independent implementation remain open;
- deterministic equal-budget multi-link classifier and active-probe baseline passed;
- packet-level, open-world, learned, and deployment-trace evaluation remains open.

### Gate I1-interoperability

- two independent codecs and state machines agree;
- fuzzing covers message, cell, reassembly, recovery, schedule, candidate, and capability paths;
- all tracked vectors reproduce;
- externally observable failure classes match.

Only after these gates should the project attempt a wider overlay deployment or traffic-flow privacy claim.
