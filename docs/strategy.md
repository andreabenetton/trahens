# Improvement strategy

## Objective

Develop Trahens as a falsifiable privacy-preserving route-discovery protocol and then as an interoperable experimental overlay. Every security claim must identify the adversary, observation boundary, required profile, retained leakage, and supporting test, proof obligation, or measurement.

## Active architecture

Core v1.1 binds U1, E1, R1, M2, W2, and T1.

- U1 replaces branch-local capabilities and representations at each honest relay.
- E1 defines deterministic state transitions, half-open deadlines, candidate windows, COMMIT, READY, cancellation, and cleanup.
- R1 discovers generic rendezvous gateways and presents a one-time endpoint capability only after READY.
- M2 defines canonical variable-length logical messages.
- W2 defines canonical fragmentation and the fixed 1,052-byte adjacent-link record.
- T1 adds encrypted selective ACKs, bounded retries, fresh retry ciphertexts, round-robin fragment interleaving, and fixed-schedule or work-conserving release.

R1 is Gate B of the cryptographic decision. The active protocol no longer depends on receiver-anonymous universal rerandomization. C1, symbolic C2, and the C2 k=2 transcription remain research providers and mandatory negative or composition controls.

## Design principles

1. **No endpoint selector in active discovery.** The raw capability, commitment, endpoint key, address, gateway pseudonym, and endpoint handle are prohibited from DISCOVER.
2. **Transform every branch-local handle.** Tokens, query nonces, reply keys, message identifiers, padding, and link ciphertexts are replaced for each child.
3. **Separate messages from transport.** M2 is semantic and variable length; W2 defines canonical fragments; T1 defines DATA, ACK, CHAFF, recovery, and release scheduling.
4. **Separate route activation from rendezvous.** CANDIDATE is tentative, COMMIT reserves, READY activates, and only then may RENDEZVOUS_OPEN carry the capability.
5. **Make trust boundaries explicit.** R1 requires a directory and gateways; private lookup and operator separation are separate profiles.
6. **Keep counterexamples executable.** C1 and the C2 audit remain reproducible and fail closed.
7. **Bound every resource.** Cells, bytes, fragments, ACKs, retries, RTO timers, schedule slots, CHAFF, contexts, branches, candidates, queues, work, registrations, and failed redemptions have finite limits.
8. **Normalize failure behavior.** Invalid capability, suite, message, cell, route, signature, and reassembly failures must not become detailed oracles.
9. **Block production claims.** Reference code and deterministic simulations are not independent cryptographic or operational validation.

## Current evidence

The R1 event model erases an upstream literal nonce marker at the first honest replacement. The correct capability redeems once, while replay, expiry, wrong gateway, all-zero input, and duplicate registration fail. The raw capability is absent from encoded DISCOVER bytes.

The C1 negative control still carries a persistent algebraic ratio relation through an honest rerandomizing relay. The symbolic C2 control rejects a non-replay-equivalent mutation before an honest relay emits a child. The C2 k=2 audit reproduces the source equations that are executable and demonstrates that the literal finite-field reduction is not multiplicative over the tested small chains.

## Workstreams

### A. Private descriptor distribution

Specify how descriptors are authenticated, privately queried, replicated, rotated, revoked, and protected from enumeration. Define what the directory learns and how gateway pseudonyms are selected.

### B. Gateway trust reduction

Evaluate multiple gateways, short epochs, operator separation, threshold registration, auditable selective denial, and end-to-end authentication that limits a stolen capability race.

### C. Reliability

T1 now provides bounded cumulative selective ACKs, RTO backoff, missing-fragment retransmission, fresh retry ciphertexts, and finite completion caches. The next reliability work is congestion interaction, schedule-capacity failure, forward error correction, and adversarial ACK behavior.

### D. Traffic scheduling

T1 fixed-schedule mode defines round-robin fragment interleaving and CHAFF-filled slots. The current claim is only link-local schedule-shape equivalence inside a pre-existing non-overflowing epoch. Next work must evaluate schedule establishment, adaptive rates, randomized release, congestion, and global cross-link classifiers before any traffic-flow claim.

### E. Independent interoperability

Implement M2/W2 and E1 independently, exchange conformance corpora, fuzz malformed inputs, and verify that both implementations produce identical acceptance and rejection behavior.

### F. Retained cryptography

Review the additive reply-key transform, custom KEM, nested candidate chain, transcript binding, and failure timing. Preserve the C2 author query and exhaustive checker; reopen endpoint-specific eligibility only after a corrected construction is independently reviewed.

## Completion gates

### Gate R1-private

- descriptor queries have a specified privacy goal and adversary;
- descriptors are authenticated, finite, rotatable, and revocable;
- directory and gateway collusion leakage is quantified;
- abuse and replication limits are defined.

### Gate T1-reliability

- bounded recovery improves multi-cell success; **baseline passed**;
- retransmission creates no stable cross-hop handle; **specified and tested**;
- retries, acknowledgements, queues, timers, and buffers have hard limits; **specified and tested**;
- loss, duplication, retry exhaustion, deep fragmentation, and trace shape are tested; **baseline passed**;
- congestion-aware overload and independent implementation remain open.

### Gate I1-interoperability

- two independent codecs and state machines agree;
- fuzzing covers message, cell, reassembly, candidate, and capability paths;
- all tracked vectors reproduce;
- externally observable failure classes match.

Only after these gates should the project attempt a wider overlay deployment or traffic-privacy claim.
