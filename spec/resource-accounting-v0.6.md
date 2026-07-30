# Trahens Core v0.6 resource accounting

- Status: Research design draft
- Scope: U1 branch-local discovery, E1 route setup, C1 cryptography, and W1 wire processing

## 1. Objective

Removing a stable attempt identifier prevents network-wide duplicate suppression. Every accepted branch must therefore have a calculable upper bound on local work, outgoing amplification, and retained state.

## 2. Counter hierarchy

A relay maintains counters at:

1. adjacent peer session;
2. link epoch and token replay domain;
3. branch context;
4. physical-node or local-service identity;
5. rolling time window;
6. node-global memory, timer, byte, and cryptographic-work pools;
7. U1 mixing queue and record class.

An input is admitted only when every applicable counter has capacity.

## 3. Accounted resources

| Resource | Charged before | Released or replenished |
|---|---|---|
| Received W1 bytes | Before link decryption | Time-window replenishment |
| Link replay marker | Replay insertion | Replay deadline |
| Branch context | Full branch allocation | Expiry, cancellation, peer loss, eviction |
| Child mapping | Token, blinding, and rerandomization | Branch expiry or candidate completion |
| URE rerandomization | Primitive invocation | Time-window replenishment |
| Reply-key blinding | Group operation | Time-window replenishment |
| Mixing queue bytes | Queue insertion | Release or drop |
| Candidate layer bytes and depth | Before each KEM open | Candidate completion or time-window replenishment |
| Candidate verification | KEM open, AEAD open, descriptor check, or signature | Time-window replenishment |
| Tentative route | Label allocation | Commit, abort, expiry, eviction |
| Active route | Activation | Close, expiry, failure, eviction |

## 4. Admission order

Implementations SHOULD apply:

1. exact 1,052-byte W1 record length;
2. peer rate and byte bucket;
3. link epoch and exact replay check;
4. adjacent-link ChaCha20-Poly1305 authentication and 1,024-byte plaintext recovery;
5. version, profile, and canonical parsing;
6. expiry and propagation bounds;
7. peer and physical-node branch-context cap;
8. global memory and timer reservation;
9. URE and group-operation work tokens;
10. full branch allocation;
11. child selection and outgoing byte reserve;
12. mixing-queue reserve.

## 5. Mandatory U1 bounds

A conforming node defines finite values for:

- branch contexts per peer;
- branch contexts per physical node;
- global branch contexts;
- child mappings per branch;
- candidate responses per branch and child;
- URE operations per second;
- group operations per second;
- mixing queue bytes and records;
- maximum batching delay;
- tentative and active route counts;
- all state lifetimes.

## 6. Overload behavior

Recommended discard order, first to last:

1. malformed or unauthenticated record;
2. exact replay beyond replay-marker capacity;
3. chaff above minimum privacy policy;
4. new branch from the most over-budget peer;
5. additional child mapping;
6. additional candidate response;
7. tentative route;
8. idle active route;
9. active route carrying admitted traffic.

When privacy policy requires a minimum chaff rate, the implementation must reserve its cost separately rather than silently violating the profile under load.

## 7. Simulator interpretation

The U1 simulator counts one accepted branch context for every admitted path ingress. It knows the complete path only to measure hidden loop re-entry. Protocol participants do not receive that path.

`context_amplification` is

\[
A_c=\frac{B}{U},
\]

where \(B\) is accepted branch contexts and \(U\) is unique physical relays reached. Values above one quantify the state cost of converging branches and loops after removing attempt-wide deduplication.
## 8. E1 concurrent-state accounting

E1 distinguishes cumulative allocations from concurrent live state. Implementations and evaluations MUST account separately for:

- live branch contexts;
- tentative route mappings;
- pending-ready reservations;
- active route mappings;
- responder offers;
- initiator candidate and transaction state.

For each class, report cumulative allocations, peak concurrent entries, final entries, and deadline-driven releases. Cumulative allocation alone can hide an unsafe concurrency peak.

Route capacity is reserved when COMMIT transitions a mapping to `PENDING_READY`. This reservation counts against active-route capacity even though data remains unauthorized. READY converts the reservation rather than allocating an unbounded additional entry.

## 9. Ingress-peer token buckets

A fresh DISCOVER consumes one token from a bucket scoped at least to `(link epoch, ingress peer, receiving node)`. Exact replay is rejected before token consumption. Let capacity be `b`, refill interval `r`, and refill amount `a`. The available token count is bounded by `b`; it never becomes negative.

Token buckets MUST be combined with per-node and node-global capacity. A distributed set of peers can each remain within its bucket while exhausting a global resource.

An evaluation MUST report token-bucket drops separately for legitimate and malicious workloads when the simulator can classify them. A defense that reduces attack work but disproportionately rejects legitimate first-hop branches requires policy revision.

## 10. Event-driven simulator interpretation

The E1 simulator accounts network transmissions when a record is emitted, including transport duplicates. Loss consumes transmission budget because the sender performed the work. Exact duplicate delivery does not allocate a second branch or route context.

The simulator reports:

- legitimate and attack transmissions;
- legitimate and attack branch allocations;
- branch, responder-offer, initiator-candidate, tentative, pending, and active peaks;
- loss, exact replay, token-bucket, capacity, and per-node drops;
- route setup failures and final cleanup.

The full path and traffic classification are simulator-only measurement aids and are not protocol-visible fields.


## 11. W1 byte accounting

The reference codec charges exactly 1,052 received bytes and, for each emitted record, exactly 1,052 transmitted bytes. Padding bytes are real bandwidth and MUST be included. Implementations MUST report at least:

- received, authenticated, rejected, and transmitted W1 records;
- complete wire bytes by legitimate, chaff, and adversarial class when the experiment can classify them;
- link-authentication failures;
- codec and canonical-encoding failures;
- record drops before and after expensive cryptography;
- mixing-queue byte occupancy and release delay.

A fixed-size record does not permit byte accounting to be replaced by an abstract message count.

## 12. Integrated C1 work accounting

The reference model charges separately for:

- URE point decoding and validation;
- URE rerandomization;
- reply-key tweak group operations;
- candidate KEM encapsulation and opening;
- candidate AEAD sealing and opening;
- Ed25519 signing and verification;
- COMMIT and READY proof generation and verification;
- nested candidate layers opened;
- malformed or tagged capsules reaching endpoint eligibility validation.

State reservation MUST precede expensive work only when the reservation itself is bounded and is released on every failure path.

## 13. Active-tag measurements

Active-tag experiments MUST report:

- tags created by compromised relays;
- downstream tag observations;
- endpoint cryptographic rejection;
- route success or failure;
- residual state after all deadlines;
- whether the tag changed record length, timing class, or only algebraic content.

The ratio-tag experiment is a security counterexample, not a production feature. It MUST remain behind a research-only fault-injection interface.
