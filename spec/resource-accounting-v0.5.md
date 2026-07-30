# Trahens Core v0.5 resource accounting

- Status: Research design draft
- Scope: U1 branch-local discovery and route setup

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
| Received record bytes | Link decryption | Time-window replenishment |
| Link replay marker | Replay insertion | Replay deadline |
| Branch context | Full branch allocation | Expiry, cancellation, peer loss, eviction |
| Child mapping | Token, blinding, and rerandomization | Branch expiry or candidate completion |
| URE rerandomization | Primitive invocation | Time-window replenishment |
| Reply-key blinding | Group operation | Time-window replenishment |
| Mixing queue bytes | Queue insertion | Release or drop |
| Candidate verification | KEM open or authentication | Time-window replenishment |
| Tentative route | Label allocation | Commit, abort, expiry, eviction |
| Active route | Activation | Close, expiry, failure, eviction |

## 4. Admission order

Implementations SHOULD apply:

1. record-size class;
2. peer rate and byte bucket;
3. link epoch and exact replay check;
4. adjacent-link authentication;
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
