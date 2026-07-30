<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v0.8 resource accounting

- Status: Active research design
- Scope: U1 branch-local discovery, E1 route setup, C2 eligibility, C1 reply/signature components, M2 logical messages, and W2 cells

## 1. Objective

Removing a stable attempt identifier prevents network-wide duplicate suppression. W2 fragmentation additionally permits one logical message to reserve multiple fixed cells and temporary reassembly memory. Every accepted cell and message must therefore have a calculable upper bound on local work, outgoing amplification, and retained state.

## 2. Counter hierarchy

A relay maintains counters at:

1. adjacent peer session;
2. link epoch and sequence replay domain;
3. W2 reassembly context;
4. branch context;
5. physical-node or local-service identity;
6. rolling time window;
7. node-global memory, timer, byte, and cryptographic-work pools;
8. U1 scheduling and mixing queue.

An input is admitted only when every applicable counter has capacity.

## 3. Accounted resources

| Resource | Charged before | Released or replenished |
|---|---|---|
| Received W2 cell bytes | Before link decryption | Time-window replenishment |
| Link replay marker | Replay insertion | Replay deadline |
| Reassembly context | First accepted fragment | Completion, conflict, expiry, peer loss |
| Reserved logical bytes | Context admission | Completion, conflict, expiry, peer loss |
| Stored fragment bytes | Fragment insertion | Completion, conflict, expiry, peer loss |
| M2 parsing work | After complete reassembly | Time-window replenishment |
| Branch context | Full branch allocation | Expiry, cancellation, peer loss, eviction |
| Child mapping | Token, blinding, rerandomization | Branch expiry or candidate completion |
| Eligibility rerandomization | Suite-selected primitive invocation | Time-window replenishment |
| Reply-key blinding | Group operation | Time-window replenishment |
| Scheduling queue bytes | Queue insertion | Release or drop |
| Candidate layer bytes and depth | Before each KEM open | Completion or work-window replenishment |
| Candidate verification | KEM, AEAD, descriptor, signature | Work-window replenishment |
| Tentative route | Label allocation | Commit, abort, expiry, eviction |
| Pending route reservation | COMMIT transition | READY, timeout, abort, expiry |
| Active route | READY activation | Close, expiry, failure, eviction |

## 4. Admission order

Implementations SHOULD apply:

1. exact 1,052-byte W2 record length;
2. peer cell-rate and byte bucket;
3. public link epoch and sequence parsing with a non-mutating replay-window precheck;
4. adjacent-link ChaCha20-Poly1305 authentication;
5. replay-state commitment and authenticated exact-duplicate rejection;
6. W2 profile and canonical fragment validation;
7. stale reassembly expiry;
8. incomplete-message and reserved-byte admission;
9. fragment insertion or exact-duplicate suppression;
10. complete-message M2 parsing and length validation;
11. expiry and propagation bounds;
12. peer and physical-node branch-context cap;
13. global route-state and timer reservation;
14. suite-selected eligibility and group-operation work tokens;
15. full branch allocation;
16. child selection and outgoing M2/W2 byte reserve;
17. scheduling-queue reserve.

## 5. Mandatory W2 bounds

A conforming node defines finite values for:

- M2 message maximum, not above 16,384 bytes for this profile;
- W2 fragments per message, not above 17;
- incomplete reassembly contexts per peer and per node;
- aggregate reserved logical bytes per peer and per node;
- stored fragment bytes;
- reassembly lifetime;
- link cells and bytes per time window;
- conflicting-fragment and malformed-metadata counters.

The reference defaults are 40 ms, 64 incomplete messages, and 128 KiB reserved logical bytes. The simulator exposes configurable bounds and reports their peaks.

## 6. Mandatory U1 and route bounds

A conforming node also defines finite values for:

- branch contexts per peer and physical node;
- global branch contexts;
- child mappings per branch;
- candidate responses per branch and child;
- eligibility rerandomization, reply-key, and group operations per second;
- scheduling queue bytes and cells;
- maximum batching delay;
- tentative, pending, and active route counts;
- all state lifetimes.

## 7. Overload behavior

Recommended discard order, first to last:

1. wrong-size or unauthenticated cell;
2. exact cell replay;
3. invalid or non-canonical fragment metadata;
4. new incomplete message from the most over-budget peer;
5. additional fragment for an expired or invalidated context;
6. chaff above the minimum privacy policy;
7. new branch from the most over-budget peer;
8. additional child mapping;
9. additional candidate response;
10. tentative route;
11. idle active route;
12. active route carrying admitted traffic.

When a privacy policy requires minimum cover traffic, its cell and queue cost must be reserved separately rather than silently violated under load.

## 8. Fragment amplification

For logical message length `L`, W2 emits:

```text
q(L) = ceil(L / 992)
```

cells and charges:

```text
wire_bytes(L) = 1052 * q(L)
```

The sender reserves all `q(L)` cells against its outgoing budget before emitting the first cell. Partial emission after budget failure is forbidden.

A receiver reserves `L` logical bytes when admitting the first fragment, not merely the bytes already received. This prevents a peer from opening many large contexts at the cost of one small first fragment.

## 9. Reassembly failure accounting

Implementations and experiments report separately:

- completed messages;
- exact duplicate fragments;
- reassembly timeouts;
- message-count capacity drops;
- reserved-byte capacity drops;
- conflicting duplicate or inconsistent-metadata failures;
- peak incomplete contexts;
- peak reserved logical bytes;
- final incomplete contexts.

A missing fragment is not classified as an M2 or cryptographic-suite failure because semantic parsing never began.

## 10. Event-driven simulator interpretation

The simulator counts one network transmission per W2 cell. It counts one logical message when a sender has constructed M2 and reserved the complete cell set. Loss consumes cell transmission budget because link work was performed. Exact replay of a cell does not allocate a second fragment or route context.

The simulator reports:

- logical messages and fixed-size cells;
- fragmented messages and complete wire bytes;
- reassembly metrics;
- legitimate and attack cells;
- legitimate and attack branch allocations;
- branch, responder-offer, initiator-candidate, tentative, pending, and active peaks;
- loss, replay, token-bucket, capacity, and per-node drops;
- route setup failures and final cleanup.

The full path and traffic classification are simulator-only measurement aids and are not protocol-visible fields.

## 11. Cryptographic work accounting

The reference model charges separately for:

- C1 negative-control URE point decoding, validation, and rerandomization;
- C2 eligibility encryption, public rerandomization, and recipient opening;
- C2 malformed-input rejection before child emission;
- reply-key tweak operations;
- candidate KEM encapsulation and opening;
- candidate AEAD sealing and opening;
- Ed25519 signing and verification;
- COMMIT and READY proofs;
- nested candidate layers opened;
- malformed or tagged capsules reaching endpoint validation.

Reassembly, M2 validation, and M2/W2 suite agreement MUST precede this work. State reservation before expensive operations is permitted only when the reservation is bounded and released on every failure path. A concrete C2 profile MUST replace the symbolic operation counters with measured primitive costs and separate parsing, proof, group, pairing or ring, and decryption work as applicable.

## 12. Active-tag measurements

Active-tag experiments report tags created, rejection at the first honest transformation, downstream observations, endpoint rejection, route outcome, residual route and reassembly state, and whether the tag changed cell count, scheduling class, or only cryptographic content. The C1 ratio tag and C2 arbitrary-mutation tests remain research-only fault-injection interfaces.
