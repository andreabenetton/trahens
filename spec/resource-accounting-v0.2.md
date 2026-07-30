# Trahens Core v0.2 resource accounting

- Status: Design draft
- Scope: discovery and setup control plane

## 1. Objective

Every accepted input must have a calculable upper bound on local work, transmitted control traffic, and retained state. Sender-declared budgets are advisory; each node enforces its own limits.

## 2. Counter hierarchy

A relay maintains counters at four levels:

1. **Peer session** - all traffic from one adjacent peer.
2. **Attempt** - one `(peer_scope, attempt_id)` context.
3. **Time window** - work admitted during a local rolling or token-bucket interval.
4. **Node global** - aggregate memory, labels, timers, bytes, and cryptographic work.

An input is admitted only when every applicable counter has capacity.

## 3. Minimum accounted resources

| Resource | Charged when | Released or replenished |
|---|---|---|
| Received control bytes | Framing succeeds | Time-window replenishment |
| Forwarded control bytes | Before enqueue | Time-window replenishment |
| DISCOVER forwarding action | Before child selection | Time-window replenishment |
| Full attempt-state entry | Immediately before allocation | Expiry, cancellation, or peer loss |
| Replay marker | Immediately before allocation | Short replay deadline |
| Candidate verification | Before public-key verification | Time-window replenishment |
| Tentative route entry | Before label generation | Commit, expiry, abort, or eviction |
| Active route entry | Before activation | Close, expiry, failure, or eviction policy |
| Timer | When scheduled | Timer firing or state removal |
| Hop label | When reserved | State removal plus reuse quarantine |

## 4. Admission order

Implementations SHOULD apply:

1. frame-size cap;
2. peer byte and message rate;
3. expiry and version checks;
4. attempt-count and replay-marker capacity;
5. node-global memory reserve;
6. canonical parsing;
7. duplicate lookup;
8. inexpensive authentication;
9. public-key work token;
10. full state allocation;
11. forwarding byte and action tokens.

A failure at one stage MUST NOT consume resources from later stages.

## 5. Attempt limits

For one accepted attempt, a relay MUST define finite limits for:

- one full parent record;
- forwarded child count;
- candidate responses accepted from each child;
- tentative routes created;
- public-key verifications;
- control bytes forwarded;
- expiration extension, which is zero unless explicitly authenticated by a future version.

## 6. Logical-discovery initiator limits

The initiator MUST stop starting rings when any of these reaches its configured limit:

- attempt count;
- overall deadline;
- cumulative DISCOVER transmissions;
- cumulative estimated state allocations;
- unique candidate count;
- control bytes;
- cryptographic operations.

The simulator's `total_state_allocation_budget` is a cumulative work proxy, not a claim that all relay state remains simultaneously live.

## 7. Overload behavior

Overload behavior MUST be deterministic for the same local state and input class. Recommended priority from first discarded to last:

1. malformed or unauthenticated input;
2. duplicate replay markers beyond quota;
3. new DISCOVER attempts from the most over-budget peer;
4. additional candidates beyond policy needs;
5. tentative routes;
6. inactive or idle active routes;
7. active routes carrying admitted traffic.

Nodes SHOULD avoid detailed error reasons that reveal capacity or topology.

## 8. Required metrics

Implementations and experiments SHOULD expose aggregate, non-secret metrics for:

- accepted and rejected attempts;
- rejection reason class;
- transmitted control bytes and messages;
- full attempt-state and replay-marker occupancy;
- tentative and active route occupancy;
- public-key operations admitted and rejected;
- state evictions;
- per-policy success rate;
- repeated observations across expanding-ring attempts.
