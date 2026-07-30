# Trahens Core v0.2

- Status: Design draft
- Date: 2026-07-30
- Scope: bounded expanding-ring service discovery and bidirectional route-state establishment
- Replaces: Core v0.1 as the active design draft

## 1. Purpose

Trahens Core discovers one or more eligible responders within a bounded graph radius and establishes opaque hop-by-hop forwarding state to a selected responder. No relay receives a complete source route. Each relay learns only the adjacent peers and local labels needed for its own forwarding decision.

Core v0.2 adds an expanding-ring policy and resource accounting across the complete logical discovery. Each ring uses a fresh wire-visible attempt identifier. The local logical-discovery identifier is never transmitted. This removes a direct identifier link between retries, but timing, origin adjacency, overlapping relay sets, and service metadata can still correlate attempts.

Core v0.2 remains a correctness and resource-safety baseline. It does not define a global destination directory or claim resistance to a global timing observer.

## 2. Normative language

The terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as in BCP 14 when written in uppercase.

## 3. Changes from v0.1

1. A logical discovery may contain multiple bounded attempts.
2. `logical_discovery_id` is local to the initiator and MUST NOT appear on the wire.
3. Each attempt carries a fresh random `attempt_id` used for duplicate suppression within that attempt.
4. Ring schedules MUST be non-decreasing in hop limit and fan-out.
5. Transmission, state-allocation, candidate, timer, and cryptographic-work budgets apply across all attempts in one logical discovery.
6. Candidate identities are deduplicated across attempts before selection.
7. Cross-attempt overlap is explicit privacy leakage and an evaluation metric.

## 4. Goals

Core v0.2 MUST provide:

1. bounded discovery by attempts, hop count, time, fan-out, and resource budgets;
2. duplicate and loop suppression within an attempt;
3. fresh attempt contexts for retries;
4. responder authentication according to a selected cryptographic profile;
5. hop-local opaque route labels;
6. tentative route establishment before initiator selection;
7. explicit commit, readiness, expiration, abort, and close behavior;
8. bidirectional forwarding state without disclosing the complete route;
9. deterministic behavior under duplication, reordering, stale messages, and loss;
10. measurable leakage and cost for every discovery policy.

## 5. Non-goals

Core v0.2 does not define:

- global endpoint lookup;
- beacon or authority operation;
- inter-domain routing policy;
- incentives or settlement;
- congestion control for application data;
- strong resistance to a passive global timing observer;
- private duplicate suppression against colluding relays within one attempt;
- proof that separate attempts are unlinkable;
- a replacement for IP or a new layer-2 technology.

## 6. Underlay contract

An underlay profile provides pairwise communication between adjacent peers. The baseline profile MUST provide:

- peer authentication or an explicitly anonymous authenticated channel;
- confidentiality and integrity for messages on one adjacent link;
- message boundaries;
- a maximum message size;
- peer-local identifiers that are not treated as global identities;
- notification of peer connection and disconnection.

Reliability, ordering, padding, batching, and constant-rate scheduling belong to underlay or privacy profiles and MUST be declared by the deployment.

## 7. Entities and discovery terms

- **Initiator**: starts a logical discovery and selects a candidate route.
- **Relay**: forwards protocol messages and stores bounded ephemeral state.
- **Responder**: accepts an attempt for a requested service class and authenticates the response.
- **Logical discovery**: local initiator operation that may execute one or more attempts.
- **Attempt**: one bounded outward `DISCOVER` propagation with a fresh `attempt_id`.
- **Ring**: the hop and fan-out limits assigned to one attempt.
- **Ring schedule**: the ordered list of rings available to a logical discovery.

One node MAY perform multiple roles.

## 8. Identifiers and labels

### 8.1 Logical discovery ID

The initiator generates a uniformly random local `logical_discovery_id` with at least 128 bits of entropy. It is used only for local accounting and application correlation. It MUST NOT be transmitted or included in an end-to-end field visible to relays.

### 8.2 Attempt ID

The initiator generates a fresh uniformly random 128-bit `attempt_id` for every attempt. It MUST NOT be reused, including after failure or restart.

Relays use `attempt_id` for duplicate suppression and attempt-scoped accounting. Colluding relays can correlate messages within the same attempt. Different attempt IDs do not prevent correlation by timing or overlapping topology.

### 8.3 Candidate ID

A responder generates a uniformly random 128-bit `candidate_id`. It identifies one candidate route until it is committed, rejected, or expires. A responder SHOULD generate a new candidate ID for each attempt unless a cryptographic profile defines an unlinkable resumption construction.

### 8.4 Route ID

The responder and initiator identify a committed route using a cryptographically random 128-bit `route_id`. It is carried only inside protected control bodies and MUST NOT be used as a forwarding label.

### 8.5 Hop labels

A relay generates each hop label independently and uniformly at random with at least 128 bits of entropy. A label is interpreted only in the context of:

- the local node;
- the adjacent peer from which it is accepted;
- one direction;
- one route generation;
- an expiration time.

A node MUST reject a label arriving from a peer other than the peer bound to the label. Labels MUST NOT be hashes of endpoint identities.

## 9. Ring schedule

A ring is the tuple:

`(hop_limit, initial_fanout, relay_fanout, candidate_window)`

The schedule MUST satisfy:

- one or more rings;
- positive values for all limits;
- non-decreasing hop limits;
- non-decreasing initial and relay fan-out;
- a configured maximum number of attempts;
- a finite total deadline for the logical discovery.

A deployment MAY repeat a ring with fresh randomness, but repeated equal rings increase observer overlap and MUST be accounted for.

## 10. Logical-discovery budgets

Before the first attempt, the initiator reserves hard limits for:

- total transmitted `DISCOVER` messages;
- total local and estimated relay state allocations;
- total candidates accepted;
- total attempts;
- total setup time;
- total cryptographic operations;
- total control bytes;
- total retries of `COMMIT` and `READY` processing.

An attempt receives only the remaining budget. A new attempt MUST NOT start when any mandatory budget is exhausted.

Relay implementations cannot trust initiator-declared totals. Each relay independently applies peer, attempt, time-window, and global limits as defined in `resource-accounting-v0.2.md`.

## 11. Local state

### 11.1 Initiator logical-discovery state

The initiator stores:

- local logical discovery ID;
- ring schedule and next ring index;
- cumulative resource use;
- unique candidate set;
- candidate-selection policy;
- overall deadline;
- selected candidate, if any.

### 11.2 Relay attempt state

A relay MAY store at most one accepted parent for `(peer_scope, attempt_id)`. The record contains:

- attempt ID;
- previous peer;
- accepted hop count and limit;
- expiration;
- response budget remaining;
- selected forwarding peers;
- accounting owner and cost.

A relay MAY remember rejected duplicates in a smaller replay-cache entry.

### 11.3 Tentative route state

A relay creates tentative state while a `CANDIDATE` travels toward the initiator. It contains:

- attempt ID and candidate ID;
- parent peer and parent-facing forward label;
- child peer and child-facing forward label;
- expiration;
- responder-authentication status;
- accounting cost.

Tentative state MUST NOT carry application data.

### 11.4 Active route state

After `COMMIT`, the relay stores:

- protected route reference;
- parent peer and forward incoming label;
- child peer and forward outgoing label;
- child peer and reverse incoming label;
- parent peer and reverse outgoing label;
- creation and expiration time;
- byte, packet, and idle limits;
- selected cryptographic and privacy profiles.

## 12. Attempt initiation

For each attempt, the initiator:

1. checks the logical-discovery deadline and cumulative budgets;
2. selects the next ring;
3. generates a new attempt ID and attempt-scoped ephemeral material;
4. derives per-attempt limits from remaining logical budgets;
5. creates local attempt state;
6. sends one `DISCOVER` to each selected adjacent peer, subject to `initial_fanout` and the remaining transmission budget.

The initiator MUST NOT expose the ring index or previous attempt identifiers on the wire.

## 13. Relay processing of DISCOVER

A relay receiving `DISCOVER` MUST use the validation order in `messages-v0.2.md`, rejecting inexpensive invalid inputs before expensive operations or state allocation.

If accepted, the relay:

1. records the previous peer as the parent;
2. evaluates whether it is an eligible responder;
3. increments the hop count exactly once;
4. selects at most `relay_fanout` child peers, excluding the parent;
5. forwards a normalized `DISCOVER` only while hop and resource budgets permit;
6. charges state and work to explicit peer, attempt, time-window, and global counters.

A duplicate MUST NOT create a second full attempt-state record. A relay MUST NOT increase sender-declared hop or fan-out limits.

## 14. Responder and candidate behavior

An eligible responder MAY return a candidate when:

- the service selector matches;
- local response budgets permit it;
- the attempt is unexpired;
- the requested profiles are supported;
- it can authenticate the candidate response.

The responder creates a candidate ID, route commitment, and child-facing forward label, then sends `CANDIDATE` toward the recorded parent.

A responder MAY answer multiple attempts from the same apparent peer. It MUST treat them as independent unless a cryptographic profile provides a protected, non-linkable resumption mechanism.

## 15. Candidate reverse propagation

When a relay receives a valid `CANDIDATE` from an expected child, it:

1. locates the matching attempt state;
2. checks candidate and response budgets;
3. validates responder authentication as required by the cryptographic profile;
4. generates a new parent-facing forward label;
5. creates tentative mapping from the parent-facing label to the child-facing label;
6. replaces the exposed forward label;
7. sends the candidate to its recorded parent.

The relay MUST NOT expose the child-facing label to its parent.

## 16. Candidate collection across rings

The initiator maintains a bounded unique candidate set for the logical discovery.

Candidates are duplicates when the authenticated responder identity and service instance are equivalent under the selected profile. Duplicate candidates MAY update freshness or path-quality metadata but MUST NOT consume a second candidate slot or trigger a second commitment.

At the end of each candidate window, the initiator:

1. selects a candidate when policy requirements are met; or
2. starts the next ring if budgets and the overall deadline permit; or
3. fails the logical discovery and releases local state.

The policy MUST declare the required number of candidates and whether selection can occur early.

## 17. Commitment and readiness

The initiator selects at most one candidate and sends `COMMIT` using the first-hop forward label. The body binds:

- attempt ID;
- candidate ID;
- route confirmation material;
- route expiration and limits;
- reverse label;
- negotiated profiles;
- cryptographic transcript confirmation.

Each relay converts matching tentative state to active bidirectional state, replaces the reverse label for its child, and forwards `COMMIT`. The responder validates the commitment, activates the route, and returns `READY` through the reverse mappings.

The initiator exposes the route to a data-plane profile only after a valid `READY`.

## 18. Expiration, cancellation, and late messages

Starting a later ring does not extend earlier attempt state. Earlier attempts SHOULD be cancelled with bounded `ABORT` messages when this can be done without amplification. Relays MUST still expire state locally without cancellation.

A late candidate from an earlier attempt MAY be accepted only when:

- its attempt state remains valid;
- the logical discovery remains open;
- candidate and resource limits remain available;
- no conflicting route has been committed.

After a successful commitment, the initiator MUST reject or ignore candidates for all other attempts in that logical discovery.

## 19. Data-plane handoff

Core defines only installed label mappings. A data-plane profile defines packet confidentiality, sequencing, replay protection, flow control, congestion handling, padding, and fragmentation.

Application data MUST NOT be sent on tentative state.

## 20. Error handling

Malformed, stale, over-budget, unknown-version, and context-invalid messages MUST be dropped without changing active forwarding state. Error responses MUST be rate-limited and MUST NOT amplify the received message size or processing cost beyond a configured constant.

Unknown optional fields MAY be ignored only when the encoding marks them as safely skippable. Unknown critical fields cause rejection.

## 21. Privacy statement for v0.2

Core v0.2 removes a direct shared identifier across retry attempts. It does not make attempts unlinkable.

A relay still observes:

- one stable attempt ID within each attempt;
- incoming and selected outgoing peers;
- hop fields unless hidden by a later profile;
- service selector unless protected;
- timing, size, candidate return, commitment, and state lifetime.

An observer may correlate attempts through the same origin-adjacent link, close timing, similar service metadata, and overlapping relay sets. Simulations MUST report the fraction of relays that observe more than one attempt and the repeated-observation count.

Traffic-analysis resistance depends on a named privacy profile. Encrypted adjacent links alone do not hide timing, volume, or peer relationships.

## 22. Required next revision

Core v0.3 should add:

1. a concrete cryptographic profile and transcript definitions;
2. canonical binary encoding and test vectors;
3. candidate reverse propagation and commitment in the simulator;
4. packet loss, delay, duplication, and state expiry;
5. adversarial resource and selective-forwarding experiments.
