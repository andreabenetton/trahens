# Trahens Core v0.1

- Status: Design draft
- Date: 2026-07-30
- Scope: bounded service discovery and bidirectional route-state establishment

## 1. Purpose

Trahens Core discovers one or more eligible responders within a bounded graph radius and establishes opaque hop-by-hop forwarding state to a selected responder. No participant receives a complete source route. Each relay learns only its adjacent predecessor and successor for an established route.

Core v0.1 is a correctness and resource-safety baseline. It does not claim resistance to colluding relays that compare the stable discovery identifier, nor does it define a global destination directory.

## 2. Normative language

The terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as in BCP 14 when written in uppercase.

## 3. Goals

Core v0.1 MUST provide:

1. bounded discovery by hop count, time, fan-out, and relay resource budget;
2. duplicate and loop suppression using a discovery-scoped identifier;
3. responder authentication according to a selected cryptographic profile;
4. hop-local opaque route labels;
5. tentative route establishment before initiator selection;
6. explicit commit, readiness, expiration, and abort behavior;
7. bidirectional forwarding state without disclosing the complete route;
8. deterministic behavior under duplication, reordering, stale messages, and loss.

## 4. Non-goals

Core v0.1 does not define:

- global endpoint lookup;
- beacon or authority operation;
- inter-domain routing policy;
- incentives or settlement;
- congestion control for application data;
- strong resistance to a passive global timing observer;
- private duplicate suppression against colluding relays;
- a replacement for IP or a new layer-2 technology.

## 5. Underlay contract

An underlay profile provides pairwise communication between adjacent peers. The baseline profile MUST provide:

- peer authentication or an explicitly anonymous authenticated channel;
- confidentiality and integrity for messages on one adjacent link;
- message boundaries;
- a maximum message size;
- peer-local identifiers that are not treated as global identities;
- notification of peer connection and disconnection.

Reliability, ordering, padding, batching, and constant-rate scheduling belong to underlay or privacy profiles and MUST be declared by the deployment.

## 6. Entities

- **Initiator**: starts discovery and selects a candidate route.
- **Relay**: forwards protocol messages and stores bounded ephemeral state.
- **Responder**: accepts a discovery for a requested service class and authenticates the response.
- **Adjacent peer**: a directly connected node under the selected underlay profile.

One node MAY perform multiple roles.

## 7. Identifiers and labels

### 7.1 Discovery ID

The initiator generates a uniformly random 128-bit `discovery_id`. It is stable for one discovery and MUST NOT be reused.

Relays use the value for duplicate suppression and resource accounting. Consequently, colluding relays can correlate messages belonging to the same discovery. This is an explicit limitation of v0.1.

### 7.2 Candidate ID

A responder generates a uniformly random 128-bit `candidate_id`. The value identifies one candidate route until it is committed, rejected, or expires.

### 7.3 Route ID

After commitment, the responder and initiator identify the route using a cryptographically random 128-bit `route_id`. The route ID is carried only inside protected control bodies and MUST NOT be used as the forwarding label.

### 7.4 Hop labels

A relay generates each hop label independently and uniformly at random with at least 128 bits of entropy. A label is interpreted only in the context of:

- the local node;
- the adjacent peer from which it is accepted;
- one direction;
- one route generation;
- an expiration time.

A node MUST reject a label arriving from a peer other than the peer bound to the label. Labels MUST NOT be hashes of long-term endpoint identities.

## 8. Local state

### 8.1 Discovery state

A relay MAY store at most one accepted parent for a `(peer_scope, discovery_id)` in Core v0.1. The record contains:

- discovery ID;
- previous peer;
- accepted hop count;
- expiration;
- response budget remaining;
- forwarding peers selected for the flood;
- state accounting owner and cost.

A relay MAY remember rejected duplicates in a smaller replay-cache entry.

### 8.2 Tentative route state

A relay creates tentative state while a `CANDIDATE` travels toward the initiator. It contains:

- candidate ID;
- parent peer and parent-facing forward label;
- child peer and child-facing forward label;
- expiration;
- responder authentication status;
- accounting cost.

Tentative state MUST NOT carry application data.

### 8.3 Active route state

After `COMMIT`, the relay stores:

- route ID or a protected local route reference;
- parent peer and forward incoming label;
- child peer and forward outgoing label;
- child peer and reverse incoming label;
- parent peer and reverse outgoing label;
- creation and expiration time;
- byte, packet, and idle limits;
- selected cryptographic and privacy profiles.

## 9. Discovery procedure

### 9.1 Initiation

The initiator:

1. generates a new discovery ID;
2. selects `hop_limit`, `candidate_limit`, `expires_at`, and service selector;
3. verifies that all values are within local and profile limits;
4. creates local discovery state;
5. sends one `DISCOVER` to each selected adjacent peer, subject to its fan-out budget.

The initiator MUST NOT send more than the configured `initial_fanout` messages for one discovery.

### 9.2 Relay processing

A relay receiving `DISCOVER` MUST process checks in the order defined by `messages-v0.1.md` so that inexpensive rejection precedes expensive cryptography.

If the discovery is acceptable, the relay:

1. records the previous peer as the parent;
2. evaluates whether it is an eligible responder;
3. decrements the remaining hop budget;
4. selects at most `relay_fanout` child peers, excluding the parent;
5. forwards a normalized `DISCOVER` to the selected peers;
6. charges all state and forwarded work to explicit peer and global budgets.

A relay MUST NOT forward when the hop budget reaches zero. A duplicate MUST NOT create a second full discovery-state record in v0.1.

### 9.3 Responder behavior

An eligible responder MAY return a candidate if:

- the service selector matches;
- its local response budget permits it;
- the discovery is unexpired;
- the requested profile is supported;
- it can authenticate the candidate response.

The responder creates a candidate ID, a route ID, and a forward label that its parent will use to send toward the responder. It then sends `CANDIDATE` to the parent recorded in discovery state.

## 10. Candidate reverse propagation

When a relay receives a valid `CANDIDATE` from an expected child, it:

1. locates the corresponding discovery state;
2. checks candidate and response budgets;
3. validates responder authentication as far as required by the cryptographic profile;
4. generates a new parent-facing forward label;
5. creates tentative mapping from the parent-facing label to the child-facing label;
6. replaces the exposed forward label with the new parent-facing label;
7. sends the candidate to its recorded parent.

The relay MUST NOT expose the child-facing label to its parent. The initiator therefore receives only the first-hop label and responder metadata.

## 11. Candidate selection and commitment

The initiator collects no more than `candidate_limit` valid candidates until the earliest of:

- the collection timer expires;
- the candidate limit is reached;
- local policy selects a candidate early.

The initiator selects at most one candidate in Core v0.1 and sends `COMMIT` using the candidate's first-hop forward label. The body contains:

- candidate ID;
- route ID confirmation material;
- route expiration and limits;
- a reverse label generated by the initiator for the first relay;
- transcript confirmation required by the cryptographic profile.

Non-selected candidates are rejected explicitly when practical or allowed to expire.

## 12. Commit forward propagation

A relay receiving `COMMIT` on a tentative forward label:

1. validates the candidate and expiration;
2. binds the reverse outgoing label supplied by its parent;
3. generates a reverse incoming label for its child;
4. converts tentative state into active bidirectional route state;
5. replaces the reverse label in the body with the child-facing reverse label;
6. forwards `COMMIT` through the stored child-facing forward label.

If any validation or resource reservation fails, the relay MUST remove tentative state and SHOULD return `ABORT` through the temporary reverse path.

## 13. Ready reverse propagation

The responder validates `COMMIT`, activates the route, and sends `READY` using the reverse label received from its parent.

Each relay forwards `READY` through its active reverse mapping. The initiator marks the route usable only after a valid `READY` arrives.

Loss of `READY` leaves the route inactive at the initiator. Retries MUST be bounded and idempotent.

## 14. Data-plane handoff

Core defines only the installed label mappings. A data-plane profile defines packet confidentiality, sequencing, replay protection, flow control, congestion handling, padding, and fragmentation.

Application data MUST NOT be sent on tentative state.

## 15. Expiration and cleanup

Every state record has an absolute expiration and an idle timeout. Nodes MUST remove expired state without requiring a remote message.

Recommended ordering of lifetimes:

`duplicate cache < discovery state < tentative route state < active route state`

An active route MAY be closed by `CLOSE`, peer disconnection, limit exhaustion, local policy, or timeout. Close processing MUST be idempotent.

## 16. Resource controls

Each implementation MUST configure hard limits for:

- concurrent discoveries per adjacent peer;
- total discovery state;
- replay-cache entries;
- relay fan-out;
- candidate responses per discovery;
- tentative and active routes;
- asymmetric cryptographic operations per peer and time window;
- bytes forwarded before authentication;
- control-message retries;
- maximum lifetimes.

A node under pressure SHOULD discard uncommitted state before active route state. It MUST define deterministic overload behavior.

## 17. Error handling

Malformed, stale, over-budget, unknown-version, and context-invalid messages MUST be dropped without changing forwarding state. Error responses MUST be rate-limited and MUST NOT amplify the received message size or processing cost.

Unknown optional fields MAY be ignored only when the message encoding marks them as safely skippable. Unknown critical fields cause rejection.

## 18. Privacy statement for v0.1

Core v0.1 aims to prevent one honest-but-curious relay from learning the complete route. A relay sees its predecessor, successor, service class, timing, and discovery ID. The stable discovery ID enables correlation by colluding relays and therefore does not meet the stronger unlinkability goal stated in the legacy draft.

Traffic-analysis resistance depends on a named privacy profile. Encrypted adjacent links alone do not hide timing, volume, or peer relationships from a capable observer.

## 19. Required next revision

Core v0.2 should evaluate at least two alternatives to the stable discovery ID:

1. per-hop transformed identifiers with privacy-preserving loop suppression;
2. removal of global deduplication in favor of strict hop, fan-out, and probabilistic suppression limits.

The choice must be based on measured amplification and collusion leakage.
