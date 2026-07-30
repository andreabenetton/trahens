# Trahens event lifecycle profile E1

- Status: Active research design
- Applies to: Core v1.2 with U1, R1, M2, W2, T1, and T2; C1 reply/signature components remain bound
- Purpose: Define event time, candidate windows, reverse setup, activation, cancellation, and deterministic cleanup

## 1. Time model

E1 models time as a monotonically increasing local clock. A protocol state created at time `t_create` with deadline `t_expire` is valid on the half-open interval

`[t_create, t_expire)`.

It is invalid at `t_expire`. An implementation MUST NOT revive expired state from a delayed message.

Clock synchronization between different nodes is not required for local expiry. Values transmitted as lifetime classes are converted into local deadlines when admitted. A profile that depends on synchronized absolute time is outside E1.

## 2. Equal-time event order

An implementation or simulator MUST define deterministic precedence for events assigned the same local timestamp. E1 uses the following order:

1. state expiry;
2. cancellation and abort processing;
3. COMMIT, READY, and other route-control processing;
4. CANDIDATE processing;
5. DISCOVER processing;
6. candidate-window closure;
7. local attack or workload generation.

Consequences:

- a message arriving exactly at a state deadline observes the state as expired;
- a candidate arriving exactly at a candidate-window deadline is eligible for that window;
- cancellation can overtake a delayed candidate when both are assigned the same arrival time.

This precedence is a conformance rule for deterministic testing. A deployment MAY use a different scheduler only if its externally observable outcomes are equivalent under the specified half-open deadlines.

## 3. Initiator-local expanding rings

The ring schedule is local policy and MUST NOT be included in a wire message. Each ring defines:

- maximum propagation depth;
- initial fan-out;
- relay fan-out class;
- candidate-window duration.

At the end of a ring window, the initiator:

1. removes expired candidate offers;
2. selects a candidate if the configured threshold is met;
3. otherwise starts the next ring, if one exists;
4. on the final ring, MAY select the best remaining candidate even when the preferred threshold is not met;
5. otherwise terminates with `NO_CANDIDATE`.

A candidate produced by an earlier ring remains eligible after a later ring starts, provided that:

- no route-selection decision has been made;
- its authenticated offer has not expired;
- its reverse tentative state remains valid;
- the initiator's candidate limit has not been reached.

A ring number, retry number, previous-ring handle, or logical-discovery identifier MUST NOT cross a link.

## 4. Candidate return

A rendezvous gateway that admits a canonical R1 discovery creates a gateway offer with a finite deadline. Eligibility is the local gateway role; the service-query nonce has no endpoint semantics. The gateway returns CANDIDATE through the reverse branch contexts.

For every relay traversed by CANDIDATE, the relay MUST:

1. verify the link-local candidate capability;
2. reject exact replays idempotently;
3. verify that the referenced branch context is live;
4. reserve tentative-route capacity;
5. create a local tentative mapping with an independent deadline;
6. replace the candidate capability and relevant labels;
7. encode a fresh canonical M2 CANDIDATE and transmit it in one or more fixed-size W2 cells toward the parent.

The gateway's branch context is not a relay tentative mapping. Gateway offer state is accounted separately.

A candidate that cannot traverse one required reverse context is discarded. No recovery response is required.

## 5. Selection and cancellation

Selection occurs only at a candidate-window boundary in E1. The default deterministic ordering is:

1. minimum hop count;
2. earliest candidate arrival;
3. gateway identifier used only as a simulator tie-breaker;
4. local candidate sequence used only as a final simulator tie-breaker.

A production privacy profile MUST replace any externally meaningful tie-breaker with a policy that does not reveal stable endpoint identity to relays.

After selection, the initiator MUST:

- stop admitting additional legitimate discovery branches for that logical discovery;
- send COMMIT along the selected tentative route;
- send CANCEL into every maximal off-route live subtree that it can address;
- treat candidates arriving after the decision as late and abort their tentative state when possible.

Cancellation is advisory for prompt reclamation. Correctness MUST NOT depend on its delivery. Expiry remains the final cleanup mechanism.

CANCEL is forwarded only through stored adjacent branch mappings belonging to the same initiator-local discovery. The initiator does not possess or cancel unrelated branch contexts created by another origin or by an attacker.

### 5.1 Cancellation races

CANCEL and CANDIDATE may cross in flight.

- If CANDIDATE traverses a context before CANCEL removes it, the relay may create tentative state and continue the candidate.
- If CANCEL removes the context first, the delayed candidate is discarded.
- If a late candidate reaches the initiator after selection, it is not eligible and its path is aborted or allowed to expire.

No race outcome may recreate expired state or change the selected route.

## 6. COMMIT and READY

### 6.1 Forward commitment

COMMIT travels from the initiator to the selected gateway through local tentative mappings. At each relay, a valid COMMIT MUST:

1. match the incoming peer, label, route generation, and protected transcript;
2. find one live tentative mapping;
3. reserve route capacity;
4. transition the mapping to `PENDING_READY`;
5. assign a ready-hold deadline;
6. forward COMMIT through the child mapping.

A relay in `PENDING_READY` MUST reject application data.

If any relay cannot reserve route capacity or cannot find its tentative state, route setup fails. Already reserved state is released by abort or expiry.

### 6.2 Reverse readiness

After validating the commit challenge, the gateway sends READY toward the initiator. At each relay, a valid READY transitions the matching `PENDING_READY` mapping to `ACTIVE` and forwards READY through the parent mapping.

The initiator MUST NOT expose the route to the data plane until it authenticates the final READY transcript.

The existence of relay `ACTIVE` state before the initiator receives READY does not authorize data transmission by the initiator. If READY is lost, such partial state expires at its local active or hold deadline.

### 6.3 Idempotency

An exact duplicate COMMIT or READY on the same adjacent-link replay domain MUST be discarded or processed idempotently. A different protected transcript presented on the same local route capability MUST be rejected.

## 7. R1 post-READY redemption

After the initiator authenticates final READY, it MAY send an end-to-end protected RENDEZVOUS_OPEN containing the private descriptor capability, client nonce, descriptor expiry, and endpoint handshake. Ordinary relays process only active-route labels.

At the selected gateway:

1. compute the domain-separated capability commitment;
2. atomically lock and locate a live registration;
3. verify gateway binding, half-open expiry, route state, and local handshake policy;
4. delete the record before returning the local endpoint handle;
5. map replay, expiry, wrong gateway, malformed input, and policy failure to one generic result.

A failed or lost redemption does not revive expired route or registration state. The core does not define descriptor lookup or subsequent endpoint rendezvous transport.

## 8. Expiry and cleanup

The following states require independent finite deadlines:

- branch context;
- gateway offer;
- relay tentative mapping;
- pending-ready reservation;
- active route mapping;
- adjacent-link replay marker;
- W2 reassembly context;
- initiator route-setup transaction.

Expiry MUST be local and non-blocking. A node MUST reclaim state without waiting for a peer acknowledgement.

When a valid state transition replaces a deadline, an already queued timer for the previous deadline is stale. The timer handler MUST compare the current state generation or current deadline and MUST NOT reclaim the state before its replacement deadline.

At the end of a bounded E1 execution, all branch, tentative, pending, and active state eventually reaches zero unless retained by a separately specified data-plane renewal.

## 9. Loss, duplication, and reordering

E1 permits adjacent-link loss, exact duplication, and reordering.

- Loss may prevent discovery, candidate return, COMMIT, or READY.
- Exact cell duplication MUST NOT allocate a second fragment, branch, or route context. A complete duplicated logical message MUST be handled idempotently.
- Reordering MUST NOT allow an earlier state generation to overwrite a later generation.
- Delayed messages MUST fail closed after the relevant state deadline.

The sender MAY retransmit only under a bounded idempotent policy. The retransmission policy is part of a deployment profile and MUST NOT introduce a stable cross-hop identifier.

## 10. Fresh-branch denial of service

An attacker may generate syntactically valid DISCOVER records with fresh link-local tokens. Exact replay protection does not stop this attack.

Before expensive cryptographic work or full branch allocation, a relay MUST enforce:

- adjacent-link byte and cell limits;
- W2 reassembly context, fragment-count, aggregate-byte, and timeout limits;
- per-ingress-peer token bucket or equivalent fair-share admission;
- per-node branch-context limit;
- node-global branch capacity;
- bounded propagation classes;
- global or administrative work limits.

A token bucket is defined by capacity `b`, refill interval `r`, and refill amount `a`. One admitted fresh branch consumes one token. Buckets are scoped at least to `(link epoch, ingress peer, receiving node)`.

Per-peer admission limits a single-source or few-source flood but does not defeat a widely distributed attack. Node-global limits remain mandatory.

## 11. Required measurements

An E1 evaluation MUST report at least:

- route-setup success rate;
- setup latency for successful routes;
- candidate count and late-candidate count;
- candidate drops caused by cancellation or expiry;
- COMMIT and READY failure counts;
- legitimate and attack logical messages and W2 cells separately;
- cumulative branch allocations by traffic class;
- peak branch, gateway-offer, initiator-candidate, tentative, pending, active, and reassembly state;
- replay, cell loss, reassembly timeout, reassembly capacity, token-bucket, and per-node drops;
- final state counts and cleanup completion rate.

A success result without final cleanup measurements is incomplete.

## 12. Security scope

E1 specifies lifecycle correctness and bounded cleanup. It does not strengthen U1 against global timing correlation or active cryptographic tagging. Event timing, W2 cell count, and fragment burst shape are observable unless a separate traffic-scheduling profile hides or quantizes them.
