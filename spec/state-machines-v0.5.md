<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v0.5 state machines

- Applies to: U1 branch-local transformation and E1 lifecycle
- Time semantics: state is valid on `[created, expiry)`

## 1. Initiator logical discovery

States:

`IDLE -> PREPARING -> COLLECTING -> SELECTING -> COMMITTING -> ACTIVE -> CLOSING -> IDLE`

A failure from any non-IDLE state transitions to `CLOSING` and then `IDLE` after local cleanup.

### IDLE

No logical-discovery state exists.

On a local request:

- resolve the application eligibility policy;
- allocate cumulative time, transmission, candidate, and state budgets;
- transition to `PREPARING`.

### PREPARING

- generate independent first-hop reply keys and eligibility capsules;
- create the local ring schedule;
- choose the first candidate-window deadline;
- transition to `COLLECTING` and transmit the first ring.

### COLLECTING

- accept authenticated candidates from any started ring while their offers remain live;
- deduplicate responder offers only inside local initiator state;
- reject or abort candidates beyond the candidate limit;
- process a candidate at the exact window deadline before the window closes;
- do not reveal ring number, retry number, or logical-discovery identity on the wire.

At a ring-window boundary:

- transition to `SELECTING` when the threshold is met;
- otherwise start the next ring and remain `COLLECTING`;
- at the final window, transition to `SELECTING` when at least one valid fallback candidate exists;
- otherwise transition to `CLOSING` with `NO_CANDIDATE`.

### SELECTING

- remove expired offers;
- select at most one candidate according to local policy;
- freeze the decision against late candidates;
- initiate CANCEL through stored adjacent mappings into every maximal off-route live subtree belonging to the logical discovery;
- transition to `COMMITTING`.

### COMMITTING

- send COMMIT through the selected tentative route;
- retain a finite route-setup deadline;
- treat duplicate COMMIT and READY idempotently;
- reject late candidates and abort their tentative state when possible;
- on authenticated final READY, transition to `ACTIVE`;
- on timeout, missing tentative state, capacity failure, responder rejection, or invalid READY, transition to `CLOSING`.

The route MUST NOT be exposed to the data plane in `COMMITTING`.

### ACTIVE

- expose the selected route generation to the data-plane profile;
- retain active lifetime and usage limits;
- on close, expiry, peer failure, or limit exhaustion, transition to `CLOSING`.

### CLOSING

- send bounded ABORT, CANCEL, or CLOSE records when useful;
- release all local candidate and route-setup state without waiting for peers;
- return to `IDLE`.

## 2. Relay branch context

States:

`ABSENT -> LIVE -> CANCELLED | EXPIRED`

### ABSENT

On DISCOVER:

1. reject exact link-local replay;
2. enforce the ingress-peer token bucket;
3. enforce per-node and node-global branch capacity;
4. validate lifetime and propagation classes;
5. perform required cryptographic transformations;
6. allocate one branch context;
7. transition to `LIVE`.

A DISCOVER with a different fresh token is an independent context, not a replay.

### LIVE

The context binds one ingress peer, one branch token, one parent mapping, bounded child mappings, one reply-key state, and one deadline.

While live, the relay may:

- forward independently transformed child DISCOVER records;
- admit bounded CANDIDATE records from stored children;
- forward transformed CANCEL into off-route children;
- expire without peer cooperation.

On CANCEL, transition to `CANCELLED`. At the deadline, transition to `EXPIRED`.

### CANCELLED

- reject delayed CANDIDATE or DISCOVER messages that require the context;
- forward no new child discovery;
- remove branch state immediately;
- retain at most bounded link-local replay markers.

### EXPIRED

- reject delayed messages;
- do not recreate the context;
- retain at most bounded replay markers until their own deadline.

## 3. Relay route mapping

States:

`ABSENT -> TENTATIVE -> PENDING_READY -> ACTIVE -> DRAINING -> ABSENT`

### TENTATIVE

Created when CANDIDATE traverses the relay toward the initiator.

- bind parent and child candidate capabilities and tentative labels;
- reject application data;
- process exact candidate duplication idempotently;
- on valid COMMIT before expiry, reserve route capacity and transition to `PENDING_READY`;
- on CANCEL, ABORT, expiry, peer loss, or pressure, transition to `ABSENT`.

### PENDING_READY

- retain the protected commit transcript and a finite ready-hold deadline; an obsolete tentative-expiry timer cannot shorten this replacement deadline;
- reject application data;
- forward COMMIT once according to bounded idempotent policy;
- on valid READY, transition to `ACTIVE`;
- on timeout, ABORT, peer loss, or transcript mismatch, transition to `ABSENT`.

### ACTIVE

- accept data only for the bound peer, direction, label, route generation, and limits;
- process duplicate READY idempotently;
- on close or failure, transition to `DRAINING` or `ABSENT` according to the data-plane profile.

### DRAINING

- reject new application flows;
- optionally forward bounded in-flight traffic;
- remove state at the drain deadline.

## 4. Responder endpoint offer

States:

`AVAILABLE -> OFFERED -> COMMITTED -> ACTIVE -> CLOSING -> AVAILABLE`

### AVAILABLE

- attempt to open the rerandomized eligibility capsule;
- enforce endpoint offer and cryptographic-work budgets;
- if eligible, create one authenticated candidate payload and finite offer deadline;
- transition the offer to `OFFERED`.

### OFFERED

- return CANDIDATE through the branch context;
- accept only a COMMIT proving knowledge of the protected challenge;
- on valid COMMIT, transition to `COMMITTED`;
- on expiry, cancellation, or abort, delete the offer and return to `AVAILABLE`.

### COMMITTED

- send READY toward the initiator;
- reserve endpoint route state for a finite interval;
- on successful local activation, transition to `ACTIVE`;
- if READY is lost, rely on local expiry rather than peer acknowledgement.

### ACTIVE

- provide the selected service under data-plane limits;
- on close, expiry, or failure, transition to `CLOSING`.

### CLOSING

- remove endpoint state and return to `AVAILABLE`.

## 5. Ingress-peer token bucket

States:

`UNINITIALIZED -> AVAILABLE | EMPTY`

For each `(link epoch, ingress peer, receiving node)` scope:

- initialize to capacity `b`;
- refill by `a` tokens for each elapsed interval `r`, capped at `b`;
- consume one token before expensive fresh-branch processing;
- when fewer than one token remains, reject the fresh branch and enter or remain `EMPTY`;
- exact replays are rejected before token consumption.

Token-bucket state expires with the link epoch or administrative idle deadline.

## 6. Mixing scheduler

States:

`EMPTY -> ACCUMULATING -> ELIGIBLE -> RELEASING -> EMPTY`

The U1 scheduler behavior is unchanged from v0.3. E1 timing measurements MUST distinguish protocol event delay from the additional mixing and release delay of a traffic-scheduling profile.
