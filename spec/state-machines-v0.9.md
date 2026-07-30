<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v0.9 state machines

- Applies to: U1 branch-local transformation, E1 lifecycle, C2 eligibility, C1 reply/signature components, M2 logical messages, and W2 cells
- Time semantics: state is valid on `[created, expiry)`

## 1. Initiator logical discovery

States:

`IDLE -> PREPARING -> COLLECTING -> SELECTING -> COMMITTING -> ACTIVE -> CLOSING -> IDLE`

A failure from any non-IDLE state transitions to `CLOSING` and then `IDLE` after local cleanup.

### IDLE

No logical-discovery state exists.

On a local request:

- resolve the application eligibility policy;
- allocate cumulative time, logical-message, cell-transmission, candidate, state, reassembly, and cryptographic-work budgets;
- transition to `PREPARING`.

### PREPARING

- generate independent first-hop C1 reply keys and suite-selected eligibility capsules; C2 is the active-security target;
- encode every first-hop DISCOVER as a canonical variable-length M2 message;
- fragment each M2 message into one or more fixed-size W2 cells;
- create the local ring schedule;
- choose the first candidate-window deadline;
- transition to `COLLECTING` and transmit the first ring.

### COLLECTING

- accept authenticated candidates from any started ring while their offers remain live;
- accept a candidate only after W2 reassembly, canonical M2 decoding, suite consistency, and C1 candidate verification succeed;
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
- on timeout, missing tentative state, capacity failure, responder rejection, invalid reassembly, or invalid READY, transition to `CLOSING`.

The route MUST NOT be exposed to the data plane in `COMMITTING`.

### ACTIVE

- expose the selected route generation to the data-plane profile;
- retain active lifetime and usage limits;
- on close, expiry, peer failure, or limit exhaustion, transition to `CLOSING`.

### CLOSING

- send bounded ABORT, CANCEL, or CLOSE messages when useful;
- release all local candidate, route-setup, and reassembly state without waiting for peers;
- return to `IDLE`.

## 2. W2 receive and reassembly

States:

`ABSENT -> COLLECTING -> COMPLETE -> PARSED | INVALID | EXPIRED`

The reassembly key is `(authenticated link scope, local_message_id)`. The identifier is local to one directional adjacent-link epoch and is not a network-wide discovery identifier.

### ABSENT

On receipt of a candidate cell:

1. require exactly 1,052 bytes;
2. authenticate and open the adjacent-link ciphertext;
3. reject exact link-local replay;
4. parse and validate the canonical W2 header;
5. reject impossible lengths, fragment indices, fragment counts, and noncanonical fragment sizes;
6. enforce per-link, per-peer, per-node, and global reassembly limits;
7. bind the suite identifier from the first admitted fragment;
8. reserve the declared total M2 message length;
9. create a bounded context and transition to `COLLECTING`.

No branch, candidate, tentative, pending, or active route state exists at this point.

### COLLECTING

The context stores authenticated fragment bytes, a received-fragment bitmap, the declared total M2 length, and an expiry.

- fragments MAY arrive out of order;
- an exact duplicate is idempotent and consumes no additional reservation;
- a conflicting duplicate or inconsistent header invalidates the complete context;
- a nonfinal fragment MUST carry exactly 992 payload bytes;
- the final fragment MUST carry exactly the canonical remainder;
- aggregate reserved bytes and concurrent contexts MUST remain within configured limits.

When all fragments are present, concatenate them in fragment-index order and transition to `COMPLETE`. At the reassembly deadline, transition to `EXPIRED`.

### COMPLETE

- verify that the reconstructed length equals the declared total length;
- release fragment bookkeeping while retaining the complete logical bytes;
- decode exactly one canonical M2 message;
- require the M2 suite identifier to equal the immutable W2 reassembly suite;
- reject trailing bytes, nonminimal varints, unknown mandatory profiles, malformed fields, suite changes, or inconsistent message lengths.

On success, transition to `PARSED`; otherwise transition to `INVALID`.

### PARSED

The complete M2 message may enter its applicable protocol state machine. Admission, deadline, resource, suite-selected eligibility, and C1 reply/signature checks still apply. A parsed message does not by itself authorize state creation.

### INVALID

- erase all fragment and reconstructed-message bytes;
- release every reservation;
- allocate no protocol state;
- emit no detailed failure oracle to the peer.

### EXPIRED

- erase incomplete fragments;
- release every reservation;
- ignore later fragments for the expired context except for bounded replay accounting.

## 3. Relay branch context

States:

`ABSENT -> LIVE -> CANCELLED | EXPIRED`

### ABSENT

On a parsed DISCOVER message:

1. require successful W2 authentication and complete M2 reassembly;
2. enforce the ingress-peer token bucket;
3. enforce per-node and node-global branch capacity;
4. validate M2 lifetime and propagation classes;
5. validate the selected eligibility suite, apply its public rerandomization, and tweak the C1 reply key;
6. allocate one branch context;
7. transition to `LIVE`.

A DISCOVER with a different fresh branch token is an independent context, not a replay. A W2 `local_message_id` is transport-local and MUST NOT be used as branch identity.

### LIVE

The context binds one ingress peer, one branch token, one parent mapping, bounded child mappings, one reply-key state, and one deadline.

While live, the relay may:

- construct independently transformed child DISCOVER messages;
- encode each child message canonically with M2 and assign a fresh W2 local message identifier per adjacent link;
- admit bounded CANDIDATE messages from stored children after complete reassembly;
- forward transformed CANCEL into off-route children;
- expire without peer cooperation.

On CANCEL, transition to `CANCELLED`. At the deadline, transition to `EXPIRED`.

### CANCELLED

- reject delayed CANDIDATE or DISCOVER messages that require the context;
- forward no new child discovery;
- remove branch state immediately;
- retain at most bounded link-local replay markers and incomplete-cell cleanup state.

### EXPIRED

- reject delayed messages;
- do not recreate the context;
- retain at most bounded replay markers until their own deadline.

## 4. Relay route mapping

States:

`ABSENT -> TENTATIVE -> PENDING_READY -> ACTIVE -> DRAINING -> ABSENT`

### TENTATIVE

Created when a completely reassembled and cryptographically valid CANDIDATE traverses the relay toward the initiator.

- bind parent and child candidate capabilities and tentative labels;
- reject application data;
- process exact candidate duplication idempotently at the logical-message layer;
- on valid COMMIT before expiry, reserve route capacity and transition to `PENDING_READY`;
- on CANCEL, ABORT, expiry, peer loss, reassembly failure, or pressure, transition to `ABSENT`.

### PENDING_READY

- retain the protected commit transcript and a finite ready-hold deadline; an obsolete tentative-expiry timer cannot shorten this replacement deadline;
- reject application data;
- forward COMMIT once according to bounded idempotent policy;
- on valid READY, transition to `ACTIVE`;
- on timeout, ABORT, peer loss, transcript mismatch, or unrecoverable fragmentation failure, transition to `ABSENT`.

### ACTIVE

- accept data only for the bound peer, direction, label, route generation, and limits;
- process duplicate READY idempotently;
- on close or failure, transition to `DRAINING` or `ABSENT` according to the data-plane profile.

### DRAINING

- reject new application flows;
- optionally forward bounded in-flight traffic;
- remove state at the drain deadline.

## 5. Responder endpoint offer

States:

`AVAILABLE -> OFFERED -> COMMITTED -> ACTIVE -> CLOSING -> AVAILABLE`

### AVAILABLE

- attempt to open the rerandomized eligibility capsule using the M2-bound suite;
- enforce endpoint offer and cryptographic-work budgets;
- if eligible, create one authenticated candidate payload and finite offer deadline;
- transition the offer to `OFFERED`.

### OFFERED

- build the exact 256-byte authenticated responder payload and seal it with C1;
- wrap the payload in the required nested relay layers;
- encode the resulting variable-length CANDIDATE as one canonical M2 message;
- fragment it into one or more W2 cells and return those cells through the branch context;
- accept only a COMMIT proving knowledge of the protected challenge;
- on valid COMMIT, transition to `COMMITTED`;
- on expiry, cancellation, or abort, delete the offer and return to `AVAILABLE`.

### COMMITTED

- send READY toward the initiator;
- reserve endpoint route state for a finite interval;
- on successful local activation, transition to `ACTIVE`;
- if READY or any required fragment is lost, rely on local expiry rather than peer acknowledgement.

### ACTIVE

- provide the selected service under data-plane limits;
- on close, expiry, or failure, transition to `CLOSING`.

### CLOSING

- remove endpoint state and return to `AVAILABLE`.

## 6. Ingress-peer token bucket

States:

`UNINITIALIZED -> AVAILABLE | EMPTY`

For each `(link epoch, ingress peer, receiving node)` scope:

- initialize to capacity `b`;
- refill by `a` tokens for each elapsed interval `r`, capped at `b`;
- consume one token before expensive fresh-branch processing, after W2/M2 validation;
- when fewer than one token remains, reject the fresh branch and enter or remain `EMPTY`;
- exact cell replays are rejected before token consumption.

Token-bucket state expires with the link epoch or administrative idle deadline.

## 7. Mixing and cell scheduler

States:

`EMPTY -> ACCUMULATING -> ELIGIBLE -> RELEASING -> EMPTY`

The scheduler accepts only complete fixed-size W2 cells. It may interleave cells from different logical messages and CHAFF, subject to bounded per-message progress and expiry. It permutes eligible cells before release and creates a fresh adjacent-link ciphertext for every output.

A traffic-scheduling profile MUST specify:

- release cadence and batch size;
- whether fragments of one logical message may be separated by CHAFF or unrelated traffic;
- the maximum scheduler delay relative to the W2 reassembly timeout;
- fairness rules preventing a multi-cell CANDIDATE from monopolizing a link;
- whether the observable number and timing of cells are padded beyond W2's equal-cell-length property.

E1 timing measurements MUST distinguish protocol event delay from scheduler and release delay.

## 8. Integrated receive pipeline

States:

`RECEIVED -> LENGTH_VALID -> LINK_OPENED -> CELL_PARSED -> REASSEMBLING -> MESSAGE_PARSED -> ADMITTED -> PROCESSED | DROPPED`

- `RECEIVED`: no protocol allocation exists.
- `LENGTH_VALID`: the adjacent-link record is exactly 1,052 bytes.
- `LINK_OPENED`: ChaCha20-Poly1305 authentication succeeds for the bound directional link context.
- `CELL_PARSED`: the 1,024-byte W2 plaintext has a canonical 32-byte header and fragment declaration.
- `REASSEMBLING`: only bounded fragment state exists; route semantics have not executed.
- `MESSAGE_PARSED`: one complete canonical M2 message has been reconstructed and decoded.
- `ADMITTED`: E1 deadline, replay, token-bucket, logical-byte, cell, state, and cryptographic-work checks have reserved capacity.
- `PROCESSED`: the applicable suite-selected eligibility operation and any required C1 reply/signature operation succeed, and the state-machine transition commits.
- `DROPPED`: all temporary reservations are released; no detailed failure is sent to the peer.

A transition cannot skip an earlier state. Link authentication, W2 parsing, reassembly, or M2 decoding failure MUST NOT create branch, candidate, tentative, pending, or active route state.

## 9. Integrated candidate opening

The initiator opens the nested candidate chain one layer at a time. For each relay layer it:

1. derives the current C1 reply secret;
2. opens and parses one canonical relay layer;
3. validates the child length and local capability fields;
4. adds the authenticated reply-key tweak modulo the group order;
5. continues with the child capsule.

The final 256-byte responder payload is accepted only after its endpoint descriptor, endpoint address, final reply public key, offer deadline, challenge, and Ed25519 signature all validate. Any failure transitions the candidate to `INVALID_CRYPTO` and leaves route selection unchanged.

W2 fragmentation is external to the nested C1 chain. Fragment boundaries carry no C1 semantic meaning and MUST NOT alter the bytes supplied to candidate opening.

## 10. Active-tag test state

The active-tagging model adds measurement-only states `TAGGED`, `REJECTED_BY_HONEST_RELAY`, and `OBSERVED`. They are not protocol-visible fields.

Under the C1 negative control, a compromised relay can replace the consistency pair with a chosen ratio relation and emit syntactically valid outgoing M2/W2 traffic. A separated colluder can test the relation after honest C1 rerandomization, and the endpoint later rejects the altered capsule.

Under the symbolic C2 backend, arbitrary mutation is not a valid replay-equivalent rerandomization. The first honest C2 transformation rejects it, transitions the branch to the ordinary invalid-crypto path, and emits no transformed capsule to the downstream colluder. This validates the lifecycle placement of the C2-TAG game but does not establish security of a concrete C2 construction.


## C2-K2 audit status

The reserved local audit suite `0x7f02` is not a network suite and MUST NOT be admitted by M2/W2. It exists only to test the exact `k = 2` arithmetic transcription described in `crypto-profile-c2-k2.md`. Full rerandomization is fail-closed because the literal finite-field map `u -> u mod q` is non-homomorphic under ordinary `QR*_p` multiplication; a corrected or replacement construction requires independent review.
