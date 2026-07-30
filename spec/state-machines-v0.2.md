# Trahens Core v0.2 state machines

## 1. Initiator logical discovery

States:

`IDLE -> ATTEMPTING -> WAITING -> SELECTING -> COMMITTING -> ACTIVE -> CLOSING -> IDLE`

Failure from any non-active setup state returns to `IDLE` after bounded cleanup.

### IDLE

- Create a fresh local logical-discovery ID.
- Reserve cumulative budgets and overall deadline.
- Load a validated ring schedule.
- Transition to `ATTEMPTING`.

### ATTEMPTING

- Verify remaining total budgets and deadline.
- Select the next ring.
- Create a fresh attempt ID and attempt-scoped ephemeral material.
- Send bounded DISCOVER messages.
- Transition to `WAITING`.

If no ring or budget remains, release state and return to `IDLE` with failure.

### WAITING

- Accept authenticated CANDIDATE messages for any still-live attempt in this logical discovery.
- Deduplicate candidates by authenticated responder/service identity.
- Ignore duplicate candidate messages idempotently.
- On sufficient candidates, transition to `SELECTING`.
- On candidate-window expiry, transition to `ATTEMPTING` when another ring is allowed; otherwise transition to `SELECTING`.

### SELECTING

- Select zero or one unique candidate.
- Zero candidates: cancel live attempts when practical, release state, and return to `IDLE`.
- One candidate: allocate a reverse label, send COMMIT, cancel or ignore other attempts, and transition to `COMMITTING`.

### COMMITTING

- Accept READY only for the selected candidate and transcript.
- Bounded retries may resend the same idempotent COMMIT.
- READY success transitions to `ACTIVE`.
- Timeout or ABORT releases local state and returns to `IDLE`.

### ACTIVE

- Hand established labels and limits to the selected data-plane profile.
- CLOSE, timeout, peer failure, or limit exhaustion transitions to `CLOSING`.

### CLOSING

- Send CLOSE when possible.
- Remove local state regardless of remote acknowledgement.
- Return to `IDLE`.

## 2. Relay attempt state

States:

`ABSENT -> ACCEPTED -> EXPIRED`

### ABSENT

On DISCOVER:

- validate framing, budgets, expiry, and duplicate status;
- if accepted, store the parent and transition to `ACCEPTED`;
- otherwise remain `ABSENT` or create only a bounded replay marker.

### ACCEPTED

- Forward to bounded children.
- Accept bounded CANDIDATE responses only from children to which the attempt was forwarded.
- A repeated DISCOVER does not create a second parent.
- An unrelated fresh attempt ID is accounted as a separate attempt and may be rejected by peer or global limits.
- On expiration, cancellation, or parent disconnect, transition to `EXPIRED`.

### EXPIRED

- Remove full attempt state.
- Retain at most a smaller replay marker for a bounded interval.
- Delayed messages cannot recreate the state.

## 3. Relay route state

States:

`ABSENT -> TENTATIVE -> ACTIVE -> DRAINING -> ABSENT`

### TENTATIVE

Created while CANDIDATE travels toward the initiator.

- Application data is rejected.
- Duplicate CANDIDATE is handled idempotently.
- Valid COMMIT converts the entry to ACTIVE.
- Timeout, ABORT, resource pressure, or peer failure removes it.

### ACTIVE

- Forward only when incoming peer, direction, and label all match.
- Apply packet, byte, idle, and absolute limits.
- Duplicate COMMIT receives idempotent treatment and MUST NOT allocate new labels.
- CLOSE or failure transitions to DRAINING or directly to ABSENT according to the data-plane profile.

### DRAINING

- Reject new application flows.
- Optionally allow bounded in-flight traffic.
- Remove state at the drain deadline.

## 4. Responder

States:

`AVAILABLE -> OFFERED -> ACTIVE -> CLOSING -> AVAILABLE`

### AVAILABLE

- Evaluate DISCOVER according to service and resource policy.
- Treat each fresh attempt ID independently.
- When responding, create candidate and tentative endpoint state, then transition one offer context to `OFFERED`.

### OFFERED

- Accept only a matching valid COMMIT.
- On success, activate reverse state, send READY, and transition that route to `ACTIVE`.
- Timeout or ABORT removes only the matching offer.

### ACTIVE

- Provide the selected service through the data-plane profile.
- CLOSE, timeout, or failure transitions to `CLOSING`.

### CLOSING

- Remove endpoint route state and return to `AVAILABLE`.

## 5. Idempotency keys

At minimum, implementations need idempotent handling for:

- `(attempt_id, incoming_peer)` for DISCOVER;
- `(attempt_id, candidate_id, incoming_peer)` for CANDIDATE;
- `(attempt_id, candidate_id, incoming_label)` for COMMIT;
- protected route reference for READY and CLOSE.
