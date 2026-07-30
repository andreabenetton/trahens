# Trahens Core v0.1 state machines

## 1. Initiator

States:

`IDLE -> DISCOVERING -> SELECTING -> COMMITTING -> ACTIVE -> CLOSING -> IDLE`

Failure from any non-active setup state returns to `IDLE` after bounded cleanup.

### IDLE

- Create a fresh discovery ID.
- Reserve local discovery budget.
- Transition to `DISCOVERING` after sending at least one valid DISCOVER.

### DISCOVERING

- Accept authenticated CANDIDATE messages up to the candidate limit.
- Ignore duplicates idempotently.
- Transition to `SELECTING` on timer expiry, limit reached, or policy decision.

### SELECTING

- Select zero or one candidate.
- Zero candidates: release state and return to IDLE.
- One candidate: allocate a reverse label and send COMMIT; transition to COMMITTING.

### COMMITTING

- Accept READY only for the selected candidate and transcript.
- Bounded retries may resend the same idempotent COMMIT.
- READY success transitions to ACTIVE.
- Timeout or ABORT releases local state and returns to IDLE.

### ACTIVE

- Hand the established labels and limits to the selected data-plane profile.
- CLOSE, timeout, peer failure, or limit exhaustion transitions to CLOSING.

### CLOSING

- Send CLOSE when possible.
- Remove local state regardless of remote acknowledgement.
- Return to IDLE.

## 2. Relay discovery state

States:

`ABSENT -> ACCEPTED -> EXPIRED`

### ABSENT

On DISCOVER:

- validate framing, budget, expiry, and duplicate status;
- if accepted, store the parent and transition to ACCEPTED;
- otherwise remain ABSENT or create only a bounded replay-cache entry.

### ACCEPTED

- Forward to bounded children.
- Accept bounded CANDIDATE responses only from children to which the discovery was forwarded.
- A repeated DISCOVER does not create a second parent in v0.1.
- On expiration or parent disconnect, transition to EXPIRED.

### EXPIRED

- Remove full discovery state.
- Retain at most a smaller replay-cache marker for a bounded interval.

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
- When responding, create candidate and tentative endpoint state, then transition to OFFERED.

### OFFERED

- Accept only a matching valid COMMIT.
- On success, activate reverse state, send READY, and transition to ACTIVE.
- Timeout or ABORT returns to AVAILABLE.

### ACTIVE

- Provide the selected service through the data-plane profile.
- CLOSE, timeout, or failure transitions to CLOSING.

### CLOSING

- Remove endpoint route state and return to AVAILABLE.

## 5. Idempotency keys

At minimum, implementations need idempotent handling for:

- `(discovery_id, incoming_peer)` for DISCOVER;
- `(discovery_id, candidate_id, incoming_peer)` for CANDIDATE;
- `(candidate_id, incoming_label)` for COMMIT;
- protected route reference for READY and CLOSE.
