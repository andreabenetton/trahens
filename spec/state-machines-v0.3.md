# Trahens Core v0.3 state machines

## 1. Initiator logical discovery

States:

`IDLE -> PREPARING -> DISCOVERING -> COLLECTING -> SELECTING -> COMMITTING -> ACTIVE -> CLOSING -> IDLE`

### IDLE

- Accept a local application request.
- Create a local logical-discovery context.
- Reserve cumulative budgets and deadline.
- Transition to `PREPARING`.

### PREPARING

- Select the next local ring policy.
- Create independent root reply key pairs and eligibility ciphertexts for each first-hop branch.
- Create fresh first-hop branch tokens.
- Do not create a wire attempt identifier.
- Transition to `DISCOVERING`.

### DISCOVERING

- Send bounded first-hop DISCOVER records.
- Charge all transmitted bytes and cryptographic operations to the logical discovery.
- Transition to `COLLECTING`.

### COLLECTING

- Accept candidate capsules for every live first-hop branch.
- Open nested key-blinding layers.
- Authenticate responder offers end to end.
- Deduplicate candidates by authenticated responder or credential policy only after decryption.
- On sufficient candidates, transition to `SELECTING`.
- On window expiry, return to `PREPARING` if another ring and budget remain; otherwise transition to `SELECTING`.

### SELECTING

- Select zero or one authenticated candidate.
- With zero candidates, release local state and return to `IDLE` with failure.
- With one candidate, send COMMIT through its first-hop label and transition to `COMMITTING`.

### COMMITTING

- Accept READY only for the selected protected transcript.
- Retransmit only according to bounded idempotent policy.
- On authenticated READY, transition to `ACTIVE`.
- On timeout or abort, release local state and return to `IDLE`.

### ACTIVE

- Pass route capabilities and limits to the data-plane profile.
- On close, expiry, peer failure, or limit exhaustion, transition to `CLOSING`.

### CLOSING

- Send CLOSE when permitted.
- Remove local state without waiting for remote cooperation.
- Return to `IDLE`.

## 2. Relay branch context

States:

`ABSENT -> ADMITTED -> FORWARDED -> EXPIRED`

### ABSENT

On DISCOVER:

- validate the adjacent-link record and local budgets;
- reject an exact link-local replay;
- reserve branch-context capacity;
- if admitted, bind ingress peer, branch token, reply public key, expiry, and limits;
- transition to `ADMITTED`.

A DISCOVER arriving over a different peer or token is an independent context, not a duplicate.

### ADMITTED

- Evaluate local responder eligibility without disclosing the result to unrelated relays.
- Select bounded children excluding the ingress peer.
- For each child, generate an independent token, key blinding scalar, rerandomization, and child mapping.
- Enqueue transformed messages into the U1 mixing batch.
- Transition to `FORWARDED` when child mappings are committed.

### FORWARDED

- Accept bounded CANDIDATE records only from stored child mappings.
- Create tentative route mappings while returning candidates.
- Reject exact local replays idempotently.
- On expiry, peer loss, cancellation, or eviction, transition to `EXPIRED`.

### EXPIRED

- Remove full branch and child state.
- Retain at most small link-local replay markers until their replay deadline.
- Delayed messages cannot recreate the expired context.

## 3. Relay route state

States:

`ABSENT -> TENTATIVE -> ACTIVE -> DRAINING -> ABSENT`

### TENTATIVE

Created during candidate return.

- Bind child and parent candidate tokens and forward labels.
- Reject application data.
- Handle duplicate candidate records idempotently.
- On valid COMMIT, atomically transition to `ACTIVE`.
- On timeout, abort, peer failure, or pressure, remove the state.

### ACTIVE

- Accept traffic only when peer, direction, label, route generation, and limits match.
- Apply byte, packet, idle, and absolute lifetimes.
- Treat duplicate COMMIT idempotently.
- On CLOSE or failure, transition to `DRAINING` or `ABSENT` according to the data-plane profile.

### DRAINING

- Reject new application flows.
- Optionally forward bounded in-flight traffic.
- Remove state at the local drain deadline.

## 4. Responder

States:

`AVAILABLE -> OFFERED -> ACTIVE -> CLOSING -> AVAILABLE`

### AVAILABLE

- Attempt to open the rerandomized eligibility capsule according to service policy.
- If eligible and within budget, construct an authenticated candidate payload and seal it to the received reply public key.
- Create tentative endpoint state and transition the offer to `OFFERED`.

### OFFERED

- Accept only a COMMIT that proves knowledge of the protected commit challenge.
- On success, activate the route, send READY, and transition to `ACTIVE`.
- On expiry or abort, delete only the matching local offer.

### ACTIVE

- Provide the selected service through the data-plane profile.
- On close, expiry, or failure, transition to `CLOSING`.

### CLOSING

- Remove endpoint route state and return to `AVAILABLE`.

## 5. Mixing scheduler

States:

`EMPTY -> ACCUMULATING -> ELIGIBLE -> RELEASING -> EMPTY`

### ACCUMULATING

- Accept transformed real and chaff records of one observable class.
- Enforce queue byte and record limits.
- On reaching the anonymity-set threshold or release deadline, transition to `ELIGIBLE`.

### ELIGIBLE

- Add chaff according to policy when required.
- Sample a uniform permutation.
- Transition to `RELEASING`.

### RELEASING

- Emit records according to the declared schedule.
- Do not preserve input ordering.
- Return to `EMPTY` or `ACCUMULATING` for residual records.
