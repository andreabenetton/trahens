# Trahens Core v0.3 abstract messages

- Status: Research design draft
- Applies to: Core v0.3
- Encoding status: Abstract; canonical binary encoding remains future work

## 1. General requirements

Every control message is carried inside one adjacent-link record. The record header exposes only values required by the underlay. Protocol message type, fields, and padding are encrypted on the adjacent link.

For U1, each message class has a fixed record length. A sender MUST reconstruct and re-encrypt a complete canonical body at every hop. A sender MUST NOT forward an unchanged opaque field unless the field is rerandomized by a primitive whose selected security definition includes unlinkability.

No message contains a network-wide discovery identifier.

## 2. Common validation order

A receiver SHOULD process an adjacent-link record in this order:

1. enforce record-length class;
2. enforce peer byte and message rate;
3. validate link epoch and sequence replay domain;
4. authenticate and decrypt the adjacent-link record;
5. validate protocol version and privacy profile;
6. validate canonical encoding and field bounds;
7. validate expiry class and propagation bounds;
8. check link-local branch or label replay state;
9. reserve local state and cryptographic-work budget;
10. perform URE, KEM, credential, or signature work;
11. allocate full branch or route state;
12. enqueue bounded outgoing work.

A failure MUST NOT consume resources from later stages.

## 3. DISCOVER

### 3.1 Purpose

Propagate one independently transformed branch toward potential responders.

### 3.2 Logical fields

- `version`
- `profile_id`
- `suite_id`
- `branch_token`
- `propagation_class`
- `fanout_class`
- `reply_public_key`
- `eligibility_capsule`
- `expiry_class`
- `options`
- `padding`

### 3.3 Prohibited fields

`DISCOVER` MUST NOT contain:

- logical discovery ID;
- attempt ID;
- previous attempt ID;
- ring index or retry count;
- source route or path vector;
- stable endpoint-address hash;
- stable candidate or route ID;
- unchanged eligibility ciphertext from the previous hop.

### 3.4 Relay transformation

For every selected child, the relay generates a fresh branch token, blinds the reply public key, rerandomizes the eligibility capsule, decrements or otherwise advances the bounded propagation control, regenerates padding, and seals a fresh link record.

## 4. CANDIDATE

### 4.1 Purpose

Return an authenticated responder offer through the reverse branch context while installing tentative hop-local route mappings.

### 4.2 Logical fields

- `version`
- `profile_id`
- `suite_id`
- `candidate_token`
- `nested_candidate_capsule`
- `parent_forward_label`
- `offer_expiry_class`
- `padding`

The responder candidate payload is inside the innermost encrypted capsule. Relays MUST NOT receive the authenticated responder identity or service offer in plaintext.

### 4.3 Relay transformation

A relay receiving a valid child candidate token:

1. verifies that the token is bound to one live child branch;
2. reserves tentative-state capacity;
3. generates a fresh parent candidate token;
4. generates a fresh parent-facing forward label;
5. wraps the child capsule using the incoming reply public key and stored blinding scalar;
6. stores the child-to-parent mapping;
7. sends a fresh fixed-size parent record.

The child candidate token and child record bytes MUST NOT be copied into the parent-visible fields.

## 5. COMMIT

### 5.1 Purpose

Select one tentative route and activate its forward mappings.

### 5.2 Logical fields

- `incoming_forward_label`
- `protected_commit_body`
- `reverse_label_offer`
- `commit_expiry_class`
- `padding`

The protected commit body contains the end-to-end commit challenge response. A relay processes only the local incoming label and the local mapping. No global candidate identifier is required.

### 5.3 Idempotency

A duplicate commit on the same peer, label, route generation, and transcript is processed idempotently. A different transcript on the same label is rejected.

## 6. READY

### 6.1 Purpose

Confirm responder activation and complete reverse mappings.

### 6.2 Logical fields

- `incoming_reverse_label`
- `protected_ready_body`
- `route_limits_class`
- `padding`

`READY` is forwarded only through active reverse mappings. The initiator exposes the route to the data plane only after the protected ready body authenticates the selected transcript.

## 7. ABORT

`ABORT` removes one tentative route mapping identified by a local label and peer binding. Nodes do not rely on ABORT for eventual cleanup. The message uses the same fixed-size and transformation rules as other setup records.

## 8. CLOSE

`CLOSE` requests removal or draining of one active route mapping. It uses local labels and an end-to-end protected close reason class. Detailed local capacity or topology information MUST NOT be exposed.

## 9. CHAFF

A U1 `CHAFF` record:

- occupies a real record-size class;
- follows the same batching and scheduling path;
- is indistinguishable from a real record to an observer without adjacent-link keys;
- is recognized and discarded only after adjacent-link authentication and profile processing;
- cannot allocate route or branch state beyond a small bounded parsing cost.

## 10. Local idempotency keys

The minimum local keys are:

- `(link_epoch, incoming_peer, branch_token)` for DISCOVER exact replay;
- `(incoming_peer, candidate_token)` for CANDIDATE;
- `(incoming_peer, incoming_forward_label, transcript_hash)` for COMMIT;
- `(incoming_peer, incoming_reverse_label, transcript_hash)` for READY;
- `(incoming_peer, local_label, route_generation)` for ABORT and CLOSE.

None of these keys is forwarded unchanged to another link.

## 11. Error behavior

Nodes SHOULD silently discard invalid discovery and candidate records after local accounting. When an error response is required, its class, size, timing policy, and amplification factor MUST be bounded and independent of secret state.
