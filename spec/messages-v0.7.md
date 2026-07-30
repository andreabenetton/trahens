# Trahens Core v0.7 messages, M1 encoding, and W2 transport

- Status: Active research design
- Applies to: Core v0.7 with U1, E1, C1, M1, and W2
- Encoding status: M1 logical fields, W2 cells, and C1 cryptographic fields are concrete

## 1. Layer separation

Trahens processes three nested representations:

1. a **protocol object**, such as DISCOVER or CANDIDATE;
2. one canonical variable-length **M1 message** representing that object;
3. one or more fixed-size encrypted **W2 cells** carrying the M1 bytes on one adjacent link.

M1 contains no padding. W2 pads every 1,024-byte cell plaintext before adjacent-link encryption. A relay MUST completely authenticate and reassemble an incoming M1 message, perform the message-specific transformation, construct a new M1 message, choose a fresh adjacent-link-local message identifier, and emit new W2 cells. It MUST NOT forward an incoming fragment, padding region, message-local identifier, or link ciphertext unchanged.

No message contains a network-wide discovery identifier.

## 2. Common receive order

A receiver SHOULD process input in this order:

1. enforce the exact 1,052-byte W2 record length;
2. enforce adjacent-link byte and cell-rate limits;
3. parse the public link epoch and sequence and perform a non-mutating replay-window precheck;
4. authenticate and decrypt the cell;
5. commit replay admission and reject an authenticated exact duplicate; unauthenticated input MUST NOT advance replay state;
6. validate W2 profile fields and canonical fragment metadata;
7. expire stale reassembly contexts;
8. enforce reassembly message-count and reserved-byte budgets;
9. accept, deduplicate, or reject the fragment;
10. after complete reassembly, validate the M1 envelope and canonical variable lengths;
11. validate message-specific field bounds;
12. convert lifetime classes into local half-open deadlines;
13. enforce peer and node work budgets;
14. reserve route-protocol state capacity;
15. perform URE, KEM, credential, AEAD, or signature work;
16. allocate or transition branch and route state;
17. enqueue bounded outgoing M1/W2 work.

A failure MUST NOT consume resources from later stages. Reassembly state is not route state and MUST expire independently. Equal-time protocol processing follows E1: expiry, cancellation, route control, candidate, discovery, then window closure.

## 3. Common M1 envelope

Every logical message contains:

- `message_type`;
- `protocol_version`;
- `u1_profile_id`;
- `e1_profile_id`;
- `suite_id` = `0x0001` for C1;
- `m1_profile_id`;
- zero reserved byte;
- canonical variable body length;
- exact body bytes.

The common fields and type are encrypted inside W2. An M1 decoder rejects trailing bytes and non-minimal variable integers.

## 4. DISCOVER

### 4.1 Purpose

Propagate one independently transformed branch toward potential responders.

### 4.2 Logical fields

- `branch_token`: 16-byte non-zero adjacent-link capability;
- `hop_remaining`;
- `fanout_class`;
- `expiry_class`;
- `options`;
- `reply_public_key`: one canonical 32-byte non-identity `ristretto255` element;
- `eligibility_capsule`: four canonical `ristretto255` elements, 128 bytes total.

The canonical M1 DISCOVER length is 190 bytes and occupies one W2 cell.

### 4.3 Prohibited fields

DISCOVER MUST NOT contain:

- logical discovery ID;
- attempt ID;
- previous attempt ID;
- ring index or retry count;
- source route or path vector;
- stable endpoint-address hash;
- stable candidate or route ID;
- previous-hop W2 message identifier;
- unchanged eligibility ciphertext from the previous hop.

### 4.4 Relay transformation

For every selected child, the relay generates a fresh branch token, blinds the reply public key, rerandomizes the eligibility capsule, advances the bounded propagation control, constructs a new M1 message, assigns a new W2 message-local identifier, fragments canonically, generates new cell padding, and applies fresh link protection.

## 5. CANDIDATE

### 5.1 Purpose

Return an authenticated responder offer through the reverse branch context while installing tentative hop-local route mappings.

### 5.2 Logical fields

- `candidate_token`: 16-byte non-zero reverse adjacency capability;
- `offer_expiry_class`;
- `layer_count`;
- canonical variable `nested_candidate_length`;
- `nested_candidate_capsule`.

The responder payload is inside the innermost C1 reply capsule. Relays do not receive the authenticated responder identity or service offer in plaintext.

### 5.3 Variable size

A candidate grows as reverse relays add authenticated C1 wrappers. M1 permits the complete message to grow to 16,384 bytes. W2 carries it in

```text
ceil(M1_length / 992)
```

cells. The sender MUST use canonical fragmentation. A receiver MUST NOT accept a short-fragment representation that produces the same bytes with a larger cell count.

`layer_count` is checked against the number of C1 layers opened by the initiator. It does not authorize skipping layers.

### 5.4 Relay transformation

A relay receiving a valid child candidate token:

1. verifies that the token is bound to one live child branch;
2. reserves tentative-state capacity;
3. generates a fresh parent candidate token;
4. generates a fresh parent-facing forward label;
5. wraps the child capsule using the incoming reply public key and stored blinding scalar;
6. stores the child-to-parent mapping;
7. constructs a new variable-length M1 candidate;
8. emits one or more new W2 cells.

The child candidate token, W2 message identifier, fragment bytes, and cell padding MUST NOT be reused on the parent link.

## 6. COMMIT

### 6.1 Purpose

Select one tentative route, reserve route capacity, and move its forward mappings to `PENDING_READY`.

### 6.2 Logical fields

The route-control M1 body contains:

- `incoming_forward_label`;
- `route_generation`;
- `commit_expiry_class`;
- canonical variable protected-body length;
- `protected_commit_body`.

The protected body contains the end-to-end commit challenge response. A relay processes only its local label, generation, peer binding, and mapping. No global candidate identifier is required.

### 6.3 Idempotency

A duplicate commit on the same peer, label, route generation, and transcript is processed idempotently. A different transcript on the same label is rejected.

## 7. READY

READY confirms responder activation and completes reverse mappings. It uses the common route-control body with an incoming reverse label and a protected ready proof.

READY is forwarded through matching `PENDING_READY` mappings and converts them to `ACTIVE`. The initiator exposes the route to the data plane only after authenticating the final protected body.

## 8. CANCEL

CANCEL promptly reclaims one off-route branch subtree after route selection or termination. It uses a local capability, local cancellation generation, expiry class, and bounded protected body.

The generation is local to one adjacent mapping and is replaced at every hop. CANCEL MUST NOT contain a global route, candidate, logical-discovery, ring, or W2 message identifier.

CANCEL is advisory. Loss of one or more cells cannot prevent eventual cleanup because every affected branch and tentative state has an independent deadline.

## 9. ABORT

ABORT removes one tentative route mapping identified by a local label, generation, and peer binding. Nodes do not rely on ABORT for eventual cleanup. It uses the same M1 route-control form and W2 processing rules as COMMIT and READY.

## 10. CLOSE

CLOSE requests removal or draining of one active route mapping. It uses local labels and an end-to-end protected close reason class. Detailed local capacity or topology information MUST NOT be exposed.

## 11. CHAFF

The M1 CHAFF body is empty. It is carried in one ordinary W2 cell and follows the same link encryption, queue, batching, and scheduling path as real traffic. It is recognized only after link authentication, reassembly, and M1 decoding.

CHAFF MUST NOT allocate branch, candidate, tentative, pending, or active route state. Its parsing and one-cell reassembly cost remain bounded.

## 12. W2 fragment fields

Every encrypted W2 cell contains:

- W2, protocol, U1, E1, and C1 profile identifiers;
- zero flags and reserved byte;
- fresh 16-byte adjacent-link-local message identifier;
- two-byte fragment index;
- two-byte canonical fragment count;
- two-byte canonical fragment length;
- two-byte total M1 length;
- up to 992 M1 bytes;
- fresh random padding to 1,024 bytes.

The complete adjacent-link record is 1,052 bytes including the public epoch, public sequence, and 16-byte AEAD tag.

## 13. Reassembly behavior

The minimum local key is:

```text
(authenticated_link_direction, message_local_id)
```

A receiver accepts fragments in any order. It ignores an exact duplicate fragment. It invalidates the context when the same index carries different bytes or when count and total metadata differ. It parses M1 only after all canonical indexes are present and the concatenated length equals the declared total.

A context expires on a half-open local deadline. Expiry removes all fragment bytes and reservations without sending an amplified error.

## 14. Local protocol idempotency keys

After M1 decoding, the minimum local keys are:

- `(link_epoch, incoming_peer, branch_token)` for DISCOVER;
- `(incoming_peer, candidate_token)` for CANDIDATE;
- `(incoming_peer, incoming_forward_label, transcript_hash)` for COMMIT;
- `(incoming_peer, incoming_reverse_label, transcript_hash)` for READY;
- `(incoming_peer, local_label, route_generation)` for CANCEL, ABORT, and CLOSE.

None is forwarded unchanged to another link.

## 15. E1 lifetime and window rules

Messages carry lifetime or expiry classes, not synchronized absolute timestamps. The receiver converts a class into a local deadline when state is admitted. State is valid on `[created, deadline)` and invalid at the deadline.

Ring indexes, retry counts, candidate-window numbers, and selection state are initiator-local and MUST NOT appear in DISCOVER or CANDIDATE. A delayed candidate from an earlier local ring remains eligible only according to initiator-local E1 state.

The W2 reassembly deadline is independent from the resulting branch, candidate, or route-state deadline.

## 16. C1 validation and error behavior

A C1 receiver rejects invalid or identity public keys, invalid encapsulated elements, non-canonical scalars, malformed URE points, URE consistency failure, eligibility marker mismatch, AEAD failure, candidate signature failure, and transcript mismatch through one state-machine result: `INVALID_CRYPTO`. The detailed reason is not transmitted.

Nodes SHOULD silently discard invalid fragments, messages, discoveries, and candidates after local accounting. When an error response is required, its class, cell count, timing policy, and amplification factor MUST be bounded and independent of secret state.

## 17. Active-tagging boundary

The C1 URE consistency pair remains malleable. A compromised relay can create a fresh, correctly authenticated W2 representation containing a persistent ratio tag. W2 prevents unauthorized edge modification, but it does not prevent an authorized relay from transforming end-to-end cryptographic fields maliciously.

The protocol therefore MUST NOT claim active-adversary message unlinkability. Tag observations and endpoint rejection are measured separately from W2 link-authentication, M1 parsing, and reassembly failures.
