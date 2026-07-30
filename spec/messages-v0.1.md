# Trahens Core v0.1 abstract messages

This document defines semantic fields, not a final binary encoding. A later wire-format document will assign canonical field numbers, lengths, and test vectors.

## 1. Common envelope

Every control message contains or is cryptographically bound to:

| Field | Purpose |
|---|---|
| `version` | Protocol semantic version |
| `message_type` | DISCOVER, CANDIDATE, COMMIT, READY, ABORT, or CLOSE |
| `suite_id` | Cryptographic profile |
| `privacy_profile_id` | Padding and scheduling profile |
| `expires_at` | Absolute expiry in the profile-defined time domain |
| `body_length` | Canonical body length |
| `body` | Message-specific fields |
| `auth` | Hop or end-to-end authentication required by the profile |

The final encoding MUST distinguish unknown optional fields from unknown critical fields.

## 2. Validation order

A node SHOULD reject in this order:

1. framing and maximum size;
2. supported version and message type;
3. expiration and coarse time window;
4. peer-local rate and state budgets;
5. canonical encoding and field ranges;
6. local context lookup;
7. replay or duplicate lookup;
8. inexpensive authentication checks;
9. public-key operations;
10. state allocation and forwarding.

No state allocation should occur before steps 1-7 pass.

## 3. DISCOVER

| Field | Description |
|---|---|
| `discovery_id` | Random 128-bit identifier, unique to one discovery |
| `hop_count` | Number of forwarding hops already traversed |
| `hop_limit` | Maximum allowed hop count |
| `candidate_limit` | Maximum number of responder candidates accepted by the initiator |
| `service_selector` | Profile-defined responder selection value |
| `initiator_reply_key` | Ephemeral key material required by the cryptographic profile |
| `request_options` | Bounded optional requirements |

Rules:

- `hop_count` MUST be strictly less than or equal to `hop_limit`.
- A relay increments `hop_count` exactly once before forwarding.
- A relay MUST normalize or remove sender-controlled fields not intended to propagate.
- `service_selector` leakage must be documented by the profile.

## 4. CANDIDATE

| Field | Description |
|---|---|
| `discovery_id` | Discovery being answered |
| `candidate_id` | Random responder-selected candidate identifier |
| `forward_label` | Label the receiving parent uses to send toward the responder |
| `route_commitment` | Commitment to responder, route ID, limits, and transcript |
| `responder_metadata` | Minimal authenticated information needed for selection |
| `response_auth` | End-to-end responder authentication material |

At every relay, `forward_label` is replaced by a newly generated parent-facing label. Other modifications are limited to profile-defined protected extensions.

## 5. COMMIT

| Field | Description |
|---|---|
| `candidate_id` | Selected tentative route |
| `route_confirmation` | Cryptographic confirmation of the responder commitment |
| `route_limits` | Expiry, idle timeout, and profile limits |
| `reverse_label` | Label the receiving child uses for traffic toward the initiator |
| `commit_auth` | Initiator authentication or capability proof |

The outer forwarding context supplies the current forward label. Each relay replaces `reverse_label` with a newly generated child-facing label.

## 6. READY

| Field | Description |
|---|---|
| `route_confirmation` | Confirmation that the responder activated the committed route |
| `accepted_limits` | Final negotiated route limits |
| `ready_auth` | Responder authentication and transcript confirmation |

READY travels through active reverse mappings.

## 7. ABORT

| Field | Description |
|---|---|
| `context_type` | Discovery, candidate, or route |
| `context_reference` | Local or protected reference |
| `reason_class` | Coarse reason that avoids exposing local topology or policy |
| `retry_after` | Optional bounded retry guidance |

ABORT is advisory. Missing ABORT never prevents local timeout cleanup.

## 8. CLOSE

| Field | Description |
|---|---|
| `route_confirmation` | Protected reference to the active route |
| `direction` | One direction or both |
| `close_auth` | Authorization to close the route |

CLOSE processing is idempotent and rate-limited.
