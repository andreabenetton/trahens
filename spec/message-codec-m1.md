<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens M1 canonical logical-message codec

- Status: Active research profile
- Applies to: Trahens Core v0.7 with U1, E1, C1, and W2
- Reference implementation: `simulator/trahens_codec/m1w2.py`

## 1. Purpose

M1 defines the semantic byte representation of a Trahens control message. M1 messages are variable length and contain no padding. Padding, fragmentation, adjacent-link identifiers, and link encryption belong to W2.

This separation permits protocol fields to evolve independently from the fixed adjacent-link cell size while preserving canonical parsing. An M1 message MUST be fully reassembled before it is parsed or submitted to C1 processing.

## 2. Bounds

The reference profile imposes these absolute limits:

| Item | Bound |
|---|---:|
| Complete M1 message | 16,384 bytes |
| Protected route-control body | 8,192 bytes |
| Branch or candidate token | 16 bytes |
| Local route label | 16 bytes |

A decoder MUST reject an empty message, a message exceeding 16,384 bytes, any declared length that exceeds the containing message, and any representation with trailing bytes.

## 3. Canonical unsigned integer

Variable lengths use unsigned base-128 LEB128. The low seven bits of each octet carry data; bit 7 indicates that another octet follows. Encodings MUST be minimal.

Examples:

| Value | Encoding |
|---:|---|
| 0 | `00` |
| 1 | `01` |
| 127 | `7f` |
| 128 | `80 01` |
| 255 | `ff 01` |
| 16,383 | `ff 7f` |
| 16,384 | `80 80 01` |

A decoder MUST reject `80 00` as a non-minimal representation of zero, an unterminated sequence, an encoding longer than five octets, and a value above the field-specific maximum.

## 4. Common envelope

Every M1 message is encoded as:

```text
message_type(1)
protocol_version(1)
privacy_profile(1)
lifecycle_profile(1)
suite_id(2)
message_profile(1)
reserved(1)
body_length(varuint)
body(body_length)
```

The current values are:

- protocol version: `0x01`;
- U1 privacy profile: `0x01`;
- E1 lifecycle profile: `0x01`;
- C1 suite: `0x0001`;
- M1 message profile: `0x01`;
- reserved: `0x00`.

The envelope, including `message_type` and all profile identifiers, is carried only inside encrypted W2 cells on an adjacent link.

## 5. Message types

| Value | Name |
|---:|---|
| `0x00` | CHAFF |
| `0x20` | DISCOVER |
| `0x21` | CANDIDATE |
| `0x22` | COMMIT |
| `0x23` | READY |
| `0x24` | CANCEL |
| `0x25` | ABORT |
| `0x26` | CLOSE |

Unknown message types are rejected after W2 authentication and complete reassembly. A rejected message produces no amplified protocol response.

## 6. DISCOVER

The DISCOVER body has one canonical length:

```text
branch_token(16)
hop_remaining(1)
fanout_class(1)
expiry_class(1)
options(1)
reply_public_key(32)
eligibility_capsule(128)
```

Requirements:

- `branch_token` MUST be non-zero and independently generated for each outgoing child;
- `fanout_class` and `expiry_class` MUST be non-zero;
- `reply_public_key` MUST be a canonical non-identity `ristretto255` element;
- the eligibility capsule MUST contain four canonical non-identity `ristretto255` elements;
- unknown option bits MUST be zero unless a negotiated extension assigns them.

The reference encoded DISCOVER message is 190 bytes and therefore occupies one W2 cell.

## 7. CANDIDATE

The CANDIDATE body is:

```text
candidate_token(16)
expiry_class(1)
layer_count(1)
candidate_blob_length(varuint)
candidate_blob(candidate_blob_length)
```

`candidate_blob` is the nested C1 reverse chain. It MAY exceed the payload of one W2 cell. `layer_count` MUST equal the number of C1 layers successfully opened by the initiator. It is a consistency check, not a substitute for cryptographic verification.

The candidate token is local to one reverse adjacency and is replaced at every relay. The blob length MUST be at least one and the complete M1 message MUST remain within the M1 maximum.

## 8. Route-control messages

COMMIT, READY, CANCEL, ABORT, and CLOSE use:

```text
local_label(16)
generation(4)
expiry_class(1)
protected_length(varuint)
protected_body(protected_length)
```

`generation` is an unsigned big-endian integer. `local_label` MUST be non-zero, adjacent-link scoped, and replaced when forwarding. `protected_body` is interpreted by the message definition and C1 transcript rules. The maximum protected body is 8,192 bytes.

## 9. CHAFF

The CHAFF body is empty. A CHAFF M1 message traverses the same W2 protection, queue, and scheduling path as real control traffic. It MUST NOT allocate reassembly state beyond its single cell and MUST NOT allocate branch, candidate, tentative, pending, or active route state.

## 10. Validation order

After W2 has produced a complete byte string, an M1 receiver validates:

1. total message bound;
2. common fixed fields;
3. canonical body length;
4. exact containment with no trailing bytes;
5. message-specific fixed fields and nested lengths;
6. resource admission for the message class;
7. C1 point, URE, KEM, AEAD, signature, and transcript rules;
8. route-state transition.

No C1 operation or route-state allocation occurs before steps 1-6 succeed.
