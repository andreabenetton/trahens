<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens W1 fixed-size wire codec

- Status: Active research profile
- Applies to: Trahens Core v0.6 with U1, E1, and C1
- Reference implementation: `simulator/trahens_codec/c1.py`

## 1. Purpose

W1 removes record-length and message-class leakage from the adjacent-link wire image. Every Trahens control record has one fixed encoded length. The message type, protocol profiles, cryptographic suite, logical fields, and padding are contained inside an authenticated adjacent-link ciphertext.

W1 does not hide the existence, direction, or timing of a transmission on an adjacent link. A traffic-scheduling profile is required for that property.

## 2. Fixed lengths

The reference profile uses:

| Item | Length |
|---|---:|
| Authenticated plaintext body | 1,024 bytes |
| Public link epoch | 4 bytes |
| Public link sequence | 8 bytes |
| ChaCha20-Poly1305 tag | 16 bytes |
| Complete adjacent-link record | 1,052 bytes |

The adjacent-link ciphertext has length 1,040 bytes: the 1,024-byte body followed by the 16-byte authentication tag.

A conforming decoder MUST reject every record whose length is not exactly 1,052 bytes before protocol parsing or route-state allocation.

## 3. Public adjacent-link header

The public header is:

```text
epoch(4) || sequence(8)
```

Both values are unsigned big-endian integers. The 12-byte header is used as the ChaCha20-Poly1305 nonce and as associated data. The sequence value is scoped to one direction of one adjacent-link epoch.

The link layer MUST prevent key and nonce reuse. The reference simulator derives deterministic test keys from the simulation seed and ordered node pair; this derivation is not a deployment key-establishment protocol.

## 4. Authenticated body common prefix

The encrypted body begins with:

```text
message_type(1)
protocol_version(1)
privacy_profile(1)
lifecycle_profile(1)
suite_id(2)
wire_profile(1)
reserved(1)
```

For W1/C1 the values are:

- protocol version: `0x01`;
- U1 privacy profile: `0x01`;
- E1 lifecycle profile: `0x01`;
- C1 suite: `0x0001`;
- W1 wire profile: `0x01`;
- reserved: `0x00`.

The entire prefix is adjacent-link encrypted. A passive observer without the link key cannot distinguish DISCOVER, CANDIDATE, route-control, or CHAFF records by record length or plaintext type.

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

Unknown values are rejected after adjacent-link authentication.

## 6. DISCOVER body

After the common prefix:

```text
branch_token(16)
hop_remaining(1)
fanout_class(1)
expiry_class(1)
options(1)
reply_public_key(32)
eligibility_capsule(128)
padding(836)
```

The branch token MUST be non-zero and independently generated for each outgoing child. The reply public key MUST be a canonical non-identity `ristretto255` element. The eligibility capsule contains four canonical non-identity `ristretto255` elements.

The padding is freshly generated for every hop and every child. A relay MUST reconstruct the whole body rather than modify received bytes in place.

## 7. CANDIDATE body

After the common prefix:

```text
candidate_token(16)
expiry_class(1)
layer_count(1)
candidate_blob_length(2)
candidate_blob(1..960)
padding(variable)
```

The length field is encrypted and therefore does not appear in the public wire image. The complete outer record remains 1,052 bytes. `layer_count` is checked by the initiator against the number of successfully opened C1 candidate layers.

The current 960-byte candidate-blob limit accommodates the responder layer plus five relay wrappers. A deployment requiring a greater route depth must select a larger fixed body or a different constant-size candidate construction; it MUST NOT silently emit a second record-size class under the W1 identifier.

## 8. Route-control body

COMMIT, READY, CANCEL, ABORT, and CLOSE use:

```text
local_label(16)
generation(4)
expiry_class(1)
protected_length(2)
protected_body(0..512)
padding(variable)
```

The local label is non-zero, adjacent-link scoped, and replaced at every forwarding hop. The protected body is opaque to relays unless the message definition explicitly assigns them a verification role.

## 9. CHAFF

A CHAFF body contains only the common prefix and fresh padding. It traverses the same link encryption, queue, batching, and scheduling path as real control traffic. It MUST NOT allocate branch, candidate, tentative, or active route state.

## 10. Validation order

A receiver processes a W1 record in this order:

1. exact 1,052-byte length;
2. epoch and sequence admission/replay checks;
3. adjacent-link AEAD authentication;
4. common-prefix and message-type validation;
5. canonical field lengths and bounds;
6. peer and node resource admission;
7. C1 point, URE, KEM, AEAD, signature, or transcript processing;
8. state allocation and bounded forwarding.

A rejected record generates no amplified protocol error.

## 11. Privacy boundary

W1 provides record-length equality and encrypts message classification on each adjacent link. It does not provide:

- traffic-flow unlinkability;
- constant-rate transmission;
- protection against compromised adjacent peers;
- active-tagging resistance inside the malleable URE capsule;
- concealment of the public link epoch or sequence from observers of that link.

Those limitations are part of the protocol claim, not implementation defects hidden by the codec.
