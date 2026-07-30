# Trahens logical-message codec M2

- Status: Current suite-agile logical-message profile
- Wire transport: W2 fixed-size encrypted cells
- Profile identifier: `0x02`

## 1. Change from M1

M2 retains canonical variable-length logical messages and no semantic padding. It adds two requirements needed for cryptographic agility:

1. the suite identifier is accepted as a profile-selected value rather than being hard-coded to C1;
2. the `DISCOVER` eligibility capsule is length-delimited with a canonical VarUInt.

M1 remains archived for C1 interoperability tests. New C2-capable implementations use M2.

## 2. Envelope

```text
message_type       u8
protocol_version   u8
privacy_profile    u8
lifecycle_profile  u8
crypto_suite       u16 big-endian
message_profile    u8 = 0x02
reserved           u8 = 0
body_length        canonical VarUInt
body               body_length bytes
```

The envelope is included inside W2 authenticated encryption. `body_length` is the unique minimal base-128 LEB128 encoding and must consume the remainder exactly.

## 3. DISCOVER body

```text
branch_token        16 bytes
hop_remaining       u8
fanout_class        u8
expiry_class        u8
options             u8
reply_public_key    32 bytes
capsule_length      canonical VarUInt
eligibility_capsule capsule_length bytes
```

The suite determines the capsule parser:

- C1 (`0x0001`): exactly 128 bytes and four canonical non-identity `ristretto255` encodings;
- symbolic C2 (`0x0002`): exactly 640 non-zero bytes; semantic validity is checked by the C2 operation, not by M2 syntax.

A concrete C2 suite will define exact cryptographic parsing under a new or reviewed suite profile.

## 4. Other messages

`CANDIDATE`, `COMMIT`, `READY`, `CANCEL`, `ABORT`, `CLOSE`, and `CHAFF` retain the M1 semantic bodies. Their M2 envelope carries the active suite so all fragments and lifecycle messages for one route setup are suite-consistent.

## 5. W2 binding

Every W2 fragment header copies the M2 suite identifier. A reassembly context is keyed by authenticated link direction and adjacent-link-local message identifier and stores the suite from its first accepted fragment. A fragment with a different suite invalidates the complete context.

After reassembly, the suite in the M2 envelope must equal the suite in the W2 fragments. Route-semantic state is allocated only after this check and complete canonical decoding.
