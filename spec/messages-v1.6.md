<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens v1.5 message roles and P1 payloads

- Status: Normative P1 supplement to M2/W2/T1
- Registry: `protocol-registry-v1.5.json`

## M2 messages

| Message | Direction | Hop-visible function | Protected content |
|---|---|---|---|
| CHAFF | either | no semantic message | none |
| DISCOVER | forward | create/replace branch state | gateway selector is absent; nonce is random and replaced per hop |
| CANDIDATE | reverse | return one nested offer | entire candidate blob is reply-encrypted |
| COMMIT | forward | select tentative route | end-to-end proof |
| READY | reverse | confirm activation | end-to-end proof |
| CANCEL | either | advisory teardown | end-to-end or empty protected reason |
| ABORT | either | failure teardown | empty protected reason |
| CLOSE | either | orderly teardown | end-to-end reason |
| RENDEZVOUS_OPEN | forward | redeem R1 capability | pseudonym and capability end-to-end encrypted |
| RENDEZVOUS_RESULT | reverse | redemption result | end-to-end status |
| DATA | either | bidirectional route data | direction, sequence, and payload end-to-end encrypted |

The stable IDs are generated in `protocol-registry-v1.6.md`. All messages use suite R1 `0x0101` in the mandatory P1 flow; on the experimental C1 profile they use `0x0003`, since the envelope names the suite whose eligibility field it carries.

ABORT is sent by a node that cannot honour a COMMIT — it cannot reserve route capacity, or the COMMIT names no live tentative mapping. It carries no sealed reason: the sender holds no route secret for either end, and a uniform failure class means the message type is the whole signal. CANCEL remains advisory and CLOSE orderly.

## M2 common prefix

```text
message_type:u8
protocol_version:u8
privacy_profile:u8
lifecycle_profile:u8
suite_id:u16
message_profile:u8
reserved:u8 = 0
body_length:minimal-varuint
body:body_length bytes
```

No trailing bytes are permitted. The reserved octet MUST be zero.

## DISCOVER body

```text
branch_token:16
hop_remaining:u8
fanout_class:u8
expiry_class:u8
depth:u8            # P1 relay depth on forwarded messages
routing_nonce:32    # suite-independent; binds the candidate chain and keys offer labels
reply_public_key:32
field_length:minimal-varuint
r1_discovery_nonce:32
```

Branch token, reply public key, and routing nonce MUST be non-zero/canonical, and the eligibility field MUST match the width the active suite fixes. `depth` MUST NOT exceed the candidate-layer limit.

The routing nonce and the eligibility field are separate since v1.6: route discovery reads only the former, so a suite may size the latter freely (ADR 0040).

## CANDIDATE body

```text
candidate_token:16
expiry_class:u8
layer_count:u8
blob_length:minimal-varuint
candidate_blob:blob_length
```

`layer_count` includes the gateway offer and is between 1 and 17 for P1.

## Control body

COMMIT through DATA use:

```text
local_label:16
generation:u32
expiry_class:u8
protected_length:minimal-varuint
protected_body:protected_length
```

The message type remains outside the end-to-end ciphertext but inside W2 link encryption. The end-to-end AEAD AAD binds the message type and generation.

## P1 protected payload tags

The stable payload tags are generated from the registry. Canonical layouts are implemented in `codec-m2`; fields are fixed-width except DATA and nested child blobs, which use minimal varuint lengths. Decoding MUST consume the entire payload and MUST reject unknown tags.

Relay candidate layers carry both parent and child routing nonces. These fields are not exposed to the relay's non-adjacent observers; they let the endpoint verify that every hop performed nonce replacement rather than preserving a stable nonce. They are 32 bytes whatever the active suite, so a candidate layer does not grow with the eligibility width.
