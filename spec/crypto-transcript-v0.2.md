# Trahens Core v0.7 cryptographic transcript

- Status: Active C1 transcript profile
- Applies to: Core v0.7, U1, E1, C1, M1, and W2

## 1. Purpose

This document separates four different binding domains:

1. adjacent-link W2 cell authentication;
2. forward DISCOVER transformation;
3. nested CANDIDATE confidentiality and responder authentication;
4. end-to-end COMMIT/READY confirmation.

No transcript hash is forwarded unchanged as a global route identifier. A hash may be stored locally or encrypted end to end where explicitly stated.

## 2. Canonical encoding

All C1 transcript inputs use `EncodeFields` from `crypto-profile-c1.md`. Field order is normative. Numeric values are encoded as fixed-width unsigned big-endian integers inside the transcript even though M1 uses compact canonical varints for its logical envelope.

## 3. Public profile context

The constant profile tuple is:

```text
protocol_version = 0x01
core_version     = ASCII("0.7")
privacy_profile  = ASCII("U1")
lifecycle_profile = ASCII("E1")
crypto_suite     = 0x0001
```

Every end-to-end transcript begins with these fields to prevent cross-version or cross-profile substitution.

## 4. DISCOVER branch body

The M1 DISCOVER body, carried inside one or more link-encrypted W2 cells, contains:

```text
branch_token
propagation_class
fanout_class
reply_public_key
eligibility_capsule
expiry_class
options
```

The branch token is a link-local capability, not an end-to-end transcript identifier. The relay validates and reconstructs the complete body for every child. C1 URE rerandomization changes all four eligibility points, and reply-key tweaking changes the reply public key.

## 5. Candidate inner transcript

The responder computes:

```text
CandidateTH = SHA-256(EncodeFields("candidate-transcript", [
    protocol_version,
    core_version,
    privacy_profile,
    lifecycle_profile,
    crypto_suite,
    endpoint_address,
    endpoint_descriptor,
    final_reply_public_key,
    offer_class,
    route_limit_class,
    offer_expiry_class,
    commit_challenge,
    responder_nonce
]))
```

The responder signs `CandidateTH` with the Ed25519 key in the endpoint descriptor. The candidate payload contains all listed fields, the signature, and any application-defined opaque offer data whose digest is included in `offer_class` or an additional length-prefixed field.

The initiator MUST verify:

- descriptor-to-address binding;
- endpoint signing key;
- signature over the exact transcript;
- final reply public key expected at the innermost depth;
- profile identifiers;
- expiry and route-limit classes;
- uniqueness of the responder nonce within the logical discovery.

## 6. Reverse relay layer

At reverse hop `i`, the relay encrypts to reply key `X_i` with:

```text
info = EncodeFields("candidate-layer-info", [
    protocol_version,
    crypto_suite,
    depth_class,
    parent_candidate_token,
    parent_forward_label
])

aad = EncodeFields("candidate-layer-aad", [
    message_class,
    parent_peer_epoch,
    offer_expiry_class
])
```

The plaintext is:

```text
layer_type = RELAY_LAYER
reply_tweak_delta
child_capsule
local_route_limit_class
child_forward_binding
layer_padding
```

`parent_peer_epoch` is not an endpoint identity. It is adjacent-link context and is not sent beyond the parent link. A change to the candidate token, label, depth class, message class, or expiry class causes AEAD failure. W2 fragment metadata is authenticated independently by the adjacent-link cell AEAD and is not inserted into the end-to-end C1 transcript.

## 7. Responder candidate layer

The responder encrypts the signed candidate payload to `X_d` with:

```text
info = EncodeFields("candidate-responder-info", [
    protocol_version,
    crypto_suite,
    depth_class,
    candidate_token
])

aad = EncodeFields("candidate-responder-aad", [
    message_class,
    offer_expiry_class
])
```

The responder layer does not contain a reply tweak scalar.

## 8. COMMIT transcript

The candidate payload supplies a uniformly random `commit_challenge`. The initiator computes:

```text
CommitTH = SHA-256(EncodeFields("commit-transcript", [
    CandidateTH,
    selected_offer_digest,
    initiator_commit_nonce,
    commit_expiry_class
]))

commit_proof = HMAC-SHA-256(commit_challenge, CommitTH)
```

`CommitTH` and `commit_proof` are carried only in the end-to-end protected COMMIT body. Relays see only local labels, route generation, capacity classes, and an opaque protected body.

## 9. READY transcript

After validating `commit_proof`, the responder computes:

```text
ReadyTH = SHA-256(EncodeFields("ready-transcript", [
    CommitTH,
    responder_ready_nonce,
    final_route_limit_class
]))

ready_proof = HMAC-SHA-256(commit_challenge, ReadyTH)
```

The initiator exposes the route only after authenticating `ready_proof` and verifying that `ReadyTH` binds the selected candidate and final limits.

## 10. Local transcript identifiers

Relays MAY store a truncated local transcript digest for idempotency, keyed by local route labels and peer bindings. Such a digest:

- MUST NOT be copied to another hop;
- MUST NOT be exposed outside adjacent-link encryption;
- MUST be deleted with the corresponding state;
- MUST be at least 128 bits if used as a collision-resistant local key.

## 11. Failure normalization

Every C1 decryption, signature, descriptor, and transcript failure maps to `INVALID_CRYPTO`. The state machine does not branch on the detailed cause. Logs MAY contain a local diagnostic code if access-controlled and excluded from protocol responses.
