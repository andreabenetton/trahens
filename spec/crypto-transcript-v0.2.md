# Trahens Core v1.4.1 reply, candidate, and route-control transcript

- Status: Active transcript profile for the retained C1 reply/signature components
- Applies to: Core v1.4.1, U1, E1, R1, M2, W2, T1, and T2
- C1 encoding version: `0x02`

## 1. Purpose

This document separates four binding domains:

1. adjacent-link T1/T2 record authentication;
2. forward DISCOVER transformation;
3. nested CANDIDATE confidentiality and responder authentication;
4. end-to-end COMMIT/READY confirmation.

No transcript hash is forwarded unchanged as a global route identifier. A hash may be stored locally or encrypted end to end only where this document explicitly permits it.

## 2. Canonical encoding

All C1 transcript inputs use `EncodeFields` from `crypto-profile-c1.md`, whose prefix is `Trahens-C1-v2`. Field order is normative. Numeric values are fixed-width unsigned big-endian integers inside the cryptographic transcript even where M2 uses canonical varints in its logical envelope.

## 3. Public profile context

The constant profile tuple is:

```text
protocol_version  = 0x01
core_version      = ASCII("1.4.1")
privacy_profile   = ASCII("U1")
lifecycle_profile = ASCII("E1")
rendezvous_profile = ASCII("R1")
crypto_suite      = 0x0001
c1_encoding       = 0x02
```

Every end-to-end transcript begins with these fields. A different version, suite, profile, direction, or message role creates a different transcript.

## 4. DISCOVER branch body

The active R1 M2 DISCOVER body contains:

```text
branch_token
propagation_class
fanout_class
reply_public_key
service_query_nonce
expiry_class
options
```

It contains no endpoint address, endpoint descriptor, endpoint public key, endpoint capability, gateway pseudonym, or deterministic endpoint selector. A relay validates and reconstructs the complete body for every child, replaces the branch token and service-query nonce, and multiplicatively blinds the reply public key.

For child `i`, if the incoming reply key is `X_i`, the relay samples a non-zero scalar `b_i` and emits `X_(i+1)=b_i X_i`. The factor is local forward state and appears only inside the authenticated reverse relay layer.

## 5. Candidate inner transcript

A rendezvous gateway computes:

```text
CandidateTH = SHA-256(EncodeFields("candidate-transcript", [
    protocol_version,
    core_version,
    privacy_profile,
    lifecycle_profile,
    rendezvous_profile,
    crypto_suite,
    c1_encoding,
    gateway_pseudonym,
    final_reply_public_key,
    offer_class,
    route_limit_class,
    offer_expiry_class,
    commit_challenge,
    responder_nonce
]))
```

The gateway signs `CandidateTH` with the Ed25519 key authenticated by the private descriptor. The candidate payload contains all listed fields, the signature, and any application-defined opaque offer data whose digest is included as a separately length-prefixed transcript field.

The initiator MUST verify:

- the gateway signing key and pseudonym against the private descriptor;
- the signature over the exact canonical transcript;
- the final reply public key derived from the recovered blinding-factor chain;
- profile and encoding identifiers;
- expiry and route-limit classes;
- uniqueness of the responder nonce within the local logical discovery.

Core does not specify how the initiator privately obtains the descriptor. D1 is a non-normative strawman for that dependency.

## 6. Reverse relay layer

At reverse hop `i`, the relay encrypts to reply key `X_i` with:

```text
info = EncodeFields("candidate-layer-info", [
    protocol_version,
    core_version,
    crypto_suite,
    c1_encoding,
    depth_class,
    parent_candidate_token,
    parent_forward_label
])

aad = EncodeFields("candidate-layer-aad", [
    message_class,
    direction = REVERSE,
    parent_peer_epoch,
    offer_expiry_class
])
```

The plaintext is:

```text
layer_type = RELAY_LAYER
reply_blinding_factor
child_capsule
local_route_limit_class
child_forward_binding
layer_padding
```

`reply_blinding_factor` is a canonical non-zero scalar `b_i`. After opening the layer with secret `x_i`, the initiator derives `x_(i+1)=b_i x_i mod q` and continues with `child_capsule`.

`parent_peer_epoch` is adjacent-link context and is not copied beyond the parent link. A change to the candidate token, label, depth class, message class, direction, profile, encoding version, or expiry class causes AEAD failure. W2 fragment metadata is authenticated independently by the adjacent-link record AEAD and is not inserted into the end-to-end reply transcript.

## 7. Responder candidate layer

The gateway encrypts the signed candidate payload to `X_d` with:

```text
info = EncodeFields("candidate-responder-info", [
    protocol_version,
    core_version,
    crypto_suite,
    c1_encoding,
    depth_class,
    candidate_token
])

aad = EncodeFields("candidate-responder-aad", [
    message_class,
    direction = REVERSE,
    offer_expiry_class
])
```

The responder layer contains no reply blinding factor.

## 8. Reply KDF

For one encapsulation `R=eB` and shared point `Z=eX`, C1 derives:

```text
context = EncodeFields("reply-kem-context", [suite_id, encode(R), encode(X), info])
prk     = HKDF-Extract(0^32, EncodeFields("reply-kem-dh", [encode(Z)]))
okm     = HKDF-Expand(prk, EncodeFields("reply-kem-key-schedule", [context]), 44)
key     = okm[0:32]
nonce   = okm[32:44]
```

No HKDF-Expand output is used as a new PRK. The production API generates `e` internally from a CSPRNG; only the separately gated test-support module accepts a deterministic ephemeral.

## 9. COMMIT transcript

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

`CommitTH` and `commit_proof` are carried only in the end-to-end protected COMMIT body. Relays see local labels, route generation, capacity classes, and an opaque protected body.

## 10. READY transcript

After validating `commit_proof`, the gateway computes:

```text
ReadyTH = SHA-256(EncodeFields("ready-transcript", [
    CommitTH,
    responder_ready_nonce,
    final_route_limit_class
]))

ready_proof = HMAC-SHA-256(commit_challenge, ReadyTH)
```

The initiator exposes the route only after authenticating `ready_proof` and verifying that `ReadyTH` binds the selected candidate and final limits.

## 11. Security boundary

Multiplicative blinding proves an exact distributional statement for the public reply keys: after one honest relay, the public key alone is uniform over non-identity group elements. This transcript binding does not prove key privacy or recipient anonymity of the custom ephemeral-static DH reply encryption. Complete passive reply-layer unlinkability remains conditional on that cryptographic property and on multi-user composition review.

## 12. Local transcript identifiers

Relays MAY store a truncated local transcript digest for idempotency, keyed by local route labels and peer bindings. Such a digest:

- MUST NOT be copied to another hop;
- MUST NOT be exposed outside adjacent-link encryption;
- MUST be deleted with the corresponding state;
- MUST be at least 128 bits if used as a collision-resistant local key.

## 13. Failure normalization

Every C1 decryption, signature, descriptor, and transcript failure maps to `INVALID_CRYPTO`. The state machine does not branch on the detailed cause. Logs MAY contain a local diagnostic code if access-controlled and excluded from protocol responses.
