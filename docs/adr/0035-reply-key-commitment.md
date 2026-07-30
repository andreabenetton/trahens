# ADR 0035: Add explicit reply-ciphertext key commitment

## Status

Accepted for C1 v2.

## Context

ChaCha20-Poly1305 authenticates ciphertext under one key but is not a committing AEAD. The nested candidate parser branches after successful decryption, so cross-recipient acceptance would be dangerous in the active-relay model. The independent review identified robustness as a prerequisite for a serious key-privacy argument.

## Decision

C1 v2 expands the reply KDF to 76 bytes and splits it into a 32-byte AEAD key, 12-byte nonce, and independent 32-byte commitment key. The sealed object appends:

```text
HMAC-SHA-256(commitment_key,
  EncodeFields("reply-key-commitment", [
    commitment-domain, encapsulation, recipient-public, aad, info, aead-ciphertext
  ]))
```

The recipient reconstructs its public key, computes the expected commitment, attempts AEAD opening, and maps either failure to the same local result. The wire format is incompatible with C1 v1 and therefore uses suite `0x0003`.

## Consequences

Each reply layer grows by 32 bytes. The change provides an explicit recipient-bound robustness mechanism under the KDF/HMAC assumptions and is covered by cross-recipient negative tests. It is not represented as a complete multi-user IK-CCA proof.
