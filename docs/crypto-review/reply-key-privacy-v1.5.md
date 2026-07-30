# C1 v2 reply-key privacy and robustness obligations

## Status

This is a reduction sketch and review checklist, not an independently verified theorem. It narrows the unresolved claim and records the exact assumptions an external reviewer must validate.

## Construction summarized

For recipient public key \(X=xB\), encryption samples \(e\), sends \(R=eB\), derives a pseudorandom key schedule from \(Z=eX\) and the context `(suite, R, X, info)`, encrypts with nonce-separated ChaCha20-Poly1305, and appends a recipient-bound HMAC commitment. Public reply keys are multiplicatively blinded between honest relays.

## Passive recipient-anonymity game

The adversary chooses equal-length messages, context, and two valid non-identity recipient keys \(X_0,X_1\). The challenger encrypts to one key and the adversary guesses the bit. It may know unrelated recipient secrets and observe arbitrarily many encryptions, but it receives no decryption oracle for the challenge recipients.

### Reduction target

In the random-oracle/PRF abstraction for the domain-separated HKDF schedule, replacing \(eX_b\) by an independent random group element reduces recipient distinguishability to deciding whether `(B, X_b, R, eX_b)` is a Diffie-Hellman tuple. The transmitted encapsulation `R` is independent of `X_b`; the recipient public key appears only inside the KDF input and commitment computation. Equal-length ciphertexts therefore expose no direct recipient identifier.

This gives a plausible **multi-user IK-CPA** route under DDH plus HKDF/HMAC/AEAD assumptions. The repository does not claim a machine-checked or publication-grade proof.

## Robustness game

The adversary wins if one sealed object is accepted under two distinct recipient secrets for the same AAD and `info`. C1 v2 derives independent AEAD and commitment keys from recipient-specific DH and context. Acceptance under both keys requires either:

1. a collision/related-input failure in the KDF schedule;
2. a valid 256-bit HMAC commitment under the second independently derived commitment key; and
3. a valid AEAD tag under the second independently derived AEAD key.

Under the stated assumptions the probability is bounded by the sum of the primitive advantages plus the commitment and AEAD forgery terms. The executable tests cover ordinary cross-recipient rejection but do not replace the reduction.

## Why IK-CCA remains open

The active protocol permits malformed ciphertext injection and observes bounded success/failure effects. A full proof must account for:

- multi-user decryption queries excluding the exact challenge;
- maliciously selected public keys and blinding factors;
- nested ciphertext parsing and layer-type dispatch;
- related keys produced by multiplicative blinding;
- generic but potentially measurable timing/resource failures;
- replay, expiry, and state-allocation side effects.

No production unlinkability claim is made until those cases are covered by a reviewed proof or the construction is replaced by a reviewed anonymous PKE/KEM.

## Implementation obligations

- validate canonical non-identity Ristretto encodings before scalar multiplication;
- reject zero scalars and identity results;
- bind suite, encapsulation, recipient public key, AAD, and `info` into the KDF;
- bind encapsulation, recipient, AAD, `info`, and full AEAD ciphertext into the commitment;
- use fresh ephemeral secrets for every encryption and retry;
- compare commitments in constant time and collapse all failures;
- allocate no durable route state before full decode and authentication;
- zeroize expired secret material in the systems implementation.
