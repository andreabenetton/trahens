# ADR 0021: Select anonymous rerandomizable RCCA encryption for eligibility

- Status: Accepted as a research target
- Date: 2026-07-30

## Context

The C1 eligibility capsule provides public rerandomization and passive receiver-key concealment, but its homogeneous consistency pair admits a persistent ratio tag. A compromised relay can introduce a relation that survives honest rerandomization and is recognizable by a separated colluding relay. Adjacent-link authentication and fixed-size cells cannot prevent an authorized relay from constructing a fresh malicious logical message.

## Decision

The active-security eligibility profile is C2. C2 requires an encryption construction with all of the following properties:

- public rerandomization without the recipient public key;
- receiver anonymity;
- rerandomizable replayable chosen-ciphertext security;
- rejection or replay-equivalent normalization of arbitrary mutations;
- no stable recipient selector or rerandomization identifier;
- uniform externally visible failure behavior.

The selected construction family is the anonymous rerandomizable RCCA-secure PKE framework of Wang et al. The protocol specification defines the abstract algorithms, security games, suite binding, and implementation gate. Until a reviewed concrete instantiation is implemented, the simulator uses an executable ideal functionality. C1 remains as a negative-control attack oracle and continues to provide the current reply-key, candidate, signature, transcript, KDF, and AEAD components.

## Consequences

- The protocol no longer treats public rerandomization alone as sufficient for active unlinkability.
- Active-security claims remain blocked until the concrete C2 gate closes.
- The ideal functionality can validate lifecycle composition, M2/W2 suite binding, failure normalization, and attack instrumentation, but cannot validate cryptographic hardness.
- The C1 ratio-tag test remains mandatory for every future C2 implementation.
