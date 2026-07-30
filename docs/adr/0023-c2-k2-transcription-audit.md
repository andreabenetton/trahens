# ADR 0023: Keep the C2 k=2 transcription fail-closed pending interoperability review

- Status: Accepted
- Date: 2026-07-30

## Context

The next C2 gate required selecting the exact anonymous rerandomizable RCCA construction, fixing `k`, defining canonical encodings, and implementing `KeyGen`, `Enc`, `ReRand`, and `Dec`. The selected source is the `k`-linear construction in Section 6.3 and Figure 6 of Wang et al., CRYPTO 2021. The source smoothness theorems require `k >= 2`, so the smallest admissible choice is `k = 2`.

A project transcription over the related quadratic-residue groups executes key generation, encryption, decryption, canonical encoding, mutation rejection, and linear strand combination. It interpreted the inner operation as integer representatives with `mu(u) = u mod q`. Under ordinary `QR*_p` multiplication, an exact counterexample (`q = 5`, `p = 11`, `3,4 in QR*_11`) gives `mu(3*4 mod 11) = 1` but `mu(3)mu(4) mod 5 = 2`. That representative-level transcription therefore cannot satisfy the required group-action equation. The likely cause is an omitted or misread abstract representation, embedding, projection, or group action.

## Decision

1. Preserve the exact `k = 2` transcription as an auditable, deterministic artifact.
2. Reserve suite `0x7f02` for local audit data only; it is not a network suite.
3. Make the public full-rerandomization entry point fail closed with `C2ConformanceGap`.
4. Keep the C2 ideal functionality as the operational protocol model until an author-confirmed correction or independently reviewed replacement is available.
5. State explicitly that the counterexample blocks the project transcription, is presumed to be an interpretation error unless confirmed otherwise, and does not refute the generic Re-T-SPHF framework or a corrected construction.
6. Require a complete corrected action, independent implementation, and cryptographic review before integrating any construction into M2/W2.

## Consequences

- The repository advances from a purely symbolic target to an exact dimensional and byte-encoding audit.
- The concrete active-security gate remains open and is represented honestly.
- No route can accidentally use partially validated cryptography.
- Future implementations have stable test vectors, field mappings, and a precise algebraic counterexample to the rejected transcription.
- Reliability work may proceed only after the cryptographic gate is either closed or deliberately rescheduled with the active-security claim still disabled.

## References

[Wang2021]: Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, DOI 10.1007/978-3-030-84259-8_10; full version, IACR ePrint 2021/862.
