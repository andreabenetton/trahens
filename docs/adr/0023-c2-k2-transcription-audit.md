# ADR 0023: Keep the C2 k=2 transcription fail-closed pending interoperability review

- Status: Accepted
- Date: 2026-07-30

## Context

The next C2 gate required selecting the exact anonymous rerandomizable RCCA construction, fixing `k`, defining canonical encodings, and implementing `KeyGen`, `Enc`, `ReRand`, and `Dec`. The selected source is the `k`-linear construction in Section 6.3 and Figure 6 of Wang et al., CRYPTO 2021. The source smoothness theorems require `k >= 2`, so the smallest admissible choice is `k = 2`.

A literal implementation over the related quadratic-residue groups executes key generation, encryption, decryption, canonical encoding, mutation rejection, and linear strand combination. The source explanation invokes the integer map `mu(u) = u mod q` as a homomorphism for the inner tag equations [Wang2021, Section 2, pp. 5-6]. An exact counterexample (`q = 5`, `p = 11`, `3,4 in QR*_11`) gives `mu(3*4 mod 11) = 1` but `mu(3)mu(4) mod 5 = 2`. The literal finite-field tag-multiplication step therefore cannot satisfy the required group-action equation.

## Decision

1. Preserve the exact `k = 2` transcription as an auditable, deterministic artifact.
2. Reserve suite `0x7f02` for local audit data only; it is not a network suite.
3. Make the public full-rerandomization entry point fail closed with `C2ConformanceGap`.
4. Keep the C2 ideal functionality as the operational protocol model until an author-confirmed correction or independently reviewed replacement is available.
5. State explicitly that the counterexample blocks the literal finite-field instantiation, but does not refute the generic Re-T-SPHF framework or a corrected construction.
6. Require a complete corrected action, independent implementation, and cryptographic review before integrating any construction into M2/W2.

## Consequences

- The repository advances from a purely symbolic target to an exact dimensional and byte-encoding audit.
- The concrete active-security gate remains open and is represented honestly.
- No route can accidentally use partially validated cryptography.
- Future implementations have stable test vectors, field mappings, and a precise algebraic counterexample to test.
- Reliability work may proceed only after the cryptographic gate is either closed or deliberately rescheduled with the active-security claim still disabled.

## References

[Wang2021]: Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, DOI 10.1007/978-3-030-84259-8_10; full version, IACR ePrint 2021/862.
