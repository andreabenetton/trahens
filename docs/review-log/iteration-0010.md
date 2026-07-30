<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Technical review - C2 k=2 construction transcription

- Date: 2026-07-30
- Scope: Trahens Core v0.9
- Status: exact arithmetic audit complete; full concrete rerandomization not approved

## 1. Objective

Select the exact concrete construction identified by the C2 profile, fix the smallest admissible `k`, define a canonical byte representation, implement the source equations outside the event simulator, and replace ambiguity with a reproducible pass/fail artifact.

## 2. Source selection

The audit targets Section 6.3 and Figure 6 of Wang et al., "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, full version IACR ePrint 2021/862. The source's smoothness results require `k >= 2`; the audit fixes `k = 2`. It uses the related quadratic-residue-group pattern proposed by the source through a length-three Cunningham chain.

## 3. Implemented surface

- exact `k = 2` vector dimensions;
- deterministic outer and inner projective keys;
- outer message-carrying and rerandomization strands;
- inner mask-carrying and rerandomization strands;
- all source-shaped hash values used by decryption;
- canonical subgroup-checked group-element encoding;
- deterministic key, ciphertext, and mutation digests;
- wrong-recipient and component-mutation rejection;
- isolated linear strand rerandomization;
- literal full rerandomization audit;
- fail-closed public API.

## 4. Deterministic result

| Check | Result |
|---|---|
| Key generation and public projection | Pass |
| Encrypt/decrypt fixed eligibility marker | Pass |
| Canonical 412-byte round trip | Pass |
| Wrong-recipient rejection | Pass |
| Selected component mutations rejected | Pass |
| Identity-tag linear strand rerandomization | Pass |
| Literal map `mu(u) = u mod q` is multiplicative | Fail; exact counterexample |
| Approved as M2/W2 suite | No |

## 5. Interpretation

The source explanation states that reducing the integer representative `u` modulo `q` supplies the homomorphism needed by the inner tag equations [Wang2021, Section 2, pp. 5-6]. Under ordinary multiplication in `QR*_p`, this is false: with `q = 5`, `p = 11`, and `3,4 in QR*_11`, the group product reduces to `1`, while the product of reductions is `2` modulo `5`. The deterministic conformance parameters provide a second witness. This blocks the literal finite-field instantiation. It is not presented as a refutation of the paper's generic framework or of an author-corrected or different instantiation.

## 6. Acceptance decision

The exact transcription is accepted as a **conformance and interoperability audit**. It is rejected as operational cryptography. Suite `0x7f02` remains reserved and non-networked, and the full rerandomization entry point fails closed. The symbolic C2 backend remains the only C2 protocol model.

## 7. Next gate

Obtain an author-confirmed correction or select an independently reviewed replacement construction with a complete group action. Then cross-run two implementations, regenerate full positive vectors, add receiver-anonymity/RCCA/tag tests over real bytes, select modern parameters, and request independent cryptographic review.

## References

[Wang2021]: Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, DOI 10.1007/978-3-030-84259-8_10; full version, IACR ePrint 2021/862.
