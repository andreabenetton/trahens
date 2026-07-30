# Trahens C2-K2 transcription and interoperability audit

- Status: Exact arithmetic transcription under review
- Source construction: Wang et al., CRYPTO 2021, full version IACR ePrint 2021/862, Section 6.3 and Figure 6
- Parameter choice: `k = 2`
- Reserved local audit suite: `0x7f02`
- Network deployment status: **disabled**

## 1. Purpose

This profile records the first byte-exact attempt to transcribe the concrete `k`-linear anonymous rerandomizable RCCA public-key encryption construction described by Wang et al. [Wang2021, Section 6.3 and Figure 6]. It is an interoperability and notation audit, not an independent cryptographic construction and not a deployable implementation.

The profile fixes `k = 2` because the smoothness statements used by the concrete construction require `k >= 2` [Wang2021, Theorems 6.2, 6.5, and 6.10]. It follows the paper's proposed related quadratic-residue groups based on a length-three Cunningham chain [Wang2021, Section 6.3].

## 2. Source mapping

The source paper gives:

- the RCCA and receiver-anonymity motivation [Wang2021, Sections 1-2];
- the rerandomizable tag-SPHF framework [Wang2021, Sections 4-5];
- the `k`-linear instantiations and smoothness conditions [Wang2021, Sections 6.1-6.2];
- the complete public-key encryption syntax [Wang2021, Section 6.3, Figure 6].

The implementation in `simulator/trahens_crypto/c2_klinear.py` maps every vector, projective key, strand, proof value, and inner malleable-encryption component to a named field. Comments in the source cite the corresponding Figure 6 operation. The module deliberately exposes `rerandomize_literal` separately from the public `rerandomize` entry point so that an unresolved mapping cannot become protocol cryptography accidentally.

## 3. Algebraic setting

Let

```text
q = 175513086009046434629810696245711941989
p = 2q + 1
r = 2p + 1 = 4q + 3
```

where `q`, `p`, and `r` are prime. The audit uses:

- an inner quadratic-residue group of order `q` modulo `p`;
- an outer quadratic-residue group of order `p` modulo `r`;
- `k = 2`, so every language vector has `k + 1 = 3` group elements.

This 128-bit chain is selected only to make deterministic conformance tests fast. It does not provide a current production security level. The source construction specifies related quadratic-residue groups from a Cunningham chain but does not prescribe these exact primes [Wang2021, Section 6.3].

## 4. Canonical audit encoding

The audit ciphertext contains 24 group elements:

- 12 outer-group elements for the two message-level strands and their hash values;
- 12 inner-group elements for the encrypted random mask and its two strands.

Each group element is encoded as an unsigned 17-byte big-endian integer after canonical range and subgroup validation. The complete encoding is:

```text
version                 1 byte
reserved audit suite    2 bytes = 0x7f02
parameter-set id        1 byte
outer elements         12 * 17 bytes
inner elements         12 * 17 bytes
------------------------------------------------
total                  412 bytes
```

The suite value is in the private-use audit range and MUST NOT be accepted by M2 or W2 as a network eligibility suite.

## 5. Executed equations

The audit executes:

1. deterministic key generation for the outer and inner projective keys;
2. encryption of the fixed Trahens eligibility group element;
3. canonical encode/decode round trips;
4. decryption and all outer and inner validity checks;
5. wrong-recipient rejection;
6. component-wise mutation rejection;
7. the linear strand-combination part of Figure 6 rerandomization;
8. the literal non-identity tag-multiplication path of Figure 6.

The key-generation, encryption, decryption, canonical encoding, mutation rejection, and linear strand-combination checks pass in the deterministic audit.

## 6. Literal finite-field non-homomorphism

The source explains the inner validity term by replacing the group element `u` with the integer reduction `u mod q` and states that this modular operation has the homomorphism property needed by rerandomization [Wang2021, Section 2, pp. 5-6]. For ordinary multiplication in `QR*_p`, that literal map is not a group homomorphism.

Define

```text
mu : QR*_p -> Z_q
mu(u) = u mod q.
```

Full rerandomization requires, at minimum,

```text
mu(r*u mod p) = mu(r) * mu(u) mod q.
```

A minimal exact counterexample is `q = 5`, `p = 11`, `r = 3`, and `u = 4`. Both `3` and `4` are in `QR*_11`; their group product is `1`, so the left side is `1`, while the right side is `(3 mod 5)(4 mod 5) mod 5 = 2`. The deterministic conformance parameters produce a second, larger witness recorded in `reports/c2-k2-transcription-audit.json`.

This result blocks the **literal finite-field instantiation** and explains why the non-identity tag-multiplication path fails. It does not refute the source's generic Re-T-SPHF framework, an author-confirmed corrected action, or another independently reviewed instantiation [Wang2021, Sections 4-6].

## 7. Fail-closed behavior

The public audit function `rerandomize(...)` raises `C2ConformanceGap`. The repository therefore cannot select this profile for route traffic. Only the following are allowed:

- deterministic conformance generation;
- byte-level parsing and mutation tests;
- equation-level audit of encryption and decryption;
- identity-tag strand tests that isolate the already-understood linear part;
- comparison with a future independently reviewed implementation.

The operational route simulator continues to use the explicitly symbolic `C2IdealOracle`. That ideal functionality is also non-deployable; it exists solely to test the protocol contract and state-machine placement.

## 8. Acceptance gate

C2-K2 may receive a network suite identifier only after all of the following:

1. an author-confirmed corrected action or an independently reviewed replacement is provided for the non-homomorphic literal finite-field map;
2. full nontrivial rerandomization decrypts and validates for randomized test populations under that corrected or replacement construction;
3. canonical public-key, secret-key, ciphertext, and error encodings are reviewed;
4. parameter generation and a modern security level are specified;
5. receiver-anonymity, rerandomizable-RCCA, replay-equivalence, and active-tag harnesses are mapped to the source proof assumptions;
6. malformed elements, subgroup inputs, identity values, truncation, substitution, and cross-suite inputs fail uniformly;
7. a second implementation reproduces the deterministic vectors;
8. independent cryptographic review approves the construction for experimental use.

## 9. Reproducibility

Run:

```bash
make c2-k2-audit
PYTHONPATH=simulator python -m unittest simulator.tests.test_crypto_c2_klinear -v
```

The generated artifact is `reports/c2-k2-transcription-audit.json`.

## References

[Wang2021]: Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, LNCS 12828, pp. 270-300, DOI 10.1007/978-3-030-84259-8_10; full version, IACR ePrint 2021/862.

[CKN2003]: Ran Canetti, Hugo Krawczyk, and Jesper Buus Nielsen, "Relaxing Chosen-Ciphertext Security," CRYPTO 2003.

[BBDP2001]: Mihir Bellare, Alexandra Boldyreva, Anand Desai, and David Pointcheval, "Key-Privacy in Public-Key Encryption," ASIACRYPT 2001.

[CS2002]: Ronald Cramer and Victor Shoup, "Universal Hash Proofs and a Paradigm for Adaptive Chosen Ciphertext Secure Public-Key Encryption," EUROCRYPT 2002.

[PR2007]: Manoj Prabhakaran and Mike Rosulek, "Rerandomizable RCCA Encryption," CRYPTO 2007.
