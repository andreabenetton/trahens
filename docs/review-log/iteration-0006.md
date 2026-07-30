<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0006 - Concrete C1 cryptography and formal paper expansion

- Date: 2026-07-30
- Status: Completed as a research interoperability baseline

## Question

Can the U1 eligibility and reverse-candidate transformations be made executable, canonically encoded, and reproducible without overstating their security, while improving the formal paper enough for technical review?

## Design change

Core v0.5 introduces cryptographic profile C1:

- `ristretto255` supplies one canonical prime-order group abstraction;
- endpoint eligibility and Ed25519 signing keys are distinct;
- a 67-byte descriptor binds suite, eligibility public key, and signing public key;
- a 128-byte GJJS-style URE capsule hides the fixed eligibility marker;
- every relay uses non-identity rerandomization coins, changing all four point encodings;
- the branch reply key evolves additively by `X_(i+1) = X_i + delta_i B`;
- `TR-KEM-R255` combines ephemeral DH, HKDF-SHA-256, and ChaCha20-Poly1305 for nested return layers;
- the responder signs an ordered CANDIDATE transcript with Ed25519;
- COMMIT and READY bind to the selected candidate through protected transcript proofs;
- every cryptographic rejection maps to `INVALID_CRYPTO`.

C1 is explicitly a research profile. The custom KEM is not an RFC 9180 HPKE suite, the URE is malleable, and no active-adversary or production-security claim is made.

## Reference implementation

The repository adds:

- `simulator/trahens_crypto/ristretto.py`, a narrow `libsodium` wrapper;
- `simulator/trahens_crypto/c1.py`, the C1 operations and encodings;
- `tools/generate_crypto_vectors.py`, a deterministic vector generator;
- `spec/crypto-test-vectors-c1.json`, the tracked vector set;
- `simulator/tests/test_crypto_c1.py`, positive and negative conformance tests.

The implementation is deliberately small and non-production. It exists to expose ambiguity and support cross-implementation review.

## Conformance results

Seven C1 tests establish:

1. rerandomization changes the wire image while preserving the marker;
2. zero `s0` and identity `s1` rerandomization choices are rejected;
3. wrong-key and malformed URE inputs fail;
4. public and secret reply-key tweaks agree;
5. a nested reply capsule opens only under the expected key and context;
6. ciphertext, AAD, and `info` changes share the generic failure path;
7. Ed25519 signatures bind the candidate transcript and tracked vectors reproduce exactly.

The complete repository suite contains 45 deterministic tests. `make check` also regenerates and byte-compares C1 vectors, executes model smoke tests, and compiles the paper.

## Paper revision

The formal rewrite is now 22 A4 pages and approximately 8,200 words. It adds:

- a document-status statement and explicit claim matrix;
- separate definitions for wire-image, batch-local, lifecycle, and traffic-flow properties;
- a consolidated notation table and key-role separation table;
- a protocol phase diagram and a three-hop nested-candidate example;
- exact C1 equations, encodings, correctness propositions, and failure behavior;
- detailed forward DISCOVER, reverse CANDIDATE, COMMIT, READY, and race explanations;
- state, message, resource, and experiment tables;
- limitations, proof obligations, and a gated implementation strategy.

Line numbers appear every five lines. The background watermark is absent. The PDF was compiled, rendered page by page, and visually checked for clipping, overlaps, table overflow, and broken glyphs.

## Findings

C1 closes the main interoperability ambiguity, but it sharpens rather than removes the security questions:

- universal rerandomization is intentionally malleable;
- the modern URE security definition and active-tagging behavior require independent review;
- the reply KEM operates under additive related keys and is custom;
- deterministic AEAD nonces are safe only because each encapsulation derives a fresh key; ephemeral reuse is prohibited;
- the complete constant-size candidate codec and depth-hiding policy remain undefined;
- all public-key mechanisms are classical rather than post-quantum.

## Decision

Accept Core v0.5 and C1 as the active research and interoperability baseline. Do not treat C1 as a deployment-approved suite. Freeze its equations and vectors only long enough to permit independent analysis and a second implementation; revise or replace the construction if review identifies a stronger alternative.

## Next question

Can C1 survive a precise modern URE security analysis and active-tagging experiments, and can a constant-size depth-hiding codec be implemented independently without adding stable cross-hop handles?
