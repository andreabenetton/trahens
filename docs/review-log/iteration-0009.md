<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Technical review - C2 active-security contract and M2 suite agility

- Date: 2026-07-30
- Scope: Trahens Core v0.8
- Branch reviewed: `feature/c2-v0.8`
- Status: protocol-integration baseline complete; concrete cryptographic gate remains open

## 1. Review objective

This review evaluates the transition from the taggable C1 eligibility capsule to the C2 active-security contract. The objective is not to claim a new cryptographic construction. It is to make the required security properties precise, bind the selected eligibility suite into the logical and wire codecs, integrate the contract into the event lifecycle, and preserve the known C1 ratio-tag attack as a mandatory negative control.

## 2. Design decisions

1. **C2 is a contract, not an unreviewed implementation.** The active target is receiver-anonymous rerandomizable RCCA public-key encryption. The exact concrete instantiation, parameters, encodings, vectors, and reduction remain a separate acceptance gate.
2. **The executable backend is an ideal functionality.** `C2IdealOracle` uses opaque registered ciphertexts to model valid rerandomization, replay equivalence, receiver separation, and arbitrary-mutation rejection. It is explicitly prohibited outside simulation and conformance testing.
3. **C1 remains a negative control.** Its ratio-tag relation and downstream recognition remain in the test suite. Retained reply-key, nested-candidate, signature, KDF, and AEAD components continue to use the existing concrete classical definitions.
4. **M2 is suite-agile.** The eligibility capsule is length-delimited, and the suite identifier selects the parser and size bound.
5. **W2 binds the suite per fragment.** Reassembly rejects cross-suite fragments, and the completed M2 suite must match the authenticated W2 suite before semantic state is allocated.
6. **Failure is normalized.** Invalid C2 mutation, suite mismatch, malformed M2, link authentication failure, and other cryptographic invalidity converge on a generic externally visible failure path.

## 3. Security-game coverage

The active specification separates:

- C2-IND: plaintext confidentiality;
- C2-RA: receiver anonymity;
- C2-RR: rerandomization correctness and output independence;
- C2-RCCA: replayable chosen-ciphertext behavior;
- C2-TAG: cross-hop persistent-tag resistance;
- C2-COMP: preservation of the primitive's claim under M2/W2 composition.

The symbolic backend exercises protocol semantics for C2-RR, C2-RA, and C2-TAG by construction. It does not establish computational security, concrete receiver anonymity, or a reduction under a named hardness assumption.

## 4. Deterministic experiment

The five-node line experiment places compromised relays at nodes 1 and 3 with one honest transformer between them. One hundred runs are executed per scenario.

| Scenario | Route success | Mean transmissions | Mean wire bytes | Mean crypto failures | Mean tags created | Downstream observations | Cleanup |
|---|---:|---:|---:|---:|---:|---:|---:|
| C1 clean | 1.00 | 16.00 | 16,832 | 0.00 | 0.00 | 0.00 | 1.00 |
| C1 ratio tag | 0.00 | 8.00 | 8,416 | 1.00 | 2.00 | 1.00 | 1.00 |
| C2 symbolic clean | 1.00 | 16.00 | 16,832 | 0.00 | 0.00 | 0.00 | 1.00 |
| C2 symbolic marker tag | 0.00 | 4.00 | 4,208 | 1.00 | 1.00 | 0.00 | 1.00 |

The C1 relation survives the honest transformation and is observed by the downstream colluder before destination rejection. The symbolic C2 mutation is rejected by the first honest transformer, so no derived capsule reaches the downstream colluder. Both attacks remain availability failures. All runs reclaim all tracked state.

## 5. Conformance evidence

- 73 deterministic unit and integration tests pass.
- The C1 and symbolic C2 vector files regenerate byte-for-byte.
- C1 and C2 DISCOVER messages round-trip through M2.
- W2 fragments preserve the suite identifier.
- A fragment with an inconsistent suite invalidates the complete reassembly context.
- The event model rejects M2/W2 suite disagreement before semantic handling.
- C2 arbitrary mutation cannot be rerandomized by the honest ideal interface.
- Clean symbolic C2 routes complete CANDIDATE, COMMIT, READY, expiry, and cleanup.

## 6. Residual risks

1. **No concrete C2 cryptosystem is implemented.** The ideal functionality cannot reveal algebraic attacks, proof-system defects, subgroup behavior, encoding ambiguity, side channels, or unexpected replay equivalence.
2. **Construction selection is incomplete.** The selected anonymous Rand-RCCA framework still requires an exact instantiation, parameter set, implementation plan, and mapping from its proofs to the Trahens transcript.
3. **Availability remains attackable.** Rejecting a tag at the first honest relay prevents downstream linkage but permits denial of route discovery.
4. **Reply and candidate mechanisms remain custom.** The additive reply KEM and nested authenticated layers require independent analysis.
5. **Traffic metadata remains outside C2.** Timing, direction, topology, and W2 cell count are not hidden by the eligibility primitive.
6. **The symbolic 640-byte capsule is a planning budget only.** A concrete construction may change logical size, cell count, work, and amplification limits.

## 7. Acceptance decision

Core v0.8 is accepted as a **symbolic active-security integration baseline**. It may claim that the protocol now states and executes the required C2 behavior at the interface and state-machine levels. It may not claim that Trahens has implemented anonymous rerandomizable RCCA encryption or achieved concrete active-adversary unlinkability.

The next cryptographic milestone is to specify and implement one exact C2 construction, publish canonical vectors and negative cases, replace the ideal oracle in the event model, and obtain independent review before raising the active-security claim.
