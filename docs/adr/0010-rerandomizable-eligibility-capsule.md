<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0010: Require a rerandomizable eligibility capsule for U1

- Status: Accepted as a research dependency
- Date: 2026-07-30

## Context

Removing stable protocol identifiers is insufficient if the destination or service selector remains an unchanged opaque ciphertext. Colluding relays can compare that ciphertext even when branch tokens and reply keys change.

Relays must not learn the destination selector, but eligible responders must be able to recognize and open it.

## Decision

The U1 profile requires a universally rerandomizable eligibility-encryption primitive. Every relay rerandomizes the capsule independently for every child branch. A deployment that forwards an unchanged selector does not conform to U1.

The primitive is specified abstractly until a reviewed construction is selected. Its security requirements include ciphertext anonymity, rerandomization indistinguishability, malformed-ciphertext behavior, and analysis of active tagging.

## Consequences

- the full forward message can be cryptographically transformed at every hop;
- the profile depends on a nontrivial research primitive;
- plain ElGamal is not accepted without integrity and tagging analysis;
- production implementation is blocked until cryptographic review succeeds;
- active-adversary unlinkability remains an explicit open problem.
