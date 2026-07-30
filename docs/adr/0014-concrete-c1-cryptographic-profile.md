# ADR-0014: Define a concrete C1 cryptographic profile

- Status: Accepted for research and interoperability testing
- Date: 2026-07-30

## Context

Core v0.4 intentionally left universal rerandomizable encryption and the tweakable reply KEM abstract. This prevented accidental deployment of an improvised construction, but it also blocked independent implementation, deterministic vectors, and precise transcript review.

## Decision

Define profile C1 using:

- `ristretto255` as the prime-order group;
- the Golle-Jakobsson-Juels-Syverson universal re-encryption construction in additive notation for the eligibility marker;
- an additively tweakable, HPKE-inspired DH KEM over `ristretto255` for reverse reply layers;
- HKDF-SHA-256 and ChaCha20-Poly1305 for KEM expansion and authenticated encryption;
- Ed25519 for responder transcript signatures.

C1 receives suite identifier `0x0001`. It includes canonical encodings, domain separation, generic failure behavior, an executable reference implementation, and deterministic vectors.

## Consequences

- Core v0.5 can be implemented consistently at the cryptographic interface.
- URE rerandomization and reply-key tweaking have executable correctness tests.
- The reply KEM is not an IANA-registered HPKE KEM and cannot claim RFC 9180 interoperability.
- The URE construction remains malleable and lacks a C1 proof against active tagging.
- C1 requires non-identity URE rerandomization coins so a conforming hop changes every eligibility point encoding.
- C1 is classical and not post-quantum.
- Production implementation remains blocked on independent review and active-adversary analysis.
