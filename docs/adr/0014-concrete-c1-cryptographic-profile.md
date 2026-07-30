# ADR-0014: Define a concrete C1 cryptographic profile

- Status: Accepted for research and interoperability testing; amended for C1 encoding v2
- Date: 2026-07-30

## Context

An executable profile is required for canonical encodings, vectors, transcript review, and simulator integration. The original C1 reply path used additive key tweaks and a non-standard HKDF chain. Independent review identified both as avoidable proof and implementation obligations and identified caller-supplied deterministic ephemerals as an API footgun.

## Decision

C1 encoding version `0x02` uses:

- `ristretto255` as the prime-order group;
- the Golle-Jakobsson-Juels-Syverson universal re-encryption construction only as an archived negative-control eligibility mechanism;
- multiplicative reply-key blinding `X_(i+1)=b_i X_i`;
- an HPKE-inspired ephemeral-static DH reply seal over `ristretto255`;
- one HKDF-SHA-256 Extract followed by one 44-byte Expand, split into the ChaCha20-Poly1305 key and nonce;
- Ed25519 for responder transcript signatures;
- a production API that generates reply ephemerals internally and a separately gated test-support API for deterministic vectors.

C1 retains suite identifier `0x0001`; its descriptor/profile encoding byte is `0x02`. Canonical encodings, domain separation, generic failure behavior, executable reference code, and deterministic vectors are normative for research interoperability.

## Consequences

- public reply-key distribution after one honest relay is exact uniform over non-identity group elements;
- no HKDF output is reused as a new PRK;
- deterministic ephemeral reuse is structurally unavailable through the production API;
- the reply seal is not an IANA-registered HPKE suite and cannot claim RFC 9180 interoperability;
- full reply-layer unlinkability remains conditional on key privacy and independent composition review;
- the archived C1 eligibility construction remains malleable and is not an active endpoint-discovery primitive;
- C1 is classical and not post-quantum;
- production deployment remains blocked on independent cryptographic review.
