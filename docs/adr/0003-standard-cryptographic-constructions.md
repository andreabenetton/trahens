# ADR-0003: Replace ad hoc key derivation with standard constructions

- Status: Proposed
- Date: 2026-07-30

## Context

The legacy algorithms use generic encryption and signature functions and a BIP32-inspired non-hardened child-key derivation mechanism. The protocol does not fully define encryption composition, transcript binding, nonce handling, downgrade resistance, or replay protection.

## Decision

The cryptographic profile will use independently specified key establishment, key derivation, authenticated encryption, and signatures. Routing labels will not require derivation of descendant private keys from an endpoint master key. Every authenticated transcript will include protocol version, suite, message type, discovery ID, direction, role, expiration, and context-specific associated data.

The exact mandatory suite remains open pending test-vector work and external review.

## Consequences

- The protocol can be reviewed using known primitive assumptions.
- Legacy pseudocode must be substantially rewritten.
- Cryptographic agility remains possible but must not introduce downgrade or fingerprinting weaknesses.

## Validation

Publish test vectors and obtain an independent review before marking the ADR Accepted.
