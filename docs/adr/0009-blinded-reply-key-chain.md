# ADR-0009: Use a blinded reply-key chain for candidate return

- Status: Accepted as a proof obligation
- Date: 2026-07-30

## Context

The legacy draft changed the public key visible at each hop using non-hardened BIP32-style derivation. That mechanism was underspecified for encryption, mixed wallet-specific derivation with routing semantics, and created difficult compromise interactions.

A responder must nevertheless encrypt its candidate to a key that differs at every hop while allowing the initiator to recover the final decryption key.

## Decision

Use an abstract tweakable reply KEM over a prime-order group. The initiator creates an independent root key for every first-hop branch. Each relay adds a fresh scalar multiple of the group generator to the incoming public key and stores the scalar in local child state.

Candidate return is nested. Each relay seals its blinding scalar and the child capsule to the incoming public key. The initiator opens the outer layer, updates the private scalar, and continues until the responder payload is recovered.

## Consequences

- public reply keys are transformed independently at every hop;
- the initiator can reconstruct the key chain without publishing derivation indices;
- relays do not learn responder payloads;
- exact route depth must be hidden by padding or another representation;
- a concrete KEM, proof, and test vectors are still required.

## Rejected alternative

Reusing one HPKE public key across all hops was rejected because compromised non-adjacent relays could compare it directly. Non-hardened BIP32 was rejected as a routing-specific cryptographic foundation.
