# Review 0011 - Core v1.0 R1 gate

## Decision

Adopt Gate B: remove endpoint-specific eligibility from active forward discovery and enable R1 rendezvous capabilities. Preserve C1, symbolic C2, and the C2 k=2 transcription as disabled research providers.

## Reasons

1. The active protocol previously depended on a receiver-anonymous, publicly rerandomizable, active-tag-resistant encryption scheme without an approved concrete instantiation.
2. The exact k=2 transcription reproduces several source equations but cannot complete full rerandomization under the literal finite-field reduction; exhaustive small-chain checks find counterexamples.
3. The updatable/randomizable PKE assessed from Dowling et al. updates the encryption key and ciphertext together and does not match the required ciphertext-only same-recipient interface.
4. R1 can remove endpoint-specific bytes from DISCOVER with a simple, testable transform, at the cost of an explicit directory and gateway trust boundary.

## Changes

- introduced the eligibility-provider interface;
- made R1 the event-model default and network-enabled provider;
- implemented non-semantic nonce replacement;
- added capability commitment, expiry, atomic redemption, replay and wrong-gateway rejection;
- added C2 author-query and alternative-primitive assessment documents;
- added exhaustive small-chain checking;
- published active Core v1.0 specifications;
- rewrote the formal paper around the current R1 architecture with point-of-use citations.

## Evidence

- 100/100 clean R1 routes activated and cleaned up in the deterministic comparison;
- 100/100 routes with an upstream literal nonce marker activated, with zero downstream marker observations;
- C1 ratio-tag control failed route activation and produced downstream observations;
- deterministic R1 vectors and capability tests cover absence from DISCOVER, nonce replacement, one-time redemption, expiry, wrong gateway, zero input, and duplicate registration;
- all 91 repository tests, deterministic artifact comparisons, repository checks, and paper compilation pass before release packaging.

## Remaining blockers

- private descriptor distribution;
- gateway/directory collusion analysis;
- bounded fragment reliability;
- traffic scheduling and timing analysis;
- independent review of the retained reply KEM and nested candidate composition;
- independent implementation and fuzzing.
