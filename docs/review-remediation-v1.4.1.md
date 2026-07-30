# v1.4.1 independent-review remediation

## Scope

This patch release blocks the prototype milestone until the substantive findings of the 30 July 2026 independent review are reflected in code, specifications, paper, and build integrity.

## Changes

1. Replace additive reply-key evolution with multiplicative `ristretto255` blinding.
2. State and prove the exact public-key distribution property, while keeping full reply-layer unlinkability conditional on key-private encryption and composition review.
3. Replace the two-stage HKDF-Expand chain with one Extract and one Expand whose output is split into key and nonce.
4. Remove caller-selected ephemeral secrets from the production-facing reply encryption API; isolate deterministic encryption in a gated test-support module.
5. Add the D1 private-directory strawman and state prominently that R1 alone is not a complete endpoint-anonymity system.
6. Reframe the C2 result as a failure of the project's literal transcription, most likely caused by an interpretation mismatch, not as evidence of a defect in the cited paper.
7. Track the exhaustive C2 report so `make check` succeeds from a fresh clone.
8. State that internal iteration logs and compressed Git history are not independent-review evidence.

## Claim boundary

The patch establishes exact distributional unlinkability of the reply public key across one honest multiplicative blinding step. It does not establish receiver anonymity or IK-CCA security of the complete nested reply encryption construction. Prototype implementation remains blocked on independent review of that composition or replacement with a reviewed anonymous encryption construction.

## Validation

- `make test`: 127 deterministic tests pass.
- `make check`: succeeds from the remediated working tree and regenerates all tracked vectors and reports.
- The complete 50-page paper compiles without unresolved references or overfull text.
- Every PDF page was rendered and visually inspected; line numbers remain present every five lines and no watermark is present.
- A clean clone successfully completed the repository integrity gate and all 127 tests. The 50-page paper also compiled from an empty build directory; an earlier intentionally interrupted compile left a corrupt auxiliary file, which was removed before the successful clean build.
