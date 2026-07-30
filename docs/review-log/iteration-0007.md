# Iteration 0007 - W1 codec, integrated cryptography, and active tagging

- Date: 2026-07-30
- Status: Completed as a research counterexample and interoperability baseline

## Question

Can the control protocol be encoded as one constant-size record, can C1 cryptography be executed inside the E1 event lifecycle, and does the present eligibility construction resist a compromised relay that actively tags a branch?

## Design change

Core v0.6 binds U1, E1, C1, and the new W1 wire profile. W1 fixes every adjacent-link control record at 1,052 bytes: a 12-byte public link header, a 1,024-byte encrypted plaintext, and a 16-byte authentication tag. The message type and all protocol fields are encrypted. Every relay reconstructs and repads the outgoing body.

The event model now executes actual C1 operations for DISCOVER, nested CANDIDATE return, responder signatures, COMMIT proofs, and READY proofs. It authenticates W1 records on every edge and records exact wire bytes and failure classes.

## Active-tagging result

The analysis found a persistent ratio tag in the C1 URE consistency pair. A malicious relay can transform the pair to `(c V1,V1)`. Honest rerandomization preserves the ratio; a colluding downstream relay can recognize it. The destination rejects the capsule unless the tag scalar equals its eligibility secret.

This is a counterexample to active-adversary message unlinkability. The protocol now states that claim boundary explicitly. Adjacent-link authentication does not repair the problem because a compromised relay can originate a new valid outgoing record.

## Deterministic experiment

Forty runs on a five-node line produced:

| Scenario | Route success | Mean wire bytes | Mean wire-auth failures | Mean tag observations | Cleanup |
|---|---:|---:|---:|---:|---:|
| Clean integrated path | 100.0% | 16,832 | 0.000 | 0.000 | 100.0% |
| 2% adjacent-link tamper | 82.5% | model dependent | 0.200 | 0.000 | 100.0% |
| One ratio-tagging relay | 0.0% | model dependent | 0.000 | 0.000 | 100.0% |
| Colluding tag relays | 0.0% | model dependent | 0.000 | 1.000 | 100.0% |

The clean path performs three discovery transformations and four nested candidate layers per run. These are deterministic model results, not deployment benchmarks or a security proof.

## Verification

The repository contains 53 deterministic tests. Added coverage verifies:

- equal W1 length for every record class;
- rejection of adjacent-link tampering;
- canonical nested candidate construction and opening;
- responder signature, endpoint address, and final reply-key validation;
- COMMIT and READY proof binding;
- persistence and downstream detection of the ratio tag;
- endpoint rejection and complete state cleanup in the integrated event model.

## Decision

Accept W1 and the integrated model as the current research baseline. Keep active-adversary unlinkability blocked. The next security task is to replace or redesign the eligibility mechanism so that a compromised relay cannot create a persistent recognizable relation or selective-failure tag.
