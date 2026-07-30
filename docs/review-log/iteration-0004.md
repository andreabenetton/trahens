<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0004 - Restore non-adjacent message unlinkability

- Date: 2026-07-30
- Status: Completed as a research design; cryptographic proof remains open

## Question

Can the protocol remove the deterministic cross-hop equality handle introduced by an attempt-wide identifier while preserving bounded discovery, and what resource cost follows from losing attempt-wide duplicate suppression?

## Design change

Core v0.3 introduces the U1 branch-local profile:

- logical discoveries, ring indexes, retry counts, and attempt identifiers remain local to the initiator;
- every outgoing branch receives a fresh peer-bound token;
- candidate and route capabilities are replaced at every hop;
- every first-hop branch uses an independent root reply key;
- every relay blinds the reply public key for each child;
- every relay rerandomizes the hidden eligibility capsule;
- messages are reconstructed, padded to a fixed record class, link-encrypted with fresh nonces, and released through a declared mixing boundary;
- exact replay rejection remains link-local;
- longer cycles and converging branches are bounded by explicit state and transmission budgets rather than a stable network-wide duplicate key.

The narrow U1 claim is passive and batch-local. It does not claim global timing resistance or active-tagging resistance. A concrete URE construction and reply-key KEM remain mandatory proof obligations.

## Experiment

The simulator compares:

1. identifier-based discovery with first-parent duplicate suppression; and
2. U1 branch-local discovery, where every accepted ingress creates an independent bounded context.

Parameters:

- 500 nodes;
- connected random undirected graph;
- average degree 8;
- responder fraction 2%;
- 100 deterministic graph seeds per parameter pair;
- hop limits 3, 4, and 5;
- fan-outs 2, 3, and 4;
- candidate limit 8;
- candidate-response limit 24;
- transmission and state budgets 1,200;
- per-node branch-context limit 8.

The complete result is in `reports/iteration-0004-unlinkability-comparison.csv` (SHA-256 `cdc827fcbb7cee2e6a4d5717941aa971fbdfbd4ccb6e011e59db68d877b28178`).

## Selected results

| Hop limit | Fan-out | Identifier success | U1 success | Identifier transmissions | U1 transmissions | Transmission overhead | Identifier state | U1 branch contexts | State overhead | Budget exhaustion |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 2 | 23% | 23% | 13.94 | 14.00 | 0.43% | 13.78 | 14.00 | 1.60% | 0% |
| 4 | 3 | 91% | 85% | 113.51 | 118.34 | 4.26% | 102.37 | 118.34 | 15.60% | 0% |
| 4 | 4 | 100% | 100% | 298.41 | 325.12 | 8.95% | 227.71 | 325.12 | 42.78% | 0% |
| 5 | 3 | 100% | 99% | 308.65 | 356.40 | 15.47% | 232.61 | 356.40 | 53.22% | 0% |
| 5 | 4 | 100% | 100% | 900.27 | 1,187.46 | 31.90% | 421.91 | 1,185.06 | 180.88% | 91% |

At hop 4 and fan-out 3, mean context amplification was 1.1291 accepted contexts per unique relay. At hop 5 and fan-out 4, it rose to 2.7020.

## Interpretation

Removing a stable attempt identifier eliminates direct identifier equality across non-adjacent relays, but it also eliminates the simplest network-wide duplicate-suppression mechanism. The cost is limited under conservative parameters and rises sharply with hop limit and fan-out. The highest tested setting nearly consumed the entire configured state budget and exhausted a budget in most runs.

The modest measured loop-context fraction does not imply low duplicate cost. Most amplification comes from converging branches and repeated arrivals at the same physical relay, not only from a branch re-entering its own measured path.

The small success-rate differences between the two models arise from different random branch selections and budget interactions; the experiment is not evidence that U1 intrinsically reduces reachability.

This experiment validates a resource trade-off, not the cryptographic U1 claim. The simulator does not model ciphertext distributions, mixing queues, event time, active tagging, or adversarial timing.

## Decision

Accept Core v0.3 and U1 as the active research design. State explicitly that unlinkability has been restored at the protocol-structure level, not proved for production.

Retain the identifier-based model as a resource baseline. Require conservative fan-out, expanding initiator-local policy, per-node context caps, and hard global budgets in every U1 simulation and future implementation.

## Next question

How do event time, candidate windows, delayed reverse messages, COMMIT/READY activation, expiration, and malicious fresh-branch generation change the success, peak-state, and privacy trade-offs?
