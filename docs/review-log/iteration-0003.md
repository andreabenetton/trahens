<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0003 - Expanding-ring discovery and cumulative budgets

- Date: 2026-07-30
- Status: Completed

## Question

Can expanding-ring discovery preserve responder success while reducing expected control traffic, and what correlation surface is created by repeated attempts?

## Design change

Core v0.2 separates one local logical discovery from multiple wire-visible attempts:

- the logical discovery ID remains local to the initiator;
- every ring uses a fresh random attempt ID;
- duplicate suppression is attempt-local;
- candidates are deduplicated across attempts;
- total transmission and state-allocation budgets span the complete logical discovery;
- experiments report relay overlap across attempts.

The evaluated ring schedule was:

`(hop 2, fan-out 2) -> (hop 3, fan-out 2) -> (hop 4, fan-out 3) -> (hop 5, fan-out 4)`

The comparison baseline was one fixed `(hop 5, fan-out 4)` attempt.

## Experiment

- 500 nodes;
- connected random undirected graph;
- average degree 8;
- 100 deterministic graph seeds per responder density;
- candidate limit 8;
- one candidate required;
- cumulative transmission budget 1,200;
- cumulative state-allocation budget 1,200;
- responder fractions 1%, 2%, and 5%.

The complete result is in `reports/iteration-0003-policy-comparison.csv` (SHA-256 `4020d9a13829853e5946bf8e79e7153717a859a07d97a7694f0b8a46cd7e8a1e`).

## Results

| Responder fraction | Fixed success | Expanding success | Fixed mean transmissions | Expanding mean transmissions | Transmission reduction | Mean attempts | Mean multi-attempt observer fraction |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1% | 100% | 99% | 895.12 | 293.63 | 67.20% | 2.90 | 9.52% |
| 2% | 100% | 100% | 895.12 | 157.65 | 82.39% | 2.61 | 6.81% |
| 5% | 100% | 100% | 895.12 | 67.52 | 92.46% | 2.08 | 4.41% |

At a 2% responder fraction, expanding rings also reduced mean cumulative state allocations from 421.14 to 116.72, a reduction of 72.28%.

## Interpretation

Expanding rings materially reduce expected discovery cost when responders are not extremely sparse. The policy is not free:

- setup requires multiple candidate windows on many runs;
- some relays observe multiple attempts and can correlate them probabilistically;
- at 1% responder density, the tested schedule lost one success in 100 runs;
- fresh attempt IDs remove direct identifier linkage but do not hide timing or topology overlap.

The fixed flood's cost is independent of responder density because the current model does not stop forwarding after a candidate is found. Expanding rings gain efficiency by stopping the logical discovery before the broadest ring on successful early attempts.

## Decision

Accept expanding-ring discovery as the active Core v0.2 policy baseline. Do not claim it is optimal. Keep fixed flooding as a comparison policy and retain all cumulative budgets.

## Next question

How do packet loss, candidate-window duration, delayed candidates, malicious responders, and selective forwarding change the success/cost/linkability trade-off?
