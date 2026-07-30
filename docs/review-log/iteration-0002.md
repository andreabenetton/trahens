# Iteration 0002 - Fan-out and hop-limit sweep

- Date: 2026-07-30
- Status: Completed

## Question

How quickly do discovery coverage and duplicate traffic grow when hop limit and relay fan-out increase under the first-parent rule?

## Experiment

- 500 nodes
- connected random undirected graph
- average degree 8
- responder probability 2 percent
- 20 deterministic seeds per parameter pair
- candidate limit 8
- hop limits 3, 4, and 5
- relay fan-out 2, 3, and 4
- initial fan-out equal to relay fan-out

The complete results are in `reports/iteration-0002-sweep.csv`.

## Selected results

| Hop limit | Fan-out | Candidate success | Mean graph coverage | Mean transmissions | Mean duplicates |
|---:|---:|---:|---:|---:|---:|
| 3 | 2 | 25% | 2.81% | 14.00 | 0.00 |
| 3 | 4 | 75% | 15.11% | 80.70 | 5.30 |
| 4 | 3 | 95% | 21.08% | 116.20 | 11.00 |
| 4 | 4 | 100% | 46.35% | 301.35 | 70.05 |
| 5 | 3 | 100% | 47.47% | 317.10 | 80.20 |
| 5 | 4 | 100% | 85.56% | 913.25 | 486.30 |

## Interpretation

The toy model shows a sharp nonlinear cost increase. Moderate parameters can find a responder reliably without covering most of the graph, but one additional hop or branch can move the protocol toward near-network-wide flooding and large duplicate volume.

This is not a network-performance result: the model excludes timers, message sizes, loss, churn, reverse candidates, cryptography, and adversarial behavior. It is sufficient to reject the assumption that one fixed flood configuration will be efficient across topologies and responder densities.

## Design consequence

An expanding-ring policy should be evaluated before fixed broad flooding. The protocol should begin with a conservative ring and expand only when the candidate window returns insufficient results. Total resource accounting must cover every ring in the logical discovery.

## Next question

Can expanding-ring discovery reduce expected transmissions while preserving candidate success, and what linkability is introduced by repeated attempts?
