# Technical review: T3 multi-link traffic analysis

Date: 2026-07-30

## Decision

Add T3 as an evaluation profile over T2 rather than a wire or congestion-control revision. T3 compares fixed, adaptive, and hybrid schedules under an exact per-link super-epoch bandwidth budget and makes route classification, boundary leakage, correlated cross traffic, and bounded active probing reproducible.

## Implemented scope

- Four observable directed links and four balanced route labels.
- Independent and shared-latent-burst background traffic.
- Observation windows of 32, 64, 128, and 256 epochs.
- Exact 40-cell-per-link-per-epoch super-epoch budget.
- Fixed, adaptive, and hybrid schedule traces.
- Transition-phase and lagged-correlation metrics.
- Standardized nearest-centroid route classifier with training-only normalization.
- Balanced active-probe detector using count and positive schedule-difference correlation.
- Deterministic vectors, reports, tests, and formal-paper integration.

## Findings

At 128 epochs with correlated background traffic, route-classifier accuracy was 0.250 for fixed, 0.990 for adaptive, and 0.365 for hybrid traces, against a balanced random baseline of 0.250. All traces used exactly 5,120 cells per link and 20,480 cells total.

The adaptive profile exposed full boundary alignment and mean pairwise lag correlation of 0.717. Hybrid scheduling reduced these values to 0.000 and 0.231 respectively. Fixed count traces were route independent in the declared model.

The active probe was not detectable from fixed count traces. Adaptive scheduling produced 0.900 true-positive and 0.075 false-positive rates. Hybrid scheduling reduced but did not eliminate detection.

## Claim boundary

These results reject the inference that equal cell length and equal total bandwidth imply equal trace shape. They do not establish resistance to learned flow correlation, open-world imbalance, packet-level timestamps, routing observation, selective-delay watermarking, adaptive probes, or deployed-network effects.

## Next gate

Build a packet-level network-emulation harness with clock skew, propagation jitter, shared bottlenecks, route churn, selective delay/loss, learned classifiers, and open-world evaluation. The hybrid schedule remains an analysis candidate until sub-epoch transition semantics and service correctness are specified.
