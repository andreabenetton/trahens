# Technical review: T4 packet-level adversarial evaluation

- Date: 2026-07-30
- Target release: Core v1.4
- Scope: packet events, clocks, bottlenecks, churn, open-world classification, and selective delay

## Decision

Accept T4 as an experimental evaluation profile. T4 adds no wire behavior and makes no deployment-level anonymity claim. It is a deterministic falsification harness for public timestamp traces emitted by T2/T3 schedules.

## Implemented model

The reference emulator uses four logical directed links, 1,052-byte cells, finite access and shared-bottleneck serializers, bounded propagation jitter, finite queues, independent affine observer clocks, timestamp noise and quantisation, partial observation, and route churn. It enforces an exact public budget online rather than appending an unobserved compensation interval.

The open-world experiment uses monitored routes 1--3, unknown calibration routes 4--6, and disjoint unknown testing routes 7--10. Feature normalization and threshold calibration exclude the test set. The selective-delay experiment uses a 60 ms bounded delay, a deterministic two-epoch pulse, a steady target workload in both classes, and a bounded phase/lag detector.

## Packet-service result

Every evaluated profile and scenario emitted exactly 2,240 public cells per trace (40 epochs x 4 links x 14 cells), with a budget-match rate and cleanup rate of 1.0.

Representative network-noise results were:

| Profile | Target delivery | Mean delay (us) | p95 delay (us) | Peak queue | Mean CHAFF |
|---|---:|---:|---:|---:|---:|
| Fixed | 0.9980 | 15,759.7 | 22,318.2 | 36.0 | 1,062.0 |
| Adaptive | 0.9814 | 15,774.5 | 22,235.2 | 42.0 | 1,030.5 |
| Hybrid | 0.9986 | 15,250.9 | 21,070.9 | 28.9 | 1,066.0 |

The route-churn scenario retained exact budgets and cleanup. Adaptive delivery fell to 0.9588 in the evaluated workload because 14.2 target cells per trace expired on average; this is a model-specific service result, not evidence about a deployment.

## Open-world result

At 40 epochs under network noise:

| Profile | Accuracy | Macro-F1 | Monitored TPR | Unknown FPR | Monitored precision |
|---|---:|---:|---:|---:|---:|
| Fixed | 0.6071 | 0.2666 | 0.0833 | 0.0000 | 0.3333 |
| Adaptive | 0.4286 | 0.4608 | 0.9167 | 0.9375 | 0.4231 |
| Hybrid | 0.3214 | 0.2556 | 0.2500 | 0.6250 | 0.2143 |

These values show why overall open-world accuracy is insufficient. Fixed rejected unknown routes but also rejected most monitored routes. Adaptive recognized monitored routes but mislabeled nearly every unknown route as monitored. The hybrid result was poor on both dimensions in this small transparent model.

Under partial observation, adaptive monitored TPR was 0.6667 with unknown FPR 0.0 in the sampled traces, while route churn reduced it to monitored TPR 0.3333 and unknown FPR 0.25. These fluctuations are not generalized: the sample count is deliberately bounded for deterministic CI and the classifier is not state of the art.

## Selective-delay result

The bounded detector did not consistently separate a 60 ms selective-delay pulse from the absent condition:

| Profile | Churn | Accuracy | TPR | FPR |
|---|---:|---:|---:|---:|
| Fixed | no | 0.4167 | 0.5000 | 0.6667 |
| Adaptive | no | 0.4167 | 0.5000 | 0.6667 |
| Hybrid | no | 0.2500 | 0.5000 | 1.0000 |
| Fixed | yes | 0.5000 | 0.5000 | 0.5000 |
| Adaptive | yes | 0.3333 | 0.1667 | 0.5000 |
| Hybrid | yes | 0.5833 | 0.3333 | 0.1667 |

This is a negative result for one transparent detector under one topology and workload. It is not evidence that Trahens resists stronger selective-delay, throughput, congestion, watermarking, or learned attacks.

## Security and modeling findings

1. Exact total bandwidth does not make packet timestamps equal.
2. Clock heterogeneity, jitter, and shared queues materially affect the public feature distribution and must be declared.
3. Route churn is a privacy-model variable, not only a route-repair event.
4. Open-world reports need monitored recall and unknown false-positive rate, not accuracy alone.
5. A failure to detect one active probe does not establish active unlinkability.
6. Route labels and target tokens are analysis-only and terminate at every modeled relay.

## Remaining gaps

- Calibrate topology, capacities, traffic, jitter, clocks, and loss from measurements.
- Reproduce the profile in Shadow, ns-3, or an independent packet emulator.
- Test stronger open-set, sequence, and learned classifiers.
- Expand to larger topologies, asymmetric paths, realistic routing churn, and longer windows.
- Evaluate adaptive selective-delay and congestion attacks with multiple compromised observation points.
- Run an independent implementation and privacy review.

## Acceptance

T4 is accepted as a reproducible research gate because it exposes these assumptions and reports failures without converting a bounded model into a security theorem.
