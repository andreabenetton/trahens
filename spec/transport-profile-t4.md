<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens T4 Packet-Level Adversarial Evaluation Profile

- Status: Active experimental evaluation profile
- Date: 2026-07-30
- Bound transport: T2 and T3
- Wire-format changes: none

## 1. Purpose

T4 defines a deterministic packet-event falsification harness for evaluating Trahens public schedules after fixed-size cells have been placed on concrete links. T3 evaluates epoch-level count traces under an exact public budget. T4 refines that model with per-cell timestamps, independent observer clocks, propagation jitter, access-link serialization, shared bottlenecks, route changes, partial observation, an open-world classifier, and a bounded selective-delay probe.

T4 is not a new transport protocol. It introduces no message class, cryptographic suite, route field, or network-visible identifier. It is also not a substitute for a validated deployment, Shadow, ns-3, a kernel prototype, or independent traffic-analysis review. Its purpose is to reject claims that fail under a transparent, reproducible model and to define the measurements required by the next implementation stage.

## 2. Event model

The reference emulator processes a finite priority queue of packet events. The event classes are:

1. logical demand arrival;
2. T2 epoch decision;
3. public slot release;
4. access-link transmission completion;
5. shared-bottleneck transmission completion;
6. next-hop arrival; and
7. observation at an instrumented link.

Events with equal true time use a fixed priority order and a monotonically increasing insertion sequence. The same seed and configuration MUST therefore produce the same byte-for-byte report and deterministic vector.

Each released cell is exactly 1,052 bytes. T4 retains only a local token identifying whether the modelled cell represents target traffic, bounded background traffic, or CHAFF. The token terminates at the next relay. A target token that continues along a route is enqueued as a newly local token after propagation and relay processing; no cross-hop cell identifier is exposed.

## 3. Link and bottleneck service

For cell size `C` bytes and link capacity `R` bits per second, the serialization time is:

```text
serialization_us(C,R) = ceil(8 * C * 1,000,000 / R)
```

Each logical link has a finite FIFO and an access-link serializer. When shared bottlenecks are enabled, selected links additionally contend for one finite-capacity serializer. Queue occupancy, drops, expiration, and the maximum number of queued cells MUST be reported.

Propagation delay for link `l` is sampled from a bounded interval around the configured base delay:

```text
D_l = base_l + J_l
-J_max <= J_l <= J_max
```

The model uses deterministic pseudorandom sampling from the experiment seed. A report MUST publish the base delays, jitter bound, access capacity, bottleneck capacity, and whether links share a bottleneck.

## 4. Observer clocks

Every observed link has an independent affine clock. If a cell is observed at true time `t`, the reported timestamp is:

```text
t_obs = Q((1 + s_l) * t + o_l + eta_l)
```

where:

- `s_l` is bounded relative clock skew;
- `o_l` is a bounded offset;
- `eta_l` is bounded measurement noise; and
- `Q` is timestamp quantisation.

Clock parameters are link-local and are not visible to the protocol. The emulator MUST preserve true event order internally and apply the observer transformation only when constructing the adversary's trace. An experiment MUST report skew, offset, noise, and quantisation bounds. Results under a shared perfect clock MUST NOT be generalized to heterogeneous observation points.

## 5. Exact public budget

T4 inherits the T3 equal-budget requirement. For `E` measured epochs, `L` links, and public budget `B` cells per link and epoch:

```text
ExpectedPublicCells = E * L * B
```

Every compared profile MUST release exactly this number of complete records over the measured interval. The reference scheduler enforces the remaining budget online; it does not append a hidden compensation interval after the trace.

Budget equality removes total record count as a trivial feature. It does not equalize timestamp distribution, queue delay, link correlation, clock error, route churn, loss, or service quality.

## 6. Route and churn model

The reference topology exposes four logical directed links. Monitored route classes are:

```text
1: (0, 1, 2)
2: (0, 1, 3)
3: (0, 2, 3)
```

Additional route combinations are reserved for open-world unknown classes. A churn experiment declares:

```text
(route_before, route_after, churn_epoch)
```

Only target cells generated at or after `churn_epoch` use the new route. Cells already in flight retain their path. The protocol is not told the classifier label; route labels and complete paths exist only in the emulator and report generator.

T4 MUST report the churn epoch, both route classes, delivery, expiry, queue occupancy, exact-budget rate, and cleanup. A classifier trained only on stable traces MUST be evaluated separately on churned traces.

## 7. Partial observation

The adversary observes a declared subset of links. Unobserved links still execute the same queue, serialization, bottleneck, propagation, and scheduling rules. Their events are omitted only from the adversary trace.

A report MUST state the observed-link set. Missing links MUST NOT be represented as zero-count observed links because doing so would give the classifier information that the adversary did not receive.

## 8. Open-world evaluation

T4 separates monitored routes from unknown routes. The mandatory reference split is:

```text
monitored training/testing routes: 1, 2, 3
unknown calibration routes:        4, 5, 6
unknown test routes:               7, 8, 9, 10
```

Unknown calibration and unknown testing routes MUST be disjoint. The classifier MUST NOT use test examples to standardize features, fit centroids, or choose the rejection threshold.

The reference classifier is a standardized nearest-centroid classifier. It extracts only public timestamp features, including binned counts, inter-arrival summaries, first differences, transition statistics, and pairwise lagged correlations. It predicts an unknown label when the minimum standardized centroid distance exceeds a threshold calibrated on monitored validation and unknown calibration traces.

The mandatory metrics are:

- overall accuracy;
- macro-F1 including the unknown class;
- monitored true-positive rate;
- unknown false-positive rate;
- monitored precision;
- rejection threshold;
- monitored and unknown class counts; and
- delivery, delay, queue, exact-budget, and cleanup measures.

Overall accuracy MUST NOT be reported alone. In an open world, it can be dominated by the unknown-class prevalence or by a classifier that rejects nearly everything.

## 9. Selective-delay probe

The T4 active adversary may add a bounded extra delay to selected target cells on one declared link. It cannot decrypt, forge, or modify a valid W2/T1/T2 record. The extra delay is finite and applies only within a declared probe pattern.

The reference probe uses a deterministic binary pulse pattern and a steady target workload in both the absent and present conditions. The detector searches only a bounded set of phases and lags and correlates the known probe with downstream inter-arrival and local-count features. Training and testing traces are disjoint.

The mandatory report includes:

- added delay in microseconds;
- probe period, width, duty cycle, and target link;
- detector accuracy;
- true-positive and false-positive rates;
- absent and present mean scores;
- threshold; and
- route-churn condition.

Failure of the reference detector to outperform chance is not evidence against stronger selective-delay, congestion, watermarking, or learned attacks. A positive result is sufficient to reject the evaluated privacy claim; a negative result only bounds this detector in this model.

## 10. Required invariants

A conforming T4 experiment MUST satisfy:

1. every public cell has the active 1,052-byte record size;
2. every compared profile has the exact declared public-cell budget;
3. packet events use deterministic tie-breaking;
4. access and bottleneck serializers never transmit two cells simultaneously on the same resource;
5. observer-clock transformation cannot alter internal protocol event order;
6. no cell or transmission identifier survives an honest relay boundary;
7. route labels and token kinds are model-only values;
8. open-world calibration and testing unknown routes are disjoint;
9. feature normalization and threshold selection use training/calibration data only;
10. partial observation omits unobserved links rather than supplying privileged zero traces;
11. selective delay is bounded and fully reported;
12. queue overflow, expiry, budget mismatch, and cleanup failure are reported;
13. all retained analysis state has explicit finite bounds; and
14. no result is described as a deployment benchmark, proof, or global-observer guarantee.

## 11. Resource bounds

The reference implementation MUST bound:

- event-queue entries;
- per-link ready cells;
- shared-bottleneck queue cells;
- trace duration and number of observed timestamps;
- number of route classes and samples;
- feature width;
- phase and lag search width;
- selective-delay amplitude and duty cycle;
- retained raw traces and report size; and
- drain-tail duration.

Analysis state is never protocol forwarding state and MUST NOT be serialized into M2, W2, T1, or T2 records.

## 12. Claim boundary

T4 may support narrow statements about the implemented model, for example:

- exact bandwidth equality does not equal timestamp-distribution equality;
- heterogeneous clocks and jitter can reduce or distort simple correlation features;
- route churn can invalidate a classifier trained only on stable routes;
- partial observation changes both monitored recall and unknown false-positive rate;
- a bounded selective-delay detector did or did not separate the declared conditions; and
- all compared traces satisfied the declared service and cleanup invariants.

T4 does not establish resistance to a global passive adversary, deep-learning classifiers, deployment-specific clocks, realistic Internet routing, adaptive congestion manipulation, large-scale shared bottlenecks, website fingerprinting, or arbitrary active watermarking. Those require independent emulation, implementation, measurement, and review.
