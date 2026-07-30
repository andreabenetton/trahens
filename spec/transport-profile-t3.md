# Trahens T3 Multi-Link Traffic-Analysis Profile

- Status: Active experimental evaluation profile
- Date: 2026-07-30
- Bound transport: T2
- Wire-format changes: none

## 1. Purpose

T3 defines how Trahens schedule policies are evaluated against multi-link passive correlation and active probing. It does not introduce a new frame class, cipher suite, or congestion controller. T3 binds an observation model, equal-bandwidth comparison rule, transparent route classifier, active-probe detector, and mandatory reporting fields to T2 traces.

The profile exists because fixed cell length and per-link schedule statements are insufficient to establish route-level traffic-flow privacy. A profile may hide the class of one cell while still exposing route-dependent rate transitions, cross-link timing, congestion propagation, observation-window effects, or an injected bandwidth pattern.

## 2. Adversary

The T3 adversary MAY observe the timestamp, direction, and fixed record count on multiple authenticated links. It does not decrypt records. Depending on the experiment, the adversary MAY:

1. observe several links on one candidate route;
2. observe links that share correlated cross traffic or a bottleneck;
3. extend the observation window;
4. train a route classifier on labeled traces generated under the same declared model;
5. inject a bounded, known positive-demand pattern at one ingress and test for a correlated downstream schedule response.

The active probe changes offered load only. It does not modify authenticated records, plaintext, route state, or cryptographic material.

## 3. Super-epoch budget

A T3 comparison defines a super-epoch of `W` T2 epochs and a public cell budget `B` per link per epoch. Every compared profile MUST expose exactly:

```text
Budget(link) = W * B
```

complete 1,052-byte records on each observed directed link during the super-epoch.

Budget equality removes total byte count as a trivial classifier feature. It does not equalize latency, queue occupancy, transition timing, loss, or the distribution of cells within the observation window.

T3 distinguishes:

- **fixed**: exactly `B` records in every epoch;
- **adaptive**: traffic-responsive allocations with rate changes aligned to T2 epoch boundaries, followed by deterministic CHAFF budget equalization over the super-epoch;
- **hybrid**: a non-zero baseline, smoothed traffic response, independent decoy uplifts, non-boundary transition phases, and exact super-epoch budget equalization.

The equalizer modifies CHAFF allocation only. It MUST NOT remove authenticated DATA required to satisfy an already admitted transmission. The executable model uses workloads whose aggregate service budget is sufficient for all admitted cells.

## 4. Multi-link workload

The reference model has four observable directed links and four labels:

```text
0: no target route
1: links (0, 1, 2)
2: links (0, 1, 3)
3: links (0, 2, 3)
```

A target signal is propagated with hop-dependent delay. Each link also carries bounded independent background demand. In the correlated-cross-traffic condition, a latent burst process affects all observed links. In the independent condition, the same marginal burst process is sampled separately per link.

The final four epochs form a low-demand reclamation tail. No hidden service interval is added after the measured super-epoch.

## 5. Boundary concealment

Adaptive T2 schedule changes occur at public epoch boundaries. T3 records each public transition phase in a finite set of micro-slots:

```text
phase in {-1, 0, ..., S-1}
```

where `-1` denotes no transition and `0` denotes the epoch boundary.

The hybrid evaluation profile assigns a non-zero phase to schedule changes and smooths its traffic response. This is an analysis mechanism, not a wire-format change. A deployable construction would require precommitted sub-epoch envelopes, clock-skew bounds, and a proof that phase selection cannot violate link service or replay ordering.

Boundary alignment is reported as:

```text
number of transitions at phase 0 / number of transitions
```

and is zero when no transition occurs.

## 6. Route-level classifier

The mandatory reference classifier is a standardized nearest-centroid classifier. It uses only public trace features:

- binned per-link cell counts;
- binned first differences;
- transition count;
- transition-boundary fraction;
- pairwise lagged Pearson correlations.

Feature columns are standardized using the training set only. Every route class has the same number of training and testing samples. Ties are resolved by the numerically smallest class label.

The reference classifier is intentionally simple. Passing it is necessary but not sufficient. A production privacy claim requires evaluation against stronger statistical and learned attacks, open-world class imbalance, partial observation, route churn, heterogeneous clocks, and deployment traces.

## 7. Observation-window experiment

The reference experiment evaluates windows of 32, 64, 128, and 256 epochs under both independent and correlated cross traffic. It reports:

- classifier accuracy;
- macro-F1;
- random baseline;
- advantage over random;
- mean boundary alignment;
- mean pairwise lagged correlation;
- mean delay and peak queue;
- exact-budget and cleanup rates.

A profile MUST NOT generalize from one window length. Increasing the observation window can improve a classifier even when every individual record has fixed length.

## 8. Active probing

The active probe is a balanced, deterministic sequence of two-epoch positive-demand pulses. The same pulse reaches each route hop after the corresponding hop delay. The observer computes the maximum lagged absolute correlation between the known probe and both:

- downstream public cell count; and
- positive downstream schedule differences.

A threshold is trained halfway between the mean absent and present score. The report includes accuracy, true-positive rate, false-positive rate, both mean scores, and the threshold.

A probe result demonstrates schedule response, not endpoint identification by itself. A realistic active adversary may also exploit congestion control, selective delay, packet loss, or bandwidth modulation. T3 therefore treats probe resistance as a separate gate from passive route classification.

## 9. Required invariants

A conforming T3 experiment MUST satisfy:

1. every profile uses the same record length and exact per-link super-epoch cell budget;
2. training and testing samples are disjoint and deterministically reproducible;
3. feature normalization uses no test-set statistics;
4. fixed traces are independent of route label within the model;
5. adaptive transition phases are public boundary events;
6. hybrid decoy choices are independent of route semantics;
7. active probe amplitude and pattern are reported;
8. queue overflow, delivery failure, cleanup failure, and budget mismatch are reported rather than omitted;
9. random baseline and class balance are explicit;
10. no result is described as a global-observer anonymity proof.

## 10. Claim boundary

T3 may support the following narrow statements:

- equal total bandwidth does not imply equal trace shape;
- fixed schedules remove route information from the modeled per-epoch count trace at the configured cost;
- adaptive schedules can remain classifiable even after exact bandwidth equalization;
- non-boundary transitions, smoothing, and decoy uplifts can reduce the simple classifier's advantage;
- an active probe may remain detectable through traffic-responsive scheduling.

T3 does not establish resistance to deep-learning correlation, website fingerprinting, watermarking, routing-level observation, shared-bottleneck inference, or a global adversary. The paper cites and discusses the relevant external attacks at their point of use.

## 11. Resource bounds

Implementations or higher-fidelity simulators MUST bound:

- super-epoch duration and stored trace history;
- classifier feature width and training sample count;
- active-probe amplitude, duty cycle, and total added cells;
- hybrid decoy budget and transition frequency;
- queue state during budget compensation;
- per-link clock and phase metadata;
- report size and retained raw traces.

T3 analysis state is not protocol forwarding state and MUST NOT be exposed through network messages.
