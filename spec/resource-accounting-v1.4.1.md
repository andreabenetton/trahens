<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.4.1 resource accounting

- Status: Active research design
- Scope: U1, E1, R1, M2, W2 canonical fragmentation, T1 recovery, and T2 congestion/scheduling

## 1. Counter hierarchy

A node maintains finite counters for:

1. adjacent peer and link epoch;
2. authenticated public sequence replay state;
3. T1 sender transmissions and fragments;
4. T1 receiver contexts and completion caches;
5. pending cumulative ACKs;
6. new-data, retransmission, and ACK queues;
7. T2 rate class, negotiations, deficits, schedule slots, and CHAFF bandwidth;
8. M2 parsing and route-protocol state;
9. rolling cryptographic-work and malformed-input windows, including reply-key scalar multiplication, reply-layer KEM/AEAD work, and directory-query work when a directory profile is enabled;
10. node-global bytes, timers, registrations, and active routes.

Admission requires capacity in every applicable counter. A relay charges one scalar multiplication for every child reply-key blinding operation. Deterministic test-only reply ephemerals are not a deployable resource class and MUST NOT be exposed through the production API.

## 2. T1 charges

| Resource | Charged | Released |
|---|---|---|
| DATA cell | Before emission | Cell-rate window |
| ACK cell | Before emission | Cell-rate window |
| SCHEDULE cell | Before negotiated control emission | Cell-rate window or negotiation release |
| CHAFF cell | Reserved by schedule policy | Cell-rate window |
| Sender transmission | M2 enqueue | Complete ACK, failure, route deadline |
| Fragment send metadata | First emission | Complete ACK or transmission release |
| Retransmission queue item | Timeout decision | Emission, ACK, or failure |
| RTO timer | DATA emission | Superseded, complete ACK, failure |
| Receiver context | First valid fragment | Completion-cache expiry, conflict, peer loss |
| Reserved logical bytes | First valid fragment | Context release |
| Pending ACK | First retained fragment | ACK emission, context release |
| Completion cache | Complete reassembly | Cache expiry or peer loss |

## 3. Admission and processing order

1. exact 1,052-byte length and peer cell-rate budget;
2. public epoch/sequence precheck without replay mutation;
3. adjacent-link authentication;
4. replay commitment;
5. T1/T2 profile, frame class, and canonical field validation;
6. CHAFF discard, ACK update, or DATA reassembly admission;
7. complete-message M2 parsing;
8. route bounds and protocol-state reservation;
9. protocol transformation and outgoing queue admission.

A failure at one stage MUST NOT consume a later-stage resource.

## 4. Mandatory T1/T2 limits

A conforming deployment specifies finite values for:

- finite rate menu, current and maximum class, epoch duration, and negotiation guard;
- hold and hysteresis counters, pressure thresholds, weights, deficits, and control reserves;
- CHAFF cells and bytes per epoch;
- sender transmissions per peer and node;
- fragments per transmission, not above 17;
- new, retransmission, and ACK queue cells;
- pending ACKs;
- receiver contexts and aggregate reserved logical bytes;
- completion-cache lifetime;
- ACK delay;
- minimum, initial, and maximum RTO;
- retransmission rounds and fragment attempts;
- timeout and malformed-input work per rolling window.

The reference model defaults to a 2 ms slot, 14 ms initial RTO, 8-96 ms RTO bounds, three recovery rounds, and finite schedule epochs selected by the experiment.

## 5. Recovery amplification

For a logical message with `q` fragments and `r` recovery rounds, the absolute DATA-cell bound is:

```text
q * (1 + r)
```

because one round enqueues each currently missing fragment at most once. ACK and CHAFF cells are separately bounded by the schedule epoch and slot rate. Implementations MUST account for ACK loss, which may cause already received fragments to be sent again before the complete cumulative ACK is delivered.

## 6. Scheduler cost

For one directed fixed schedule with epoch length `E` and slot interval `Delta`, the emitted-cell count is fixed by:

```text
N = floor(E / Delta) + 1
wire_bytes = 1052 * N
```

Real DATA, ACK, and SCHEDULE consume slots that would otherwise carry CHAFF; they do not increase `N` while the queue stays within capacity. The privacy cost is therefore explicit reserved bandwidth. A node MUST NOT promise a fixed schedule whose CHAFF reserve cannot be sustained.

## 7. Overload behavior

Recommended discard or degradation order:

1. unauthenticated or malformed record;
2. replay;
3. new receive context from the most over-budget peer;
4. additional new logical transmission;
5. additional retransmission round;
6. low-priority new DATA under queue pressure;
7. optional CHAFF above the minimum declared schedule policy;
8. route branch, tentative, or active state according to local eviction policy.

A deployment that drops CHAFF below its declared fixed schedule has exited that privacy profile and MUST report the resulting schedule break.

## 8. Reported metrics

Experiments report:

- route success and successful setup latency;
- DATA, ACK, CHAFF, retry, lost, and total cells;
- wire bytes;
- fragmented messages and acknowledged fragments;
- timeout events, recovery rounds, and retry exhaustion;
- queue drops, admission rejections, malformed cells, and schedule-control failures;
- duplicate fragments;
- peak and final sender/receiver transport state;
- public inter-arrival coefficient of variation and rate-class changes;
- weighted fairness, queue peak, residence delay, and retry exhaustion;
- per-direction public trace cell count and multi-link count correlation;
- cleanup completion.


## 9. Reply-path and directory accounting

A deployment MUST bound reply layers, reply KEM encapsulations/decapsulations, scalar blinding operations, candidate bytes, and cryptographic failures per peer and globally. The private-directory dependency is outside Core; if D1 or another directory profile is enabled, publication records, query work, retained epochs, authorization state, and replica/relay connection state require independent finite budgets.

## 10. T2 resource additions

Each directed link additionally accounts for:

- current and pending rate class;
- epoch and negotiation identifiers;
- OFFER/ACCEPT/REJECT cells and guard timers;
- consecutive-high, consecutive-low, and minimum-hold counters;
- per-class queue cells, bytes, deficits, weights, and residence deadlines;
- rejected whole-transmission reservations;
- schedule-control reserve;
- public rate transitions and fixed-profile breaks.

For epoch `e`, the physical-cell budget is exactly `r[c_e]`. DATA, ACK, SCHEDULE, and CHAFF partition that budget; none may add an undeclared extra slot. At maximum class, new admission is rejected before the first fragment if the complete first-send reservation does not fit.

## T3 analysis budgets

T3 analysis MUST set finite limits for observation epochs, observed links, route classes, samples per class, feature width, active-probe cells, hybrid decoy cells, retained raw traces, and report rows. These budgets are local research-tool limits and do not enlarge relay forwarding state.

## T4 analysis resources

T4 analysis MUST set finite limits for:

- event-queue entries;
- ready tokens per logical link;
- shared-bottleneck queue cells;
- observed timestamps per link;
- trace epochs and drain epochs;
- route classes, training samples, calibration samples, and testing samples;
- classifier feature width;
- rejection-threshold candidates;
- selective-delay pulse count, amplitude, phase search, and lag search;
- raw trace retention and report output; and
- experiment wall-clock time.

These resources are not protocol forwarding resources. Exhaustion aborts or marks the experiment invalid; it MUST NOT alter a network message to fit the analysis budget.
