# Roadmap

| Milestone | Purpose | Gate | State |
|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | current and historical material are separated | Complete |
| M1 Core semantics | Make bounded discovery unambiguous | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | work, state, bytes, queues, and time are finite | Active |
| M3 Structural unlinkability | Remove stable cross-hop handles | reply-key distribution is explicit; full layer unlinkability remains conditional | Active review |
| M4 Event lifecycle | Complete setup and cleanup | races have deterministic bounded outcomes | Complete model |
| M5 Retained crypto baseline | Make reply and authentication operations executable | multiplicative blinding, standard KDF, and independent key-privacy review | Review open |
| M6 Message/cell separation | Preserve variable semantics and equal cells | canonical parsing and bounded reassembly | Complete research baseline |
| M7 Active-eligibility audit | Test endpoint-specific cryptographic candidates | failing constructions remain reproducible and disabled | Complete research audit |
| M8 R1 rendezvous profile | Remove unresolved eligibility primitive from active discovery | endpoint capability is absent from DISCOVER and redeemable once after READY | Active baseline complete |
| M9 Private descriptor profile | Hide and authenticate descriptor distribution | D1 strawman exists; concrete PIR/oblivious lookup and collusion evaluation required | Strawman only |
| M10 T1 reliability | Bound multi-cell loss recovery | delivery improves without stable cross-hop handles | Baseline complete |
| M11 T2 congestion and schedules | Define overload, fair service, and adaptive leakage | schedule changes are bounded, negotiated, measured, and claim-scoped | Baseline complete |
| M12 Overlay interoperability | Prove independent agreement | two implementations agree under faults and churn | Planned |
| M13 Traffic privacy | Evaluate multi-link metadata resistance | every claim is scheduler- and adversary-specific | Research active |

## Current milestone

Core v1.4.1 binds T1 recovery to T2 scheduling and T3 equal-budget and T4 packet-event adversarial trace evaluation on each authenticated directed link. T2 publishes a finite rate-class menu, changes class only at epoch boundaries, requires encrypted adjacent-link OFFER/ACCEPT negotiation, applies asymmetric hysteresis, and uses weighted deficit round robin for admitted new DATA. Persistent overload at the maximum class cannot silently accelerate the cadence; admission, retry, queue residence, and failure behavior are bounded.

The measurements deliberately expose the privacy/efficiency trade-off. Fixed-high scheduling hides activity from the evaluated class-presence distinguisher but spends substantial CHAFF. Adaptive scheduling reduces CHAFF and queueing while making its public rate sequence activity-dependent. Work-conserving release is efficient but highly correlatable across the evaluated two-link model.

## Next increment

1. Convert D1 from a strawman into a concrete private-directory profile, including authentication, exact PIR or oblivious-query construction, replication, enumeration resistance, rotation, revocation, and collusion tests.
2. Replace the abstract T2 peer agreement with a complete loss, timeout, conflict, and restart state machine for schedule negotiation.
3. Evaluate randomized or differentially private rate transitions against deterministic hysteresis, including utility and privacy budgets.
4. Add queue-aware route deadlines, authenticated receiver feedback, and adversarial ACK/schedule-control tests.
5. Evaluate limited redundancy or erasure coding against retransmission under correlated burst loss.
6. Build an independent M2/W2/T1/T2 implementation and differential-fuzz codecs, reassembly, recovery, and schedule state.
7. Run multi-link timing classifiers over realistic topologies, variable propagation delay, clock noise, congestion, and route churn.
8. Obtain independent review of the multiplicatively blinded reply-key chain, key-private reply KEM/PKE assumption, capability store, T1 recovery, and T2 claim boundary.

## Core v1.4 traffic-analysis gate

T3 now supplies the baseline multi-link falsification harness required by milestone M13. It compares fixed, adaptive, and hybrid schedules under the same exact cell budget, measures route classification over 32--256 epochs, includes correlated background traffic, records transition-boundary alignment, and evaluates a bounded active bandwidth probe.

The baseline remains incomplete for a traffic-flow privacy claim. The next work must replace synthetic count traces with packet-level or event-level timing, heterogeneous clock noise, partial observation, route churn, open-world class imbalance, stronger learned classifiers, and deployment-derived cross traffic. The hybrid policy is an offline evaluation envelope until its online negotiation and overload behavior are specified.

## T4 packet-level gate

T4 supplies the next M13 falsification layer. It converts public fixed-size cells into deterministic packet events with access serialization, shared bottlenecks, propagation jitter, independent observer clocks, timestamp quantisation, route churn, partial observation, disjoint open-world unknown classes, and bounded selective delay. It preserves the exact per-link public budget and reports service, queue, cleanup, monitored-recall, unknown-false-positive, and detector metrics separately.

T4 remains a transparent model. The next gate is independent implementation and higher-fidelity emulation using calibrated network parameters, larger topologies, adaptive/open-set attacks, and deployment-derived traces.
