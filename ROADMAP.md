# Roadmap

| Milestone | Purpose | Gate | State |
|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | current and historical material are separated | Complete |
| M1 Core semantics | Make bounded discovery unambiguous | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | work, state, bytes, queues, and time are finite | Active |
| M3 Structural unlinkability | Remove stable cross-hop handles | U1 mechanism and claim scope are explicit | Complete research design |
| M4 Event lifecycle | Complete setup and cleanup | races have deterministic bounded outcomes | Complete model |
| M5 Retained crypto baseline | Make reply and authentication operations executable | independent review of retained composition | Review open |
| M6 Message/cell separation | Preserve variable semantics and equal cells | canonical parsing and bounded reassembly | Complete research baseline |
| M7 Active-eligibility audit | Test endpoint-specific cryptographic candidates | failing constructions remain reproducible and disabled | Complete research audit |
| M8 R1 rendezvous profile | Remove unresolved eligibility primitive from active discovery | endpoint capability is absent from DISCOVER and redeemable once after READY | Active baseline complete |
| M9 Private descriptor profile | Hide and authenticate descriptor distribution | lookup and replication have explicit privacy and abuse properties | Planned |
| M10 T1 reliability | Bound multi-cell loss recovery | delivery improves without stable cross-hop handles | Baseline complete |
| M11 T2 congestion and schedules | Define overload, fair service, and adaptive leakage | schedule changes are bounded, negotiated, measured, and claim-scoped | Baseline complete |
| M12 Overlay interoperability | Prove independent agreement | two implementations agree under faults and churn | Planned |
| M13 Traffic privacy | Evaluate multi-link metadata resistance | every claim is scheduler- and adversary-specific | Research active |

## Current milestone

Core v1.3 binds T1 recovery to T2 scheduling and T3 adversarial trace evaluation on each authenticated directed link. T2 publishes a finite rate-class menu, changes class only at epoch boundaries, requires encrypted adjacent-link OFFER/ACCEPT negotiation, applies asymmetric hysteresis, and uses weighted deficit round robin for admitted new DATA. Persistent overload at the maximum class cannot silently accelerate the cadence; admission, retry, queue residence, and failure behavior are bounded.

The measurements deliberately expose the privacy/efficiency trade-off. Fixed-high scheduling hides activity from the evaluated class-presence distinguisher but spends substantial CHAFF. Adaptive scheduling reduces CHAFF and queueing while making its public rate sequence activity-dependent. Work-conserving release is efficient but highly correlatable across the evaluated two-link model.

## Next increment

1. Specify private descriptor distribution, including authentication, query privacy, replication, enumeration resistance, rotation, and revocation.
2. Replace the abstract T2 peer agreement with a complete loss, timeout, conflict, and restart state machine for schedule negotiation.
3. Evaluate randomized or differentially private rate transitions against deterministic hysteresis, including utility and privacy budgets.
4. Add queue-aware route deadlines, authenticated receiver feedback, and adversarial ACK/schedule-control tests.
5. Evaluate limited redundancy or erasure coding against retransmission under correlated burst loss.
6. Build an independent M2/W2/T1/T2 implementation and differential-fuzz codecs, reassembly, recovery, and schedule state.
7. Run multi-link timing classifiers over realistic topologies, variable propagation delay, clock noise, congestion, and route churn.
8. Obtain independent review of the reply-key chain, custom reply KEM, capability store, T1 recovery, and T2 claim boundary.

## Core v1.3 traffic-analysis gate

T3 now supplies the baseline multi-link falsification harness required by milestone M13. It compares fixed, adaptive, and hybrid schedules under the same exact cell budget, measures route classification over 32--256 epochs, includes correlated background traffic, records transition-boundary alignment, and evaluates a bounded active bandwidth probe.

The baseline remains incomplete for a traffic-flow privacy claim. The next work must replace synthetic count traces with packet-level or event-level timing, heterogeneous clock noise, partial observation, route churn, open-world class imbalance, stronger learned classifiers, and deployment-derived cross traffic. The hybrid policy is an offline evaluation envelope until its online negotiation and overload behavior are specified.
