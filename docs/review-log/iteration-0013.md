# Technical review: T2 congestion and quantized scheduling

- Date: 2026-07-30
- Scope: adjacent-link congestion response, rate negotiation, fair service, burst loss, schedule leakage, and multi-link correlation
- Active specification: Core v1.2 with T2

## Decision

Adopt T2 as an experimental adjacent-link profile above T1. T2 keeps the 1,052-byte encrypted cell, publishes a finite rate menu, changes class only at epoch boundaries, requires authenticated OFFER/ACCEPT negotiation, and uses asymmetric hysteresis. New DATA service is weighted deficit round robin after bounded ACK, schedule-control, and retransmission reserves.

The fixed profile retains the narrow active/idle slot-shape claim under a pre-existing non-overloaded epoch. Adaptive cadence explicitly gives up that claim because public rate classes are activity-dependent. Work-conserving release remains a baseline with no cover-traffic claim.

## Model findings

- Under equal overload, fixed-low delivered 78.43% of admitted work and dropped 15%; fixed-high delivered all work with 1,600 chaff cells; adaptive delivered all work with a peak queue of 98, 370 chaff cells, and seven class changes.
- Under saturated weights 1:2:3, normalized weighted throughput fairness was at least 0.999996 in the evaluated horizon.
- A rate-presence classifier had advantage 0 against fixed-high idle/active traces and advantage 1 against both evaluated adaptive policies.
- At the same nominal mean loss of 11.14%, the Gilbert-Elliott process produced more retry-exhaustion events and higher delay than independent loss.
- Fixed public-count traces had no variance; adaptive traces retained positive two-link correlation; work-conserving traces were perfectly correlated in the deliberately synchronized model.

## Claim boundary

T2 does not provide an end-to-end congestion controller, a global-observer theorem, hidden rate negotiation, or privacy under schedule start/stop observation. Rate class, epoch boundaries, direction, topology, queue-induced transitions, and overload failures remain visible. The deterministic simulator abstracts control-frame loss and cannot support production performance claims.

## Follow-up

1. Complete the schedule-negotiation loss/conflict/restart state machine.
2. Evaluate randomized or privacy-budgeted rate adaptation.
3. Add adversarial ACK and schedule-control behavior.
4. Compare bounded redundancy with retransmission under burst loss.
5. Implement an independent T2 scheduler and differential tests.
6. Run realistic multi-link classifiers with propagation delay, noise, churn, and heterogeneous rates.
