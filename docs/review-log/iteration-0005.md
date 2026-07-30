<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0005 - Event-driven route lifecycle and fresh-branch abuse

- Date: 2026-07-30
- Status: Completed as deterministic protocol model

## Question

How do explicit event time, candidate windows, delayed reverse messages, cancellation races, COMMIT/READY activation, expiry, transport faults, and malicious fresh-branch generation affect success, peak state, and cleanup?

## Design change

Core v0.4 adds lifecycle profile E1:

- state is valid on a half-open interval and cannot be revived after expiry;
- equal-time events have deterministic precedence;
- candidate windows are initiator-local;
- delayed candidates from earlier rings remain eligible until a selection decision, subject to offer and tentative deadlines;
- CANDIDATE creates tentative reverse mappings;
- COMMIT reserves `PENDING_READY` state;
- READY activates mappings and gates initiator data-plane exposure;
- off-route branches are cancelled, while expiry remains authoritative;
- exact duplicates are link-local replays;
- fresh-token floods are admitted through optional per-ingress-peer token buckets plus global limits.

## Simulator

The deterministic discrete-event simulator models:

- random bounded adjacent-link delay and natural reordering;
- record loss and exact duplication;
- branch, offer, tentative, pending, active, replay, and initiator deadlines;
- candidate-window closure and later-ring expansion;
- candidate/cancellation races;
- forward COMMIT and reverse READY;
- forced message loss for fault-injection tests;
- malicious fresh DISCOVER bursts;
- per-peer token buckets, per-node limits, global capacities, and transmission budget;
- peak and final state by lifecycle class.

The full route and legitimate/malicious classification exist only as simulator measurement aids.

The model asserts that every transmitted record crosses an actual graph edge. The initiator cancels only branches belonging to its own logical discovery; attacker-created contexts are reclaimed by their local deadlines.

## Experiment

The tracked comparison uses:

- 500-node connected random undirected graphs;
- average degree 8;
- 2 percent responder fraction;
- 100 deterministic graph seeds per scenario;
- rings `(d=2,f=2,18 ms)`, `(d=3,f=2,24 ms)`, and `(d=4,f=3,32 ms)`;
- branch TTL 70 ms, tentative TTL 55 ms, ready hold 40 ms, and active lifetime 80 ms;
- transmission budget 2,000;
- branch capacity 1,200 and per-node branch limit 8.

Four scenarios are compared:

1. clean transport;
2. 2 percent loss and 5 percent exact duplication;
3. six fresh-branch attack bursts from approximately 1 percent malicious nodes, without token buckets;
4. the same attack with a one-token per-ingress-peer bucket refilling one token every 10 ms.

The complete output is `reports/iteration-0005-lifecycle-comparison.csv`.

## Results

| Scenario | Success | Mean setup latency | Mean total transmissions | Mean attack transmissions | Peak branch state | Cleanup |
|---|---:|---:|---:|---:|---:|---:|
| Clean | 89% | 72.60 ms | 212.77 | 0 | 103.92 | 100% |
| Loss and duplication | 80% | 72.89 ms | 207.68 | 0 | 96.92 | 100% |
| Fresh-branch attack, open | 32% | 55.13 ms | 1,440.33 | 1,389.94 | 1,140.38 | 100% |
| Fresh-branch attack, bucket | 76% | 66.93 ms | 1,176.56 | 1,037.09 | 904.67 | 100% |

The loss-and-duplication scenario generated a mean 3.72 lost transmissions and 10.14 exact replay drops per run. It produced an 80 percent successful final READY rate, nine percentage points below clean transport. Failed setup was divided between absence of a candidate and route-setup timeout.

The open fresh-branch attack dominated traffic, drove mean peak branch state above 1,100 entries, and reduced success to 32 percent. The one-token bucket increased success to 76 percent, reduced attack transmissions by 25.4 percent, reduced attack branch allocations by 24.8 percent, and reduced mean peak branch state by 20.7 percent. It did not restore clean behavior.

All scenarios reached zero final branch, responder-offer, initiator-candidate, tentative, pending, and active state in every run. This validates bounded cleanup under the simulated deadlines; it does not validate a production implementation.

## Targeted race tests

Unit tests additionally establish:

- a candidate arriving exactly at a window deadline is eligible;
- a delayed candidate from the preceding ring can be selected in a later window;
- cancellation can overtake a delayed candidate;
- expired tentative state causes COMMIT failure;
- a stale tentative-expiry event cannot shorten an extended `PENDING_READY` deadline;
- cancellation of a divergent subtree is transmitted only across the adjacent parent edge;
- lost READY produces setup timeout and deterministic cleanup;
- exact link duplicates do not allocate additional branch contexts;
- expired responder offers and initiator candidate records are reclaimed;
- transmission budget remains a hard limit under attack.

## Decision

Accept Core v0.4 and E1 as the active lifecycle design. Treat ready-gated activation, half-open deadlines, deterministic equal-time precedence, and final cleanup reporting as normative.

Accept per-ingress-peer token buckets as one admission layer, not as a complete denial-of-service solution. The next resource iteration must test distributed attackers, adaptive bucket policies, responder/candidate spam, and fairness to legitimate branches.

## Next question

Can a concrete URE and reply-key construction satisfy the U1 transcript under active manipulation, and can canonical vectors be produced without adding a stable proof or suite fingerprint?
