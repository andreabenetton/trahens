# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per accepted context and discovery policy | Active |
| M3 Unlinkability restoration | Remove stable cross-hop handles | Core v0.3, U1, branch-local model, ADR-0008..0010 | claim is scoped; mechanism and costs are explicit | Structural design complete |
| M4 Cryptographic profile | Make transformations concrete | URE and reply-KEM suites, transcript proof, test vectors | independent cryptographic review passes | Blocked on primitive selection |
| M5 Event simulation | Model time and complete route setup | candidate windows, delayed return, COMMIT/READY, expiry, attacks | failure and race behavior is deterministic | Next |
| M6 Overlay prototype | Prove interoperability | binary codec, node, conformance tests | routes survive loss, duplication, reordering, and churn | Planned |
| M7 Traffic privacy | Measure metadata resistance | mixing and scheduling profiles, correlation tests | claims are profile-specific and evidenced | Planned |
| M8 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core properties | Deferred |

## Current milestone

M3 has restored the *protocol structure* needed for non-adjacent message unlinkability: no attempt-wide wire identifier, per-branch capability replacement, reply-key blinding, eligibility-capsule rerandomization, fixed record classes, and a mixing requirement. The U1 claim is deliberately conditional. It does not cover global timing correlation or active tagging, and it cannot become a production guarantee until the URE and tweakable reply-KEM constructions are selected and reviewed.

M2 remains active because branch-local discovery sacrifices global duplicate suppression. The tracked comparison shows modest overhead at conservative parameters and severe amplification at high hop/fan-out settings.

## Next increment

Proceed with the previously planned event-driven model:

1. explicit event time and candidate windows;
2. delayed candidates from earlier rings and cancellation races;
3. candidate reverse propagation and tentative relay state;
4. COMMIT and READY propagation;
5. expiry and deterministic cleanup;
6. malicious fresh-branch floods and relay-local token buckets.

Cryptographic primitive selection and proof work continue in parallel, but network implementation remains blocked until M4 passes its gate.
