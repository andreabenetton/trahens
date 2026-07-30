# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per accepted context and discovery policy | Active |
| M3 Unlinkability restoration | Remove stable cross-hop handles | Core v0.3, U1, branch-local model, ADR-0008..0010 | claim is scoped; mechanism and costs are explicit | Structural design complete |
| M4 Event lifecycle | Model time and complete route setup | Core v0.4, E1, candidate windows, COMMIT/READY, expiry, attacks | races and cleanup have deterministic bounded outcomes | Complete model |
| M5 Cryptographic profile | Make transformations concrete | URE and reply-KEM suites, transcript proof, test vectors | independent cryptographic review passes | Next; blocked on primitive selection |
| M6 Overlay prototype | Prove interoperability | binary codec, node, conformance tests | routes survive loss, duplication, reordering, and churn | Planned |
| M7 Traffic privacy | Measure metadata resistance | mixing and scheduling profiles, correlation tests | claims are profile-specific and evidenced | Planned |
| M8 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core properties | Deferred |

## Current milestone

M4 defines half-open deadlines, equal-time event precedence, candidate windows, delayed candidate acceptance across rings, cancellation races, tentative return state, pending-ready reservation, reverse activation, loss, exact duplication, and deterministic cleanup.

The event model shows that clean setup succeeds in 89% of the tracked topology runs and that 2% loss with 5% exact duplication reduces success to 80%. A concentrated fresh-token attack remains severe. Per-ingress-peer token buckets improve availability but do not constitute distributed-denial or Sybil resistance. M2 therefore remains active.

## Next increment

Proceed to the cryptographic profile while continuing resource analysis:

1. select candidate URE and tweakable reply-KEM constructions;
2. define canonical encodings, transcript domain separation, and error behavior;
3. create deterministic test vectors;
4. build active-tagging and unchanged-field negative tests;
5. evaluate distributed fresh-branch attacks and adaptive bucket fairness;
6. keep network implementation blocked until the cryptographic gate passes.
