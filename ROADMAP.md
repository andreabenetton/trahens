# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per accepted context and discovery policy | Active |
| M3 Unlinkability restoration | Remove stable cross-hop handles | Core v0.3, U1, branch-local model | claim is scoped; mechanism and costs are explicit | Structural design complete |
| M4 Event lifecycle | Model time and complete route setup | Core v0.4, E1, COMMIT/READY, expiry, attacks | races and cleanup have deterministic bounded outcomes | Complete model |
| M5 Cryptographic profile | Make transformations executable | Core v0.5, C1, transcripts, vectors, reference code | independent cryptographic review passes | Concrete research profile complete; review open |
| M6 Wire integration | Freeze and exercise the codec with the lifecycle | W1 codec, integrated C1/E1 model, tagging analysis | exact records and failure paths are executable | Complete research baseline; active-security gate closed |
| M7 Overlay prototype | Prove interoperability | independent codec, node, conformance tests | independent nodes survive loss, duplication, reordering, and churn | Next engineering milestone |
| M8 Traffic privacy | Measure metadata resistance | mixing and scheduling profiles, correlation tests | claims are profile-specific and evidenced | Planned |
| M9 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core properties | Deferred |

## Current milestone

M6 fixes the W1 record at 1,052 bytes, executes W1 and C1 inside the E1 lifecycle, and adds adjacent-link tampering and compromised-relay tagging experiments. The codec and integrated state transitions are executable.

The active-security result is negative and therefore useful: the C1 URE consistency pair admits a persistent ratio tag. A colluding downstream relay can detect the relation after honest rerandomization, and the endpoint rejects the altered capsule. Active-adversary message unlinkability remains blocked.

## Next increment

Proceed in three coordinated tracks:

1. **Eligibility redesign** - replace or modify the C1 eligibility mechanism so that compromised relays cannot install a persistent recognizable relation or selective-failure tag.
2. **Independent codec track** - specify W1 in a schema language, implement a second parser/encoder, fuzz both implementations, and cross-check every canonical and malformed input.
3. **Prototype track** - connect independent nodes over an authenticated transport only after the codec and active-security replacement have reviewable evidence.

Resource and traffic-privacy work remains active: model distributed fresh-branch attackers, candidate spam, adaptive peer rotation, batching, release delay, and admission fairness.
