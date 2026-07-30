# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per accepted context and discovery policy | Active |
| M3 Unlinkability restoration | Remove stable cross-hop handles | Core v0.3, U1, branch-local model | claim is scoped; mechanism and costs are explicit | Structural design complete |
| M4 Event lifecycle | Model time and complete route setup | Core v0.4, E1, COMMIT/READY, expiry, attacks | races and cleanup have deterministic bounded outcomes | Complete model |
| M5 Cryptographic profile | Make transformations executable | Core v0.5, C1, transcripts, vectors, reference code | independent cryptographic review passes | Concrete research profile complete; review open |
| M6 Integrated wire baseline | Exercise cryptography and lifecycle through an exact codec | W1, integrated C1/E1 model, tagging analysis | exact records and failure paths are executable | Complete historical baseline |
| M7 Message/cell separation | Remove the single-record depth ceiling while retaining equal cell length | M1, W2, bounded reassembly, fragmentation experiments | canonical messages and cells are independently testable and resource bounded | Complete research baseline |
| M8 Overlay prototype | Prove interoperability | independent codec, node, conformance tests | independent nodes survive loss, duplication, reordering, fragmentation, and churn | Next engineering milestone |
| M9 Traffic privacy | Measure metadata resistance | mixing and scheduling profiles, correlation tests | claims are profile-specific and evidenced | Planned |
| M10 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core properties | Deferred |

## Current milestone

M7 separates message semantics from observable framing. M1 uses canonical variable-length logical messages without semantic padding. W2 carries those messages in one or more fixed 1,052-byte adjacent-link cells with 992 bytes of fragment payload. Reassembly is bounded by message length, fragment count, concurrent contexts, aggregate reserved bytes, and timeout, and no route state is created before complete canonical M1 decoding.

The integrated model shows that a six-layer candidate fits one cell, a seven-layer candidate requires two, and a sixteen-layer candidate requires three. The former hard one-record depth ceiling is removed, at the cost of observable fragment count and greater exposure to cell loss. The active-security result remains negative: the C1 URE consistency pair admits a persistent ratio tag.

## Next increment

Proceed in four coordinated tracks:

1. **Eligibility redesign** - replace or modify the C1 eligibility mechanism so compromised relays cannot install a persistent recognizable relation or selective-failure tag.
2. **Independent codec track** - specify M1/W2 in a schema suitable for two independent implementations, fuzz both, and cross-check every canonical and malformed input.
3. **Scheduling track** - define interleaving, padding of fragment counts, release cadence, and reassembly-aware fairness; quantify the latency and bandwidth cost.
4. **Prototype track** - connect independent nodes over an authenticated transport only after the codec and active-security replacement have reviewable evidence.

Resource work remains active: model fragment sprays, distributed fresh-branch attackers, candidate spam, adaptive peer rotation, bounded retransmission, and admission fairness.
