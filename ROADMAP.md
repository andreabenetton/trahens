# Roadmap

| Milestone | Purpose | Main artifacts | Gate |
|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per input, peer, and logical discovery |
| M3 Crypto profile | Make authentication and confidentiality concrete | transcript spec, suites, test vectors | independent cryptographic review passes |
| M4 Simulation | Compare design choices quantitatively | deterministic simulator, experiments, reports | target discovery and resource metrics are met |
| M5 Overlay prototype | Prove interoperability | binary codec, node, conformance tests | routes survive loss, duplication, reordering, and churn |
| M6 Privacy profiles | Measure metadata resistance | shaping profiles and correlation tests | claims are profile-specific and evidenced |
| M7 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core privacy properties |

## Current milestone

M2 is active. Core v0.2 defines expanding-ring discovery, fresh per-attempt identifiers, cumulative logical-discovery budgets, and relay-local resource-accounting requirements. The simulator now compares fixed and expanding policies and measures cross-attempt relay overlap.

The next increment adds event time, candidate windows, delayed candidates, packet loss, and adversarial work generation. Cryptographic choices remain deliberately unfrozen until message transcripts and state transitions are stable.
