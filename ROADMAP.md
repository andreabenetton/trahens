# Roadmap

| Milestone | Purpose | Main artifacts | Gate |
|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated |
| M1 Core semantics | Make local discovery unambiguous | Core v0.1, messages, state machines, invariants | independent implementation is possible in principle |
| M2 Resource safety | Bound abuse and amplification | quotas, replay cache, simulator attack cases | work and state are bounded per input and peer |
| M3 Crypto profile | Make authentication and confidentiality concrete | transcript spec, suites, test vectors | independent cryptographic review passes |
| M4 Simulation | Compare design choices quantitatively | deterministic simulator, experiments, reports | target discovery and resource metrics are met |
| M5 Overlay prototype | Prove interoperability | binary codec, node, conformance tests | routes survive loss, duplication, reordering, and churn |
| M6 Privacy profiles | Measure metadata resistance | shaping profiles and correlation tests | claims are profile-specific and evidenced |
| M7 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core privacy properties |

## Current milestone

M1 is active. The repository contains a first scoped Core v0.1, a deterministic bounded-flood simulator, and an initial parameter sweep showing the coverage/amplification trade-off. Expanding-ring discovery is the next proposed simulation increment. Cryptographic choices are deliberately not frozen yet.
