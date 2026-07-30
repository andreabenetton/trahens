# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and historical material are separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, budgets, attack simulations | work and state are bounded | Active |
| M3 Structural unlinkability | Remove stable cross-hop handles | U1, branch-local transformations | claim scope and mechanism are explicit | Complete research design |
| M4 Event lifecycle | Complete route setup and cleanup | E1, COMMIT/READY, expiry | races have deterministic bounded outcomes | Complete model |
| M5 Concrete component baseline | Make reply and authentication operations executable | C1 components, transcripts, vectors | independent review of retained components | Research baseline; review open |
| M6 Message/cell separation | Preserve variable semantics and equal cells | M2, W2, bounded reassembly | canonical parsing and bounded reassembly | Complete research baseline |
| M7 Active eligibility contract | Replace taggable eligibility semantics | C2, security games, ideal functionality | protocol integration is executable and claim is honest | Complete symbolic baseline |
| M8 Concrete C2 implementation | Instantiate anonymous Rand-RCCA encryption | exact algorithms, encodings, vectors, game harness | ratio tag and mutation suite fail under reviewed construction | Next cryptographic milestone |
| M9 Reliability profile | Bound loss recovery for multi-cell messages | acknowledgements, retries, fresh encryption | delivery improves without stable cross-hop handles | Planned |
| M10 Overlay prototype | Prove interoperability | two codecs, nodes, conformance and fuzzing | independent nodes agree under faults and churn | Planned |
| M11 Traffic privacy | Measure metadata resistance | mixing, scheduling, cover profiles | every claim is profile-specific and measured | Planned |
| M12 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves Core properties | Deferred |

## Current milestone

Core v0.8 selects C2 as the active-security eligibility contract. The concrete target is receiver-anonymous rerandomizable RCCA encryption. M2 binds cryptographic suite selection in both the logical envelope and every encrypted W2 fragment. The simulator executes a C2 ideal functionality alongside the C1 ratio-tag negative control.

The symbolic result is deliberately narrow: it demonstrates that arbitrary mutation can be rejected by the first honest transformation, that no tagged output reaches a separated colluder, and that cleanup remains bounded. It does not provide a concrete security proof or implementation.

## Next increment

1. Choose the exact C2 construction parameters and algebraic setting.
2. Specify canonical encodings for keys, ciphertexts, proofs, scalars, and malformed inputs.
3. Implement `KeyGen`, `Enc`, `ReRand`, and `Dec` independently of the simulator.
4. Add deterministic positive and negative vectors.
5. Run C2-RA, C2-RCCA, C2-TAG, and composition tests, including the C1 ratio tag.
6. Obtain independent cryptographic review before any active-unlinkability claim.
7. Then define bounded reliability for fragmented W2 messages.
