# Roadmap

| Milestone | Purpose | Main artifacts | Gate | State |
|---|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | legacy paper, assessment, ADRs | current and legacy material are clearly separated | Complete |
| M1 Core semantics | Make local discovery unambiguous | Core v0.2, messages, state machines, invariants | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | quotas, cumulative budgets, attack simulations | work and state are bounded per accepted context and discovery policy | Active |
| M3 Unlinkability restoration | Remove stable cross-hop handles | Core v0.3, U1, branch-local model | claim is scoped; mechanism and costs are explicit | Structural design complete |
| M4 Event lifecycle | Model time and complete route setup | Core v0.4, E1, COMMIT/READY, expiry, attacks | races and cleanup have deterministic bounded outcomes | Complete model |
| M5 Cryptographic profile | Make transformations executable | Core v0.5, C1, transcripts, vectors, reference code | independent cryptographic review passes | Concrete research profile complete; review open |
| M6 Overlay prototype | Prove interoperability | binary codec, node, conformance tests | independent nodes survive loss, duplication, reordering, and churn | Next engineering milestone |
| M7 Traffic privacy | Measure metadata resistance | mixing and scheduling profiles, correlation tests | claims are profile-specific and evidenced | Planned |
| M8 Directory protocol | Add long-range resolution separately | registration and lookup protocol | resolution preserves stated Core properties | Deferred |

## Current milestone

M5 removes undefined generic cryptographic operations from the active design. C1 specifies canonical `ristretto255` encodings, a concrete GJJS-style eligibility capsule, mandatory non-identity rerandomization, an additive reply-key chain, `TR-KEM-R255`, HKDF-SHA-256, ChaCha20-Poly1305, Ed25519 candidate authentication, transcript field order, generic cryptographic failure, and deterministic vectors.

This is an interoperability and analysis milestone, not a production-security gate. The URE security definition, active-tagging behavior, custom reply KEM, depth-hiding codec, side channels, and post-quantum migration remain unresolved.

## Next increment

Proceed in two parallel tracks:

1. **Cryptographic review track** - align C1 with a precise URE security definition, construct active-tagging experiments, review related-key behavior of the reply KEM, expand malformed-input vectors, and obtain independent analysis.
2. **Prototype preparation track** - freeze constant-size message classes, generate a canonical binary codec, build a negative parser corpus, and implement two independent codecs before adding network I/O.

Resource work remains active: model distributed fresh-branch attackers, candidate spam, adaptive peer rotation, and fairness under admission control.
