# Baseline assessment

## Summary

The legacy draft contains a credible research direction but not yet an implementable protocol specification. Its strongest idea is the creation of hop-local routing state during bounded discovery so that no relay needs the complete path or global topology. Its weakest areas are the delegated underlay assumptions, incomplete long-range resolution, underspecified cryptography, and missing resource-abuse controls.

## Preserve

- Privacy is a control-plane property, not an optional data-plane add-on.
- Route labels are short-lived and meaningful only at a local forwarding context.
- Discovery may return multiple candidate routes.
- Intermediate route state is distributed rather than carried as a complete source route.
- Control traffic needs batching, padding, and explicit traffic-analysis evaluation.
- Stable directory functions should be separated from rapidly changing local topology.

## Redesign

| Area | Baseline problem | Direction |
|---|---|---|
| Scope | Attempts to cover a new layer 2 extension, layer 3 routing, anonymity, and a global directory at once | Define a small overlay discovery core first |
| Threat model | Calls the adversary global while assuming honest edges cannot be observed | Split adversaries by observation and compromise capability |
| Cryptography | Uses generic encryption notation and BIP32-like non-hardened derivation | Use composable standard primitives and explicit transcripts |
| Flooding | No complete duplicate suppression, admission control, or resource budget | Add bounded state, per-neighbor quotas, replay caches, and amplification limits |
| Wire format | Several messages and facility operations are not encoded | Define canonical encoding and validation rules before code |
| Directory | Beacon and authority lifecycle is incomplete | Defer the directory layer until local discovery is measurable |
| Claims | Unlinkability statements are stronger than the analysis | Convert each claim into an experiment, proof obligation, or hypothesis |
| Routing model | Unweighted, undirected graph only | Keep this for Core v0.3 simulation, then add weighted, asymmetric, and policy-aware topologies |

## Primary risks

1. **Traffic-analysis resistance dominates cost.** Link encryption is insufficient; timing and volume remain observable unless the deployment profile pays for shaping and cover traffic.
2. **Flood amplification can become the primary denial-of-service vector.** Privacy-related degree obfuscation can increase this cost further.
3. **Directory privacy is not solved by repeated hashing.** Deterministic address-derived lookups remain correlatable and enumerable.
4. **Stateful relays create exhaustion and recovery problems.** State lifetime, quotas, and repair must be first-class protocol elements.
5. **The original paper and the protocol specification are mixed together.** Normative behavior must move into versioned specification documents.

## Initial recommendation

Develop Trahens as an experimental privacy-preserving route-discovery overlay. The first implementation should discover and establish bounded routes among controlled nodes over an existing authenticated transport. The global beacon/authority design should remain outside the core until the local mechanism is specified, simulated, and attacked.
