<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v0.3 invariants

The simulator, conformance tests, and implementations must check these invariants.

## Routing

1. **Local-label scope**: a route label is accepted only from its bound adjacent peer and direction.
2. **No complete route object**: no relay state contains the full ordered path.
3. **Tentative isolation**: application data never traverses tentative state.
4. **Commit consistency**: active forward and reverse mappings refer to the same protected transcript and route generation.
5. **Idempotent setup**: exact duplicate CANDIDATE, COMMIT, READY, ABORT, or CLOSE messages do not allocate additional route state.

## Unlinkability structure

6. **No wire discovery ID**: logical discovery and local attempt identifiers never appear on the wire.
7. **Fresh branch token**: every outgoing branch uses a new unpredictable token.
8. **Token locality**: an ingress branch or candidate token is never copied to an outgoing link.
9. **Independent root keys**: first-hop branches do not share a reply public key.
10. **Reply-key transformation**: every relay blinds the reply key independently for every child.
11. **Eligibility rerandomization**: every relay rerandomizes the eligibility capsule for every child.
12. **Fresh link ciphertext**: every transmission uses a fresh adjacent-link nonce and ciphertext.
13. **Canonical reconstruction**: a relay constructs a fresh canonical body rather than forwarding received bytes.
14. **Fixed observable class**: conforming U1 records have the configured fixed length for their observable class.
15. **No hidden stable field**: no unchanged variable field can cross a U1 transformation boundary unless its primitive proves rerandomization unlinkability.
16. **Batch permutation**: batch-local unlinkability is claimed only when an honest relay permutes at least two indistinguishable records.

## Branch lifecycle

17. **Branch-local replay**: exact replay suppression is scoped to link epoch, peer, and local token.
18. **No cross-branch deduplication**: a distinct token arriving over another branch is accounted as a distinct context.
19. **Immediate-backtrack exclusion**: a relay does not forward DISCOVER to its ingress peer.
20. **Finite branch lifetime**: every branch and child mapping has a finite local expiration.
21. **No resurrection**: delayed input cannot recreate expired branch or route state.

## Resource safety

22. **Mandatory hard budgets**: U1 discovery cannot run without finite transmission and branch-state limits.
23. **Bounded fan-out**: one accepted branch creates at most the configured child records.
24. **Per-node context cap**: one physical node enforces a finite number of simultaneous branch contexts.
25. **Bounded candidate responses**: candidate work is capped per child, branch, peer, and node.
26. **Budget-before-crypto**: resource checks occur before URE, KEM, credential, or signature work whenever possible.
27. **No error amplification**: an error response is bounded by a configured constant relative to the input.
28. **Pressure priority**: chaff and uncommitted state are evicted before active admitted routes unless safety policy requires otherwise.

## Authentication and cryptography

29. **Transcript binding**: end-to-end authentication covers version, profile, suite, eligibility transcript, service offer, commit challenge, limits, and expiry.
30. **Domain separation**: cryptographic operations use distinct protocol, version, purpose, role, and direction contexts.
31. **Scalar validation**: reply-key blinding scalars and group points are canonically encoded and validated.
32. **Downgrade resistance**: profile or suite changes are end-to-end authenticated.
33. **Indistinguishable failure**: nested-capsule failures do not disclose the failing depth or primitive.

## Claim discipline

34. **Wire-image scope**: absence of stable fields supports only wire-image unlinkability.
35. **Batch-local scope**: non-adjacent message unlinkability is conditional on the complete U1 profile and its adversary model.
36. **No traffic claim**: U1 does not imply timing, volume, endpoint, or flow unlinkability.
37. **Active-adversary caveat**: active tagging resistance is not claimed before a concrete reviewed URE profile.
38. **Measured amplification**: experiments report branch contexts, unique relays, repeated contexts, loop re-entry, and budget exhaustion.
39. **Legacy claim refinement**: the legacy \(m_i\) to \(m_{i\pm k}\), \(k>2\), statement is treated as a conditional research claim rather than an unconditional guarantee.
