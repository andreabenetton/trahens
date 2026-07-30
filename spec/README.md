# Specifications

## Active research draft

- [`core-v0.7.md`](core-v0.7.md) - bounded branch-local discovery, M1/W2 framing, concrete cryptography, and ready-gated route establishment.
- [`message-codec-m1.md`](message-codec-m1.md) - canonical variable-length logical-message encoding without semantic padding.
- [`wire-cell-w2.md`](wire-cell-w2.md) - exact 1,052-byte encrypted adjacent-link cells, fragmentation, and bounded reassembly.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - executable persistent-ratio-tag counterexample and claim boundary.
- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable classical cryptographic research profile.
- [`crypto-transcript-v0.2.md`](crypto-transcript-v0.2.md) - ordered CANDIDATE, COMMIT, READY, KDF, and AAD domains.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) - deterministic C1 conformance vectors.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - conditional passive non-adjacent message-unlinkability profile.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event time, windows, races, activation, expiry, and admission.
- [`messages-v0.7.md`](messages-v0.7.md) - logical message roles and their M1/W2 representation.
- [`state-machines-v0.7.md`](state-machines-v0.7.md) - initiator, relay, responder, W2 reassembly, receive-pipeline, and scheduler behavior.
- [`invariants-v0.7.md`](invariants-v0.7.md) - routing, timing, privacy, message, cell, resource, and cryptographic invariants.
- [`resource-accounting-v0.7.md`](resource-accounting-v0.7.md) - cumulative, concurrent, logical-byte, cell, reassembly, and cryptographic-work limits.

Core v0.7 combines U1, E1, C1, M1, and W2. Variable logical messages remove the former single-record route-depth ceiling, while fixed-size cells preserve per-cell length equality. Fragment count and cell timing remain observable unless a separate scheduler profile hides them. Active-adversary message unlinkability is not claimed because the tracked ratio-tag experiment is distinguishable.

## Historical drafts

Earlier versioned specifications, including W1, are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.
