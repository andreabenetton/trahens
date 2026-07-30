# Specifications

## Active research draft

- [`core-v0.9.md`](core-v0.9.md) - bounded branch-local discovery, C2 eligibility contract, M2/W2 framing, and READY-gated route establishment.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) - selected anonymous rerandomizable RCCA target, symbolic ideal functionality, and concrete acceptance gate.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) - exact k=2 Figure 6 transcription, 412-byte canonical audit encoding, and fail-closed interoperability result.
- [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) - C2 confidentiality, receiver-anonymity, rerandomization, RCCA, tagging, and composition games.
- [`message-codec-m2.md`](message-codec-m2.md) - suite-agile canonical variable-length logical messages and length-delimited eligibility capsules.
- [`wire-cell-w2.md`](wire-cell-w2.md) - exact 1,052-byte encrypted adjacent-link cells, fragmentation, and bounded reassembly.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - executable C1 persistent-ratio-tag counterexample retained as a negative control.
- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable classical profile retained for reply/signature components and negative-control eligibility tests.
- [`crypto-transcript-v0.2.md`](crypto-transcript-v0.2.md) - ordered CANDIDATE, COMMIT, READY, KDF, and AAD domains.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) - deterministic C1 conformance vectors.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - branch-local passive unlinkability profile and active-security dependency.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event time, windows, races, activation, expiry, and admission.
- [`messages-v0.9.md`](messages-v0.9.md) - logical message roles and M2/W2 representation.
- [`state-machines-v0.9.md`](state-machines-v0.9.md) - initiator, relay, responder, W2 reassembly, receive-pipeline, and scheduler behavior.
- [`invariants-v0.9.md`](invariants-v0.9.md) - routing, timing, privacy, message, cell, resource, suite, and cryptographic invariants.
- [`resource-accounting-v0.9.md`](resource-accounting-v0.9.md) - cumulative, concurrent, logical-byte, cell, reassembly, and cryptographic-work limits.

Core v0.9 combines U1, E1, C2, M2, and W2. C2 selects the anonymous rerandomizable RCCA security contract required to prevent the C1 persistent ratio tag. The repository integrates this contract through a symbolic ideal functionality and separately transcribes the selected CRYPTO 2021 k=2 construction for equation and byte-level audit [Wang2021](../docs/citation-audit.md#wang2021). The source's literal finite-field map `u -> u mod q` is not a multiplicative homomorphism under ordinary `QR*_p` multiplication, so full rerandomization is fail-closed and no concrete active-adversary unlinkability claim is made.

M2 makes the logical envelope suite-agile and length-delimits the eligibility capsule. W2 continues to provide fixed-size cells and now binds one suite identifier across all fragments in a reassembly context. Fragment count and cell timing remain observable unless a separate scheduling profile hides them.

## Historical drafts

Earlier versioned specifications, including C1-only M1 and W1, are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.
