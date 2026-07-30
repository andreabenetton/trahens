# Specifications

## Active research draft

- [`core-v1.0.md`](core-v1.0.md) - bounded branch-local gateway discovery, R1 redemption, M2/W2 framing, and READY-gated route establishment.
- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md) - capability issuance, non-semantic discovery nonce, gateway candidate filtering, and atomic post-READY redemption.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) - provider boundary and source-independent requirements for any future endpoint-specific suite.
- [`message-codec-m2.md`](message-codec-m2.md) - suite-agile canonical variable-length logical messages.
- [`wire-cell-w2.md`](wire-cell-w2.md) - exact 1,052-byte encrypted cells, canonical fragmentation, and bounded reassembly.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - branch-local structural unlinkability and scheduling dependency.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event ordering, candidate windows, races, activation, expiry, and admission.
- [`messages-v1.0.md`](messages-v1.0.md) - active message roles, including post-READY rendezvous opening.
- [`state-machines-v1.0.md`](state-machines-v1.0.md) - initiator, relay, gateway, reassembly, and redemption state machines.
- [`invariants-v1.0.md`](invariants-v1.0.md) - route, timing, privacy, capability, message, cell, resource, and failure invariants.
- [`resource-accounting-v1.0.md`](resource-accounting-v1.0.md) - cumulative and concurrent limits, including gateway registrations and failed redemptions.

Core v1.0 combines U1, E1, R1, M2, and W2. R1 removes endpoint-specific material from forward discovery. The active suite identifier is `0x0101`; the suite-specific DISCOVER field is an independent non-zero 32-byte service-query nonce replaced by every honest relay. The endpoint capability is sent only through an active route after READY and is consumed atomically at the selected gateway.

## Research-only cryptographic profiles

- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable negative-control eligibility plus retained reply/signature components.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - persistent C1 ratio-tag counterexample.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) - receiver-anonymous rerandomizable RCCA target and ideal functionality.
- [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) - C2 confidentiality, receiver-anonymity, rerandomization, RCCA, tagging, and composition games.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) - exact k=2 transcription and fail-closed finite-field audit.
- [`r1-test-vectors.json`](r1-test-vectors.json) - deterministic active-profile capability and nonce vectors.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) and [`crypto-test-vectors-c2-symbolic.json`](crypto-test-vectors-c2-symbolic.json) - deterministic research-control vectors.

Suites `0x0001` and `0x0002` are research controls. Reserved suite `0x7f02` MUST be rejected by network decoders. None is an active endpoint-discovery mechanism.

## Superseded drafts

Earlier versioned specifications are retained for traceability. They are not the active implementation target.
