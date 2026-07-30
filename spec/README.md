# Specifications

## Active research draft

- [`core-v0.6.md`](core-v0.6.md) - bounded branch-local discovery, fixed-size records, concrete cryptography, and ready-gated route establishment.
- [`wire-codec-w1.md`](wire-codec-w1.md) - exact 1,052-byte adjacent-link record and message layouts.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - executable persistent-ratio-tag counterexample and claim boundary.
- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable classical cryptographic research profile.
- [`crypto-transcript-v0.2.md`](crypto-transcript-v0.2.md) - ordered CANDIDATE, COMMIT, READY, KDF, and AAD domains.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) - deterministic C1 conformance vectors.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - conditional passive non-adjacent message-unlinkability profile.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event time, windows, races, activation, expiry, and admission.
- [`messages-v0.6.md`](messages-v0.6.md) - logical messages and exact W1 envelope.
- [`state-machines-v0.6.md`](state-machines-v0.6.md) - initiator, relay, responder, receive-pipeline, and scheduler behavior.
- [`invariants-v0.6.md`](invariants-v0.6.md) - routing, timing, privacy, wire, resource, and cryptographic invariants.
- [`resource-accounting-v0.6.md`](resource-accounting-v0.6.md) - cumulative, concurrent, wire-byte, and cryptographic-work limits.

Core v0.6 combines U1, E1, C1, and W1. The fixed-size codec and integrated event model close major interoperability gaps. They do not close the production-security gate. Passive batch-local unlinkability remains conditional on the declared assumptions and mixing boundary. Active-adversary message unlinkability is not claimed because the tracked ratio-tag experiment is distinguishable.

## Historical drafts

Earlier versioned specifications are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.
