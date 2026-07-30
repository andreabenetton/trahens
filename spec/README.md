# Specifications

## Active research draft

- [`core-v0.5.md`](core-v0.5.md) - bounded branch-local discovery and ready-gated route establishment.
- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable classical cryptographic research profile.
- [`crypto-transcript-v0.2.md`](crypto-transcript-v0.2.md) - ordered CANDIDATE, COMMIT, READY, KDF, and AAD domains.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) - deterministic conformance vectors.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - conditional non-adjacent message-unlinkability claim.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event time, windows, races, activation, expiry, and admission.
- [`messages-v0.5.md`](messages-v0.5.md) - abstract outer messages with concrete C1 cryptographic fields.
- [`state-machines-v0.5.md`](state-machines-v0.5.md) - initiator, relay, responder, token-bucket, and scheduler behavior.
- [`invariants-v0.5.md`](invariants-v0.5.md) - routing, timing, privacy, resource, and C1 invariants.
- [`resource-accounting-v0.5.md`](resource-accounting-v0.5.md) - cumulative and concurrent limits and abuse accounting.

Core v0.5 combines the U1 privacy structure, E1 deterministic lifecycle, and C1 concrete research cryptography. C1 closes the interoperability ambiguity of generic primitives but does not close the production-security gate. Batch-local unlinkability remains conditional on the selected URE assumptions and a conforming mixing boundary; traffic-flow unlinkability and active-tagging resistance are not claimed.

## Historical drafts

Core v0.1 through v0.4 and their supporting documents are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.

The active documents still do not freeze the complete outer binary codec or a production-approved cryptographic suite.
