# Specifications

## Active research draft

- [`core-v0.4.md`](core-v0.4.md) - branch-local discovery and ready-gated route establishment.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - conditional non-adjacent message unlinkability claim.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event time, candidate windows, races, COMMIT/READY, expiry, and fresh-branch admission.
- [`crypto-transcript-v0.1.md`](crypto-transcript-v0.1.md) - abstract URE and reply-key-blinding transcript.
- [`messages-v0.4.md`](messages-v0.4.md) - abstract messages, validation order, lifetimes, and CANCEL.
- [`state-machines-v0.4.md`](state-machines-v0.4.md) - initiator, relay, responder, token-bucket, and scheduler behavior.
- [`invariants-v0.4.md`](invariants-v0.4.md) - routing, time, race, privacy, and resource properties.
- [`resource-accounting-v0.4.md`](resource-accounting-v0.4.md) - cumulative and concurrent state, quotas, and abuse limits.

Core v0.4 retains the U1 structure and adds the deterministic E1 lifecycle. U1 remains conditional on a reviewed universally rerandomizable eligibility-encryption construction, a tweakable reply KEM, fixed-size records, and a conforming mixing boundary. E1 adds lifecycle correctness and bounded cleanup; it does not claim traffic-flow unlinkability.

## Historical drafts

Core v0.1, v0.2, and v0.3 and their supporting documents are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.

The active documents do not yet define a canonical binary encoding, production cryptographic suite, or complete active-adversary proof.
