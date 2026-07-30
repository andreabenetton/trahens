# Specifications

## Active research draft

- [`core-v0.3.md`](core-v0.3.md) - branch-local discovery and route establishment.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - conditional non-adjacent message unlinkability claim.
- [`crypto-transcript-v0.1.md`](crypto-transcript-v0.1.md) - abstract URE and reply-key-blinding transcript.
- [`messages-v0.3.md`](messages-v0.3.md) - abstract message semantics and validation order.
- [`state-machines-v0.3.md`](state-machines-v0.3.md) - initiator, relay, and responder behavior.
- [`invariants-v0.3.md`](invariants-v0.3.md) - safety, privacy, and resource properties.
- [`resource-accounting-v0.3.md`](resource-accounting-v0.3.md) - admission, quota, and amplification limits.

Core v0.3 restores the structure needed for the legacy bit-pattern unlinkability objective, but the U1 property remains conditional on a reviewed universally rerandomizable eligibility-encryption construction, a tweakable reply KEM, fixed-size records, and a conforming mixing boundary.

## Historical drafts

Core v0.1 and Core v0.2 and their supporting documents are retained for design traceability. They are superseded and MUST NOT be treated as the active implementation target.

These documents do not yet define a canonical binary encoding, production cryptographic suite, or complete active-adversary proof.
