# Specifications

## Active research draft

- [`core-v1.1.md`](core-v1.1.md) - bounded gateway discovery, R1 redemption, M2/W2 framing, T1 recovery/scheduling, and READY-gated route establishment.
- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md) - capability issuance, non-semantic discovery nonce, gateway candidate filtering, and atomic post-READY redemption.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) - provider boundary and source-independent requirements for future endpoint-specific suites.
- [`message-codec-m2.md`](message-codec-m2.md) - suite-agile canonical variable-length logical messages.
- [`wire-cell-w2.md`](wire-cell-w2.md) - canonical 992-byte fragmentation and the 1,052-byte authenticated adjacent-link record.
- [`transport-profile-t1.md`](transport-profile-t1.md) - encrypted DATA/ACK/CHAFF frames, cumulative selective acknowledgements, bounded recovery, fresh retry ciphertexts, interleaving, and fixed-schedule release.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - branch-local structural unlinkability and scheduling dependency.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event ordering, candidate windows, races, activation, expiry, and admission.
- [`messages-v1.1.md`](messages-v1.1.md) - routed message roles and adjacent-link T1 frame semantics.
- [`state-machines-v1.1.md`](state-machines-v1.1.md) - route, T1 sender, receiver, ACK, timeout, and scheduler state machines.
- [`invariants-v1.1.md`](invariants-v1.1.md) - route, privacy, encoding, reliability, scheduling, resource, and failure invariants.
- [`resource-accounting-v1.1.md`](resource-accounting-v1.1.md) - cumulative and concurrent limits for route state, recovery, ACKs, timers, queues, and CHAFF.

Core v1.1 combines U1, E1, R1, M2, W2, and T1. Endpoint-specific capability material remains absent from forward discovery. T1 identifiers are adjacent-link-local and replaced at every relay. A retransmission uses the same local identifier and fragment index only where required for repair, while the public sequence, padding, authentication tag, and ciphertext are fresh.

Fixed-schedule mode emits one 1,052-byte record per directed slot and fills idle slots with CHAFF. The resulting claim is deliberately narrow: inside a pre-existing non-overflowing epoch, a passive observer of one direction sees the same slot timestamps and record lengths for active and empty traffic. The schedule's existence, rate, start, end, topology, congestion behavior, and global cross-link correlations remain observable.

## Research-only cryptographic profiles

- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable negative-control eligibility plus retained reply/signature components.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - persistent C1 ratio-tag counterexample.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) - receiver-anonymous rerandomizable RCCA target and ideal functionality.
- [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) - C2 confidentiality, receiver-anonymity, rerandomization, RCCA, tagging, and composition games.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) - exact k=2 transcription and fail-closed finite-field audit.
- [`r1-test-vectors.json`](r1-test-vectors.json) - deterministic active-profile capability and nonce vectors.
- [`t1-test-vectors.json`](t1-test-vectors.json) - deterministic DATA, retry, selective-ACK, CHAFF, fixed-length, and fresh-ciphertext vectors.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) and [`crypto-test-vectors-c2-symbolic.json`](crypto-test-vectors-c2-symbolic.json) - deterministic research-control vectors.

Suites `0x0001` and `0x0002` are research controls. Reserved suite `0x7f02` MUST be rejected by network decoders. None is an active endpoint-discovery mechanism.

## Superseded drafts

Earlier versioned specifications are retained for traceability. They are not the active implementation target.
