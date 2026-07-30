# Specifications

## Active research draft

- [`core-v1.2.md`](core-v1.2.md) - bounded gateway discovery, R1 redemption, M2/W2 framing, T1 recovery, T2 congestion/scheduling, and READY-gated route establishment.
- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md) - capability issuance, non-semantic discovery nonce, gateway filtering, and atomic post-READY redemption.
- [`message-codec-m2.md`](message-codec-m2.md) - suite-agile canonical variable-length logical messages.
- [`wire-cell-w2.md`](wire-cell-w2.md) - canonical 992-byte fragmentation and 1,052-byte authenticated adjacent-link records.
- [`transport-profile-t1.md`](transport-profile-t1.md) - encrypted DATA/ACK/CHAFF frames, cumulative selective acknowledgements, bounded recovery, fresh retry ciphertexts, and interleaving.
- [`transport-profile-t2.md`](transport-profile-t2.md) - fixed and quantized-adaptive epochs, encrypted SCHEDULE control, hysteresis, weighted DRR, admission, overload, and privacy boundaries.
- [`unlinkability-profile-u1.md`](unlinkability-profile-u1.md) - branch-local structural unlinkability and scheduler dependency.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) - event ordering, candidate windows, races, activation, expiry, and admission.
- [`messages-v1.2.md`](messages-v1.2.md) - routed operation roles and T1/T2 adjacent-link frame semantics.
- [`state-machines-v1.2.md`](state-machines-v1.2.md) - route, recovery, ACK, timeout, queue, negotiation, and schedule state machines.
- [`invariants-v1.2.md`](invariants-v1.2.md) - route, privacy, encoding, recovery, scheduling, fairness, overload, and failure invariants.
- [`resource-accounting-v1.2.md`](resource-accounting-v1.2.md) - finite route, reassembly, recovery, queue, rate, schedule-control, and CHAFF budgets.

Core v1.2 combines U1, E1, R1, M2, W2, T1, and T2. Endpoint capability material remains absent from forward discovery. Recovery identifiers and schedule negotiations terminate at every adjacent relay. Each retry uses a fresh public sequence, padding, authentication tag, and ciphertext.

T2 fixed mode emits one 1,052-byte record per declared slot and fills idle slots with CHAFF. Adaptive mode changes among a finite public rate menu at epoch boundaries. Its rate-class sequence is observable and is not covered by the fixed-trace claim. Work-conserving mode is a no-chaff baseline.

## Research-only cryptographic profiles

- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) - source-independent provider boundary.
- [`crypto-profile-c1.md`](crypto-profile-c1.md) - executable negative-control eligibility plus retained reply/signature components.
- [`active-tagging-analysis.md`](active-tagging-analysis.md) - persistent C1 ratio-tag counterexample.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) - receiver-anonymous rerandomizable RCCA target and ideal functionality.
- [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) - C2 security games.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) - exact k=2 transcription and fail-closed finite-field audit.

## Deterministic vectors

- [`r1-test-vectors.json`](r1-test-vectors.json) - capability and nonce replacement.
- [`t1-test-vectors.json`](t1-test-vectors.json) - DATA, ACK, CHAFF, retry, and fixed-length framing.
- [`t2-test-vectors.json`](t2-test-vectors.json) - fixed-size encrypted schedule OFFER and ACCEPT frames.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) and [`crypto-test-vectors-c2-symbolic.json`](crypto-test-vectors-c2-symbolic.json) - research controls.

Suites `0x0001` and `0x0002` are research controls. Reserved suite `0x7f02` MUST be rejected by network decoders. Earlier versioned specifications are retained only for traceability.
