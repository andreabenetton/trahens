# Overlay implementation

Core v1.2 provides enough precision to begin independent codec, recovery, scheduler, and conformance work. It does not provide enough assurance for production deployment.

The first implementation should:

- run in user space over an existing authenticated adjacent-link transport;
- implement active U1, E1, R1, M2, W2, T1, and T2 profiles as separate modules;
- keep logical discoveries, expanding-ring policy, recovery identifiers, and schedule negotiations strictly local;
- replace branch, candidate, route, message, transmission, and negotiation capabilities at every relay boundary;
- use canonical M2 encoding and W2 fragmentation rather than handwritten ad hoc layouts;
- emit exact 1,052-byte encrypted DATA, ACK, SCHEDULE, and CHAFF records;
- bound reassembly contexts, aggregate logical bytes, sender state, completion caches, ACKs, retries, RTO timers, queues, deficits, negotiations, rate transitions, and CHAFF;
- reserve a complete first-send fragment set before admitting a new transmission;
- implement T2 fixed, adaptive, and work-conserving modes behind explicit configuration;
- enforce one-class boundary transitions, matched OFFER/ACCEPT state, peer maximums, hold time, hysteresis, and fail-closed overload;
- expose deterministic clocks and randomness in tests;
- support fault injection for cell loss, burst loss, delay, duplication, reordering, corruption, ACK suppression, negotiation loss, congestion, and disconnect;
- normalize externally visible cryptographic, codec, reassembly, route, capability, recovery, and negotiation failures;
- emit replayable structured traces without logging secret route mappings, raw capabilities, or private descriptors;
- keep C1, symbolic C2, and C2-k2 providers disabled outside research tests.

Before network deployment, the project should implement a second independent M2/W2/T1/T2 stack, exchange vectors, differential-fuzz canonical and malformed inputs, verify cleanup under adversarial streams, and compare scheduler output under identical workloads. The implementation MUST NOT claim adaptive activity hiding or global traffic-flow unlinkability.

No implementation language has been selected. Selection should prioritize memory safety, constant-time library support, generated-codec support, fuzzing quality, bounded-allocation control, deterministic simulation hooks, and observability sufficient to verify queue and schedule invariants without exposing secrets.

## Independent review gates

- cryptographic review of the additive reply-key chain, custom KEM, nested candidate transcript, and failure timing;
- concurrency review of atomic capability redemption and queue reservation;
- transport review of selective ACK, RTO, retry exhaustion, and replay handling;
- scheduler review of weighted DRR, control reserves, negotiation races, and fixed-profile breaks;
- traffic-analysis evaluation with realistic multi-link traces;
- operational review of directory, gateway, relay admission, abuse, and logging policy.
