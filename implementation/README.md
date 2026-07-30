# Overlay implementation

Core v0.6, C1, and W1 provide enough precision to begin independent codec and conformance work, but not enough assurance for a production network implementation.

The first implementation should:

- run in user space over an existing authenticated transport;
- keep logical discoveries and ring policy strictly local;
- expose only peer-bound branch contexts on the wire;
- replace branch, candidate, and route capabilities at every hop;
- implement C1 only behind an explicit research-profile switch;
- use canonical `ristretto255`, Ed25519, HKDF-SHA-256, and ChaCha20-Poly1305 library operations;
- generate the outer codec from a reviewed schema rather than handwritten parsing;
- encode every control message in the exact 1,052-byte W1 record;
- keep protocol state separate from transport sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for loss, delay, duplication, reordering, corruption, and disconnect;
- enforce peer, link, branch, time-window, queue, cryptographic-work, and global budgets;
- normalize all C1 cryptographic failures to one state-machine result;
- keep the active ratio-tag fault injection disabled outside research tests;
- emit replayable structured traces without logging secret route mappings.

Before network I/O, the project should implement a second independent W1 codec, cross-check the C1 vectors, and build a malformed-input corpus. The first prototype MUST NOT claim active-adversary unlinkability or production U1 security while the ratio-tag counterexample remains unresolved.

No implementation language has been selected. Selection should follow memory-safety, constant-time library support, generated-codec support, fuzzing quality, and fault-injection needs.
