# Overlay implementation

Core v0.5 and C1 now provide enough precision to begin codec and conformance work, but not enough assurance for a production network implementation.

The first implementation should:

- run in user space over an existing authenticated transport;
- keep logical discoveries and ring policy strictly local;
- expose only peer-bound branch contexts on the wire;
- replace branch, candidate, and route capabilities at every hop;
- implement C1 only behind an explicit research-profile switch;
- use canonical `ristretto255`, Ed25519, HKDF-SHA-256, and ChaCha20-Poly1305 library operations;
- generate the outer codec from a reviewed schema rather than handwritten parsing;
- use constant-size record classes for each declared privacy profile;
- keep protocol state separate from transport sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for loss, delay, duplication, reordering, corruption, and disconnect;
- enforce peer, link, branch, time-window, queue, cryptographic-work, and global budgets;
- normalize all C1 cryptographic failures to one state-machine result;
- emit replayable structured traces without logging secret route mappings.

Before network I/O, the project should implement two independent codecs, cross-check the C1 vectors, and build a malformed-input corpus. The first prototype MUST NOT implement the legacy Beacon/Authority directory and MUST NOT claim production U1 security.

No implementation language has been selected. Selection should follow memory-safety, constant-time library support, generated-codec support, fuzzing quality, and fault-injection needs.
