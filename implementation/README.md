# Overlay implementation

Core v0.7, C1, M1, and W2 provide enough precision to begin independent codec and conformance work, but not enough assurance for a production network implementation.

The first implementation should:

- run in user space over an existing authenticated transport;
- keep logical discoveries and ring policy strictly local;
- expose only peer-bound branch contexts on the wire;
- replace branch, candidate, route, and W2 local-message capabilities at every hop;
- implement C1 only behind an explicit research-profile switch;
- use canonical `ristretto255`, Ed25519, HKDF-SHA-256, and ChaCha20-Poly1305 library operations;
- generate M1 and W2 codecs from reviewed schemas rather than handwritten parsing;
- encode each control operation as one canonical variable-length M1 message;
- fragment M1 messages into fixed 1,052-byte W2 cells with a 992-byte payload capacity;
- bound concurrent reassemblies, aggregate reserved bytes, fragment count, and timeout before any route-semantic allocation;
- keep protocol state separate from transport and reassembly sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for cell loss, delay, duplication, reordering, corruption, and disconnect;
- enforce peer, link, branch, time-window, queue, logical-byte, cell, cryptographic-work, and global budgets;
- normalize all C1 cryptographic failures to one state-machine result;
- keep the active ratio-tag fault injection disabled outside research tests;
- emit replayable structured traces without logging secret route mappings.

Before network I/O, the project should implement a second independent M1/W2 codec, cross-check the C1 vectors, fuzz canonical and malformed messages/cells, and verify reassembly cleanup under adversarial fragment streams. The first prototype MUST NOT claim active-adversary unlinkability or production U1 security while the ratio-tag counterexample remains unresolved.

No implementation language has been selected. Selection should follow memory safety, constant-time library support, generated-codec support, fuzzing quality, bounded-allocation control, and fault-injection needs.
