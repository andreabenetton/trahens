# Overlay implementation

Network implementation is deferred until the first cryptographic profile is stable enough for interoperability testing. Core v0.4 already provides the deterministic event-lifecycle baseline.

The initial implementation should:

- run in user space over an existing authenticated transport;
- keep logical discoveries and ring policy strictly local;
- expose only peer-bound branch contexts on the wire;
- replace branch, candidate, and route capabilities at every hop;
- blind reply keys and rerandomize eligibility capsules through reviewed primitives;
- use a canonical generated codec rather than handwritten field parsing;
- keep protocol state separate from transport sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for loss, delay, duplication, reordering, and peer disconnect;
- enforce peer, link, branch, time-window, queue, and global budgets;
- reject malformed and over-budget records before expensive cryptography;
- emit structured traces that can be replayed in the simulator;
- expose aggregate resource metrics without logging secret route mappings.

The first prototype MUST NOT implement the legacy Beacon/Authority directory. It MUST NOT claim U1 conformance until the URE and reply-key suites, fixed record classes, mixing behavior, test vectors, and conformance tests are complete.

No implementation language has been selected. Selection should follow the conformance harness, memory-safety requirements, constant-time cryptographic library support, and fault-injection needs rather than precede protocol decisions.
