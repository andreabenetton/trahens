# Overlay implementation

Network implementation is deferred until Core v0.2 state machines, resource rules, event behavior, and the first cryptographic profile are stable enough to test interoperability.

The initial implementation should:

- run in user space over an existing authenticated transport;
- implement logical discoveries separately from wire attempts;
- generate a fresh unpredictable attempt ID and ephemeral context for every ring;
- use a canonical generated codec rather than handwritten field parsing;
- keep protocol state separate from transport sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for loss, delay, duplication, reordering, and peer disconnect;
- enforce peer, attempt, time-window, global, and logical-discovery budgets;
- reject malformed and over-budget messages before expensive cryptography;
- emit structured traces that can be replayed in the simulator;
- expose aggregate overlap and resource metrics without logging secret route mappings.

The first prototype MUST NOT implement the legacy Beacon/Authority directory or claim traffic-analysis resistance. No implementation language has been selected. Selection should follow the conformance harness, memory-safety requirements, and availability of reviewed cryptographic libraries rather than precede protocol decisions.
