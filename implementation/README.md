# Overlay implementation

Network implementation is deferred until the state machines, resource rules, and cryptographic profile are stable enough to test interoperability.

The initial implementation should:

- run in user space over an existing authenticated transport;
- use a canonical generated codec rather than handwritten field parsing;
- keep protocol state separate from transport sessions;
- expose deterministic clocks and randomness in tests;
- support fault injection for loss, duplication, reordering, and peer disconnect;
- reject malformed and over-budget messages before expensive cryptography;
- emit structured traces that can be replayed in the simulator.

No implementation language has been selected. The selection should follow the needs of the conformance harness and cryptographic libraries rather than precede the protocol decisions.
