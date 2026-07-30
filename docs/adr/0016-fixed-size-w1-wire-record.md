# ADR-0016: Fix one constant-size W1 control record

- Status: Accepted for research interoperability
- Date: 2026-07-30

## Context

U1 requires equal record classes and fresh per-hop reconstruction, but the prior specification did not freeze the complete adjacent-link encoding. Variable outer lengths would expose message classes and nested candidate depth. An abstract codec also prevented malformed-input testing and exact bandwidth accounting.

## Decision

Define W1 as one authenticated adjacent-link record:

- 12-byte public header: 4-byte link epoch and 8-byte sequence;
- 1,024-byte encrypted plaintext body;
- 16-byte ChaCha20-Poly1305 authentication tag;
- 1,052 bytes total for every control message.

Message type, protocol and profile identifiers, suite identifier, logical fields, and padding are encrypted. The common plaintext prefix is eight bytes. DISCOVER, CANDIDATE, route controls, and CHAFF have exact canonical layouts. Every outgoing hop reconstructs the plaintext, regenerates padding, and uses a unique link nonce.

## Consequences

- adjacent observers do not learn message type or nested-candidate length from record size;
- exact wire-byte accounting becomes possible;
- invalid length and link authentication fail before protocol-state allocation;
- padding cost is paid for every control record;
- W1 does not hide timing, direction, record count, or queue behavior;
- independent codecs and a malformed-input corpus remain required before network deployment.
