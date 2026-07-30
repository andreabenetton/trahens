<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0020: Bound W2 reassembly before semantic processing

- Status: Accepted
- Date: 2026-07-30

## Context

Fragmentation moves a denial-of-service surface from logical-message parsing to the adjacent-link receiver. A peer can start many incomplete messages, advertise large totals, replay fragments, or send conflicting metadata. The receiver must reject such work before expensive C1 operations or route-state allocation.

## Decision

A W2 receiver maintains a reassembly table keyed by authenticated adjacent-link scope and a 128-bit local message identifier. The implementation MUST enforce:

- a maximum logical message length;
- a maximum fragment count;
- a maximum number of concurrent incomplete messages;
- a maximum aggregate reserved-byte budget;
- a half-open reassembly deadline;
- canonical fragment count and fragment lengths;
- one immutable metadata tuple per reassembly context;
- exact-duplicate suppression;
- context invalidation on conflicting duplicates or metadata;
- semantic parsing only after complete, contiguous reassembly.

The reference profile limits an M1 message to 16,384 bytes, a W2 fragment payload to 992 bytes, and a message to at most 17 cells. Reference reassembly defaults are 64 messages, 128 KiB of reserved logical bytes, and 40 ms; deployment profiles may lower these bounds but must not silently raise the M1 or W2 maxima.

## Consequences

- Reassembly work is calculable before C1 processing.
- Incomplete messages expire without creating branch or route state.
- Exact duplicate fragments are inexpensive and idempotent.
- Fragment retransmission requires a separate bounded reliability rule; W2 itself does not retransmit.
- A traffic scheduler may interleave fragments, but it must preserve reassembly deadlines and resource bounds.
