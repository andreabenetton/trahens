# ADR 0025: Hop-local selective recovery

- Status: Accepted
- Date: 2026-07-30

## Context

W2 canonical fragmentation permits a logical message to span up to 17 cells. Under independent cell loss, one missing fragment prevents M2 decoding and route-state progress. End-to-end retries would retain partial state across several relays, create large latency, and risk introducing a stable cross-hop recovery handle.

## Decision

Add T1 hop-local recovery. Each adjacent sender assigns a fresh transmission identifier, retains one cumulative ACK bitmap, and retransmits only missing fragments after a bounded RTO. ACK is an encrypted same-size adjacent-link frame. A relay terminates recovery before transforming and forwarding the M2 message.

Retransmissions reuse the local transmission identifier and fragment index only on the same link. They use a new public sequence, fresh padding, and fresh AEAD ciphertext. Recovery rounds, timers, queues, attempts, completion caches, and bytes are bounded.

## Consequences

- Multi-cell delivery is materially more reliable under independent loss.
- The authenticated adjacent peer can link retries, which is required for repair.
- No retry identifier crosses a relay.
- ACK and retransmission cells consume explicit bandwidth.
- T1 is not an end-to-end congestion-control protocol.

## Sources

The RTO estimator follows the structure of RFC 6298. The use of cumulative selective acknowledgement and acknowledgement-based recovery is informed by RFC 6675 and RFC 9002, without adopting TCP or QUIC wire formats or congestion control.
