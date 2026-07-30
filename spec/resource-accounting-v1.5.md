<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.5 P1 resource accounting

- Status: Normative limits for the P1 implementation
- Source: `protocol-registry-v1.5.json`

## Mandatory ceilings

| Resource | Ceiling |
|---|---:|
| logical message | 16,384 bytes |
| protected control | 8,192 bytes |
| fragments per message | 17 |
| reassembly contexts per peer | 64 |
| global reserved reassembly bytes | 131,072 |
| sender transmissions per peer | 64 |
| routes per peer | 256 |
| routes globally | 2,048 |
| candidate relay layers | 16 |
| T1 retries | 8 |
| T1 RTO | initial 100 ms, clamped to [25, 3000] ms |
| T1 ACK delay | 25 ms maximum |
| pending ACKs per link | 64 |
| replay window | 1,024 cells |
| fixed T2 queue per peer | 256 cells |
| fixed T2 queue globally | 2,048 cells |
| failed redemptions per route | 2 |
| branch contexts per ingress peer | 64 |
| branch contexts globally | 1,024 |
| candidate responses per discovery | 64 |
| ingress token bucket | capacity 8, +1 token per 100 ms |
| registrations per endpoint | 8 |
| registrations per gateway | 1,024 |
| endpoint handle lifetime | 5,000 ms |
| fan-out class | 3 maximum |

The generated registry remains authoritative if this explanatory table disagrees.

## Admission order

1. exact UDP/W2 record length;
2. epoch and non-mutating replay precheck;
3. W2 authentication;
4. replay commit;
5. T1 frame canonicality;
6. bounded sender/receiver/reassembly processing;
7. complete canonical M2 decode;
8. route-state and cryptographic-work admission;
9. typed protocol transition;
10. outgoing queue reservation.

A failure at one stage MUST NOT consume later-stage state.

## State-class deadlines

Every lifecycle state class carries an independent finite deadline from the
registry: branch contexts expire after `branch_ttl_ms`, candidate offers
after `offer_ttl_ms`, tentative routes after `tentative_ttl_ms`, the
READY hold after `ready_hold_ms`, and a complete route setup attempt after
`route_setup_timeout_ms`. Active routes keep `route_ttl_ms`, renewed on
valid transitions per E1 §8. Reassembly, replay, and completion-cache
lifetimes are unchanged.

## Memory discipline

Reassembly reserves aggregate bytes on first accepted fragment. Route maps store only two adjacent labels, generation, expiry, and the minimum cryptographic material needed for that hop. Capability storage keeps a commitment rather than a raw capability. Secret scalars, route secrets, signing secret keys, and presented capabilities use zeroizing wrappers.

The prototype uses bounded synchronous process channels, bounded T1 transmission maps, bounded replay windows, and fixed-size W2 buffers. A production implementation should add allocator-level or process-level hard memory limits; v1.5 CI treats registry ceilings as the protocol-level acceptance boundary.

## Recovery amplification

For `q` fragments and at most `r` retries, DATA emission is bounded by `q * (1 + r)`. ACK and CHAFF are separately bounded by fixed T2 slots. Retry exhaustion emits one failure event, releases sender state, and does not allocate a new logical transmission automatically.

## Metrics

Each process reports cells and bytes, logical messages, retries, malformed/replay events, peak queue cells, fixed-schedule classes, live route count, cleanup latency, and CPU/memory observations supplied by the harness. The aggregate report additionally records route setup, redemption, chaff ratio, topology, MTU, and `netem` parameters.
