<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Iteration 0008 - M1 logical messages, W2 fixed cells, and bounded reassembly

- Date: 2026-07-30
- Status: Completed as the active message-and-cell interoperability baseline

## Question

Can Trahens retain equal adjacent-link transmission length without forcing every logical control message into one fixed record, and can multi-cell messages be admitted, reassembled, and expired without creating unbounded memory or route-state exposure?

## Design change

Core v0.7 separates two protocol layers:

- **M1** is a canonical variable-length logical-message codec. It uses minimal unsigned base-128 integers, exact body lengths, message-specific bounds, and no semantic padding.
- **W2** is a fixed-size adjacent-link cell profile. Every encrypted cell contains a 32-byte fragment header, up to 992 bytes of M1 data, and fresh random padding inside a 1,024-byte plaintext. The public 12-byte link header and 16-byte AEAD tag produce an exact 1,052-byte record.

An M1 message is at most 16,384 bytes and therefore requires at most 17 W2 cells. Non-final fragments are exactly 992 bytes. The final fragment is the unique remainder. Alternative fragment counts or lengths are non-canonical.

Every relay fully authenticates and reassembles an incoming M1 message before semantic processing. It then performs the branch-local transformation, constructs a new M1 message, selects a fresh 128-bit link-local message identifier, fragments again, regenerates padding, and emits new link ciphertexts. Fragment identifiers and padding are never forwarded unchanged.

## Reassembly and replay safety

Reassembly is keyed by authenticated directional link scope and the link-local message identifier. It has independent limits for:

- concurrent incomplete messages;
- aggregate reserved logical bytes;
- fragment count and declared message length;
- residence time;
- duplicate and conflicting-fragment processing.

Exact duplicate fragments are idempotent. A conflicting duplicate or inconsistent metadata invalidates the complete local reassembly context. Incomplete contexts expire without allocating branch, candidate, tentative, pending, or active route state.

The receive pipeline now distinguishes a non-mutating public-sequence precheck from replay-state commitment. A receiver commits a sequence to the replay window only after adjacent-link authentication. This prevents an unauthenticated forged record from reserving a future sequence and suppressing the valid record that later uses it. Authenticated exact replay rejection still occurs before reassembly and route cryptography.

## Deterministic capacity result

The C1 candidate chain grows by 115 bytes for every relay wrapper in the current encoding. The transition across the one-cell boundary is:

| Relay wrappers | Candidate layers | M1 bytes | W2 cells | Wire bytes |
|---:|---:|---:|---:|---:|
| 5 | 6 | 909 | 1 | 1,052 |
| 6 | 7 | 1,024 | 2 | 2,104 |
| 11 | 12 | 1,599 | 2 | 2,104 |
| 15 | 16 | 2,059 | 3 | 3,156 |

The result removes the former single-record candidate-depth ceiling. It does not hide cell count: an observer that can group cells may still infer a coarse logical-size class.

## Integrated lifecycle result

Forty deterministic runs were executed for each line-route depth and transport condition:

| Condition | Hops | Route success | Logical messages | W2 cells | Fragmented messages | Cleanup |
|---|---:|---:|---:|---:|---:|---:|
| Clean | 2 | 100% | 8.00 | 8.00 | 0.00 | 100% |
| Clean | 5 | 100% | 20.00 | 20.00 | 0.00 | 100% |
| Clean | 8 | 100% | 32.00 | 34.00 | 2.00 | 100% |
| Clean | 12 | 100% | 48.00 | 54.00 | 6.00 | 100% |
| 2% cell loss | 2 | 80% | 7.53 | 7.53 | 0.00 | 100% |
| 2% cell loss | 5 | 65% | 16.43 | 16.43 | 0.00 | 100% |
| 2% cell loss | 8 | 50% | 25.55 | 27.15 | 1.60 | 100% |
| 2% cell loss | 12 | 30% | 30.83 | 34.30 | 3.48 | 100% |

Clean routes activate and reclaim all state. Under independent cell loss, success declines as candidate chains span more indispensable cells. The result confirms the need for a separately specified retransmission, interleaving, or erasure strategy; it is not evidence that independent cell loss is an adequate transport model.

## Verification

The repository contains 61 deterministic tests. New coverage verifies:

- minimal and canonical M1 integer and body encodings;
- absence of semantic padding in logical messages;
- fixed 1,052-byte W2 records for short and fragmented messages;
- link authentication and tamper rejection;
- canonical fragmentation and out-of-order reassembly;
- duplicate idempotency, conflict invalidation, timeout cleanup, and capacity limits;
- deep candidate fragmentation inside the E1/C1 route lifecycle;
- prevention of unauthenticated replay-window poisoning;
- deterministic capacity and lifecycle reports.

The formal paper was rewritten as one current protocol draft. It contains no historical architecture or iteration narration, retains five-line numbering, has no watermark, and explains the M1/W2 separation, canonical encoding, bounded reassembly, fragment-count leakage, reliability cost, and receive pipeline in formal and plain language.

## Decision

Accept M1 and W2 as the active research interoperability baseline. Keep individual W2 cells fixed size, but keep logical messages variable and canonical. Do not claim message-size or traffic-flow unlinkability from cell-length equality alone.

The next gates are:

1. replace or repair the active-tag-vulnerable eligibility construction;
2. define a traffic scheduler for fragment interleaving, cell-count padding, release timing, and cover cells;
3. add bounded retransmission or erasure behavior without introducing stable cross-hop identifiers;
4. implement an independent M1/W2 codec and cross-language conformance vectors;
5. fuzz malformed messages, fragment metadata, collisions, timeout churn, and reassembly exhaustion.
