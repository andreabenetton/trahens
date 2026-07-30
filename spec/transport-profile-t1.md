# Trahens T1 hop-local reliability and scheduled-cell profile

- Status: Active experimental transport profile
- Applies to: Trahens Core v1.3; T2 governs congestion and schedule adaptation
- Depends on: U1, E1, R1, M2, and the W2 fragmentation limits
- Observable adjacent-link record length: 1,052 bytes

## 1. Purpose

T1 adds bounded hop-local recovery and a profile-specific traffic schedule to the fixed-cell transport. It addresses two limitations of bare W2 delivery:

1. one lost fragment prevents completion of a multi-cell logical message; and
2. fixed cell length alone does not conceal fragment bursts, idle periods, or message timing.

T1 does not create an end-to-end transport session. Reliability state exists only between two authenticated adjacent peers. Every relay terminates the incoming T1 transmission, reconstructs and validates the M2 message, performs the protocol transformation, and starts a new T1 transmission toward each selected child or parent. No T1 transmission identifier crosses a relay.

## 2. Security and design boundary

T1 MUST preserve the following separation:

- M2 is the variable-length semantic message;
- W2 defines the 992-byte canonical fragment payload and the maximum of 17 fragments;
- T1 defines DATA, ACK, and CHAFF frames, bounded retransmission, and release scheduling;
- adjacent-link AEAD provides authentication, confidentiality, and fresh ciphertexts;
- U1 requires each relay to replace all link-local transmission state before forwarding.

The T1 schedule is intended to reduce link-local timing and count leakage. It does not by itself establish end-to-end traffic-flow unlinkability, protection against a global observer correlating different links, or protection from schedule-start and schedule-stop leakage.

## 3. Terms

- **Transmission identifier** `z`: a fresh non-zero 128-bit value scoped to one directed adjacent-link epoch and one M2 message.
- **Fragment** `f_i`: the canonical M2 byte range at index `i`, where `0 <= i < q` and `q <= 17`.
- **Selective acknowledgement bitmap** `A`: a 32-bit value whose bit `i` acknowledges `f_i`; bits at indices `i >= q` are zero.
- **Slot**: one scheduled opportunity to emit exactly one 1,052-byte adjacent-link record in one direction.
- **Recovery round**: one bounded enqueueing of all currently unacknowledged fragments after timeout.
- **Schedule epoch**: a previously established interval during which a directed link follows a declared slot schedule.

## 4. Encrypted T1 body

The public adjacent-link header remains:

| Field | Bytes | Meaning |
|---|---:|---|
| Link epoch | 4 | Directional key and replay epoch |
| Sequence | 8 | Unique AEAD nonce input within the epoch |

The encrypted body is exactly 1,024 bytes. The authentication tag is 16 bytes. The total record is therefore 1,052 bytes.

The common encrypted T1 header is 32 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | T1 wire profile `0x03` |
| 1 | 1 | Protocol version |
| 2 | 1 | U1 profile |
| 3 | 1 | E1 profile |
| 4 | 2 | Cryptographic suite |
| 6 | 1 | Frame type: DATA `0x00`, ACK `0x01`, CHAFF `0x02` |
| 7 | 1 | Flags, zero in this profile |
| 8 | 16 | Adjacent-link transmission identifier |
| 24 | 8 | Frame-type-specific fields |
| 32 | 992 | Fragment bytes or random padding |

The frame type, transmission identifier, fragment metadata, acknowledgement bitmap, and padding are all encrypted.

## 5. DATA frame

For DATA, bytes 24-31 contain:

| Bytes | Field |
|---:|---|
| 2 | Fragment index |
| 2 | Fragment count |
| 2 | Fragment length |
| 2 | Total M2 message length |

The fragment payload begins at byte 32. Canonical fragmentation is inherited from W2:

```text
q(L) = ceil(L / 992)
1 <= L <= 16384
1 <= q <= 17
```

Every non-final fragment has length 992. The final fragment has the unique remaining length. Alternative fragment counts or short non-final fragments are invalid.

## 6. ACK frame

For ACK, bytes 24-31 contain:

| Bytes | Field |
|---:|---|
| 2 | Fragment count `q` |
| 2 | Receiver acknowledgement delay in milliseconds |
| 4 | Selective acknowledgement bitmap `A` |

An ACK is cumulative for the adjacent-link transmission identifier: every set bit denotes a fragment already retained by the receiver. The receiver MAY coalesce multiple fragment arrivals into one ACK. A duplicate DATA fragment MUST NOT allocate a second fragment; it SHOULD cause the current cumulative bitmap to be acknowledged again.

ACK frames are adjacent-link controls, not routed M2 messages. They MUST NOT create branch, candidate, tentative, pending, active, or rendezvous state.

## 7. CHAFF frame

A CHAFF frame contains a fresh non-zero random transmission identifier, zero type-specific fields, and random padding. It carries no semantic fragment and receives no ACK. It follows the same slot, outer length, key, nonce, and AEAD path as DATA and ACK.

The reference simulator does not execute a receive-side AEAD operation for every modeled idle CHAFF slot; codec conformance tests independently verify the exact encoding. The simulation still charges one complete 1,052-byte record and one scheduled timestamp per CHAFF slot.

## 8. Sender state machine

For every M2 message, the sender:

1. chooses a fresh transmission identifier `z` for the directed link and epoch;
2. creates the canonical fragment set `f_0,...,f_{q-1}`;
3. reserves sender state and queue capacity for all `q` fragments;
4. emits fragments according to the scheduler;
5. records per-fragment send count and most recent send time;
6. processes authenticated cumulative ACK bitmaps;
7. releases state when all `q` bits are acknowledged;
8. on timeout, enqueues only missing fragments, subject to the recovery-round limit;
9. fails the local transmission after the configured maximum recovery rounds.

A relay MUST NOT forward an M2 message until all fragments have been authenticated, reassembled, and canonically decoded.

## 9. Fresh retransmission requirement

A retransmitted fragment retains only the information required for adjacent-link recovery:

- the same link-local transmission identifier;
- the same fragment index and canonical fragment bytes.

Every emission MUST use:

- a new public link sequence number;
- a fresh AEAD nonce derived from that sequence;
- fresh random cell padding;
- a newly computed authentication tag and ciphertext.

Consequently, an unauthenticated passive observer cannot identify retries by ciphertext equality. The authenticated adjacent peer can link retries within the local transmission, which is necessary for selective recovery. This local relation MUST NOT be copied into a forwarded M2 message or a transmission on another link.

## 10. Timeout estimation and bounded recovery

T1 uses acknowledgement-based loss detection and a bounded retransmission timer. The structure is informed by TCP RTO estimation and QUIC acknowledgement-based recovery, but T1 is neither TCP nor QUIC and does not adopt their end-to-end congestion-control semantics.

For a non-retransmitted fragment with measured round-trip sample `R`:

```text
first sample:
    SRTT   = R
    RTTVAR = R / 2
later samples:
    RTTVAR = 3/4 * RTTVAR + 1/4 * abs(SRTT - R)
    SRTT   = 7/8 * SRTT   + 1/8 * R
RTO = clamp(SRTT + max(G, 4 * RTTVAR), RTO_min, RTO_max)
```

A fragment that has been retransmitted is not used as an RTT sample. On timeout the sender doubles the current RTO up to `RTO_max`, enqueues the currently missing fragments, and increments the recovery-round counter. All timers, retries, and retained bytes are bounded.

References: RFC 6298, *Computing TCP's Retransmission Timer*; RFC 9002, *QUIC Loss Detection and Congestion Control*; RFC 6675, *A Conservative Loss Recovery Algorithm Based on Selective Acknowledgment (SACK) for TCP*.

## 11. Scheduler

### 11.1 Fixed-schedule mode

For each directed link, an active schedule epoch defines an origin `T_0`, slot interval `Delta`, and finite epoch end. Exactly one record is emitted at every time

```text
T_0 + k * Delta
```

inside the epoch. The scheduler selects, in order:

1. a due cumulative ACK;
2. one retransmission fragment;
3. one new fragment chosen by round-robin across live transmissions;
4. CHAFF.

The selection class is encrypted. Fragment round-robin prevents one large candidate from occupying all available DATA slots before smaller control messages receive service. Implementations MUST bound queue occupancy and MUST specify overload behavior rather than silently expanding the schedule.

### 11.2 Work-conserving mode

A work-conserving deployment uses the same selection order but emits nothing in an empty slot. This mode provides reliability and interleaving but does not provide a constant public link trace.

### 11.3 Conditional schedule-shape property

During a pre-existing fixed schedule epoch, if the queue never exceeds its declared capacity and the link continues emitting CHAFF when no real frame is pending, the public record times and lengths are independent of whether the queue contains DATA, ACK, or no protocol traffic. The reference experiment verifies identical per-direction cell counts and zero inter-arrival coefficient of variation for an active route setup and an empty schedule.

This property does not hide:

- the existence, start, end, or negotiated rate of the schedule epoch;
- link direction or topology;
- congestion-induced schedule changes or queue overflow;
- correlation across multiple links by a global observer;
- compromise of either adjacent peer.

Constant-rate shaping is related to the data-phase strategy evaluated in TARANET. Loopix instead uses Poisson mixing and cover traffic; T1 does not claim to implement the Loopix statistical model.

## 12. Replay and malformed input

The public sequence number is checked without mutating replay state before AEAD authentication. Replay state advances only after successful authentication. A forged future sequence therefore cannot reserve the sequence number and suppress the valid record.

A receiver rejects uniformly:

- wrong total record length;
- failed adjacent-link authentication;
- unsupported T1 profile or frame type;
- non-zero reserved fields;
- invalid transmission identifier;
- non-canonical fragment count or length;
- ACK bits outside the declared fragment count;
- conflicting duplicate fragments;
- suite mismatch within one reassembly context.

## 13. Mandatory limits

A conforming implementation defines finite values for:

- schedule epoch length and slot rate;
- sender transmissions per peer and node;
- queued new and retransmission fragments;
- pending ACKs;
- receiver contexts and reserved logical bytes;
- ACK delay;
- minimum, initial, and maximum RTO;
- retransmission rounds and attempts per fragment;
- receiver completion-cache lifetime;
- malformed, replay, and timeout work per time window;
- CHAFF bandwidth reserved by policy.

Recovery traffic MUST be charged against the same physical-link and node-global budgets as first transmissions. CHAFF cost MUST be explicit and MUST NOT be described as free privacy.

## 14. Reference evidence

The repository contains:

- exact DATA, ACK, and CHAFF codec tests;
- a test that retransmission changes padding and ciphertext;
- selective bitmap validation;
- bounded retry exhaustion under total loss;
- a deterministic case in which recovery succeeds after unrecovered delivery fails;
- multi-hop candidate fragmentation and recovery;
- fixed-schedule trace equivalence between active and empty traffic;
- reproducible route-depth and loss sweeps.

The model is a falsification and resource-analysis tool. It is not a proof of traffic-analysis resistance, a congestion controller, or a production network implementation.
