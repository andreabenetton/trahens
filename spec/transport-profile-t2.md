<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens T2 Congestion and Quantized Scheduling Profile

- Status: Active experimental research profile. The fixed profile is
  mandatory; adaptive is implemented and selectable with `--schedule-profile
  adaptive` and has its own CI gate.
- Date: 2026-07-30
- Extends: T1 hop-local recovery and fixed-cell framing
- Wire record: 1,052 bytes
- Scope: one authenticated directed adjacent link

## 1. Purpose

T1 defines reliable equal-size DATA, ACK, and CHAFF cells but deliberately does not define how a fixed schedule reacts when offered load exceeds its capacity. T2 adds a bounded congestion and scheduling policy without introducing identifiers that cross a relay.

T2 has five objectives:

1. make overload behavior deterministic and finite;
2. distribute admitted DATA service fairly among concurrent link-local transmissions;
3. negotiate cadence only from a finite public rate menu;
4. change cadence only at explicit epoch boundaries with hysteresis;
5. state exactly what schedule adaptation reveals to a link observer.

T2 is not TCP, QUIC, or an end-to-end congestion controller. The design borrows the general requirement to limit injected traffic under uncertain capacity from RFC 5681 and RFC 9002, while applying it to one authenticated fixed-cell link. Weighted service uses the deficit-round-robin structure of Shreedhar and Varghese. Fairness is reported with the Jain-Chiu-Hawe index. Burst-loss experiments use the two-state channel family introduced by Gilbert and developed by Elliott.

## 2. Terms and notation

For one directed link:

- `Delta_e` is the fixed duration of schedule epoch `e`.
- `R=(r_0,...,r_k)` is a strictly increasing finite menu of cells per epoch.
- `c_e` is the public rate class used during epoch `e`.
- `Q_e` is queued DATA work after service in epoch `e`.
- `rho_e=min(Q_e/r_{c_e},1)` is the bounded queue-pressure signal.
- `theta_up` and `theta_down` are high and low pressure thresholds with `theta_down < theta_up`.
- `H_up`, `H_down`, and `H_hold` are consecutive-high, consecutive-low, and minimum-hold epoch counts.
- `w_f` is the positive configured weight of flow or transmission class `f`.
- `d_f` is its DRR deficit counter.

The public cadence of epoch `e` is exactly `r_{c_e}` equal-size cells at deterministic positions declared by the profile. The cell class and content remain encrypted; the selected rate class is observable from cadence.

## 3. Scheduler modes

A deployment selects one of the following modes per direction.

### 3.1 Fixed

One rate class is held for the complete declared schedule interval. Every slot emits DATA, ACK, SCHEDULE, or CHAFF. This mode can make active and empty epochs have the same public timestamp-and-length trace, provided the queue never exceeds the declared service capacity and the epoch boundaries are already established independently of the protected activity.

### 3.2 Adaptive

A finite rate class is held for each epoch. A change:

- takes effect only at the next authenticated epoch boundary;
- moves by at most one adjacent rate class;
- requires a matched encrypted OFFER and ACCEPT for the same negotiation identifier and effective epoch;
- obeys minimum-hold and hysteresis counters;
- never exceeds the peer-advertised maximum class.

Adaptive mode reduces reserved CHAFF bandwidth under variable load, but the public sequence `(c_0,c_1,...)` leaks coarse queue pressure. T2 therefore makes no activity-presence or traffic-flow unlinkability claim for adaptive cadence.

### 3.3 Work-conserving research baseline

The scheduler emits only when a real local cell is available. It is retained as an efficiency and correlation baseline and carries no fixed-trace privacy claim.

## 4. Encrypted schedule frame

T2 adds one adjacent-link frame class, `SCHEDULE`. It is encrypted and padded to the same 1,052-byte record as every other T1/T2 cell.

The encrypted 32-byte header contains:

```text
wire_profile          1 byte   value 0x04
protocol_version      1 byte
privacy_profile       1 byte
lifecycle_profile     1 byte
crypto_suite          2 bytes
frame_type            1 byte   SCHEDULE = 0x03
reserved              1 byte   zero
negotiation_id       16 bytes  non-zero, link-local
effective_epoch       4 bytes  unsigned big-endian
current_class         1 byte
requested_class       1 byte
maximum_class         1 byte
action                1 byte   OFFER, ACCEPT, or REJECT
```

The remaining encrypted body is random padding. `negotiation_id`, offers, accepts, rate history, and pressure measurements terminate at the adjacent peer and MUST NOT be copied into an outgoing routed message.

## 5. Rate update rule

An adaptive sender computes pressure after the current epoch's service:

```text
rho_e = min(Q_e / r[c_e], 1)
```

It updates consecutive counters:

```text
if rho_e >= theta_up:
    high += 1; low = 0
else if rho_e <= theta_down:
    low += 1; high = 0
else:
    high = 0; low = 0
```

Subject to `hold >= H_hold`:

```text
if high >= H_up and c_e < c_max:
    requested = c_e + 1
else if low >= H_down and c_e > c_min:
    requested = c_e - 1
else:
    requested = c_e
```

The peer accepts at most `min(requested, peer_maximum)`. A transition cannot skip a class. A failed, stale, conflicting, or unauthenticated negotiation leaves the next epoch at the current class.

Hysteresis reduces rapid oscillation. It does not make the class sequence independent of traffic.

## 6. Queue service and fairness

T1 priority remains bounded:

1. due ACK;
2. accepted SCHEDULE control;
3. missing-fragment retransmission;
4. new DATA selected by weighted DRR;
5. CHAFF.

ACK and SCHEDULE reserves MUST be finite. They MUST NOT starve DATA indefinitely.

For fixed-size cells, one unit of deficit pays for one DATA cell. On each visit to a backlogged class `f`, the scheduler adds `w_f * quantum` to `d_f`, emits while `d_f >= 1` and slots remain, and decrements `d_f` by one per emitted cell. Empty classes reset their deficit. Weights are local policy; they are not carried across relays.

The reference evaluation reports normalized throughput fairness using:

```text
J(x_1,...,x_n) = (sum x_i)^2 / (n * sum x_i^2)
```

where `x_i=delivered_i/w_i` for backlogged classes.

## 7. Admission and overload

Before admitting a new M2 transmission, an implementation knows its canonical fragment count. It SHOULD reserve the complete first-send fragment set atomically. If the reservation would exceed a per-flow, per-peer, or global queue limit, the transmission is rejected before its first fragment is emitted.

At the maximum rate class, persistent overload MUST NOT cause an implicit faster cadence. The implementation instead applies finite policy in this order:

1. reject unauthenticated and malformed cells;
2. expire stale receive and completion contexts;
3. reject new over-budget transmissions;
4. limit further recovery rounds;
5. expire low-priority queued work by local deadline;
6. fail the local route operation through the generic transport-failure interface.

Dropping a declared fixed-schedule slot is a visible schedule break and exits the fixed-trace claim. CHAFF is not a queue item and cannot be used as unbounded reserve.

## 8. Loss and congestion signals

T2 does not treat every loss as proof of congestion. Wireless corruption, burst loss, and adversarial dropping are possible. Rate adaptation uses authenticated local queue pressure and explicit peer caps. T1 timeout and retry exhaustion may contribute to local admission policy but MUST NOT cause an immediate unquantized cadence change.

The reference burst experiment uses a two-state Gilbert-Elliott process only as a reproducible stress model. Passing it is not evidence for a production loss model.

## 9. Privacy boundary

T2 provides the following narrow properties:

- every slot remains one 1,052-byte encrypted cell;
- frame class remains hidden from a passive adjacent observer;
- fixed mode preserves the declared per-epoch timestamp-and-length shape under non-overflow assumptions;
- negotiation contents and queue weights are link-confidential;
- rate changes occur only at finite public boundaries.

T2 does not hide:

- the selected rate class;
- epoch start, end, or direction;
- rate transitions or their approximate timing;
- topology or peer identity at the link layer;
- schedule correlation across multiple observed links;
- overload-induced failure or route setup completion;
- globally observed timing.

Adaptive-padding research shows that practical padding may reduce some classifiers while leaving subtle fingerprints and substantial model dependence. T2 therefore treats its own adaptive trace as observable evidence, not as a privacy proof.

## 10. Mandatory bounds

A conforming T2 deployment publishes finite values for:

- rate menu and maximum class;
- epoch duration and negotiation guard time;
- minimum-hold, up, and down counters;
- queue-pressure thresholds;
- per-flow, per-peer, and global queued cells and bytes;
- ACK and SCHEDULE control reserve;
- DRR quantum and admissible weights;
- maximum queue residence time;
- maximum recovery attempts and retry work;
- CHAFF bytes per epoch and total schedule lifetime;
- malformed, stale, and rejected negotiation work.

## 11. Reference-model limits

The deterministic model abstracts authenticated OFFER/ACCEPT delivery and models fixed-size cell workloads rather than complete M2 transmission reservations. It evaluates queue bounds, weighted service, rate-class transitions, CHAFF cost, a simple activity distinguisher, burst losses, and two-link public-count correlation. Its measurements are not network benchmarks and do not establish anonymity.
