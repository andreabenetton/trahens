<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.1 state machines

- Status: Active research design
- Adds: T1 hop-local sender, receiver, ACK, timeout, and scheduler state

## 1. T1 sender transmission

```text
NONE
  -- enqueue canonical M2 --> QUEUED
QUEUED
  -- first DATA emission --> IN_FLIGHT
IN_FLIGHT
  -- partial cumulative ACK --> IN_FLIGHT
  -- complete ACK --> COMPLETE
  -- RTO with missing fragments and retries available --> RECOVERY
  -- RTO with retry limit exhausted --> FAILED
RECOVERY
  -- retransmission emission --> IN_FLIGHT
COMPLETE | FAILED
  -- local release --> NONE
```

Every state has finite memory and timer bounds. COMPLETE and FAILED are local outcomes and are not forwarded as identifiers.

## 2. T1 receiver context

```text
NONE
  -- first valid DATA --> INCOMPLETE
INCOMPLETE
  -- new canonical fragment --> INCOMPLETE
  -- exact duplicate --> INCOMPLETE
  -- conflicting metadata or bytes --> INVALIDATED
  -- all fragments present --> COMPLETE_CACHE
  -- deadline --> EXPIRED
COMPLETE_CACHE
  -- duplicate DATA --> COMPLETE_CACHE and ACK again
  -- cache deadline --> EXPIRED
INVALIDATED | EXPIRED
  -- release --> NONE
```

M2 and route-state processing occurs exactly once on the transition to COMPLETE_CACHE.

## 3. ACK state

The reverse directed link holds at most one pending cumulative ACK per live transmission identifier. New fragments update the bitmap. The scheduler emits the current bitmap when its due time is reached. Lost ACKs are repaired indirectly when later DATA or retry traffic causes another cumulative ACK.

## 4. Scheduler

At every fixed slot:

```text
if due ACK exists: emit ACK
else if retransmission exists: emit one missing DATA fragment
else if new DATA exists: emit one round-robin fragment
else: emit CHAFF
```

In work-conserving mode the final branch is silence. Scheduler queues and epochs are finite. An ACK is a local control and never enters the routed E1 state machine.

## 5. Route lifecycle interaction

The E1 branch and route states remain:

```text
DISCOVER -> BRANCH
CANDIDATE -> TENTATIVE
COMMIT -> PENDING_READY
READY -> ACTIVE
CANCEL | ABORT | CLOSE | expiry -> reclaimed
```

A route event is delivered to E1 only after T1 has completed authenticated reassembly and M2 validation. T1 timeout failure may cause the local route operation to fail, but cannot extend route state beyond its existing E1 deadline.
