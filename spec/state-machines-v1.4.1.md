<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.4.1 state machines

- Status: Active research design
- Adds: T1 recovery plus T2 queue, negotiation, rate, fairness, and overload state

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

## 4. T1/T2 scheduler

At every fixed or adaptive physical slot:

```text
if due ACK exists within reserve: emit ACK
else if due SCHEDULE control exists within reserve: emit SCHEDULE
else if due retransmission exists within reserve: emit one missing DATA fragment
else if admitted new DATA exists: emit one weighted-DRR fragment
else: emit CHAFF
```

Work-conserving mode uses the same ordering but leaves the final branch silent. ACK, SCHEDULE, and retransmission reserves are finite and cannot create undeclared slots. Queue and epoch state are finite. Adjacent-link control never enters the routed E1 state machine.

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



## 5.1 Reply-key child state

For each forwarded child, a relay stores one non-zero scalar blinding factor `b_i`, the incoming non-identity reply public key `X_i`, and the outgoing key `X_(i+1)=b_i X_i`. The reverse relay layer carries `b_i` only inside authenticated encryption to `X_i`. After opening that layer, the initiator derives `x_(i+1)=b_i x_i mod q`. Public-key distribution after one honest relay is exact uniform over non-identity group elements; complete reply-layer unlinkability remains conditional on key privacy of the reply encryption and on composition review.

## 6. T2 schedule negotiation

```text
STABLE(c,e)
  -- local sustained high/low pressure --> OFFERED(c',e+1)
OFFERED(c',e+1)
  -- matching ACCEPT before guard --> PENDING(c',e+1)
  -- REJECT, conflict, stale, timeout --> STABLE(c,e+1)
PENDING(c',e+1)
  -- epoch boundary --> STABLE(c',e+1)
```

`|c'-c| <= 1`. Schedule state is adjacent-link-local. The current epoch never changes after it begins.

## 7. T2 overload state

```text
NORMAL
  -- queue pressure above high threshold --> PRESSURED
PRESSURED
  -- accepted higher class --> NORMAL or PRESSURED
  -- maximum class and capacity available --> PRESSURED
  -- admission limit reached --> SHEDDING
SHEDDING
  -- new whole transmission --> REJECT
  -- queue below recovery threshold --> NORMAL
```

SHEDDING cannot create extra slots or extend a route deadline.

## T3 analysis lifecycle

```text
CONFIGURED -> GENERATING -> BUDGET_VERIFIED -> FEATURED -> CLASSIFIED -> REPORTED
```

Any budget mismatch, train/test overlap, malformed trace, queue-accounting inconsistency, or non-deterministic vector moves the run to `INVALID`. T3 analysis state is never route forwarding state.

## T4 analysis-state machine

T4 maintains a finite analysis-only event queue with the following transitions:

```text
DEMAND_ARRIVAL -> LINK_READY_QUEUE
EPOCH_DECISION -> SLOT_RELEASE*
SLOT_RELEASE -> ACCESS_SERIALIZATION
ACCESS_COMPLETE -> BOTTLENECK_SERIALIZATION | PROPAGATION
BOTTLENECK_COMPLETE -> PROPAGATION
PROPAGATION_COMPLETE -> OBSERVATION + NEXT_HOP_READY
```

Equal-time events use a fixed priority and insertion order. Observer-clock transformation occurs only after the true-time observation event and cannot change protocol processing order. Route churn changes the path of newly generated target tokens only; tokens already in flight retain their path. Selective delay adds a bounded propagation delay to matching model-local target tokens and does not create, mutate, or expose a protocol field.
