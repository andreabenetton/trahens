# Trahens Core v1.2

- Status: Active experimental research design
- Date: 2026-07-30
- Active profiles: U1, E1, R1, M2, W2, T1, T2
- Research-only profiles: C1 negative control, symbolic C2, disabled C2-k2 audit

## 1. Purpose

Trahens Core discovers generic rendezvous gateways within a bounded graph radius and establishes opaque bidirectional forwarding state to one selected gateway. Endpoint-specific rendezvous occurs only after the route reaches READY through a private, short-lived, single-use R1 capability.

A relay learns only its adjacent predecessor and successor relationships and the local capabilities required to forward messages. The protocol never transmits a complete source route. Every forwarded branch receives a fresh adjacent capability, a tweaked reply public key, a replacement R1 service-query nonce, a new M2 logical message, a new adjacent-link transmission identifier, new padding, and fresh ciphertexts.

Core v1.2 binds T1 recovery to T2 congestion and scheduling. T1 repairs lost fragments without introducing a cross-hop identifier. T2 defines fixed or quantized-adaptive schedule epochs, finite rate negotiation, weighted fair service, and fail-closed overload behavior. Fixed epochs can replace idle slots with encrypted CHAFF; adaptive epochs reveal their public rate class and do not carry an activity-presence privacy claim.

## 2. Bound profiles

- **U1**: branch-local representation replacement and conditional passive unlinkability.
- **E1**: deterministic event time, candidate windows, route activation, expiry, and cleanup.
- **R1**: generic rendezvous-gateway discovery plus post-READY one-time capability redemption.
- **M2**: canonical suite-agile variable-length logical messages without semantic padding.
- **W2**: canonical 992-byte fragmentation, fixed 1,024-byte encrypted cell body, and bounded reassembly.
- **T1**: encrypted DATA, ACK, and CHAFF frames, selective acknowledgement, bounded timeout recovery, fresh retransmission ciphertexts, and fragment interleaving.
- **T2**: finite schedule epochs, quantized rate classes, authenticated adjacent-link negotiation, hysteresis, weighted DRR, bounded overload behavior, and explicit adaptive-trace leakage.

## 3. Goals

Core v1.2 MUST provide:

1. bounded discovery by hop limit, fan-out, time, branch state, logical bytes, cells, queues, timers, retries, and cryptographic work;
2. no endpoint address, endpoint public key, deterministic endpoint selector, or endpoint capability in DISCOVER;
3. no stable discovery or transport identifier visible across non-adjacent links;
4. fresh branch-local representation for every forwarded child;
5. authenticated responder candidates returned through a nested reply chain;
6. tentative route establishment before initiator selection;
7. explicit COMMIT, READY, CANCEL, ABORT, CLOSE, and expiry behavior;
8. no data-plane authorization before final READY;
9. one-time, finite-lifetime rendezvous capability redemption after route activation;
10. bounded hop-local recovery for incomplete fragmented messages;
11. fresh link encryption and padding for every retry;
12. explicit cost and claim boundaries for CHAFF and fixed-rate scheduling;
13. deterministic fail-closed behavior for disabled research suites;
14. exact separation between equal cell length, fixed-epoch schedule shape, adaptive rate leakage, passive structural unlinkability, active tagging, and end-to-end traffic-flow privacy;
15. bounded queue admission, quantized rate transitions, and weighted fair sharing among concurrent link-local transmissions.

## 4. Non-goals

Core v1.2 does not itself provide:

- private directory queries or descriptor distribution;
- protection from a malicious gateway correlating registration and redemption;
- a global endpoint lookup system;
- inter-domain policy, incentives, or Sybil resistance;
- an end-to-end reliable byte stream;
- end-to-end or production congestion control beyond one authenticated adjacent link;
- traffic-flow unlinkability against a global observer;
- protection from link schedule start/stop correlation;
- production readiness or post-quantum security;
- a replacement for IP or a physical/link layer.

## 5. System model

The network is an undirected graph `G=(V,E)`. A node may act as initiator, ordinary relay, rendezvous gateway, or any combination. An edge denotes an authenticated adjacent-link association. Each direction of an edge has its own key epoch, sequence space, T1 sender state, receiver state, and optional schedule.

A route is a sequence `(n_0,...,n_d)` with adjacent pairs in `E`. The route is never transmitted as one object. Route state consists only of peer-bound local labels and mappings.

## 6. Adjacent-link contract

The adjacent-link association MUST provide:

- peer authentication or an explicitly anonymous authenticated association;
- confidentiality and integrity;
- exact 1,052-byte record boundaries for the active T1/T2 transport profiles;
- directional epoch and replay sequence;
- key and nonce uniqueness;
- connection and disconnection notification;
- finite queue and timer budgets.

The public 12-byte header contains only the link epoch and sequence. The encrypted body contains T1/T2 class, suite, link-local transmission or negotiation state, type-specific metadata, and random padding. Cell length equality hides exact per-cell content length. Fixed-schedule mode additionally hides whether one slot carries DATA, ACK, SCHEDULE, or CHAFF, but does not hide the schedule itself.

## 7. Discovery and R1

The endpoint registers a random 32-byte capability at selected rendezvous gateways and privately distributes a descriptor containing the capability, expiration, and acceptable short-lived gateway pseudonyms.

An R1 DISCOVER message contains a fresh 32-byte service-query nonce with no endpoint semantics. Every honest relay replaces it independently for each child. A node responds only if it locally serves as a rendezvous gateway.

The candidate payload contains the gateway's short-lived pseudonym inside the authenticated end-to-end candidate chain. The initiator accepts only candidates listed in the private descriptor. After READY, the initiator sends the capability through the active route; the gateway atomically consumes a live matching registration.

## 8. Forward and reverse transformation

For every outgoing adjacent link, a relay:

1. authenticates T1/T2 records and commits replay state only after authentication;
2. updates the adjacent-link ACK/reassembly context;
3. obtains the complete canonical M2 message;
4. validates local bounds and protocol state;
5. performs the U1 branch, reply-key, nonce, label, or candidate transformation;
6. constructs a new M2 message;
7. chooses a fresh T1 transmission identifier for the next link;
8. creates canonical fragments;
9. schedules DATA under the next link's active T1/T2 policy;
10. uses fresh padding and AEAD ciphertext for every first transmission and retry.

Incoming T1 identifiers, ACK state, fragment indexes as a set, send timestamps, retry counters, and scheduler state MUST NOT be copied into the outgoing M2 object.

## 9. Candidate return and route activation

A gateway signs and seals a responder payload containing its short-lived pseudonym, offer expiry, final reply key, commit challenge, and nonce. Each reverse relay adds one authenticated layer and installs tentative mappings.

COMMIT reserves the selected path and moves mappings to `PENDING_READY`. READY confirms responder activation and converts mappings to `ACTIVE`. Application data and RENDEZVOUS_OPEN MUST NOT be forwarded before the initiator authenticates final READY. CANCEL, ABORT, and CLOSE are advisory; local deadlines remain authoritative for cleanup.

## 10. M2, W2, and T1

M2 encodes one complete semantic control message with canonical lengths and no semantic padding. W2 supplies the canonical fragment rule:

```text
q = ceil(L / 992)
1 <= L <= 16384
1 <= q <= 17
```

T1 places each canonical fragment in a DATA frame and adds encrypted ACK and CHAFF frame types. All complete adjacent-link records remain 1,052 bytes.

ACK uses a 32-bit cumulative bitmap, sufficient for the current 17-fragment maximum. A receiver may delay and coalesce ACKs. The sender retransmits only unacknowledged fragments, uses a bounded RTO with exponential backoff, and gives up after a finite number of recovery rounds.

A retransmission reuses the link-local transmission identifier and fragment index only on the same adjacent link and epoch. It MUST use a new link sequence number, fresh padding, and a fresh ciphertext. The next relay transmission uses a new identifier.

## 11. T2 congestion and scheduling

T2 defines a finite menu of public cells-per-epoch rates. Fixed mode holds one class. Adaptive mode changes by at most one class at an authenticated epoch boundary after a matching encrypted OFFER/ACCEPT exchange, minimum hold time, and asymmetric queue-pressure hysteresis.

At each slot, due ACKs and bounded schedule controls have priority, followed by retransmissions, weighted deficit-round-robin new DATA, and CHAFF.

Under no-overflow assumptions, the public timestamp and length trace of a fixed epoch is independent of whether a slot carried DATA, ACK, or CHAFF. Work-conserving mode omits empty-slot CHAFF and therefore makes no constant-trace claim.

Schedule origin, duration, rate class, direction, topology, congestion changes, and cross-link timing remain observable. Adaptive rate transitions are explicitly treated as coarse traffic evidence. T2 provides no global-observer theorem.

## 12. Resource safety

Implementations MUST bound:

- cell and byte rate per peer and globally;
- live T1 transmissions, fragments, retries, ACKs, RTO timers, and completion caches;
- new-data, retransmission, and ACK queues;
- fixed-schedule CHAFF bandwidth;
- concurrent reassemblies and reserved logical bytes;
- branch, candidate, tentative, pending, active, and rendezvous state;
- cryptographic operations, registration count, and failed redemption work;
- setup time and all local deadlines.

Unauthenticated input MUST NOT advance replay state. A failed earlier stage MUST NOT consume resources assigned to later stages. Recovery and CHAFF are charged as complete physical cells.

## 13. Security claims

### 13.1 Structurally claimed

- all active T1/T2 records have equal complete length;
- endpoint capability bytes do not appear in DISCOVER;
- branch tokens and R1 nonces are replaced by honest relays;
- T1 transmission identifiers are link-local and replaced at every relay;
- retries produce fresh padding and ciphertext;
- one-time capability replay is rejected by atomic redemption;
- all route, transport, and reassembly state has finite cleanup.

### 13.2 Conditional schedule-shape claim

During a pre-existing fixed T2 schedule epoch, when the queue remains within its configured capacity and CHAFF is emitted in every otherwise idle slot, a passive observer of one link direction sees the same record length and slot timestamps whether the schedule carries protocol traffic or is empty.

### 13.3 Not claimed

- end-to-end or global traffic-flow unlinkability;
- concealment of schedule establishment or termination;
- anonymity against colluding directory, gateway, and network observers;
- congestion safety equivalent to a standardized transport;
- active-security properties of C1 or the disabled concrete C2 transcription;
- production cryptographic security.

## 14. Conformance and evidence

The repository includes deterministic vectors and tests for R1, M2, W2, T1 DATA/ACK/CHAFF encoding, T2 SCHEDULE encoding, fresh retry ciphertexts, selective ACK validation, bounded retry exhaustion, multi-hop fragmented route setup, quantized rate transitions, weighted service, queue overload, fixed/adaptive leakage, burst loss, and multi-link count correlation.

The experiments show that bounded selective recovery materially improves delivery under independent cell loss. Fixed scheduling yields an identical modeled per-direction public slot trace for active and empty traffic at substantial CHAFF cost. Adaptive scheduling reduces CHAFF and queueing in the evaluated overload workload but exposes an activity-dependent public rate sequence. These artifacts are regression and falsification tools, not proofs of anonymity, stability, or production performance.


## 15. T2 conformance additions

A Core v1.2 implementation claiming T2 MUST:

1. configure a finite strictly increasing rate menu and finite epoch duration;
2. encode SCHEDULE as an equal-size encrypted adjacent-link cell;
3. bind offer and acceptance to a non-zero link-local negotiation identifier and future epoch;
4. leave the rate unchanged on stale, conflicting, missing, or invalid negotiation;
5. move by at most one rate class per epoch and enforce finite hold and hysteresis counters;
6. apply bounded ACK and schedule-control priority, then retransmission, weighted DRR new DATA, and CHAFF;
7. reserve or reject new fragmented transmissions before partial first-send admission when their canonical size is known;
8. refuse to exceed the negotiated maximum cadence during overload;
9. report queue drops, rate changes, fairness, CHAFF, and schedule-boundary leakage separately;
10. make no adaptive activity-presence or multi-link unlinkability claim.
