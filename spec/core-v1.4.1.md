<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.4.1

- Status: Active experimental research design
- Date: 2026-07-30
- Active profiles: U1, E1, R1, M2, W2, T1, T2, T3, T4
- Research-only profiles: C1 negative control, symbolic C2, disabled C2-k2 audit

## 1. Purpose

Trahens Core discovers generic rendezvous gateways within a bounded graph radius and establishes opaque bidirectional forwarding state to one selected gateway. Endpoint-specific rendezvous occurs only after the route reaches READY through a private, short-lived, single-use R1 capability.

**System-level boundary.** Core v1.4.1 is not a complete endpoint-anonymity system. R1 removes endpoint-specific selectors from forward discovery, but an authorized initiator still requires a private descriptor-distribution and lookup mechanism. Until D1 or an equivalent independently reviewed directory profile is implemented, directory enumeration, lookup correlation, and directory--gateway collusion remain load-bearing unresolved problems.

A relay learns only its adjacent predecessor and successor relationships and the local capabilities required to forward messages. The protocol never transmits a complete source route. Every forwarded branch receives a fresh adjacent capability, a multiplicatively blinded reply public key, a replacement R1 service-query nonce, a new M2 logical message, a new adjacent-link transmission identifier, new padding, and fresh ciphertexts.

Core v1.4.1 binds T1 recovery to T2 congestion and scheduling and adds T3/T4 adversarial trace evaluation. T1 repairs lost fragments without introducing a cross-hop identifier. T2 defines fixed or quantized-adaptive schedule epochs, finite rate negotiation, weighted fair service, and fail-closed overload behavior. Fixed epochs can replace idle slots with encrypted CHAFF; adaptive epochs reveal their public rate class and do not carry an activity-presence privacy claim.

## 2. Bound profiles

- **U1**: branch-local representation replacement and conditional passive unlinkability.
- **E1**: deterministic event time, candidate windows, route activation, expiry, and cleanup.
- **R1**: generic rendezvous-gateway discovery plus post-READY one-time capability redemption.
- **M2**: canonical suite-agile variable-length logical messages without semantic padding.
- **W2**: canonical 992-byte fragmentation, fixed 1,024-byte encrypted cell body, and bounded reassembly.
- **T1**: encrypted DATA, ACK, and CHAFF frames, selective acknowledgement, bounded timeout recovery, fresh retransmission ciphertexts, and fragment interleaving.
- **T2**: finite schedule epochs, quantized rate classes, authenticated adjacent-link negotiation, hysteresis, weighted DRR, bounded overload behavior, and explicit adaptive-trace leakage.
- **T3**: equal-budget multi-link traffic-analysis evaluation, route classification, correlated-cross-traffic stress, boundary-phase measurement, and active probing.
- **T4**: deterministic packet-event emulation with clock heterogeneity, jitter, shared bottlenecks, route churn, partial observation, open-world rejection, and bounded selective delay.
- **D1 (non-normative)**: a private-directory strawman that makes descriptor-distribution assumptions and collusion boundaries explicit; D1 is not an active wire profile.

## 3. Goals

Core v1.4.1 MUST provide:

1. bounded discovery by hop limit, fan-out, time, branch state, logical bytes, cells, queues, timers, retries, and cryptographic work;
2. no endpoint address, endpoint public key, deterministic endpoint selector, or endpoint capability in DISCOVER;
3. no stable discovery or transport identifier visible across non-adjacent links;
4. fresh branch-local representation for every forwarded child;
5. authenticated responder candidates returned through a nested reply chain whose public keys are multiplicatively blinded at every honest relay;
6. tentative route establishment before initiator selection;
7. explicit COMMIT, READY, CANCEL, ABORT, CLOSE, and expiry behavior;
8. no data-plane authorization before final READY;
9. one-time, finite-lifetime rendezvous capability redemption after route activation;
10. bounded hop-local recovery for incomplete fragmented messages;
11. fresh link encryption and padding for every retry;
12. explicit cost and claim boundaries for CHAFF and fixed-rate scheduling;
13. deterministic fail-closed behavior for disabled research suites;
14. exact separation between equal cell length, fixed-epoch schedule shape, adaptive rate leakage, passive structural unlinkability, active tagging, and end-to-end traffic-flow privacy;
15. bounded queue admission, quantized rate transitions, and weighted fair sharing among concurrent link-local transmissions;
16. equal-bandwidth comparison of fixed, adaptive, and hybrid public schedules under multi-link passive and active analysis;
17. packet-level timestamp evaluation with declared clocks, jitter, bottlenecks, churn, observation scope, open-world metrics, and bounded selective delay.

## 4. Non-goals

Core v1.4.1 does not itself provide:

- an implemented or proven private directory query and descriptor-distribution system;
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

The endpoint registers a random 32-byte capability at selected rendezvous gateways and distributes a descriptor containing the capability, expiration, and acceptable short-lived gateway pseudonyms through a private mechanism outside Core. D1 documents one non-normative two-replica PIR / oblivious-relay strawman. Core does not claim the privacy of descriptor publication or retrieval.

An R1 DISCOVER message contains a fresh 32-byte service-query nonce with no endpoint semantics. Every honest relay replaces it independently for each child. A node responds only if it locally serves as a rendezvous gateway.

The candidate payload contains the gateway's short-lived pseudonym inside the authenticated end-to-end candidate chain. The initiator accepts only candidates listed in the private descriptor. After READY, the initiator sends the capability through the active route; the gateway atomically consumes a live matching registration.

## 8. Forward and reverse transformation

For every outgoing adjacent link, a relay:

1. authenticates T1/T2 records and commits replay state only after authentication;
2. updates the adjacent-link ACK/reassembly context;
3. obtains the complete canonical M2 message;
4. validates local bounds and protocol state;
5. performs the U1 branch, multiplicative reply-key blinding, nonce, label, or candidate transformation;
6. constructs a new M2 message;
7. chooses a fresh T1 transmission identifier for the next link;
8. creates canonical fragments;
9. schedules DATA under the next link's active T1/T2 policy;
10. uses fresh padding and AEAD ciphertext for every first transmission and retry.

Incoming T1 identifiers, ACK state, fragment indexes as a set, send timestamps, retry counters, and scheduler state MUST NOT be copied into the outgoing M2 object.

## 9. Candidate return and route activation

A gateway signs and seals a responder payload containing its short-lived pseudonym, offer expiry, final reply key, commit challenge, and nonce. Each reverse relay adds one authenticated layer containing its non-zero blinding factor and installs tentative mappings. If the incoming reply key is `X_i=x_i B`, the relay samples `b_i` uniformly from `Z_q^*`, emits `X_(i+1)=b_i X_i`, and the initiator later derives `x_(i+1)=b_i x_i mod q`. For a fixed non-identity `X_i`, multiplication by a uniform non-zero scalar gives an exactly uniform non-identity public key. This establishes only the distribution of public reply keys; full nested-layer unlinkability remains conditional on a key-private reply KEM/PKE and composition review.

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

## 12. T3 multi-link traffic analysis

T3 defines an evaluation contract over T2 public traces. It changes no record format. A comparison uses a finite super-epoch and requires every observed directed link to emit the same exact total number of fixed-size cells under fixed, adaptive, and hybrid policies. This removes total bandwidth as a trivial feature while preserving schedule shape, transition timing, queueing, and cross-link correlation as observable evidence.

The mandatory reference attack classifies four route labels using binned public counts, first differences, transition metadata, and lagged cross-link correlation. Independent and correlated background conditions and observation windows of 32, 64, 128, and 256 epochs are evaluated separately. An active-probe experiment injects a bounded known demand pattern and tests for a downstream schedule response.

The hybrid evaluation policy combines a non-zero baseline, smoothed queue response, independent decoy uplifts, and non-boundary transition phases. It is not a new negotiated T2 mode until a deployable online envelope, clock model, and fail-closed overload behavior are separately specified.

T3 results are falsification evidence only. Equal bandwidth does not imply trace equivalence; passing the reference nearest-centroid classifier does not establish resistance to learned correlation, watermarking, routing-level observation, open-world inference, or a global observer.

## 13. Resource safety

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

## 14. Security claims

### 14.1 Structurally claimed

- all active T1/T2 records have equal complete length;
- endpoint capability bytes do not appear in DISCOVER;
- branch tokens and R1 nonces are replaced by honest relays;
- after one honest relay, the reply public key alone is exactly uniform over non-identity group elements under the multiplicative blinding rule;
- T1 transmission identifiers are link-local and replaced at every relay;
- retries produce fresh padding and ciphertext;
- one-time capability replay is rejected by atomic redemption;
- all route, transport, and reassembly state has finite cleanup.

### 14.2 Conditional schedule-shape claim

During a pre-existing fixed T2 schedule epoch, when the queue remains within its configured capacity and CHAFF is emitted in every otherwise idle slot, a passive observer of one link direction sees the same record length and slot timestamps whether the schedule carries protocol traffic or is empty.

### 14.3 Not claimed

- end-to-end or global traffic-flow unlinkability;
- concealment of schedule establishment or termination;
- meaningful complete-system endpoint anonymity before an implemented and reviewed private-directory profile exists;
- anonymity against colluding directory, gateway, and network observers;
- congestion safety equivalent to a standardized transport;
- active-security properties of C1 or the disabled concrete C2 transcription;
- full reply-layer unlinkability without a key-private KEM/PKE argument and composition review;
- production cryptographic security.

## 15. Reply-path security boundary

The active reply path uses the following independently scoped statements:

1. **Public-key distribution.** For every non-identity `X` in the prime-order group, the map `b -> bX` from `Z_q^*` to the non-identity group elements is a bijection. A fresh uniform factor therefore erases the incoming public key as an equality handle after one honest relay.
2. **KDF discipline.** Each reply layer uses one HKDF-Extract and one HKDF-Expand. The 44-byte output is split into a 32-byte AEAD key and a 12-byte nonce; no Expand output is reused as a PRK.
3. **Ephemeral generation.** The production reply-seal API has no caller-supplied ephemeral-secret parameter. Deterministic ephemerals exist only in a separately gated test-support module.
4. **Conditional composition.** The exact public-key statement does not prove that complete encapsulations and ciphertext layers are unlinkable. That claim requires key privacy / receiver anonymity, multi-user chosen-ciphertext analysis, transcript review, and timing/resource analysis.

The detailed games and proof obligation are in `docs/crypto-review/reply-path-security.md`.

## 16. Conformance and evidence

The repository includes deterministic vectors and tests for multiplicative reply-key blinding, a single RFC 5869-style Extract-then-Expand reply-key schedule, production/test API separation for reply ephemerals, R1, M2, W2, T1 DATA/ACK/CHAFF encoding, T2 SCHEDULE encoding, fresh retry ciphertexts, selective ACK validation, bounded retry exhaustion, multi-hop fragmented route setup, quantized rate transitions, weighted service, queue overload, fixed/adaptive leakage, burst loss, and multi-link count correlation.

The experiments show that bounded selective recovery materially improves delivery under independent cell loss. Fixed scheduling yields an identical modeled per-direction public slot trace for active and empty traffic at substantial CHAFF cost. Adaptive scheduling reduces CHAFF and queueing in the evaluated overload workload but exposes an activity-dependent public rate sequence. These artifacts are regression and falsification tools, not proofs of anonymity, stability, or production performance.


## 17. T2 conformance additions

A Core v1.4.1 implementation claiming T2 MUST:

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


## 18. T3 conformance additions

A Core v1.4.1 implementation or simulator claiming T3 conformance MUST:

1. use the same per-link cell budget for every compared schedule profile;
2. report route-classification accuracy, macro-F1, random baseline, and observation window;
3. evaluate both independent and correlated cross traffic;
4. keep training and testing samples disjoint;
5. report schedule-boundary alignment and lagged cross-link correlation;
6. include a bounded active-probe present/absent experiment;
7. report delivery, queue, cleanup, and budget mismatches;
8. distinguish an offline equal-budget evaluation envelope from a deployable online T2 scheduler;
9. publish deterministic vectors and report-generation commands;
10. make no global traffic-flow unlinkability claim.

## 19. T4 conformance additions

T4 refines the T3 equal-budget trace into timestamped per-cell packet events. It models finite access-link serialization, optional shared bottlenecks, bounded propagation jitter, independent observer-clock skew and offset, timestamp noise and quantisation, partial observation, route churn, open-world classification, and a bounded selective-delay probe.

T4 is an analysis profile only. It introduces no message, frame, field, identifier, key, or scheduler negotiation. Every target cell that crosses an honest relay is represented by a new model-local token; route labels and target/background classifications are never network-visible.

A Core v1.4.1 implementation or simulator claiming T4 conformance MUST:

1. preserve the declared exact public-cell budget for every compared profile and report every mismatch;
2. use a deterministic packet-event model with finite serialization and explicitly declared propagation, jitter, queue, and bottleneck parameters;
3. model each observer clock independently and publish skew, offset, noise, and timestamp-quantisation parameters;
4. keep monitored-route training and testing disjoint, use separate unknown routes for rejection-threshold calibration, and reserve another disjoint unknown set for testing;
5. report monitored true-positive rate, unknown false-positive rate, monitored precision, macro-F1, delivery, delay, queue, cleanup, and exact-budget metrics rather than overall accuracy alone;
6. declare the observed-link subset and evaluate partial observation separately from complete observation;
7. declare the route-churn process and report its effect on delivery, expiry, and inference separately;
8. state the delayed link, delay amplitude, pulse period, pulse width, phase/lag search bound, and training/testing split for every selective-delay experiment;
9. ensure that model-only route labels, target classifications, and lineage tokens never become wire-visible protocol fields; and
10. treat the reference classifier and probe as falsification instruments only, making no global traffic-flow unlinkability claim and no general inference from a negative detector result.

The active Core profiles therefore impose three distinct public-trace statements:

1. T1 fixed scheduling can make per-slot encrypted class independent under the stated epoch assumptions;
2. T3 tests route-level count traces under an exact total bandwidth budget; and
3. T4 tests timestamp traces under a declared packet, clock, bottleneck, churn, observation, and active-probe model.

None of these statements is a theorem against a global observer or a substitute for independent implementation measurements.
