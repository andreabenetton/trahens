<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Threat model

- Status: Core v1.4 research model
- Date: 2026-07-30

## 1. Scope

This model covers bounded gateway discovery, U1 branch-local replacement, nested candidate return, E1 route commitment and cleanup, R1 capability redemption, M2 logical messages, W2 fragmentation, T1 selective recovery, T2 adjacent-link scheduling, T3 multi-link count-trace evaluation, and T4 packet-level adversarial evaluation. It does not specify a private directory, global endpoint lookup, incentives, inter-domain policy, application anonymity, end-to-end congestion control, or a production traffic-analysis defense.

## 2. Protected assets

- destination capability and endpoint authentication material;
- association between a private descriptor and forward DISCOVER traffic;
- complete route topology;
- association between non-adjacent branch, recovery, or scheduling representations;
- gateway pseudonym before candidate decryption;
- branch, candidate, route, reassembly, queue, and link-local transmission capabilities;
- candidate, COMMIT, READY, RENDEZVOUS_OPEN, ACK, and SCHEDULE plaintexts;
- relay and gateway CPU, memory, bandwidth, timers, label space, queue service, and registration storage.

## 3. Trust assumptions

1. Honest adjacent peers use authenticated encryption, unique nonces, and an authenticated replay domain.
2. Honest relays generate independent randomness and apply every required U1 and R1 replacement.
3. Local clocks are sufficient for bounded half-open deadlines and schedule epochs.
4. The retained standard primitives satisfy their stated assumptions; their custom composition remains review-required.
5. Gateway capability lookup and deletion are atomic.
6. The private descriptor reaches an authorized initiator without exposure through the route protocol.
7. T2 peers enforce the negotiated finite rate menu, queue limits, and epoch boundaries.
8. A fully compromised endpoint cannot preserve its own secrets or anonymity.

The directory and gateway are explicit trust roles. Core v1.4 makes no privacy claim against their collusion. T2 negotiation contents are confidential only from parties that do not control either adjacent endpoint; cadence remains public.

## 4. Adversary classes

- **A0 passive adjacent peer:** observes plaintext protocol state and local timing at one compromised node.
- **A1 active relay:** injects, drops, delays, reorders, duplicates, replaces, tags, selectively forwards, manipulates ACK timing, or proposes schedule changes.
- **A2 colluding relays:** combine observations at placements separated by zero or more honest relays.
- **A3 partial link observer:** sees direction, fixed record length, cell count, epoch boundaries, public rate class, and timing on selected links.
- **A4 global network observer:** observes all link timing, volume, rate changes, topology-level relationships, and schedule starts/stops.
- **A5 resource adversary:** creates peers, fresh branches, fragments, retransmissions, negotiations, candidates, invalid redemptions, and registrations to exhaust resources.
- **A6 compromised initiator or destination:** controls descriptors, capabilities, keys, randomness, and route choices.
- **A7 malicious directory or gateway:** observes or manipulates descriptor delivery, registration, candidate response, redemption, endpoint handles, and selective service.
- **A8 congestion adversary:** induces queue pressure, burst loss, ACK suppression, or competing traffic to force rate changes, visible overload, or deadline failure.
- **A9 T3 trace adversary:** observes several directed links over a declared window, uses correlated background traffic and labeled training traces, and injects a bounded positive-demand probe without modifying authenticated records.
- **A10 T4 packet adversary:** observes timestamped fixed-size cells through declared heterogeneous clocks, may see only a subset of links, trains open-world classifiers on disjoint route sets, observes route churn, and applies a bounded selective delay to one declared link.

## 5. Security objectives

### Forward discovery

- No endpoint capability, commitment, key, address, gateway pseudonym, or endpoint handle appears in active DISCOVER.
- The R1 service-query nonce is independent of destination choice and replaced at every honest relay.
- No network-wide discovery, recovery, or schedule-negotiation identifier is transmitted.

### Authentication and activation

- The initiator verifies the selected gateway candidate and READY transcript.
- A relay accepts tokens and route labels only from their bound peer, link epoch, direction, generation, and lifetime.
- Application traffic and capability redemption are forbidden before final READY.

### Capability use

- The capability is carried only inside an end-to-end protected active route.
- At most one redemption succeeds for one live commitment.
- Replay, expiry, wrong gateway, and malformed input share a generic failure class.

### T1 recovery

- Transmission identifiers, fragment bitmaps, timers, and retry counters terminate at every relay.
- Retries use fresh public sequence numbers, padding, tags, and ciphertexts.
- Partial or unauthenticated reassembly cannot allocate route-semantic state.
- Recovery work and completion caches are finite.

### T2 congestion and schedules

- The rate menu, maximum class, epoch duration, queue capacity, weights, control reserve, and transition counters are finite.
- Adaptive changes occur only at authenticated epoch boundaries and move by at most one class.
- A stale, conflicting, rejected, or unauthenticated negotiation cannot change the cadence.
- At maximum class, persistent overload causes bounded admission rejection or local failure, not an implicit faster schedule.
- Weighted service cannot be remotely converted into unbounded priority or deficit.
- DATA, ACK, SCHEDULE, and CHAFF share the declared physical-cell budget; controls do not create hidden extra slots.


### T3 traffic-analysis evaluation

- Every compared profile uses the same exact per-link super-epoch cell budget.
- Training and testing traces are disjoint; feature normalization uses training data only.
- Route-class balance, random baseline, observation window, cross-traffic condition, and failure accounting are explicit.
- Probe amplitude and duty cycle are finite and reported.
- T3 trace and classifier state never enters forwarding messages or route-semantic state.
- No one-classifier result is promoted to a global traffic-flow anonymity claim.

### T4 packet-level evaluation

- Every compared profile retains the exact declared public-cell budget.
- Access-link and shared-bottleneck serialization, propagation jitter, clock skew, offset, noise, and quantisation are explicit.
- Unknown calibration and unknown testing routes are disjoint.
- Feature normalization and rejection-threshold selection exclude test traces.
- Reports include monitored true-positive rate, unknown false-positive rate, precision, delivery, delay, queues, budget, and cleanup.
- Selective delay is bounded and reported; a negative detector result creates no general active-security claim.
- T4 model labels, token kinds, clock state, and classifier state never enter protocol messages or route state.

### Resource safety

- Accepted work is bounded per peer and globally.
- Local cleanup does not require remote cooperation.
- Advisory control messages cannot indefinitely extend deadlines.
- Queue occupancy, residence time, retries, rate transitions, and CHAFF lifetime are bounded.

## 6. Claim classes

### C-LEN: fixed cell length

A passive observer sees one outer length for DATA, ACK, SCHEDULE, and CHAFF. This does not hide cell count, timing, direction, or rate class.

### C-U1: structural replacement

After at least one honest relay, no protocol field is intentionally copied as a stable cross-hop equality handle. This excludes timing, topology, active delay tags, selective forwarding, compromised endpoints, and implementation side channels.

### C-FIXED: conditional fixed-schedule shape

Inside a pre-existing, non-overloaded fixed epoch, public timestamps and lengths are independent of whether each encrypted slot carries DATA, ACK, SCHEDULE, or CHAFF. The claim excludes epoch establishment, start/stop, direction, topology, overflow, peer compromise, and cross-link correlation.

### C-ADAPT: adaptive-rate transparency

Adaptive T2 does **not** claim activity-presence hiding. The public rate-class sequence and transition times are treated as coarse traffic evidence. Encrypted negotiation hides reasons and local queue values, not the resulting cadence.


### C-T3: equal-budget adversarial evaluation

T3 removes aggregate byte count as a trivial feature by equalizing complete per-link super-epoch cell budgets. It does not claim equal trace distributions. Route classification, transition phases, lagged correlation, and active-probe detectability are measured and reported as evidence of residual schedule leakage.

### C-T4: packet-level adversarial evaluation

T4 refines exact-budget schedules into timestamped packet events under a declared clock, jitter, bottleneck, churn, observation, open-world, and selective-delay model. It is a falsification profile, not evidence against stronger learned, adaptive, or global attacks.

### C-GLOBAL: traffic-flow unlinkability

No C-GLOBAL claim is made. Equal-length cells, local replacement, CHAFF, and quantized adaptation do not by themselves prevent a global observer from correlating timing and volume.

## 7. Attacks and required responses

- **Fresh-branch flood:** token buckets, branch/global budgets, expiry, and bounded fan-out.
- **Fragment spray:** authenticated-cell processing, reserved-byte limits, context caps, conflict invalidation, and timeout.
- **ACK manipulation:** authentication, canonical bitmaps, finite delayed-ACK bounds, retry cap, and no cross-hop propagation.
- **Schedule negotiation flood:** authenticated peer-only frames, bounded pending negotiations, guard time, and control reserve.
- **Rate oscillation:** adjacent-class transitions, minimum hold, asymmetric high/low hysteresis, and peer maximum.
- **Queue capture:** atomic first-send reservation, per-flow/per-peer/global limits, finite weights, and DRR.
- **Burst loss:** finite recovery and cleanup; no assumption that every loss proves congestion.
- **Schedule fingerprinting:** fixed profile for the narrow shape claim; adaptive profile declares rate leakage; realistic classifiers remain required.
- **Multi-link correlation:** T3 provides an equal-budget count-trace classifier. T4 adds packet timestamps, partial observation, open-world unknowns, and churn; stronger learned and deployment attacks remain outside protection.
- **Selective delay:** T4 measures one bounded phase/lag detector; adaptive watermarking, congestion, loss, and multi-point attacks remain outside protection.
- **Capability replay:** atomic one-time consume and generic failure.
- **Directory/gateway collusion:** not prevented; must be addressed by a separate profile.

## 8. Residual leakage

Even when all current requirements hold, an observer may learn or infer:

- adjacent peer identities and topology;
- epoch start, end, direction, fixed or adaptive rate, and class transitions;
- route length or candidate size through cell count and timing;
- congestion, retry exhaustion, overload rejection, and setup completion;
- correlation from shared bottlenecks, propagation delay, clock behavior, or synchronized scheduling;
- gateway use, registration timing, and redemption timing at a compromised gateway;
- descriptor queries at a compromised directory.

## 9. Evidence boundary

Deterministic tests establish codec invariants, finite cleanup, reproducibility, and modeled behavior. They do not establish cryptographic reductions, anonymity against an unmodeled observer, network stability, throughput in real deployments, or side-channel resistance. A production claim requires independent implementations, fuzzing, independent packet/network emulation, open-world and adaptive classifier evaluation, and external cryptographic and transport review.
