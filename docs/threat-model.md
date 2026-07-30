# Threat model

- Status: Initial model for Core v0.2
- Date: 2026-07-30

## 1. Scope

This model covers expanding-ring discovery, candidate return, route commitment, and active hop-label state. It does not cover a global directory, economic incentives, endpoint malware, or application-layer anonymity failures.

## 2. Protected assets

- endpoint long-term identity keys;
- responder authentication keys;
- route-selection intent;
- complete route topology;
- association between separate ring attempts;
- hop labels and route-state mappings;
- message plaintext and authentication transcripts;
- availability of relay CPU, memory, bandwidth, timers, and label space;
- unlinkability of separate logical discoveries where a privacy profile claims it.

## 3. Trust assumptions

Core v0.2 assumes:

1. cryptographic primitives satisfy their documented security properties;
2. honest nodes generate fresh randomness and enforce local limits;
3. the baseline underlay protects confidentiality and integrity on one adjacent link;
4. local clocks are sufficient to enforce bounded expiry windows;
5. an endpoint device that is fully compromised cannot preserve that endpoint's secrets or anonymity.

Core does not assume that relays, responders, directories, or network operators are globally trusted.

## 4. Adversary classes

### A0 - Passive adjacent peer

Controls one adjacent peer session and records all messages, sizes, timing, and attempt identifiers visible at that node but otherwise follows the protocol.

### A1 - Active relay

Controls one relay and can inspect local state, delay, drop, replay, reorder, modify, inject, or selectively forward messages subject to verification by honest nodes.

### A2 - Colluding relays

Controls multiple relays and combines their local state and observations. Adjacency, placement, and corruption fraction are experiment parameters.

### A3 - Link observer

Observes timing, direction, and size on some underlay links but cannot decrypt honest adjacent-link payloads.

### A4 - Global network observer

Observes all underlay links and may correlate timing and volume. It does not automatically control node memory or keys.

### A5 - Resource adversary

Creates many peer sessions, fresh attempt IDs, duplicates, candidate responses, malformed messages, or incomplete commitments to exhaust bandwidth, CPU, memory, timers, or label space. It may operate Sybil nodes where the underlay admits them.

### A6 - Compromised endpoint

Controls an initiator or responder, including long-term keys, randomness, application state, ring schedule, and route choices. Protection of that endpoint's own identity is outside scope, but damage to unrelated routes should remain bounded.

## 5. Security objectives

### Authentication

- An initiator can verify that READY corresponds to the selected responder and committed transcript.
- A responder can verify that COMMIT is authorized by the attempt initiator or by a capability carried in the selected profile.
- A relay accepts forwarding labels only from the peer and direction to which each label is bound.

### Confidentiality

- Adjacent passive observers cannot read control-message plaintext under the baseline underlay.
- End-to-end protected candidate and commitment fields are not readable or modifiable by relays unless explicitly defined as relay-visible.

### Route-position privacy

- One relay should not learn the complete ordered route.
- A relay necessarily learns its predecessor, selected successors, timing, local labels, and local state lifetime.
- Core v0.2 exposes a stable attempt ID within one attempt; A2 adversaries can correlate that attempt.

### Cross-attempt separation

- The local logical-discovery ID is never transmitted.
- Every ring uses a fresh attempt ID and fresh attempt-scoped ephemeral material.
- Messages do not expose a previous attempt ID, ring index, or retry count.
- No claim is made that timing and topology observers cannot correlate attempts.

### Replay resistance

- Replayed messages cannot allocate unbounded state, extend expiration without fresh authorization, or reactivate expired routes.
- A replay from one attempt is invalid in another attempt context.

### Availability

- Accepted work and state are bounded per peer, per attempt, per time window, globally, and at the initiator across a logical discovery.
- Error behavior does not create a useful amplification oracle.
- Local cleanup does not require cooperation from a malicious peer.

## 6. Privacy objectives by profile

| Objective | Baseline encrypted-link profile | Padded batch profile | Scheduled constant-rate profile |
|---|---|---|---|
| Payload confidentiality on one link | Required | Required | Required |
| Message-size hiding | No | Partial or class-based | Required by profile |
| Timing hiding from A3 | No | Limited | Target property |
| Correlation resistance to A4 | No | Hypothesis only | Experimentally evaluated, not assumed |
| Within-attempt correlation resistance to A2 | No, stable attempt ID | No, stable attempt ID | No, stable attempt ID |
| Cross-attempt direct identifier linkage | Removed | Removed | Removed |
| Cross-attempt timing/topology linkage | Present | Reduced only if profile demonstrates it | Experimentally evaluated |

## 7. Explicit leakage in Core v0.2

A relay can observe:

- a stable attempt ID for one ring;
- incoming and selected outgoing adjacent peers;
- hop count and hop limit unless a later profile hides them;
- service selector unless a later profile protects it;
- message timing and size at the local node;
- whether a child returned a candidate;
- whether the candidate was committed;
- route lifetime and local traffic volume.

Across attempts, an observer may infer a relationship from:

- the same origin-adjacent peer;
- close timing or regular candidate-window spacing;
- similar service selector or options;
- overlapping relay sets;
- similar message-size and profile fingerprints.

The specification must not describe fresh attempt IDs as sufficient unlinkability.

## 8. Attacks to simulate next

1. duplicate injection within one attempt;
2. many fresh attempt IDs from one peer;
3. high-degree topology with maximum legal fan-out;
4. malicious responder candidate spam;
5. delayed candidate arriving during a later ring;
6. replayed COMMIT after tentative state removal;
7. selective forwarding by a strategically placed relay;
8. colluding relays correlating attempts through timing and overlap;
9. peer disconnect during DISCOVER, CANDIDATE, COMMIT, and READY;
10. state pressure that forces deterministic eviction;
11. a Sybil cluster that attracts expanding-ring traffic;
12. adversarial attempts that consume the initiator's full schedule without producing a candidate.

## 9. Required experiment metrics

Cross-attempt experiments must report at least:

- attempts used;
- total transmissions and state allocations;
- unique relays observing any attempt;
- relays observing multiple attempts;
- repeated relay observations;
- candidate repeats;
- success and failure reason;
- setup-time proxy or simulated elapsed time.

## 10. Claim discipline

Every future privacy or security claim must include:

- adversary class and placement;
- corrupted-node fraction or count;
- underlay and privacy profile;
- topology and traffic model;
- protected value and success metric;
- baseline comparison;
- assumptions and known counterexamples.
