# Threat model

- Status: Initial model for Core v0.1
- Date: 2026-07-30

## 1. Scope

This model covers bounded discovery, candidate return, route commitment, and active hop-label state. It does not cover a global directory, economic incentives, endpoint malware, or application-layer anonymity failures.

## 2. Protected assets

- endpoint long-term identity keys;
- responder authentication keys;
- route-selection intent;
- complete route topology;
- hop labels and route-state mappings;
- message plaintext and authentication transcripts;
- availability of relay CPU, memory, bandwidth, and label space;
- unlinkability of separate discoveries where the selected privacy profile claims it.

## 3. Trust assumptions

Core v0.1 assumes:

1. cryptographic primitives satisfy their documented security properties;
2. honest nodes generate fresh randomness and enforce local limits;
3. the baseline underlay protects confidentiality and integrity on one adjacent link;
4. local clocks are sufficient to enforce bounded expiry windows;
5. an endpoint device that is fully compromised cannot preserve that endpoint's secrets or anonymity.

Core does not assume that relays, responders, directories, or network operators are globally trusted.

## 4. Adversary classes

### A0 - Passive adjacent peer

Controls one adjacent peer session and records all messages, sizes, and timing visible at that node but follows the protocol.

### A1 - Active relay

Controls one relay and can inspect local state, delay, drop, replay, reorder, modify, inject, or selectively forward messages subject to cryptographic verification by honest nodes.

### A2 - Colluding relays

Controls multiple relays and combines their local state and observations. Adjacency and placement are parameters of the experiment.

### A3 - Link observer

Observes timing, direction, and size on some set of underlay links but cannot decrypt honest adjacent-link payloads.

### A4 - Global network observer

Observes all underlay links and may correlate timing and volume. It does not automatically control node memory or keys.

### A5 - Resource adversary

Creates many sessions, discoveries, duplicates, candidate responses, or malformed messages to exhaust bandwidth, CPU, memory, timers, or label space. It may also operate Sybil nodes where the underlay admits them.

### A6 - Compromised endpoint

Controls an initiator or responder, including its long-term keys, randomness, application state, and route choices. Protection of that endpoint's own identity is outside scope, but damage to unrelated routes should remain bounded.

## 5. Security objectives

### Authentication

- An initiator can verify that READY corresponds to the selected responder and committed transcript.
- A responder can verify that COMMIT is authorized by the discovery initiator or by the capability carried in the discovery profile.
- A relay accepts forwarding labels only from the peer and direction to which each label is bound.

### Confidentiality

- Adjacent passive observers cannot read control-message plaintext under the baseline underlay.
- End-to-end protected candidate and commitment fields are not readable or modifiable by relays unless explicitly defined as relay-visible.

### Route-position privacy

- One relay should not learn the full ordered route.
- A relay necessarily learns its predecessor, successor, timing, local labels, and local state lifetime.
- Core v0.1 does not hide the stable discovery ID from relays; A2 adversaries can use it for correlation.

### Replay resistance

- Replayed messages cannot allocate unbounded state, extend expiration without fresh authorization, or reactivate expired routes.

### Availability

- Accepted work and state are bounded per peer, globally, and per discovery.
- Error behavior does not create a useful amplification oracle.
- Local cleanup does not require cooperation from a malicious peer.

## 6. Privacy objectives by profile

| Objective | Baseline encrypted-link profile | Padded batch profile | Scheduled constant-rate profile |
|---|---|---|---|
| Payload confidentiality on one link | Required | Required | Required |
| Message-size hiding | No | Partial or class-based | Required by profile |
| Timing hiding from A3 | No | Limited | Target property |
| Correlation resistance to A4 | No | Hypothesis only | Experimentally evaluated, not assumed |
| Correlation resistance to A2 in Core v0.1 | No, stable discovery ID | No, stable discovery ID | No, stable discovery ID |

A profile cannot claim stronger unlinkability until the stable discovery identifier is removed or transformed.

## 7. Explicit leakage in Core v0.1

A relay can observe:

- a stable discovery ID for one discovery;
- incoming and selected outgoing adjacent peers;
- hop count and hop limit unless a later profile hides them;
- service selector unless a later profile protects it;
- message timing and size at the local node;
- whether a child returned a candidate;
- whether the candidate was committed;
- route lifetime and local traffic volume.

The specification must not describe these values as hidden.

## 8. Attacks to simulate first

1. duplicate flood injection from one peer;
2. many parallel discovery IDs from one peer;
3. high-degree topology with maximum legal fan-out;
4. malicious responder candidate spam;
5. delayed candidate arriving after discovery expiry;
6. replayed COMMIT after tentative state removal;
7. selective forwarding by a strategically placed relay;
8. colluding relays correlating the stable discovery ID;
9. peer disconnect during DISCOVER, CANDIDATE, COMMIT, and READY;
10. state pressure that forces deterministic eviction.

## 9. Claim discipline

Every future privacy or security claim must include:

- adversary class and placement;
- corrupted-node fraction or count;
- underlay and privacy profile;
- topology and traffic model;
- protected value and success metric;
- baseline comparison;
- assumptions and known counterexamples.
