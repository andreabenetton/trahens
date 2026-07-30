# Threat model

- Status: Core v1.1 research model
- Date: 2026-07-30

## 1. Scope

This model covers bounded gateway discovery, U1 branch-local replacement, nested candidate return, E1 route commitment and cleanup, R1 capability redemption, M2 logical messages, W2 fixed cells, and bounded reassembly. It does not specify a private directory, global endpoint lookup, incentives, inter-domain policy, application anonymity, or a production traffic scheduler.

## 2. Protected assets

- destination capability and endpoint authentication material;
- association between a private descriptor and forward DISCOVER traffic;
- complete route topology;
- association between non-adjacent branch representations;
- gateway pseudonym before candidate decryption;
- branch, candidate, route, and W2 local capabilities;
- candidate, commit, ready, and rendezvous-open plaintexts;
- relay and gateway CPU, memory, bandwidth, queues, timers, label space, and registration storage.

## 3. Trust assumptions

1. Honest adjacent peers use authenticated encryption, unique nonces, and a replay domain.
2. Honest relays generate independent randomness and apply every required U1 and R1 replacement.
3. Local clocks are sufficient for bounded half-open deadlines.
4. The retained standard primitives satisfy their stated assumptions; their custom composition is still review-required.
5. Gateway capability lookup and deletion are atomic.
6. The private descriptor reaches an authorized initiator without being exposed through the route protocol.
7. A fully compromised endpoint cannot preserve its own secrets or anonymity.

The directory and gateway are explicit trust roles. Core v1.1 makes no privacy claim against their collusion.

## 4. Adversary classes

- **A0 passive adjacent peer:** records plaintext protocol fields and local timing visible at one compromised node.
- **A1 active relay:** injects, drops, delays, reorders, duplicates, replaces, tags, or selectively forwards messages.
- **A2 colluding relays:** combine observations at multiple placements separated by zero or more honest relays.
- **A3 partial link observer:** sees direction, fixed cell count, and timing on selected links but not honest link plaintext.
- **A4 global network observer:** observes all cell timing and volume.
- **A5 resource adversary:** creates peers, fresh branches, fragments, candidates, invalid redemptions, and registrations to exhaust resources.
- **A6 compromised initiator or destination:** controls local descriptors, capabilities, keys, randomness, and route choices.
- **A7 malicious directory or gateway:** observes or manipulates descriptor delivery, registration, candidate response, redemption, endpoint handles, and selective service.

## 5. Security objectives

### Forward discovery

- No endpoint capability, capability commitment, endpoint key, endpoint address, gateway pseudonym, or endpoint handle appears in active DISCOVER.
- The R1 service-query nonce is independent of destination choice and replaced at every honest relay.
- No network-wide discovery identifier is transmitted.

### Authentication and activation

- The initiator verifies the selected gateway candidate and READY transcript.
- A relay accepts tokens and route labels only from their bound peer, link epoch, direction, generation, and lifetime.
- Application traffic and capability redemption are forbidden before final READY.

### Capability use

- The capability is carried only inside an end-to-end protected active route.
- At most one redemption succeeds for one live commitment.
- Replay, expiry, wrong gateway, and malformed input share a generic failure class.

### Resource safety

- Accepted work is bounded per peer and globally.
- Incomplete reassembly cannot allocate route-semantic state.
- Local cleanup does not require remote cooperation.
- Advisory cleanup loss cannot create permanent state.

## 6. Profile-dependent privacy

| Property | Link baseline | U1/R1 transform | U1/R1 plus scheduler | Separate directory profile |
|---|---|---|---|---|
| Link payload confidentiality | Required | Required | Required | Independent |
| Endpoint selector absent from DISCOVER | No | Required | Required | Descriptor dependent |
| Branch-local field replacement | No | Required | Required | Independent |
| Fixed cell length | Optional | Required by W2 | Required | Independent |
| Batch-local matching resistance | No | Structural only | Conditional claim | Independent |
| Traffic-flow unlinkability | No | No | Evaluated profile required | Independent |
| Private descriptor lookup | No | No | No | Required |
| Directory/gateway collusion resistance | No | No | No | Separate claim required |

## 7. Explicit leakage

A compromised relay learns its ingress and selected egress peers, local branch and route capabilities, hop and fan-out classes not otherwise hidden, cell direction and timing, candidate return, local commit/ready status, route lifetime, and local traffic volume. A link observer sees fixed-size cell timing and count. A gateway learns registration commitments, redemption time, and the local endpoint handle. A directory may learn which descriptor was delivered.

## 8. Claims not made

Core v1.1 does not claim:

- sender or destination anonymity against a global timing observer;
- private descriptor lookup;
- protection against colluding directory and gateway operators;
- active unlinkability through timing, selective delay, or topology;
- security of C1, symbolic C2, or the disabled C2 transcription as active eligibility;
- proof of the custom reply KEM composition;
- post-quantum or production security.

## 9. Required experiments

1. multi-relay passive and active matching with one honest replacement boundary;
2. selective delay and drop tags under a scheduler;
3. capability theft and redemption races;
4. malicious gateway pseudonyms and candidate spam;
5. directory enumeration and selective descriptor denial;
6. fragment sprays, conflicting duplicates, and distributed peer rotation;
7. bounded retransmission under loss and attacker-induced repair;
8. Sybil gateway clusters and operator collusion;
9. traffic classifiers over timing, direction, and cell count;
10. independent parser, state-machine, and capability-store fuzzing.
