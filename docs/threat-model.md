# Threat model

- Status: Core v0.3 research model
- Date: 2026-07-30

## 1. Scope

This model covers branch-local discovery, candidate return, route commitment, active hop-label state, and the U1 non-adjacent message unlinkability profile. It does not cover a global directory, endpoint malware, application-layer anonymity failures, incentives, or inter-domain routing policy.

## 2. Protected assets

- endpoint and responder long-term authentication keys;
- responder eligibility and route-selection intent;
- complete route topology;
- association between protocol messages at non-adjacent hops;
- association between local expanding-ring attempts;
- hop labels, branch tokens, candidate tokens, and route-state mappings;
- candidate and commit plaintexts;
- relay CPU, memory, bandwidth, timers, queue space, and label space.

## 3. Trust assumptions

Core v0.3 assumes:

1. selected primitives satisfy their documented security definitions;
2. honest nodes generate independent randomness and erase expired secrets;
3. the adjacent-link underlay provides authenticated encryption and a replay domain;
4. U1-conforming relays apply every required field transformation and batch permutation;
5. local clocks are sufficient for bounded expiry and queue deadlines;
6. a fully compromised endpoint cannot preserve its own secrets or anonymity.

No relay, responder, network operator, or future directory is globally trusted.

## 4. Adversary classes

### A0 - Passive adjacent peer

Controls one adjacent peer session and records plaintext protocol bodies, local tokens, sizes, and timing visible at that node while otherwise following the protocol.

### A1 - Active relay

Controls one relay and can inspect local state, delay, drop, replay, reorder, modify, inject, tag, or selectively forward messages subject to validation by honest nodes.

### A2 - Colluding relays

Controls multiple relays and combines their local states and observations. Placement, distance, corruption fraction, and whether an honest mixing boundary lies between observations are explicit experiment parameters.

### A3 - Partial link observer

Observes direction, size, and timing on selected underlay links but cannot decrypt records on honest adjacent links.

### A4 - Global network observer

Observes all underlay links and correlates timing and volume. It does not automatically control node memory or keys.

### A5 - Resource adversary

Creates many peer sessions, branch tokens, rerandomized messages, candidates, malformed capsules, or incomplete commitments to exhaust bandwidth, cryptographic work, memory, timers, or mixing queues. It may operate Sybil nodes where admitted by the underlay.

### A6 - Compromised endpoint

Controls an initiator or responder, including keys, randomness, application state, local ring policy, and route choices. Harm to unrelated routes must remain bounded.

## 5. Security objectives

### Authentication

- The initiator verifies that READY corresponds to the selected responder candidate and commit transcript.
- The responder verifies the protected commit challenge.
- A relay accepts branch tokens and route labels only from their bound peer and link epoch.

### Confidentiality

- Adjacent external observers cannot read link-protected protocol bodies.
- Relays cannot read end-to-end candidate, commit, and ready payloads.
- Eligibility information is hidden according to the selected rerandomizable-encryption profile.

### Route-position privacy

- A relay does not receive the complete ordered route.
- A relay necessarily learns its ingress peer, selected child peers, local queue behavior, local capabilities, and state lifetime.

### Non-adjacent message unlinkability

Under U1 and its passive challenge game, protocol fields should not permit matching of one input message to one output message across an honest transformation and mixing boundary. This property is conditional on the URE and reply-key-blinding primitives, fixed-size records, and the absence of timing side channels.

### Cross-attempt separation

- Logical-discovery and ring identifiers are local only.
- First-hop branches use independent keys, tokens, and ciphertexts.
- No claim is made that origin adjacency, scheduling, or topology cannot correlate local attempts.

### Replay resistance

- Exact link-local replays cannot allocate unbounded state or extend lifetimes.
- A token or label is invalid outside its peer, link epoch, direction, and generation.
- Distinct branch tokens are not treated as duplicates, and their cost is bounded separately.

### Availability

- Accepted work is bounded per peer, branch, physical node, time window, queue, and node global state.
- Local cleanup does not require remote cooperation.
- Error behavior does not provide an amplification or detailed capacity oracle.

## 6. Privacy properties by profile

| Property | Encrypted-link baseline | U1 wire transformation | U1 plus mixing | Future traffic-scheduling profile |
|---|---|---|---|---|
| Link payload confidentiality | Required | Required | Required | Required |
| Stable protocol-field removal | No | Required | Required | Required |
| Fixed-size control records | Optional | Required | Required | Required |
| Eligibility-capsule rerandomization | No | Required | Required | Required |
| Reply-key blinding | No | Required | Required | Required |
| Batch input/output permutation | No | No | Required | Required |
| Passive non-adjacent matching resistance | No | Cryptographic wire-image only | Conditional U1 claim | Conditional plus timing model |
| Active tagging resistance | No | Not claimed | Not claimed until reviewed primitive | Required by future profile |
| Global timing correlation resistance | No | No | No | Experimentally evaluated |

## 7. Explicit leakage in Core v0.3

A compromised relay can observe:

- its ingress and selected egress peers;
- one link-local branch token and local child tokens;
- propagation and fan-out classes unless later hidden;
- record class and local timing;
- whether a child returned a candidate;
- whether a local tentative mapping was committed;
- route lifetime and local traffic volume;
- repeated independent branch contexts reaching the same physical relay.

Across local ring attempts, observers may correlate:

- the same origin-adjacent link;
- close or periodic candidate windows;
- identical record-class and suite fingerprints;
- overlapping relay populations;
- similar resource and stop behavior.

## 8. Claims not made

Core v0.3 does not claim:

- sender or receiver anonymity against A4;
- flow unlinkability from adjacent-link encryption alone;
- active-tagging resistance for an unspecified URE scheme;
- that branch-local contexts are cheaper than attempt-wide deduplication;
- that fixed-size records hide timing or origin adjacency;
- post-quantum security.

## 9. Required experiments

1. U1 matching game with two compromised non-adjacent relays and one honest mixer;
2. unchanged-field and malformed-capsule negative tests;
3. active tagging and selective-delay experiments;
4. branch-context amplification on cyclic and high-degree graphs;
5. malicious fresh-branch floods under token buckets;
6. candidate spam and incomplete commit pressure;
7. cross-ring correlation by origin adjacency and timing;
8. mixing queue overflow and minimum-chaff behavior;
9. packet loss, churn, and delayed candidate return;
10. Sybil clusters and strategically placed relays.

## 10. Claim discipline

Every claim names:

- adversary class and placement;
- passive or active behavior;
- honest-relay count between observations;
- underlay, U1, mixing, and traffic profiles;
- topology and workload;
- protected value and success metric;
- resource limits;
- assumptions, exclusions, and known counterexamples.
