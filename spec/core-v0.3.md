# Trahens Core v0.3

- Status: Research design draft
- Date: 2026-07-30
- Scope: bounded route discovery with branch-local contexts and conditional non-adjacent message unlinkability
- Replaces: Core v0.2 as the active design draft

## 1. Purpose

Trahens Core discovers one or more eligible responders within a bounded graph radius and establishes opaque bidirectional forwarding state to one selected responder. A relay learns only its adjacent predecessor and successor relationships and the local capabilities required to forward messages. No relay receives a complete source route.

Core v0.3 restores the unlinkability objective of the 2020 draft by removing attempt-wide wire identifiers and by requiring a complete cryptographic transformation at every forwarding hop. Each outgoing branch receives a fresh link-local token, a fresh blinded reply public key, a rerandomized eligibility capsule, fresh forwarding labels, and a fresh adjacent-link ciphertext.

This version distinguishes three properties that were conflated in the legacy draft:

1. **wire-image unlinkability** - protocol fields do not provide a deterministic equality test across non-adjacent hops;
2. **batch-local message unlinkability** - after at least one honest transformation and mixing boundary, a passive observer cannot match one input message to one output message with more than negligible cryptographic advantage plus the inverse anonymity-set advantage;
3. **traffic-flow unlinkability** - resistance to correlation by timing, volume, topology, and active tagging.

Core v0.3 specifies the first property and the protocol mechanism required for the second. The second is conditional on the U1 privacy profile. The third requires an independently specified traffic-scheduling profile and remains outside Core.

## 2. Normative language

The terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as in BCP 14 when written in uppercase.

## 3. Changes from v0.2

1. `attempt_id` is removed from the wire protocol.
2. Attempt-wide duplicate suppression is removed from the U1 profile.
3. Every accepted ingress creates an independently bounded branch context.
4. Exact replays are rejected only within the adjacent-link replay domain.
5. Every outgoing branch uses an independently random branch token.
6. The initiator uses an independent root reply key for each first-hop branch.
7. Every relay blinds the reply public key before forwarding.
8. Every relay rerandomizes the responder eligibility capsule before forwarding.
9. Candidate identifiers and route identifiers are either link-local capabilities or end-to-end protected values; they are not stable relay-visible identifiers.
10. Candidate return is a nested encrypted capsule that permits the initiator to reconstruct the reply-key blinding chain.
11. Fixed-size control records and a mixing boundary are mandatory for the U1 unlinkability claim.
12. The loss of attempt-wide deduplication is explicitly charged as state and transmission amplification.

## 4. Goals

Core v0.3 MUST provide:

1. bounded discovery by hop limit, fan-out, time, branch-context count, control bytes, and cryptographic work;
2. no stable discovery identifier visible at more than one adjacent link;
3. fresh branch context for every forwarded copy;
4. responder authentication inside an end-to-end protected candidate capsule;
5. hop-local opaque route labels;
6. tentative route establishment before initiator selection;
7. explicit commit, readiness, expiration, abort, and close behavior;
8. bidirectional forwarding state without disclosing the complete route;
9. deterministic local behavior under exact replay, stale messages, loss, and resource pressure;
10. measurable cost for the removal of attempt-wide duplicate suppression;
11. a precisely scoped non-adjacent message unlinkability claim under the U1 profile.

## 5. Non-goals

Core v0.3 does not by itself provide:

- global endpoint lookup;
- inter-domain routing policy;
- incentives or settlement;
- congestion control for application data;
- protection against a passive global timing observer;
- active-tagging resistance without a concrete reviewed rerandomizable-encryption profile;
- Sybil resistance;
- a replacement for IP or a new layer-2 technology;
- a proof that expanding-ring attempts cannot be correlated by origin adjacency or timing.

## 6. System model

The network is an undirected graph \(G=(V,E)\). A node can act as initiator, relay, responder, or any combination of these roles. An edge denotes an authenticated adjacent-link association supplied by the underlay profile.

A route of length \(d\) is a sequence

\[
\rho=(n_0,n_1,\ldots,n_d),
\]

where \((n_i,n_{i+1})\in E\), \(n_0\) is the initiator, and \(n_d\) is a responder. The protocol does not transmit \(\rho\) as an object.

## 7. Underlay contract

The baseline underlay MUST provide:

- adjacent-peer authentication or an explicitly anonymous authenticated channel;
- confidentiality and integrity for one adjacent link;
- message boundaries and a maximum record size;
- a link epoch and replay domain;
- notification of peer connection and disconnection;
- a peer-local identifier that is not treated as a global identity.

For U1, the underlay or privacy profile MUST additionally provide:

- fixed-size records for each control-message class;
- fresh nonces and ciphertexts for every transmission;
- batching and permutation with a declared minimum anonymity set;
- a declared release schedule and cover-traffic policy.

## 8. Discovery scopes

### 8.1 Logical discovery

A logical discovery is local initiator state. It contains the application request, ring policy, cumulative budgets, candidate set, deadline, and selection policy. Its identifier MUST NOT be transmitted.

### 8.2 Local ring attempt

A ring attempt is also local policy state. The ring index, retry count, previous ring parameters, and previous branch tokens MUST NOT be transmitted.

### 8.3 Branch context

A branch context is the only relay-visible discovery scope. It is bound to:

- one ingress peer;
- one ingress branch token;
- one adjacent-link epoch;
- one incoming blinded reply public key;
- one expiration;
- bounded child mappings and candidate-response counters.

A branch context has no network-wide identifier.

## 9. Link-local capabilities

### 9.1 Branch token

For every outgoing child, a sender samples an independent uniformly random branch token \(\tau\) with at least 128 bits of entropy. The tuple

\[
(\text{link epoch},\text{peer},\tau)
\]

is meaningful only to the two adjacent peers. A token MUST NOT be reused.

### 9.2 Candidate token

A relay maps a child-local candidate token to an independently generated parent-local candidate token. Candidate tokens MUST NOT be forwarded unchanged.

### 9.3 Route labels

Forward and reverse route labels are independently random local capabilities. A label is accepted only from its bound peer, in its bound direction, during its bound route generation, and before expiration.

## 10. Reply-key blinding

The U1 profile uses a prime-order group \(\mathbb{G}\) of order \(q\) with generator \(G\). For each first-hop branch, the initiator samples

\[
x_0\leftarrow \mathbb{Z}_q^*,\qquad P_0=x_0G.
\]

A relay receiving reply public key \(P_i\) and forwarding to child \(j\) samples an independent non-zero scalar

\[
\delta_{i,j}\leftarrow \mathbb{Z}_q^*
\]

and computes

\[
P_{i+1,j}=P_i+\delta_{i,j}G.
\]

The relay stores \(\delta_{i,j}\) only in the child branch context. The outgoing public key is computationally independent of the incoming key under the stated group assumptions. A concrete tweakable KEM and its security proof are required before implementation.

## 11. Eligibility capsule

The initiator creates an eligibility capsule \(Q_0\) that can be opened only by an eligible responder or service group. Each forwarding relay computes

\[
Q_{i+1,j}\leftarrow\operatorname{ReEnc}(Q_i;r_{i,j})
\]

using fresh randomness \(r_{i,j}\). The rerandomization operation MUST preserve the plaintext and destination eligibility while making the output unlinkable to the input under the selected URE security definition.

A deployment that forwards an unchanged eligibility capsule does not conform to U1 and MUST NOT claim non-adjacent wire-image unlinkability.

## 12. Discovery initiation

For each first-hop branch, the initiator:

1. checks cumulative deadline and budgets;
2. samples a fresh root reply key pair \((x_0,P_0)\);
3. samples a fresh branch token;
4. independently encrypts or rerandomizes the eligibility capsule;
5. constructs one fixed-size `DISCOVER` body;
6. sends the body in a fresh adjacent-link record.

No two first-hop branches reuse a reply public key, branch token, eligibility ciphertext, or adjacent-link ciphertext.

## 13. Relay processing of DISCOVER

A relay receiving `DISCOVER` MUST apply the validation order in `messages-v0.3.md`. If admitted, it creates one branch context. It MUST NOT search for a network-wide duplicate identifier because none exists.

For each selected child, the relay:

1. excludes the ingress peer;
2. samples a fresh child branch token;
3. samples a fresh reply-key blinding scalar;
4. computes the child reply public key;
5. rerandomizes the eligibility capsule;
6. rewrites all mutable fields into a fresh canonical body;
7. pads the body to the profile record size;
8. enqueues it into the configured mixing batch.

Longer cycles and converging branches can cause the same physical node to accept multiple independent contexts. Hard limits are therefore mandatory.

## 14. Candidate return

An eligible responder authenticates its offer inside a candidate payload and seals it to the received reply public key. Let the responder be at depth \(d\). It constructs

\[
C_d=\operatorname{Seal}(P_d,\mathsf{CandidatePayload}).
\]

For the selected child branch, relay \(n_i\) stores the blinding scalar \(\delta_i\) used to derive \(P_{i+1}\) from \(P_i\). On reverse propagation it constructs

\[
C_i=\operatorname{Seal}
\left(P_i,\operatorname{Encode}(\delta_i,C_{i+1},\mathsf{LocalOfferData}_i)\right).
\]

The relay replaces the child candidate token with a fresh parent candidate token and creates tentative route labels. It does not learn the responder payload.

The initiator decrypts \(C_0\) with \(x_0\), obtains \(\delta_0\), derives

\[
x_1=x_0+\delta_0\pmod q,
\]

and repeats until it recovers and authenticates the responder candidate.

## 15. Commit and readiness

The candidate return installs tentative hop-local mappings. The initiator selects at most one candidate and sends `COMMIT` through the first-hop tentative label. Every relay:

- validates the incoming peer and label;
- atomically activates the selected tentative mapping;
- replaces any child-facing setup label with a fresh active label when required by the profile;
- forwards the commit without a global candidate or route identifier.

The responder verifies the end-to-end commit secret contained in the protected candidate transcript and returns `READY` through the reverse mappings. Application traffic is admitted only after `READY` succeeds.

## 16. Exact replay and loop handling

The adjacent-link replay domain rejects exact retransmission of a record or branch token on the same link epoch. A branch arriving over another peer or with another token is not a duplicate for U1 and may be accepted as a separate context.

The protocol excludes immediate backtracking to the ingress peer. A deployment MAY use a privacy-preserving two-hop adjacency-intersection mechanism, but it MUST NOT expose a stable path vector or route fingerprint.

## 17. Resource bounds

Every node MUST define finite limits for:

- accepted branch contexts per peer and per node;
- contexts for one physical node or local service identity;
- outgoing children per branch;
- total transmitted discovery records per time window;
- candidate responses per child, branch, peer, and node;
- tentative and active mappings;
- public-key, rerandomization, and signature operations;
- branch, candidate, and route lifetimes;
- retained bytes and timers.

The initiator separately enforces cumulative logical-discovery budgets across all rings and first-hop branches.

## 18. Conditional unlinkability statement

Let \(m_i\) and \(m_{i+k}\) denote two representations of one logical discovery branch observed at non-adjacent positions, with \(k>2\). Under U1, the direct protocol-field matching advantage is intended to be negligible when:

1. at least one intermediate relay is honest and performs all required transformations;
2. branch tokens, labels, nonces, blinding scalars, and rerandomization coins are sampled independently;
3. the eligibility capsule satisfies the selected URE anonymity and rerandomization definitions;
4. reply-key blinding satisfies the selected tweakable-KEM security definition;
5. records are equal in length and message class;
6. the honest relay releases a permuted batch containing at least two indistinguishable records;
7. the adversary is passive for the observed messages and is not given a timing or volume side channel.

This is not a claim against a global timing observer or an active tagging adversary. Those claims require additional profiles and proofs.

## 19. Required measurements

Experiments MUST report at least:

- discovery success rate;
- discovery transmissions;
- accepted branch contexts;
- unique relays reached;
- repeated contexts at one physical relay;
- loop re-entry contexts, measured by the simulator but not protocol-visible;
- candidate responses and unique authenticated candidates;
- per-node context maximum;
- transmission and state budget exhaustion;
- context amplification \(A_c=B/U\), where \(B\) is accepted branch contexts and \(U\) is unique relays;
- adversarial matching success under the declared batching and traffic model.

## 20. Status of the design

Core v0.3 restores the protocol structure required for the legacy bit-pattern unlinkability objective. It does not yet provide a production cryptographic suite or a complete proof. `unlinkability-profile-u1.md` and `crypto-transcript-v0.1.md` define the remaining proof and implementation obligations.
