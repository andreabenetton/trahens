# Trahens Core v0.8

- Status: Active research design
- Date: 2026-07-30
- Scope: bounded privacy-enabled route discovery with branch-local contexts, variable logical messages, fixed-size encrypted cells, bounded reassembly, and an integrated cryptographic lifecycle
- Supersedes: Core v0.7

## 1. Purpose

Trahens Core discovers one or more eligible responders within a bounded graph radius and establishes opaque bidirectional forwarding state to one selected responder. A relay learns only its adjacent predecessor and successor relationships and the local capabilities required to forward messages. No relay receives a complete source route.

Every forwarded branch is independently transformed. It receives a fresh adjacent-link token, a tweaked reply public key, a rerandomized eligibility capsule, regenerated padding, and a fresh authenticated link ciphertext. Candidate return uses a nested C1 reply chain; COMMIT and READY authenticate the selected route transcript; every state has a finite local deadline.

The protocol distinguishes four properties:

1. **cell-length equality** - W2 gives every adjacent-link cell one 1,052-byte encoding while M2 messages remain variable length;
2. **wire-image unlinkability** - protocol fields do not provide a passive deterministic equality test across non-adjacent hops;
3. **batch-local message unlinkability** - after at least one honest transformation and mixing boundary, passive matching is intended to be bounded by the cryptographic and anonymity-set advantages;
4. **traffic-flow and active-adversary unlinkability** - resistance to timing, volume, topology, selective failure, and algebraic tagging.

Core v0.8 specifies the first property, the protocol structure for the second, and the lifecycle necessary to test both. The third remains conditional on U1 and a declared mixing profile. For the fourth, C2 selects an anonymous rerandomizable RCCA security contract and integrates a symbolic ideal functionality. A concrete active-adversary claim remains closed until the selected construction is implemented and independently reviewed.

## 2. Normative language

The terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as in BCP 14 when written in uppercase.

## 3. Bound profiles

Core v0.8 binds five profiles:

- **U1**, branch-local passive unlinkability;
- **E1**, deterministic event time and route-state lifecycle;
- **C2**, anonymous rerandomizable RCCA eligibility contract, with C1 retained as a negative-control backend and as the current reply/signature component set;
- **M2**, suite-agile canonical variable-length logical messages;
- **W2**, fixed-size encrypted adjacent-link cells with bounded fragmentation and reassembly.

The reference simulator executes all five profiles together. Under C1 it performs the existing `ristretto255` URE transformations as a negative control. Under `c2-ideal` it performs replay-equivalent symbolic rerandomization and mutation rejection while retaining the concrete reply-key tweaks, nested candidate encryption, Ed25519 verification, COMMIT/READY proof checks, M2 encoding, W2 fragmentation and reassembly, fixed-size cell protection, and adjacent-link ChaCha20-Poly1305 authentication. The C2 symbolic backend is not deployable cryptography.

## 4. Goals

Core v0.8 MUST provide:

1. bounded discovery by hop limit, fan-out, time, branch-context count, wire bytes, and cryptographic work;
2. no stable discovery identifier visible at more than one adjacent link;
3. fresh branch context and cryptographic representation for every forwarded copy;
4. canonical variable-length logical messages carried in one or more equal-length encrypted cells;
5. responder authentication inside an end-to-end protected candidate chain;
6. hop-local opaque route labels;
7. tentative route establishment before initiator selection;
8. explicit COMMIT, READY, expiration, cancellation, abort, and close behavior;
9. bidirectional forwarding state without disclosing the complete route;
10. deterministic local behavior under replay, stale messages, loss, tampering, and resource pressure;
11. measurable amplification caused by the absence of attempt-wide duplicate suppression;
12. explicit separation of the C2 active-security contract from the unimplemented concrete construction.

## 5. Non-goals

Core v0.8 does not by itself provide:

- global endpoint lookup;
- inter-domain routing policy;
- incentives or settlement;
- application-data congestion control;
- constant-rate transmission or protection against a passive global timing observer;
- a concrete active-tagging-resistant C2 implementation or proof;
- Sybil resistance;
- a replacement for IP or a new link technology;
- post-quantum security;
- a production deployment recommendation.

## 6. System model

The network is an undirected graph \(G=(V,E)\). A node can act as initiator, relay, responder, or any combination of these roles. An edge denotes an authenticated adjacent-link association.

A route of length \(d\) is a sequence

\[
\rho=(n_0,n_1,\ldots,n_d),
\]

where \((n_i,n_{i+1})\in E\), \(n_0\) is the initiator, and \(n_d\) is a responder. The protocol does not transmit \(\rho\) as an object.

## 7. Adjacent-link contract

The adjacent-link transport MUST provide:

- adjacent-peer authentication or an explicitly anonymous authenticated association;
- confidentiality and integrity for one adjacent link;
- exact record boundaries;
- a directional link epoch and replay sequence;
- notification of peer connection and disconnection;
- a peer-local identifier that is not treated as a global identity;
- key and nonce uniqueness for every accepted record.

M2 defines canonical, suite-agile variable-length control messages without semantic padding. W2 fragments them into 1,024-byte authenticated plaintext cells and produces 1,052-byte adjacent-link records. Message type, profile identifiers, suite identifiers, fragment metadata, logical fields, and padding are encrypted. The public 12-byte header contains only the link epoch and sequence.

A separate scheduling profile is required to define batching, release timing, fragment interleaving, cover traffic, and the minimum anonymity set. W2 alone does not hide when or in which direction a cell crosses an edge, nor how many cells compose a logical message when timing permits grouping.

## 8. Cryptographic and wire binding

C2 uses suite identifier `0x0002` for the destination-eligibility capsule and the abstract `KeyGen`, `Enc`, `ReRand`, and `Dec` contract in `crypto-profile-c2.md`. The current executable backend is symbolic and is not deployable cryptography. C1 (`0x0001`) remains a negative-control eligibility suite and supplies the currently executable reply-key, candidate-protection, signature, transcript, KDF, AEAD, and failure-handling components.

M2 uses the exact logical layouts in `message-codec-m2.md`; W2 uses the exact cell framing in `wire-cell-w2.md`. A conforming implementation MUST reject non-canonical message lengths, variable integers, fragment counts, fragment lengths, profiles, suite mismatches, fields, points, scalars, and nested candidate lengths before state activation.

The protocol distinguishes three key roles:

- endpoint C2 eligibility key `(sk_D,pk_D)`, used only to recognize DISCOVER capsules;
- endpoint signing key `(sk_S,vk_S)`, used to authenticate responder candidates;
- per-branch C1 reply key `(x_i,X_i)`, used for the nested reverse candidate chain.

These keys and domains are not interchangeable. The integrated reference model additionally authenticates the adjacent link and verifies candidate, COMMIT, and READY cryptographic material before a route becomes ACTIVE.

## 9. Logical messages, cells, and reassembly

M2 and W2 are distinct protocol layers. An M2 message is the complete semantic object processed by the route protocol. A W2 cell is an adjacent-link transmission unit. Encryption does not conceal ciphertext length; therefore W2 pads each cell to one fixed size before link encryption, while M2 remains compact and variable length.

For an M2 message of length \(L\), W2 uses payload capacity \(P=992\) bytes and emits

\[
q=\left\lceil\frac{L}{P}\right\rceil
\]

cells. The profile bounds \(1\le L\le 16384\) and \(1\le q\le 17\). Non-final fragments contain exactly 992 message bytes; the final fragment contains the remainder. Alternative fragmentations are non-canonical and MUST be rejected.

A relay authenticates each cell, validates fragment metadata, and reassembles the complete M2 message before semantic or suite-specific cryptographic processing. Reassembly is keyed only by authenticated link direction and a fresh 128-bit message-local identifier. The identifier is replaced after every relay transformation and is never forwarded across a second edge.

Every node MUST bound incomplete-message count, aggregate reserved bytes, fragment count, logical length, and reassembly lifetime. Exact duplicate fragments are idempotent. Conflicting duplicates or inconsistent metadata invalidate the local reassembly context. Incomplete contexts expire without branch or route-state allocation.

W2 guarantees equal individual cell length, not equal cells per logical message. Fragment count and timing can expose an approximate message-size class unless a separate traffic profile interleaves fragments, pads transaction cell counts, or emits cover cells.

## 10. Discovery scopes

### 10.1 Logical discovery

A logical discovery is local initiator state. It contains the application request, ring policy, cumulative budgets, candidate set, deadline, and selection policy. Its identifier MUST NOT be transmitted.

### 10.2 Local ring attempt

A ring attempt is also local policy state. The ring index, retry count, previous ring parameters, and previous branch tokens MUST NOT be transmitted.

### 10.3 Branch context

A branch context is the only relay-visible discovery scope. It is bound to:

- one ingress peer;
- one ingress branch token;
- one adjacent-link epoch;
- one incoming blinded reply public key;
- one expiration;
- bounded child mappings and candidate-response counters.

A branch context has no network-wide identifier.

## 11. Link-local capabilities

### 11.1 Branch token

For every outgoing child, a sender samples an independent uniformly random branch token \(\tau\) with at least 128 bits of entropy. The tuple

\[
(\text{link epoch},\text{peer},\tau)
\]

is meaningful only to the two adjacent peers. A token MUST NOT be reused.

### 11.2 Candidate token

A relay maps a child-local candidate token to an independently generated parent-local candidate token. Candidate tokens MUST NOT be forwarded unchanged.

### 11.3 Route labels

Forward and reverse route labels are independently random local capabilities. A label is accepted only from its bound peer, in its bound direction, during its bound route generation, and before expiration.

## 12. Reply-key blinding

C1 uses the `ristretto255` prime-order group \(\mathbb{G}\) of order \(q\), generator \(B\), and identity \(\mathcal O\). For each first-hop branch, the initiator samples

\[
x_0\leftarrow \mathbb{Z}_q^*,\qquad X_0=x_0B.
\]

A relay receiving reply public key \(X_i\) and forwarding to child \(j\) samples an independent non-zero scalar

\[
\delta_{i,j}\leftarrow \mathbb{Z}_q^*
\]

and computes

\[
X_{i+1,j}=X_i+\delta_{i,j}B.
\]

The relay stores \(\delta_{i,j}\) only in the child branch context. The relay rejects the identity result and resamples the tweak. Reverse candidate layers use the `TR-KEM-R255` construction in C1. Correctness follows from `(x_i+\delta_{i,j})B=X_i+\delta_{i,j}B`; security remains subject to independent review of the custom KEM.

## 13. Eligibility capsule

Core v0.8 selects C2 as the active-security target for destination eligibility. The abstract capsule is produced by

```text
Q_0 <- C2.Enc(pk_D, C2_MARKER)
```

and every forwarding relay computes

```text
Q_{i+1,j} <- C2.ReRand(Q_i)
```

without receiving `pk_D`. The exact active-security contract, receiver-anonymity requirement, replay-equivalence semantics, and concrete implementation gate are defined in `crypto-profile-c2.md` and `active-unlinkability-games-c2.md`.

The repository currently supplies two backends:

- C1, retained as a negative control that demonstrates the persistent ratio-tag attack;
- `c2-ideal`, a symbolic anonymous Rand-RCCA functionality used to exercise M2/W2 and lifecycle composition.

The symbolic backend is not deployable cryptography and does not close the C2 security gate. A deployment MUST NOT claim concrete active-adversary unlinkability until the selected anonymous Rand-RCCA construction is implemented, encoded, tested, and independently reviewed.

## 14. Discovery initiation

For each first-hop branch, the initiator:

1. checks cumulative deadline and budgets;
2. samples a fresh root reply key pair \((x_0,X_0)\);
3. samples a fresh branch token;
4. independently encrypts the C2 marker or rerandomizes a valid C2 eligibility capsule;
5. constructs one canonical M2 `DISCOVER` message;
6. fragments it canonically into W2 cells;
7. sends each cell with fresh padding and adjacent-link protection.

No two first-hop branches reuse a reply public key, branch token, eligibility ciphertext, or adjacent-link ciphertext.

### 14.1 Suite binding

A route-discovery branch uses one cryptographic suite from initiation through cleanup. M2 carries the suite identifier in every logical message; W2 repeats it in every fragment header. A node rejects a cross-suite fragment, an M2/W2 suite mismatch, or a control message that changes suite mid-lifecycle before route-semantic state is allocated.

## 15. Relay processing of DISCOVER

A relay receiving `DISCOVER` MUST apply the validation order in `messages-v0.8.md`. If admitted, it creates one branch context. It MUST NOT search for a network-wide duplicate identifier because none exists.

For each selected child, the relay:

1. excludes the ingress peer;
2. samples a fresh child branch token;
3. samples a fresh reply-key blinding scalar;
4. computes the child reply public key;
5. applies the selected suite's public eligibility rerandomization;
6. rewrites all mutable fields into a fresh canonical M2 message;
7. assigns a fresh adjacent-link-local W2 message identifier;
8. fragments the message canonically, regenerates every cell padding region, and encrypts every cell;
9. enqueues the cells into the configured scheduling and mixing profile.

Longer cycles and converging branches can cause the same physical node to accept multiple independent contexts. Hard limits are therefore mandatory.

## 16. Candidate return

An eligible responder authenticates its offer inside a candidate payload and seals it to the received reply public key. Let the responder be at depth \(d\). It constructs

\[
C_d=\operatorname{Seal}(X_d,\mathsf{CandidatePayload}).
\]

For the selected child branch, relay \(n_i\) stores the blinding scalar \(\delta_i\) used to derive \(X_{i+1}\) from \(X_i\). On reverse propagation it constructs

\[
C_i=\operatorname{Seal}
\left(X_i,\operatorname{Encode}(\delta_i,C_{i+1},\mathsf{LocalOfferData}_i)\right).
\]

The relay replaces the child candidate token with a fresh parent candidate token and creates tentative route labels. It does not learn the responder payload.

The initiator decrypts \(C_0\) with \(x_0\), obtains \(\delta_0\), derives

\[
x_1=x_0+\delta_0\pmod q,
\]

and repeats until it recovers and authenticates the responder candidate.

## 17. Commit and readiness

Candidate return installs tentative hop-local mappings. The initiator selects at most one candidate and sends `COMMIT` through the first-hop tentative label. Every relay:

- validates the incoming peer, local label, route generation, and protected transcript;
- reserves route capacity;
- transitions the selected tentative mapping to `PENDING_READY`;
- assigns a finite ready-hold deadline;
- forwards COMMIT without a global candidate or route identifier.

The responder verifies the end-to-end commit secret contained in the protected candidate transcript and returns `READY` through the reverse mappings. Each relay transitions the matching pending mapping to `ACTIVE` when READY is accepted. The initiator exposes the route to the data plane only after authenticating the final READY.

## 18. Event time and candidate windows

Core v0.8 adopts the E1 profile in `event-lifecycle-profile-e1.md`. Every local state is valid on a half-open interval `[t_create, t_expire)`. Expiry is processed before a message assigned the same timestamp. Candidate delivery is processed before closure of a candidate window assigned the same timestamp.

Ring schedules remain local policy. A candidate returned from an earlier ring MAY be selected during a later ring if no decision has been made and all offer and tentative deadlines remain valid. No ring index or retry handle is transmitted.

Selection occurs at a window boundary. After selection, the initiator stops admitting new legitimate branches, sends COMMIT on the selected route, and sends CANCEL into maximal off-route subtrees. CANCEL is an optimization; expiry is authoritative.

## 19. Tentative state, COMMIT, and READY

CANDIDATE creates one tentative relay mapping at every reverse hop. A tentative mapping rejects application data and expires independently.

COMMIT moves forward through the selected mappings. Each relay MUST reserve route capacity and transition the mapping to `PENDING_READY` before forwarding. The responder returns READY only after authenticating the commit challenge. READY moves backward and transitions each matching pending mapping to `ACTIVE`.

The initiator MUST NOT expose the route to the data plane before authenticating the final READY. Partial pending or active state caused by loss of COMMIT or READY MUST be reclaimed by local deadlines without remote cooperation.

## 20. Cancellation, loss, and fresh-branch attacks

CANDIDATE and CANCEL may cross. A candidate that traverses a live context first may continue; a candidate that arrives after cancellation is discarded. A candidate reaching the initiator after selection is late and cannot alter the decision.

Exact adjacent-link duplicates are rejected idempotently. Fresh syntactically valid branch tokens are not replays and therefore require pre-cryptographic per-peer token buckets, per-node context limits, and node-global capacities. Per-peer admission mitigates concentrated floods but does not remove the need for global limits under distributed attack.

## 21. Exact replay and loop handling

The adjacent-link replay domain rejects exact retransmission of a cell or branch token on the same link epoch. A branch arriving over another peer or with another token is not a duplicate for U1 and may be accepted as a separate context.

The protocol excludes immediate backtracking to the ingress peer. A deployment MAY use a privacy-preserving two-hop adjacency-intersection mechanism, but it MUST NOT expose a stable path vector or route fingerprint.

## 22. Resource bounds

Every node MUST define finite limits for:

- accepted branch contexts per peer and per node;
- contexts for one physical node or local service identity;
- outgoing children per branch;
- total transmitted discovery cells per time window;
- candidate responses per child, branch, peer, and node;
- tentative and active mappings;
- public-key, rerandomization, and signature operations;
- branch, candidate, and route lifetimes;
- retained bytes and timers;
- incomplete M2 messages per peer and per node;
- aggregate reassembly bytes, fragment count, and reassembly deadline.

The initiator separately enforces cumulative logical-discovery budgets across all rings and first-hop branches.

## 23. Conditional unlinkability statement

Let \(m_i\) and \(m_{i+k}\) denote two representations of one logical discovery branch observed at non-adjacent positions, with \(k>2\). Under U1, the direct protocol-field matching advantage is intended to be negligible when:

1. at least one intermediate relay is honest and performs all required transformations;
2. branch tokens, labels, nonces, blinding scalars, and rerandomization coins are sampled independently;
3. the eligibility capsule satisfies the selected URE anonymity and rerandomization definitions;
4. reply-key blinding satisfies the selected tweakable-KEM security definition;
5. every observed W2 cell has the same length, while the scheduling profile prevents fragment count from becoming a direct class label;
6. the honest relay releases a permuted batch containing at least two indistinguishable records;
7. the adversary is passive for the observed messages and is not given a timing or volume side channel.

This is not a claim against a global timing observer or an active tagging adversary. Those claims require additional profiles and proofs.

## 24. Required measurements

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
- adversarial matching success under the declared batching and traffic model;
- setup latency and route-setup stop reason;
- peak branch, responder-offer, initiator-candidate, tentative, pending, and active state;
- late-candidate, cancellation-race, expiry, COMMIT, and READY failures;
- legitimate and malicious transmissions and allocations separately;
- replay, loss, token-bucket, capacity, and per-node drops;
- final state counts and cleanup completion;
- complete W2 wire bytes and cell counts;
- M2 logical message counts and lengths;
- fragmented-message counts;
- reassembly completions, duplicate fragments, timeouts, capacity drops, metadata failures, peak reserved bytes, and final incomplete contexts;
- adjacent-link authentication and codec failures;
- C2 eligibility transformations, C1 negative-control transformations, and candidate layers;
- candidate, COMMIT, and READY authentication failures;
- active tags created and downstream tag observations;
- route success and cleanup under link tampering and ratio tagging.

## 25. Active-tagging boundary

The C1 eligibility consistency pair permits a persistent ratio tag. A malicious relay can replace `(U_1,V_1)` by `(cV_1,V_1)` for a known non-zero scalar `c`. Honest C1 rerandomization scales both elements and preserves `U_1=cV_1`, allowing a colluding downstream relay to recognize the branch. The endpoint subsequently rejects the capsule unless `c` equals its secret eligibility scalar. C1 is therefore retained only as a negative control for this property.

C2 requires receiver-anonymous rerandomizable RCCA security and defines an explicit cross-hop tagging game. In the symbolic backend, arbitrary mutation is rejected by the first honest transformation and is not delivered to a separated downstream colluder. This validates protocol composition and failure handling, but it is not evidence for a concrete construction. Core v0.8 MUST NOT claim concrete active-adversary unlinkability until the implementation gate in `crypto-profile-c2.md` is closed.

## 26. Status of the design

Core v0.8 has executable M2 and W2 codecs and integrates a symbolic C2 eligibility functionality with the concrete C1 reply/signature components, cell fragmentation, bounded reassembly, and the E1 lifecycle. Passive structural claims remain conditional on U1, the selected cryptographic suites, W2, and an honest scheduling and mixing boundary. The C1 counterexample is reproducible; the C2 protocol contract and game harness are executable; the concrete C2 cryptographic implementation and proof mapping remain open. The protocol is a research design and is not suitable for production deployment.
