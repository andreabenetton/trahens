# Trahens U1 non-adjacent message unlinkability profile

- Status: Research profile
- Applies to: Core v0.5 (retained from Core v0.3)
- Property class: cryptographic and batch-local message unlinkability

## 1. Objective

U1 prevents protocol-visible values from serving as stable handles across non-adjacent forwarding hops. It restores the narrow unlinkability objective expressed by the legacy Trahens draft while separating it from traffic-flow unlinkability.

## 2. Adversary

The U1 claim considers a probabilistic polynomial-time adversary that:

- passively observes or controls two non-adjacent relays;
- sees plaintext protocol bodies at those compromised relays;
- knows the topology and protocol parameters;
- can choose other discovery traffic in the same experiment;
- does not observe precise link timing or queue occupancy at the honest mixing relay;
- does not modify the challenge messages.

Active tagging, selective delay, and global timing correlation are separate experiments and are not covered by U1.

## 3. Challenge game

The challenger selects two conforming input discovery records \(a_0,a_1\) entering an honest relay. The relay independently transforms both records, places them in one eligible mixing batch, samples a uniform permutation \(\pi\), and emits \(b_0,b_1\). The adversary receives the inputs and outputs but not \(\pi\), and returns a guess for the correspondence.

For a two-record batch, the advantage is

\[
\operatorname{Adv}^{\mathsf{U1}}_{\mathcal A}
=
\left|\Pr[\mathcal A\text{ guesses }\pi]-\frac12\right|.
\]

For a batch of size \(s\), the baseline matching probability is \(1/s\). A profile is conforming only if the residual cryptographic advantage above this baseline is negligible under its stated assumptions.

## 4. Required transformations

An honest relay MUST, independently for each child branch:

1. replace the ingress branch token;
2. replace all candidate and setup capabilities;
3. blind the reply public key;
4. rerandomize the eligibility capsule;
5. reconstruct the canonical message body rather than patching the received bytes;
6. apply fresh padding randomness when the padding format permits it;
7. transmit under a fresh adjacent-link nonce and ciphertext;
8. place the record in an eligible mixing batch.

Any unchanged variable-length opaque field invalidates the U1 claim unless its selected primitive explicitly proves rerandomization unlinkability.

## 5. Record classes

U1 defines fixed-size classes for `DISCOVER`, `CANDIDATE`, `COMMIT`, `READY`, `ABORT`, `CLOSE`, and `CHAFF`. A deployment MAY use more than one size class, but the class itself is then explicit leakage and must be included in the adversary model.

A `CHAFF` record MUST be indistinguishable from a real record to an observer that lacks the adjacent-link keys and MUST consume the same scheduling path.

## 6. Mixing rule

An eligible batch contains at least \(s_{min}\ge2\) records of the same observable class. The relay applies a cryptographically secure uniform permutation. The release policy MUST state:

- maximum batching delay;
- action when fewer than \(s_{min}\) records are available;
- chaff injection rule;
- whether records are released at constant or quantized intervals;
- queue-overflow behavior.

A deployment that immediately forwards a solitary transformed record can claim wire-image unlinkability but not batch-local message unlinkability.

## 7. Explicit leakage

U1 does not conceal:

- the predecessor and successor peers of a compromised relay;
- local acceptance or rejection decisions;
- configured record class;
- coarse time window unless another profile conceals it;
- local resource pressure;
- the fact that several independent branch contexts reached the same compromised relay;
- origin adjacency across local expanding-ring attempts.

## 8. Active attack requirements

Before extending U1 to an active adversary, a concrete profile MUST demonstrate:

- tagging detection or non-transferability;
- ciphertext integrity across rerandomization;
- replay handling that does not introduce a stable global tag;
- resistance to malformed-ciphertext partitioning;
- indistinguishable error behavior;
- bounded work before expensive verification.

## 9. Conformance evidence

A U1 implementation requires:

- canonical test vectors for every hop transformation;
- statistical tests showing fresh output distributions;
- a two-relay matching experiment;
- active-tagging negative tests;
- record-size and queue-schedule captures;
- independent cryptographic review of URE and reply-key blinding.
