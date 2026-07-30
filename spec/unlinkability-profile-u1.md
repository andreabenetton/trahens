<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens U1 branch-local unlinkability profile

- Status: Active research profile
- Applies to: Core v1.4.1 with R1, M2, W2, T1, and T2
- Property class: structural and conditional batch-local message unlinkability

## 1. Objective

U1 prevents protocol-visible branch values from serving as stable equality handles across non-adjacent forwarding hops. It does not claim traffic-flow unlinkability.

## 2. Adversary

The narrow passive game considers an adversary that observes or controls two non-adjacent relays, sees plaintext protocol bodies at those relays, knows topology and parameters, and chooses background traffic. At least one honest transforming and mixing relay lies between observations. Precise global timing, active modification, selective delay, directory/gateway collusion, and endpoint compromise are separate experiments.

## 3. Challenge game

The challenger selects two conforming input branches entering an honest relay. The relay independently transforms both, encodes new M2 messages, carries them in W2 cells, places eligible cells in a mixing or interleaving set, and emits a hidden permutation. The adversary guesses the input/output correspondence.

For a two-message challenge:

```text
Adv_U1(A) = | Pr[A guesses the permutation] - 1/2 |.
```

For an anonymity set of size `s`, the random baseline is `1/s`. Any claim must state cell-count class, release timing, topology, honest-relay placement, and background load.

## 4. Required transformations

For each child branch, an honest relay MUST independently:

1. replace the ingress branch token;
2. replace candidate and setup capabilities;
3. multiplicatively blind the reply public key with a fresh non-zero scalar;
4. replace the complete R1 service-query nonce with a fresh independent non-zero value;
5. reconstruct one canonical M2 message rather than patching received bytes;
6. assign a fresh link-local W2 message identifier;
7. fragment canonically and generate fresh padding;
8. use a fresh adjacent-link nonce, sequence, and ciphertext;
9. enter the cells into the declared scheduler or mixing treatment.

The raw R1 endpoint capability, capability commitment, endpoint key, endpoint address, gateway pseudonym, and endpoint handle MUST NOT appear in DISCOVER.

## 5. Observable classes

W2 equalizes individual cell length at 1,052 bytes. M2 messages may occupy different cell counts. The scheduler must state whether fragments are interleaved, cell counts are padded, chaff is inserted, and releases are constant, quantized, or event-driven.

A solitary immediately forwarded cell supports only structural field-replacement claims. It does not support batch-local matching resistance.

## 6. Explicit leakage

The public reply-key sequence satisfies one exact algebraic statement: for any fixed non-identity incoming key, one honest uniform non-zero multiplicative factor makes the outgoing public key uniform over all non-identity group elements. Full reply-layer unlinkability remains conditional on key privacy of the reply encryption and does not follow from this public-key statement alone.

U1 does not conceal predecessor and successor peers, local acceptance decisions, cell count, coarse timing, queue pressure, route depth inferred from candidate growth, repeated contexts at one physical relay, origin adjacency across local rings, gateway choice, or directory and redemption observations.

## 7. Active attacks

R1 removes literal discovery-field tags by complete replacement. This does not defeat tags encoded through selective delay, drop, topology, reply-key manipulation, cell count, or other protocol behavior. Extending the claim to active adversaries requires explicit experiments and review of the multiplicatively blinded reply-key chain, key-private reply KEM/PKE assumption, candidate authentication, failure normalization, and scheduler.

C1 remains a negative control whose ratio tag survives an honest rerandomization. Symbolic C2 remains a composition oracle. Neither is an active network suite.

## 8. Conformance evidence

A U1 implementation requires:

- deterministic per-hop transformation vectors;
- proof that endpoint capability bytes are absent from DISCOVER;
- statistical freshness tests for branch tokens, R1 nonces, message identifiers, padding, and link ciphertexts;
- passive matching experiments with at least one honest scheduler boundary;
- literal-field, selective-delay, drop, and malformed-input attacks;
- cell-count and timing captures;
- independent review of the retained reply-key and nested-candidate components.
