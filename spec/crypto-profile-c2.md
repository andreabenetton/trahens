# Trahens cryptographic profile C2

- Status: Selected active-security target with executable ideal functionality and fail-closed k=2 transcription audit
- Applies to: Trahens Core v0.9, U1, E1, M2, and W2
- Suite identifier: `0x0002`
- Deployment status: **not approved for production**

## 1. Purpose

C2 replaces the C1 destination-eligibility capsule as the active-security target. C1 is publicly rerandomizable and receiver-key hiding under a passive interpretation, but its homogeneous consistency pair admits a persistent algebraic ratio tag. C2 therefore requires an eligibility encryption primitive that is simultaneously:

1. publicly rerandomizable without the destination public key;
2. receiver-anonymous (key-private) under adaptive attack;
3. replayable chosen-ciphertext secure (RCCA);
4. resistant to persistent cross-hop tagging except for replay-equivalent rerandomizations;
5. encodable as a bounded M2 logical field and transportable through W2 cells;
6. externally failure-uniform.

The selected construction family is the anonymous rerandomizable RCCA-secure PKE framework of Wang, Chen, Yang, Huang, Wang, and Yung (CRYPTO 2021; IACR ePrint 2021/862). That work gives a generic construction from rerandomizable smooth projective hash functions and a concrete k-linear-assumption instantiation. The profile also adopts the minimal/composable URE security perspective of Banfi, Maurer, and Ritsch (IACR ePrint 2023/1165) when stating application-facing unlinkability requirements.

C2 changes the destination-eligibility primitive only. Until separately revised, responder signatures, branch-reply key tweaking, nested candidate encryption, transcript binding, HKDF-SHA-256, ChaCha20-Poly1305, Ed25519, and adjacent-link protection retain the concrete C1 definitions. A conforming implementation must keep eligibility keys domain-separated from reply and signing keys.

## 2. Current implementation status

The repository does **not** yet contain a reviewed implementation of the CRYPTO 2021 construction. It contains two deliberately separated artifacts:

1. `trahens_crypto.c2_ideal.C2IdealOracle`, an executable ideal functionality used to test:

- M2 suite agility;
- W2 fragmentation and reassembly;
- replay-equivalent rerandomization semantics;
- arbitrary mutation rejection;
- receiver-key non-disclosure at the message layer;
- active-tagging and selective-failure state-machine behavior;
- deterministic cost accounting.

2. `trahens_crypto.c2_klinear`, a byte-exact `k = 2` transcription audit of the construction in Wang et al., Section 6.3 and Figure 6. The source smoothness results require `k >= 2`, and the source proposes related quadratic-residue groups obtained from a length-three Cunningham chain [Wang2021, Theorems 6.2, 6.5, 6.10; Section 6.3]. The audit validates key generation, encryption, decryption, canonical encoding, mutation rejection, and the linear strand equations. It then tests the literal map `mu(u) = u mod q`, which the source invokes for the related-group tag equations [Wang2021, Section 2, pp. 5-6; Figure 6]. A minimal exact counterexample shows that `mu` is not multiplicative under ordinary `QR*_p` group multiplication. The public rerandomization API therefore fails closed and reserved suite `0x7f02` is prohibited on the network.

The ideal functionality is not cryptography. The transcription audit is not approved cryptography. Neither artifact MUST be used outside simulation, conformance testing, or interoperability review. Passing either test set does not close the concrete active-security gate.

## 2.1 Concrete transcription audit

The detailed audit is specified in `crypto-profile-c2-k2.md` and reproduced by `make c2-k2-audit`. Its 412-byte ciphertext representation contains 24 canonically encoded group elements. The audit parameters are intentionally small and deterministic; they do not provide a production security level.

The current result must be read narrowly. It demonstrates that the selected paper can be mapped to explicit data structures and that most source equations are executable. It also establishes that the literal integer-reduction map stated in the finite-field explanation is not a multiplicative group homomorphism: for `q = 5`, `p = 11`, and quadratic residues `3,4`, `mu(3*4 mod 11) = 1`, while `mu(3)mu(4) mod 5 = 2`. This blocks the literal finite-field instantiation audited here [Wang2021, Section 2, pp. 5-6; Section 6.3, Figure 6]. It does not invalidate the generic Re-T-SPHF framework, a corrected action, or a different instantiation.

## 3. Abstract syntax

C2 defines four algorithms:

```text
KeyGen(1^lambda) -> (pk, sk)
Enc(pk, m; r) -> c
ReRand(c; rho) -> c'
Dec(sk, c) -> m | replay | invalid
```

`ReRand` does not take `pk`. For every valid ciphertext `c = Enc(pk,m;r)`, an honestly rerandomized ciphertext `c'` decrypts to the same message and belongs to the same replay-equivalence class. An arbitrary modification that is not an output of `ReRand` for a valid ciphertext MUST decrypt to `invalid`, except with negligible probability under the selected construction's security assumptions.

The only eligibility plaintext used by Trahens is the fixed domain-separated marker:

```text
C2_MARKER = SHA-256("Trahens-C2/eligibility-marker/v1")
```

A responder is eligible only when `Dec(sk,c)` returns exactly `C2_MARKER`.

## 4. Receiver anonymity

A C2 ciphertext MUST NOT expose which of two admissible public keys was used, even to an adaptive adversary with the decryption capabilities permitted by the receiver-anonymous RCCA game. In particular:

- the public key MUST NOT appear as a field in `DISCOVER`;
- rerandomization MUST NOT require or reveal the public key;
- the encoding MUST NOT contain a deterministic key fingerprint;
- validation proofs MUST NOT contain a stable recipient selector;
- error behavior MUST NOT distinguish a wrong recipient from malformed ciphertext.

Receiver anonymity is stronger than public-key-free rerandomization. A scheme may permit universal rerandomization and still reveal or test the recipient key by another algebraic relation.

## 5. Replay equivalence and RCCA behavior

Let `~pk` be the equivalence relation over ciphertexts that decrypt under `sk` to the same plaintext and are reachable through the scheme-defined rerandomization relation. C2 permits an adversary to create replay-equivalent ciphertexts, but it does not permit arbitrary related plaintexts or persistent distinguishable tags.

Trahens treats replay-equivalent eligibility capsules as semantically identical. It does not transmit an equivalence-class identifier, ciphertext digest, proof identifier, or rerandomization counter. Duplicate suppression remains adjacent-link-local and exact; it MUST NOT use a public C2 equivalence test.

## 6. Active-tag resistance requirement

For non-adjacent compromised relays `A` and `B` separated by at least one honest transforming relay, the following experiment defines the protocol requirement:

1. `A` receives a valid capsule `c`.
2. `A` emits any same-profile ciphertext `c_A`.
3. An honest relay parses, transforms, and rerandomizes according to C2, producing `c_H`, or rejects.
4. `B` receives `c_H` when one is produced and attempts to decide whether it originated from the selected input branch.

The construction passes the Trahens C2 tag game only if either:

- the honest relay rejects before `B` receives a transformed capsule; or
- `B`'s linking advantage is negligible beyond traffic and topology leakage declared by the scheduling profile.

A destination-only rejection is insufficient when `B` can recognize a tag before the destination processes the branch.

## 7. Symbolic ideal functionality

The symbolic backend represents a valid C2 ciphertext as an opaque 640-byte string registered inside the simulator. Public rerandomization creates an independent 640-byte string associated with the same hidden recipient, plaintext, and replay-equivalence class. An attacker-controlled marker mutation produces an unregistered string and cannot be rerandomized by the honest C2 interface.

The 640-byte value is a **non-normative sizing budget** corresponding to twenty 32-byte group-element slots in a k=1 planning model. It is not asserted to be the canonical encoding size of the CRYPTO 2021 construction. A concrete implementation MUST replace this budget with an exact encoding specification and vectors.

## 8. M2 and W2 binding

M2 includes the two-byte suite identifier in the logical-message envelope and length-delimits the eligibility capsule. For suite `0x0002`, the symbolic profile accepts exactly 640 capsule bytes. A future concrete C2 encoding MAY change the capsule length only with a new suite identifier or a reviewed profile revision.

W2 copies the suite identifier into every encrypted fragment header. Reassembly MUST reject fragments with inconsistent suite identifiers. After reassembly, the M2 envelope suite MUST match the W2 fragment suite before any protocol-semantic state is allocated.

## 9. Failure normalization

All of the following map to one externally visible invalid-input result:

- malformed group or ring elements;
- invalid proof or SPHF relation;
- unknown suite;
- recipient mismatch;
- non-replay-equivalent mutation;
- malformed M2 length;
- inconsistent W2 suite or fragmentation metadata;
- decryption or authentication failure.

Implementations SHOULD equalize cryptographic work where practical and MUST NOT emit a detailed network error. Local counters MAY distinguish causes for testing, but those counters are not sent to peers.

## 10. Concrete implementation gate

C2 is not complete until the repository contains all of the following:

1. an author-confirmed corrected action or an independently reviewed replacement for the non-homomorphic literal Figure 6 finite-field tag map;
2. a reviewed parameter generation method and current security level for the related groups or an approved alternative instantiation;
3. canonical public-key, secret-key, ciphertext, proof, scalar, and group encodings confirmed by a second implementation;
4. exact `KeyGen`, `Enc`, `ReRand`, and `Dec` algorithms, with nontrivial full rerandomization enabled only after the audit gap is closed;
5. deterministic positive and negative vectors;
6. subgroup, identity, malformed-element, truncation, substitution, and replay tests;
7. a receiver-anonymity game harness;
8. an active-tagging harness including the C1 ratio tag and component-wise mutations;
9. a reduction or direct mapping from the cited security definitions to the deployed parameters;
10. independent cryptographic review.

Until this gate is closed, the paper may claim only that the protocol has selected and integrated the **security contract** of an anonymous Rand-RCCA primitive, not that Trahens has implemented or proved that primitive.

## 11. References

[Wang2021]: Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, "Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved," CRYPTO 2021, LNCS 12828, pp. 270-300; full version IACR ePrint 2021/862.

[Banfi2023]: Fabio Banfi, Ueli Maurer, and Silvia Ritsch, "On the Security of Universal Re-Encryption," IACR ePrint 2023/1165.

[CKN2003]: Ran Canetti, Hugo Krawczyk, and Jesper Buus Nielsen, "Relaxing Chosen-Ciphertext Security," CRYPTO 2003.

[BBDP2001]: Mihir Bellare, Alexandra Boldyreva, Anand Desai, and David Pointcheval, "Key-Privacy in Public-Key Encryption," ASIACRYPT 2001.

[CS2002]: Ronald Cramer and Victor Shoup, "Universal Hash Proofs and a Paradigm for Adaptive Chosen Ciphertext Secure Public-Key Encryption," EUROCRYPT 2002.

[PR2007]: Manoj Prabhakaran and Mike Rosulek, "Rerandomizable RCCA Encryption," CRYPTO 2007.
