# Reply-path cryptographic analysis

## Status

This note analyzes the reply-key evolution and nested reverse-candidate construction used by the current Trahens research profile. It separates one property that follows directly from group algebra from properties that remain assumptions about the full encryption composition.

The profile is a conformance and research construction. It is not production cryptography and has not received independent cryptographic review.

## Construction

Let \(G\) be the prime-order `ristretto255` group of order \(q\), written additively, with generator \(B\). The initiator creates a fresh reply secret \(x_0\in\mathbb Z_q^*\) and public key

\[
X_0=x_0B.
\]

For each child branch, an honest relay samples an independent factor

\[
b_i\sample\mathbb Z_q^*
\]

and computes the Sphinx-style multiplicative blinding transform

\[
X_{i+1}=b_iX_i,
\qquad
x_{i+1}=b_ix_i\pmod q.
\]

The relay stores \(b_i\) in the authenticated reverse layer that is encrypted to \(X_i\). The initiator decrypts that layer with \(x_i\), derives \(x_{i+1}\), and continues.

This replaces the earlier additive evolution \(X_{i+1}=X_i+\delta_iB\). The multiplicative form follows the public-key blinding pattern used by Sphinx, but the Trahens nested reply composition is not the Sphinx packet format and does not inherit the complete Sphinx proof.

## Game RPK-BLIND

The adversary chooses any valid non-identity \(X\in G\). The challenger samples \(b\sample\mathbb Z_q^*\) and returns \(Y=bX\). The adversary attempts to distinguish \(Y\) from an independently uniform element of \(G\setminus\{0\}\).

### Proposition 1: exact public-key distribution

For fixed non-identity \(X\), the map

\[
\phi_X:\mathbb Z_q^*\longrightarrow G\setminus\{0\},
\qquad b\longmapsto bX
\]

is a bijection. Therefore \(Y=bX\) is exactly uniform over non-identity group elements and the adversary's distinguishing advantage in RPK-BLIND is zero.

The same result holds after any number of honest transformations because the product of independent uniform non-zero scalars is uniform in \(\mathbb Z_q^*\).

### Consequence

Two separated passive relays do not obtain a deterministic equality handle from the reply public key alone when at least one honest relay lies between them. This proposition covers only the distribution of the public-key sequence. It says nothing about timing, branch fan-out, ciphertext length, route state, or the key privacy of encrypted reply layers.

## Game RPK-LINK

The challenger constructs two candidate reply paths and gives the adversary:

- the public reply keys observed by corrupted relays;
- the encapsulated public values and reply-layer ciphertexts visible at those relays;
- all local state and blinding factors of corrupted relays;
- chosen valid protocol metadata permitted by the threat model.

At least one relay between the selected observations is honest. The adversary must determine which downstream observation descends from a selected upstream branch.

A reduction from RPK-LINK to Proposition 1 additionally requires the reply encryption scheme to hide the recipient public key and the plaintext under the relevant multi-user, chosen-ciphertext, and related-key conditions. That property is commonly called key privacy or recipient anonymity. The current ephemeral-static DH seal has not been proved to meet it, and RFC 9180 does not state a receiver-anonymity guarantee for HPKE.

Therefore the current claim is conditional:

> Reply-public-key unlinkability is established algebraically. Full passive reply-layer unlinkability remains conditional on an independently reviewed key-private KEM/PKE composition and on the declared traffic-shaping assumptions.

## Key schedule

The reply seal now performs one HKDF-Extract followed by one HKDF-Expand. The 44-byte output is split into a 32-byte ChaCha20-Poly1305 key and a 12-byte nonce. No HKDF output is reused as a new pseudorandom key. Domain-separated context includes the suite, encapsulated group element, recipient public key, and application `info` value.

This follows the Extract-then-Expand structure of RFC 5869. It is not represented as RFC 9180 HPKE because the profile defines a custom `ristretto255` KEM and does not inherit HPKE's registered suite or proof.

## Ephemeral-key safety

The production-facing `reply_seal` API always obtains fresh operating-system entropy and has no argument through which a caller can provide an ephemeral secret. Deterministic encryption is isolated in `trahens_crypto.test_support`, is not exported by the package, and requires the explicit `TRAHENS_TEST_CRYPTO=1` gate. It exists only for vectors and deterministic simulator runs.

Reusing the same ephemeral secret for the same reply public key would repeat the encapsulated point and the derived AEAD key and nonce. Such reuse is forbidden.

## Active adversaries

Multiplicative public-key blinding does not provide availability or active unlinkability by itself. A compromised relay can drop, delay, fork, or replace a branch, choose malicious-but-valid values, and exploit observable success or failure. Point validation, transcript binding, candidate signatures, AEAD verification, uniform public errors, and finite state reduce some attack surfaces but do not constitute a proof of the complete composition.

## Remaining review obligations

1. Prove or replace the key-private reply KEM/PKE under a multi-user chosen-ciphertext model.
2. Analyze maliciously selected reply public keys and blinding factors.
3. Bind every route, suite, direction, layer, and expiry field into the authenticated transcript.
4. Review failure timing and resource use for decryption-oracle leakage.
5. Evaluate whether a standard anonymous PKE can replace the custom seal without unacceptable size or route-depth cost.
6. Obtain an independent cryptographic review before enabling any production profile.

## References

- George Danezis and Ian Goldberg, “Sphinx: A Compact and Provably Secure Mix Format,” IEEE Symposium on Security and Privacy, 2009, DOI 10.1109/SP.2009.15.
- Mihir Bellare, Alexandra Boldyreva, Anand Desai, and David Pointcheval, “Key-Privacy in Public-Key Encryption,” ASIACRYPT 2001.
- Hugo Krawczyk and Pasi Eronen, RFC 5869, “HMAC-based Extract-and-Expand Key Derivation Function (HKDF),” 2010.
- Richard Barnes, Karthikeyan Bhargavan, Benjamin Lipp, and Christopher A. Wood, RFC 9180, “Hybrid Public Key Encryption,” 2022.
- Henry de Valence et al., RFC 9496, “The ristretto255 and decaf448 Groups,” 2023.
