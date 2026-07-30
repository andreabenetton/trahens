# Trahens cryptographic profile C1

- Status: Concrete research profile
- Applies to: Trahens Core v1.4.1 reply path; eligibility construction retained only as a research negative control
- Suite identifier: `0x0001`
- Profile encoding version: `0x02`
- Security status: Interoperability and analysis only; not approved for production deployment

## 1. Purpose and claim boundary

C1 defines the executable classical components retained by Core v1.4.1 and the archived eligibility negative control. It defines:

1. endpoint eligibility keys and descriptors;
2. a universally rerandomizable eligibility capsule;
3. a multiplicatively blinded reply-key chain and AEAD wrapper;
4. responder signatures and candidate transcript binding;
5. canonical encodings, domain separation, malformed-input behavior, and deterministic vectors.

C1 does **not** claim post-quantum security, active-adversary unlinkability, traffic-flow unlinkability, or independent cryptographic review. The URE construction is an adaptation of the Golle-Jakobsson-Juels-Syverson universal re-encryption construction to the `ristretto255` prime-order group. The reply KEM is an HPKE-inspired, unregistered research KEM over the same group. Both choices require independent analysis before deployment.

## 2. Primitive suite

| Function | C1 primitive | Reference |
|---|---|---|
| Prime-order group | `ristretto255` | RFC 9496 |
| Hash | SHA-256 and SHA-512 | FIPS 180-4 |
| KDF | HKDF-SHA-256 | RFC 5869 |
| AEAD | ChaCha20-Poly1305, full 128-bit tag | RFC 8439 |
| Signature | Ed25519 | RFC 8032 |
| Archived eligibility negative control | GJJS universal re-encryption, written in additive group notation | CT-RSA 2004; C1 definition below |
| Reply encryption | `TR-KEM-R255` plus HKDF-SHA-256 and ChaCha20-Poly1305 | C1 definition below |

## 3. Mathematical notation

Let:

- \(\mathbb G\) be the `ristretto255` prime-order group;
- \(q=2^{252}+27742317777372353535851937790883648493\) be its order;
- \(B\) be the canonical generator;
- \(\mathcal O\) be the identity element;
- lower-case letters denote scalars in \(\mathbb Z_q\);
- upper-case letters denote group elements;
- \(\langle X\rangle\) denote the canonical 32-byte encoding of group element \(X\);
- `LE32(x)` denote the canonical 32-byte little-endian encoding of scalar \(x\).

A scalar field that is required to be non-zero MUST satisfy \(1\le x<q\). A group element received from the wire MUST decode according to RFC 9496. The identity is rejected wherever this profile explicitly requires a public key or ephemeral DH element.

## 4. Canonical field encoding and domain separation

Let `Prefix = ASCII("Trahens-C1-v2")` and let `LP16(x)` be a two-byte unsigned big-endian length followed by `x`. The function

```text
EncodeFields(label, values) = Prefix || LP16(label) || LP16(values[0]) || ...
```

is used for all C1 transcript and KDF inputs. A field longer than 65,535 bytes is invalid. Implementations MUST NOT substitute implicit concatenation, JSON, platform serialization, or a different character encoding.

## 5. Endpoint keys, descriptor, and address

An endpoint has two independent long-term key pairs:

- eligibility key \((a,A)\), where \(a\in\mathbb Z_q^*\) and \(A=aB\);
- Ed25519 signing key pair \((sk_S,vk_S)\).

The C1 endpoint descriptor is:

```text
version(1) || suite_id(2) || encode(A)(32) || vk_S(32)
```

and is therefore 67 bytes. The C1 endpoint address is:

```text
SHA-256(EncodeFields("endpoint-address", [descriptor]))
```

The descriptor, not only the address hash, is required to create an eligibility capsule. A directory or out-of-band exchange that supplies a descriptor MUST authenticate the binding between descriptor and address.

## 6. Eligibility marker

C1 encrypts one fixed group element rather than a structured plaintext. Let:

```text
uniform = SHA-512("Trahens-C1-element-v2" || "eligibility-marker")
M*      = ristretto255_from_uniform_bytes(uniform)
```

where the element-derivation operation is the 64-byte derivation interface specified for `ristretto255`. A node is eligible only if valid decryption yields exactly \(M^*\).

This construction means that a node with the wrong secret key obtains either an invalid consistency check or a group element unequal to \(M^*\), except with negligible probability.

## 7. Universal rerandomizable eligibility encryption

### 7.1 Encryption

To encrypt \(M^*\) to eligibility public key \(A=aB\), sample independent \(r_0,r_1\leftarrow\mathbb Z_q^*\) and compute:

\[
\begin{aligned}
U_0 &= M^* + r_0A, & V_0 &= r_0B,\\
U_1 &= r_1A,       & V_1 &= r_1B.
\end{aligned}
\]

The ciphertext is

\[
Q=((U_0,V_0),(U_1,V_1))
\]

and its wire encoding is the 128-byte string

```text
encode(U0) || encode(V0) || encode(U1) || encode(V1)
```

### 7.2 Universal rerandomization

A relay does not need \(A\). It samples \(s_0\leftarrow\mathbb Z_q^*\) and \(s_1\leftarrow\mathbb Z_q^*\setminus\{1\}\), then computes:

\[
\begin{aligned}
U'_0 &= U_0+s_0U_1, & V'_0 &= V_0+s_0V_1,\\
U'_1 &= s_1U_1,     & V'_1 &= s_1V_1.
\end{aligned}
\]

For a valid input this changes the effective randomness to
\(r'_0=r_0+s_0r_1\) and \(r'_1=s_1r_1\), while preserving the plaintext and recipient key. Every outgoing child branch MUST use independently sampled \((s_0,s_1)\). Requiring \(s_0\ne0\) and \(s_1\ne1\) ensures that all four point encodings change for a valid ciphertext. An implementation MUST reject coins that produce an unchanged ciphertext.

### 7.3 Decryption and eligibility test

A node with eligibility secret \(a\) computes:

\[
T=U_1-aV_1.
\]

It rejects unless \(T=\mathcal O\). If the check succeeds, it computes:

\[
M=U_0-aV_0
\]

and declares itself eligible only when \(M=M^*\).

The consistency pair \((U_1,V_1)\) prevents an arbitrary four-point string from being treated as a valid encryption. It does not make the construction CCA-secure and does not by itself prevent every active tagging strategy.

### 7.4 Required validation

Before rerandomization or decryption, all four points MUST decode canonically. Invalid encodings are rejected before scalar multiplication. No protocol-visible error distinguishes malformed encoding, consistency failure, wrong recipient, or marker mismatch.

## 8. Multiplicatively blinded reply-key chain

For each first-hop branch, the initiator samples \(x_0\leftarrow\mathbb Z_q^*\) and publishes the branch-local reply public key

\[
X_0=x_0B.
\]

A relay forwarding to one child samples an independent factor \(b_i\leftarrow\mathbb Z_q^*\) and computes

\[
X_{i+1}=b_iX_i.
\]

The initiator later derives the corresponding secret value as

\[
x_{i+1}=b_ix_i\pmod q.
\]

Correctness follows from

\[
x_{i+1}B=(b_ix_i)B=b_i(x_iB)=b_iX_i=X_{i+1}.
\]

For every fixed non-identity \(X_i\), the map \(b\mapsto bX_i\) from \(\mathbb Z_q^*\) to \(\mathbb G\setminus\{\mathcal O\}\) is a bijection. Consequently one honest transformation makes the outgoing public key exactly uniform over non-identity group elements. This is a statement about the public-key distribution only; it does not prove key privacy of the reply ciphertext or unlinkability of the complete nested composition.

The factor \(b_i\) is stored only in the relay's child branch context and is disclosed to the initiator inside the authenticated encrypted reverse layer. A zero factor, identity input key, or identity output key is invalid.

## 9. `TR-KEM-R255`

### 9.1 Encapsulation

For recipient reply key \(X=xB\), the sender samples \(e\leftarrow\mathbb Z_q^*\) and computes:

\[
R=eB,\qquad Z=eX.
\]

The encapsulated value is \(\langle R\rangle\). The KEM context and key schedule are:

```text
context = EncodeFields("reply-kem-context", [suite_id, encode(R), encode(X), info])
prk     = HKDF-Extract(0^32, EncodeFields("reply-kem-dh", [encode(Z)]))
okm     = HKDF-Expand(prk, EncodeFields("reply-kem-key-schedule", [context]), 44)
key     = okm[0:32]
nonce   = okm[32:44]
```

This is one Extract followed by one Expand. No HKDF output is reused as a new PRK.

### 9.2 Decapsulation

The recipient validates \(R\ne\mathcal O\), computes \(Z=xR\), reconstructs \(X=xB\), and performs the same derivation. Invalid point encodings and the identity are rejected.

### 9.3 AEAD wrapper

C1 returns:

```text
encode(R) || ChaCha20-Poly1305(key, nonce, plaintext, aad)
```

The nonce is deterministic relative to a fresh encapsulation-specific key. Reuse of the same ephemeral scalar \(e\) with the same recipient key and `info` would repeat both key and nonce and is prohibited. The production-facing `reply_seal` API obtains \(e\) from an approved CSPRNG and exposes no caller-supplied deterministic ephemeral parameter. Deterministic sealing is isolated in a non-exported, explicitly gated test-support module used only by vectors and deterministic simulations.

`TR-KEM-R255` follows the context-binding discipline of HPKE, but it is not an IANA-registered HPKE KEM and MUST NOT be advertised as RFC 9180 interoperability. In particular, this document does not inherit a receiver-anonymity or key-privacy theorem from HPKE.

## 10. Candidate authentication

The responder signs a 32-byte candidate transcript digest:

```text
th = SHA-256(EncodeFields("candidate-transcript", ordered_fields))
sig = Ed25519.Sign(sk_S, th)
```

The ordered field list is specified by `crypto-transcript-v0.2.md`. It includes the endpoint address, offer parameters, commit challenge, final reply public key, protocol profiles, and expiry classes. A verifier rejects a signature if any field changes, if an alternate encoding is used, or if the signing key does not match the endpoint descriptor.

## 11. Failure behavior

Cryptographic failures are mapped to one local result: `INVALID_CRYPTO`. A relay or endpoint MUST NOT send a differentiated error for:

- invalid point encoding;
- non-canonical or zero scalar where prohibited;
- identity public key or encapsulation;
- URE consistency failure;
- eligibility marker mismatch;
- AEAD authentication failure;
- AAD or `info` mismatch;
- invalid responder signature;
- transcript mismatch.

Timing equalization is implementation-dependent and not claimed by this reference code. Network behavior MUST remain bounded and independent of the specific failure cause.

## 12. Security considerations

### 12.1 Public reply-key distribution and conditional layer unlinkability

Multiplicative reply-key blinding gives the exact public-key distribution stated in Section 8. Complete reply-layer unlinkability additionally requires the reply encryption to be key-private or receiver-anonymous in the relevant multi-user chosen-ciphertext setting; that composition remains an open review obligation.

The archived URE construction is intended to make two valid ciphertext representations computationally unlinkable without the recipient key, under the relevant group assumptions and the selected URE security definition. C1 adopts it as a research hypothesis, not as a new proof.

### 12.2 Active modification

The URE capsule is malleable by design. The marker and consistency pair cause many modifications to fail, but C1 does not prove resistance to all active tagging or chosen-ciphertext strategies. U1 active-adversary unlinkability remains unclaimed.

### 12.3 Key privacy

The eligibility construction is used because the target public key need not appear beside the ciphertext and rerandomization does not require it. Formal recipient-anonymity and composability must be reviewed against the 2023 URE security framework before deployment.

### 12.4 Forward secrecy and compromise

Reply keys are ephemeral per first-hop branch. Endpoint eligibility and signing keys are long-term. Compromise of an eligibility key allows recognition of retained C1 capsules encrypted to that key. C1 therefore does not provide retrospective destination hiding after endpoint key compromise.

### 12.5 Post-quantum status

Every asymmetric primitive in C1 is vulnerable to a cryptographically relevant quantum computer. A hybrid or post-quantum profile requires a separate design; ordinary KEM replacement is insufficient because the eligibility capsule must remain universally rerandomizable.

## 13. Reference implementation and vectors

The non-production reference implementation is located in:

- `simulator/trahens_crypto/ristretto.py`
- `simulator/trahens_crypto/c1.py`
- `simulator/trahens_crypto/test_support.py` (test-only deterministic sealing)

It uses the installed `libsodium` `ristretto255` operations and the Python `cryptography` implementation of Ed25519 and ChaCha20-Poly1305. Deterministic vectors are stored in `crypto-test-vectors-c1.json` and regenerated by:

```bash
PYTHONPATH=simulator python tools/generate_crypto_vectors.py \
  --output spec/crypto-test-vectors-c1.json
```

The vector seeds are public test inputs and MUST NOT be reused as operational keys.
