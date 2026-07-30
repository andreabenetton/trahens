# Trahens cryptographic profile C1 v2

- Status: frozen research-interoperability profile for P1
- Applies to: Trahens Core v1.5 reply-path protection; eligibility construction retained only as a negative control
- Suite identifier: `0x0003`
- Profile encoding version: `0x02`
- Replaces: incompatible C1 v1 suite `0x0001`, which is retired and MUST be rejected
- Security status: implementation and analysis only; not approved for production deployment

## 1. Purpose and claim boundary

C1 v2 defines the executable classical components used by the P1 prototype:

1. endpoint keys and descriptors;
2. the archived universally rerandomizable eligibility negative control;
3. multiplicatively blinded reply keys;
4. recipient-bound reply encryption with explicit key commitment;
5. responder signatures and candidate transcript binding;
6. canonical encodings, domain separation, uniform failures, and vectors.

C1 v2 does **not** claim post-quantum security, traffic-flow unlinkability, or a complete multi-user IK-CCA proof. The URE construction is a negative control, not the active R1 discovery mechanism. The reply construction remains subject to external cryptographic review.

## 2. Primitive suite

| Function | Primitive |
|---|---|
| Prime-order group | `ristretto255` |
| Hash | SHA-256 and SHA-512 |
| KDF | HKDF-SHA-256 |
| AEAD | ChaCha20-Poly1305, 128-bit tag |
| Key commitment | HMAC-SHA-256 with an independently derived 32-byte key |
| Signature | Ed25519 |
| Eligibility negative control | GJJS-style universal re-encryption in additive notation |
| Reply encryption | `TR-KEM-R255-v2` plus HKDF, AEAD, and explicit commitment |

## 3. Mathematical notation and validation

Let \(\mathbb G\) be the `ristretto255` prime-order group, \(q\) its order, \(B\) its canonical generator, and \(\mathcal O\) its identity. Scalars are canonical 32-byte little-endian values. Fixed-width protocol integers outside scalar encodings are unsigned big-endian.

A scalar required to be non-zero MUST satisfy \(1\le x<q\). Every received group element MUST decode canonically. Public keys and ephemeral DH elements MUST NOT be the identity.

## 4. Authoritative registry and domain separation

The machine-readable authority for suite IDs, widths, limits, and labels is [`protocol-registry-v1.5.json`](protocol-registry-v1.5.json). Generated Python, Rust, and Markdown bindings MUST compare byte-for-byte with that source in CI.

Let `Prefix = ASCII("Trahens-C1-v2")`, `LP16(x) = BE16(len(x)) || x`, and:

```text
EncodeFields(label, values) = Prefix || LP16(label) || LP16(values[0]) || ...
```

The complete C1 v2 domain set is:

| Use | Domain |
|---|---|
| Generic scalar derivation | `Trahens-C1-scalar-v2` |
| Generic element derivation | `Trahens-C1-element-v2` |
| URE encryption coins | `Trahens-C1-ure-r0-v2`, `Trahens-C1-ure-r1-v2` |
| URE rerandomization coins | `Trahens-C1-ure-s0-v2`, `Trahens-C1-ure-s1-v2` |
| Reply ephemeral derivation in vectors | `Trahens-C1-reply-ephemeral-v2` |
| Candidate AAD and info | `Trahens-C1-candidate-layer-aad-v2`, `Trahens-C1-candidate-layer-info-v2` |
| COMMIT and READY proofs | `Trahens-C1-COMMIT-v2`, `Trahens-C1-READY-v2` |
| Active-tag experiments | `Trahens-C1-active-tag-scalar-v2` |
| Reply key commitment | `Trahens-C1-reply-key-commitment-v2` |

No C1 v1 domain is valid under suite `0x0003`.

## 5. Endpoint keys, descriptor, and address

An endpoint has an eligibility key pair \((a,A=aB)\) and an independent Ed25519 signing key pair. The descriptor is:

```text
version(1) || suite_id(2) || encode(A)(32) || signing_public(32)
```

It is 67 bytes and carries suite `0x0003`. The endpoint address is:

```text
SHA-256(EncodeFields("endpoint-address", [descriptor]))
```

A descriptor source MUST authenticate its binding to the address.

## 6. Eligibility marker and negative-control URE

The fixed marker is:

```text
uniform = SHA-512("Trahens-C1-element-v2" || "eligibility-marker")
M*      = ristretto255_from_uniform_bytes(uniform)
```

For recipient \(A=aB\), encryption samples independent non-zero \(r_0,r_1\) and computes:

\[
U_0=M^*+r_0A,\quad V_0=r_0B,\quad U_1=r_1A,\quad V_1=r_1B.
\]

The canonical ciphertext is `encode(U0)||encode(V0)||encode(U1)||encode(V1)` (128 bytes). A relay samples non-zero \(s_0\) and \(s_1\ne1\), then computes:

\[
U'_0=U_0+s_0U_1,\quad V'_0=V_0+s_0V_1,\quad U'_1=s_1U_1,\quad V'_1=s_1V_1.
\]

The recipient rejects unless \(U_1-aV_1=\mathcal O\), then accepts eligibility only if \(U_0-aV_0=M^*\). This construction remains malleable and is not an active discovery suite.

## 7. Multiplicatively blinded reply-key chain

The initiator samples \(x_0\leftarrow\mathbb Z_q^*\) and publishes \(X_0=x_0B\). Relay \(i\) samples independent \(b_i\leftarrow\mathbb Z_q^*\) and emits:

\[
X_{i+1}=b_iX_i.
\]

The initiator derives \(x_{i+1}=b_ix_i\pmod q\). Zero factors, identity inputs, and identity outputs are invalid.

For any fixed non-identity \(X\), the map \(b\mapsto bX\) is a bijection from \(\mathbb Z_q^*\) to \(\mathbb G\setminus\{\mathcal O\}\). One honest blinding therefore produces an exactly uniform non-identity public key. This proves only the public-key distribution; complete ciphertext unlinkability still depends on reply-encryption key privacy.

## 8. `TR-KEM-R255-v2`

### 8.1 Encapsulation and KDF

For recipient \(X=xB\), sample fresh non-zero \(e\), compute \(R=eB\) and \(Z=eX\), and derive:

```text
context = EncodeFields("reply-kem-context", [0x0003, encode(R), encode(X), info])
prk     = HKDF-Extract(0^32, EncodeFields("reply-kem-dh", [encode(Z)]))
okm     = HKDF-Expand(prk, EncodeFields("reply-kem-key-schedule", [context]), 76)
aead_key       = okm[0:32]
nonce          = okm[32:44]
commitment_key = okm[44:76]
```

No Expand output is reused as a PRK.

### 8.2 Ciphertext and key commitment

Let:

```text
aead_ciphertext = ChaCha20-Poly1305(aead_key, nonce, plaintext, aad)
commit_input = EncodeFields("reply-key-commitment", [
    "Trahens-C1-reply-key-commitment-v2",
    encode(R), encode(X), aad, info, aead_ciphertext
])
commitment = HMAC-SHA-256(commitment_key, commit_input)
```

The sealed object is:

```text
encode(R)(32) || aead_ciphertext(variable, includes 16-byte tag) || commitment(32)
```

The receiver reconstructs `X=xB`, derives the same keys, computes and constant-time compares the commitment, and attempts AEAD opening. Any commitment or AEAD failure maps to the same local result. Implementations SHOULD perform both checks before returning failure to reduce distinguishability.

The commitment is intended to provide recipient robustness under the KDF/HMAC assumptions; it does not by itself establish the full multi-user IK-CCA theorem required for a production anonymity claim.

### 8.3 Freshness

Every sealing operation MUST use a fresh ephemeral scalar. The production API MUST NOT accept a caller-selected ephemeral value. Deterministic vector sealing is confined to `tools/` and is not included in the installable Python package or any runtime executable.

## 9. Candidate authentication

The responder signs:

```text
th  = SHA-256(EncodeFields("candidate-transcript", ordered_fields))
sig = Ed25519.Sign(signing_secret, th)
```

The ordered fields are defined in `crypto-transcript-v0.2.md`. Verification binds the endpoint descriptor, endpoint address, final reply public key, offer, expiry, and commit challenge.

## 10. Uniform failure behavior

Malformed points, invalid scalars, identity elements, marker mismatch, AEAD failure, commitment failure, context mismatch, signature failure, and transcript mismatch all map to `AUTHENTICATION_FAILED`/`INVALID_CRYPTO` locally. No differentiated protocol response is sent. State allocation that survives the receive operation MUST occur only after complete canonical decoding and authentication.

## 11. Security status

- Public-key blinding distribution: proved exactly uniform over non-identity elements.
- Reply correctness: covered by canonical vectors and implementation tests.
- Recipient robustness: explicit commitment added; bounded tests reject cross-recipient opening.
- Reply key privacy: proof obligations and a reduction sketch are in `docs/crypto-review/reply-key-privacy-v1.5.md`; external review remains required.
- Post-quantum migration: requires a reply-path redesign, not a primitive substitution; see ADR 0036.
- URE eligibility: research negative control only.

## 12. Reference code and vectors

Runtime code:

- `simulator/trahens_crypto/ristretto.py`
- `simulator/trahens_crypto/c1.py`
- `simulator/trahens_crypto/candidate.py`

Deterministic test-only helpers:

- `tools/vector_crypto_support.py`
- `tools/vector_candidate_support.py`

Canonical vectors are in `crypto-test-vectors-c1.json` and are regenerated with:

```bash
PYTHONPATH=simulator python tools/generate_crypto_vectors.py \
  --output spec/crypto-test-vectors-c1.json
```
