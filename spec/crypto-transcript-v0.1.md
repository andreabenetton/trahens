# Trahens cryptographic transcript v0.1

- Status: Proof-oriented design draft
- Applies to: Core v0.3 U1 profile
- Implementation status: Not approved for production

## 1. Primitive interfaces

The specification uses the following abstract primitives until concrete suites and test vectors are selected.

### 1.1 Link AEAD

`LinkSeal(link_key, epoch, sequence, aad, plaintext)` and `LinkOpen(...)` provide confidentiality, integrity, and replay-domain binding on one adjacent link.

### 1.2 Universally rerandomizable eligibility encryption

- `URE.KeyGen()`
- `URE.Enc(pk, plaintext; r)`
- `URE.ReEnc(pk, ciphertext; r')`
- `URE.Dec(sk, ciphertext)`

The selected URE construction MUST state ciphertext anonymity, rerandomization indistinguishability, malformed-ciphertext behavior, and active-tagging properties. Plain ElGamal without the required integrity analysis is not sufficient for a production profile.

### 1.3 Tweakable reply KEM

For prime-order group \(\mathbb G\):

- `TRKEM.KeyGen()` returns \((x,P=xG)\);
- `TRKEM.Blind(P,delta)` returns \(P'=P+\delta G\);
- `TRKEM.TweakSecret(x,delta)` returns \(x'=x+\delta\pmod q\);
- `Seal(P,plaintext,aad)` and `Open(x,ciphertext,aad)` provide CCA-secure KEM-DEM encryption.

The selected construction MUST prove that a blinded public key and encapsulation do not reveal the predecessor key or blinding scalar to the stated adversary.

### 1.4 Signatures or anonymous credentials

Responder authentication MAY use a signature or anonymous credential. The identity disclosure policy is part of the service profile. Authentication is carried only inside the end-to-end candidate payload.

## 2. Domain separation

Every hash, KDF, signature, and AEAD operation MUST include:

- protocol string `Trahens`;
- core version;
- privacy-profile identifier;
- cryptographic-suite identifier;
- message purpose;
- role and direction;
- expiration class;
- canonical transcript hash.

## 3. Forward transcript

A U1 `DISCOVER` logical body contains:

- protocol and profile negotiation protected against downgrade;
- remaining-hop class or another bounded propagation control;
- relay fan-out class;
- link-local branch token;
- blinded reply public key;
- rerandomized eligibility capsule;
- expiry class;
- padding.

The body MUST NOT contain a logical-discovery ID, attempt ID, ring index, path vector, retry count, stable candidate ID, or stable route ID.

## 4. Candidate payload

The responder candidate payload contains at least:

- responder ephemeral key;
- responder identity or credential proof according to policy;
- service-offer parameters;
- candidate expiration;
- commit challenge or commit public key;
- transcript hash of the opened eligibility request;
- responder authentication over all preceding fields.

## 5. Nested reverse capsule

At depth \(d\):

\[
C_d=\operatorname{Seal}(P_d,M_d,\mathsf{aad}_d).
\]

For \(i=d-1,\ldots,0\):

\[
C_i=\operatorname{Seal}
(P_i,\delta_i\parallel C_{i+1}\parallel L_i,\mathsf{aad}_i),
\]

where \(L_i\) contains only the local offer limits and first-hop label information needed by the initiator after decryption. Each layer is padded to a declared maximum-depth representation or another construction that does not reveal exact route length.

## 6. Initiator opening

Starting with root secret \(x_0\), the initiator performs:

1. \((\delta_i,C_{i+1},L_i)\leftarrow\operatorname{Open}(x_i,C_i,\mathsf{aad}_i)\);
2. validate scalar encoding and transcript context;
3. \(x_{i+1}=x_i+\delta_i\pmod q\);
4. continue until a valid responder candidate payload is reached.

Every failure produces one indistinguishable local failure class and MUST NOT trigger an amplified network error.

## 7. Commit transcript

The candidate payload supplies a fresh commit challenge. The initiator sends a proof or authenticated encryption of that challenge to the responder through the tentative hop-label mappings. Relays process only local labels and do not receive a global candidate identifier.

`READY` authenticates:

- the commit challenge;
- selected service parameters;
- route-generation limits;
- initiator and responder ephemeral transcript keys;
- profile and suite identifiers.

## 8. Open proof obligations

1. Select a concrete URE construction and verify its active security properties.
2. instantiate TR-KEM using a reviewed group and KEM-DEM construction;
3. prove key privacy and unlinkability of the blinding chain;
4. prove that nested padding does not reveal route depth;
5. define post-quantum migration without introducing suite fingerprinting;
6. publish canonical test vectors;
7. obtain independent cryptographic review.
