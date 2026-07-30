# C2 active-unlinkability games

- Status: Normative research game suite
- Applies to: C2 eligibility capsules embedded in U1 discovery

## 1. Purpose

These games separate cryptographic properties that are often collapsed into the word "unlinkability." They are protocol-facing acceptance tests. A concrete C2 implementation must additionally satisfy the formal definitions and assumptions of its cited construction.

## 2. Game C2-IND

The adversary selects equal-length eligibility plaintexts `m0,m1` and one admissible public key. It receives `Enc(pk,mb)` for random bit `b`, with the decryption restrictions of the selected RCCA definition. Its advantage in guessing `b` must be negligible.

Trahens uses one fixed marker, so this game mainly prevents future profile extensions from relying on an encryption primitive that leaks plaintext structure.

## 3. Game C2-RA

The adversary selects two admissible public keys `pk0,pk1` and one plaintext `m`. It receives `Enc(pkb,m)` for random `b`, with the adaptive decryption access permitted by receiver-anonymous RCCA security. Its advantage in guessing the recipient must be negligible.

No destination public key, deterministic key fingerprint, or recipient-specific proof identifier may be carried beside the capsule.

## 4. Game C2-RR

For any valid `c <- Enc(pk,m)`, repeated calls to `ReRand(c)` must:

- decrypt to `m` under `sk`;
- produce canonical ciphertexts;
- produce independently distributed wire encodings within the scheme's rerandomization class;
- require no public or secret key;
- avoid a no-op output except with negligible probability.

## 5. Game C2-RCCA

The adversary may submit ciphertexts to the RCCA decryption oracle, subject to the selected challenge restrictions. Rerandomizations of a challenge may be classified as `replay`; ciphertexts that are neither invalid nor replay-equivalent must not reveal the challenge bit or yield a controlled related plaintext.

Trahens maps `replay` and successful decryption of the fixed marker to the same eligibility result. It does not expose the replay classification on the network.

## 6. Game C2-TAG

Two colluding relays are separated by at least one honest relay. The upstream relay may replace the input capsule by any same-profile bytes. The honest relay applies canonical validation and `ReRand`, or rejects. The downstream relay receives the output only if the honest transformation succeeds.

The game is won when the downstream relay identifies the selected upstream branch with non-negligible advantage using capsule contents. Observable timing, direction, cell count, and topology are excluded from this cryptographic game and are handled by the traffic profile.

An acceptable outcome for an invalid tag is rejection at the honest relay before the downstream colluder receives a transformed capsule. Availability is analyzed separately.

## 7. Game C2-COMP

The adversary receives the complete M2/W2 protocol view: suite identifier, logical lengths after compromise, fragment count, timing, adjacent peers, and all state at compromised nodes. The cryptographic C2 claim is restricted to capsule content. The protocol must not add a stable identifier that invalidates C2-RA or C2-TAG even when the primitive itself satisfies them.

## 8. Required negative cases

The conformance suite must include:

- the C1 ratio tag;
- bit flips in every ciphertext component;
- component substitution between two valid ciphertexts;
- truncation and extension;
- identity and malformed elements;
- public-key substitution;
- replay of an honest rerandomization;
- repeated rerandomization;
- adaptive selective-failure observation;
- cross-suite fragment substitution;
- inconsistent M2 and W2 suite identifiers.

## 9. Current evidence

The symbolic C2 ideal functionality passes the protocol semantics of C2-RR, C2-RA, and C2-TAG by construction. In the integrated five-node line experiment, an upstream marker mutation is rejected by the first honest C2 transformation, and a separated downstream colluder records zero tag observations. This is evidence about the state machine and game harness only; it is not evidence that a concrete cryptographic construction satisfies the games.
