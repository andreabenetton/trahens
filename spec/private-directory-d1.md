<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# D1 private-directory strawman

## Status

D1 is a non-normative architecture profile that makes the unresolved directory dependency explicit. It is not enabled by Core v1.4.1 and has no wire identifier. R1 alone removes endpoint-specific selectors from route discovery; it does not tell an authorized initiator how to obtain the private descriptor without exposing that lookup.

A complete system cannot claim meaningful endpoint anonymity until D1 or an equivalent independently reviewed profile is implemented and evaluated.

## Roles

- **Publisher**: the destination endpoint that creates an R1 descriptor.
- **Client**: an authorized initiator that already holds an authorization secret.
- **Directory replicas**: at least two independently operated, non-communicating replicas.
- **Oblivious relay**: an optional network intermediary that separates a client's source address from a directory replica.
- **Rendezvous gateway**: a gateway named only by a short-lived pseudonym inside the encrypted descriptor.

## Descriptor epochs

For epoch `e`, the publisher derives from an authorization secret `K_auth`:

```text
handle_e = HKDF-Expand(HKDF-Extract(salt_e, K_auth),
                       "Trahens-D1-handle" || e, 32)
key_e    = HKDF-Expand(HKDF-Extract(salt_e, K_auth),
                       "Trahens-D1-descriptor-key" || e, 32)
```

The descriptor contains only epoch-scoped material:

```text
version
service class
not-before / not-after
one or more short-lived gateway pseudonyms
one or more R1 capability records or derivation inputs
gateway authentication material
optional next-epoch recovery data
```

The publisher encrypts the descriptor with an independently reviewed AEAD using `key_e`, a fresh nonce, and associated data binding the epoch and service class. The directory stores:

```text
(handle_e, encrypted_descriptor, expiry)
```

A handle and ciphertext expire together. Replicas MUST reject duplicate handles with inconsistent ciphertexts.

## Private lookup modes

### D1-PIR

The preferred strawman uses at least two non-colluding replicas and a private-information-retrieval interface. The client sends correlated queries whose individual views hide `handle_e`; responses combine to recover the encrypted descriptor. The exact PIR construction, database layout, update protocol, denial-of-service controls, and leakage profile remain to be selected.

### D1-OHTTP

A weaker deployment mode sends an encrypted lookup through an Oblivious HTTP relay to one directory gateway. This separates the client's transport address from plaintext query content when relay and gateway do not collude, but the directory gateway still learns the requested handle after decapsulation. It is therefore a metadata-separation profile, not private information retrieval.

## Authorization and sharing

D1 assumes that an authorized client obtains `K_auth`, the current epoch, and any recovery material through a channel outside route discovery. Group sharing, revocation, compromise recovery, and contact discovery are unresolved. Static long-lived handles are forbidden.

## Security boundaries

D1 does not provide its intended query privacy when:

- all PIR replicas collude;
- the OHTTP relay colludes with the directory gateway;
- authorization material is compromised;
- descriptors or handles are reused across epochs;
- access timing or publication timing uniquely identifies the endpoint;
- the directory and rendezvous gateway correlate publisher registration, lookup, and redemption metadata.

Replication, short epochs, padded update batches, fixed query sizes, independent operators, and anonymous transport can reduce exposure, but they do not by themselves prove system-level endpoint anonymity.

## Required evaluation

Before D1 becomes active, a report MUST state:

1. the exact PIR or oblivious-query construction and security assumption;
2. the number and independence assumption of replicas and relays;
3. descriptor size, padding, update cadence, retention, and epoch overlap;
4. query and publication timing leakage;
5. authorization, revocation, recovery, and compromise behavior;
6. directory/gateway collusion experiments;
7. enumeration, replay, rollback, equivocation, and denial-of-service handling;
8. the source-address and connection-linkability protection used for each query.

## Relationship to prior systems

DP5 demonstrates that privacy-preserving presence and high-integrity status updates can support rendezvous-oriented applications, while still relying on explicit infrastructure and security assumptions. Tor onion services demonstrate operational separation among descriptors, introduction points, and rendezvous points. Oblivious HTTP demonstrates source-address/content separation under a non-collusion assumption. D1 borrows only these architectural lessons; it does not inherit their security analyses.
