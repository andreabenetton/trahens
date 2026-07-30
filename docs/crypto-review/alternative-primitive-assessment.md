<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Alternative primitive assessment

## Security target

Trahens originally sought a destination-eligibility primitive with ciphertext-only public rerandomization, receiver anonymity, preservation of the recipient and plaintext, and resistance to persistent active tags. This target follows the application-level role of universal re-encryption described by Banfi, Maurer, and Ritsch, who define URE as public-key encryption with keyless ciphertext rerandomization and provide a composable mixnet-oriented treatment: [IACR ePrint 2023/1165](https://eprint.iacr.org/2023/1165).

## CRYPTO 2021 anonymous rerandomizable RCCA PKE

Wang et al. present the first receiver-anonymous rerandomizable RCCA-secure PKE framework and a concrete k-linear instantiation: [IACR ePrint 2021/862](https://eprint.iacr.org/2021/862), DOI `10.1007/978-3-030-84259-8_10`.

The repository contains an exact `k = 2` transcription audit. Key generation, encryption, decryption, canonical encoding, selected mutation rejection, and the linear strand equations are executable. The project's literal mapping of the related-group tag operation to ordinary integer representatives in `QR*_p` does not satisfy the required equation. This is treated as an interpretation/transcription failure, not as evidence of a flaw in the paper. Until an author-confirmed interpretation or a second reviewed instantiation is available, the concrete suite remains disabled.

## ASIACRYPT 2022 updatable and randomizable PKE

Dowling, Hauck, Riepel, and Rösler introduce randomizable PKE and updatable/randomizable PKE in *Strongly Anonymous Ratcheted Key Exchange*: [IACR ePrint 2022/1187](https://eprint.iacr.org/2022/1187), DOI `10.1007/978-3-031-22969-5_5`.

Their randomization interface is materially different from the Trahens requirement. The paper defines `rPKE.rr(ek, c)` to return a randomized **encryption key and ciphertext together**. Its purpose is to make exposed sender keys and their ciphertexts look independent in a ratcheted-key-exchange state. Trahens requires an untrusted relay to transform a ciphertext without possessing or changing the destination encryption key and without forwarding a stable destination key. Consequently, this primitive is not a drop-in replacement for universal destination eligibility.

## Decision matrix

| Requirement | Wang et al. 2021 | Dowling et al. 2022 | Trahens R1 fallback |
|---|---:|---:|---:|
| Ciphertext-only public rerandomization | Claimed; concrete interpretation unresolved | No; randomizes `(ek,c)` together | Not required |
| Receiver/key anonymity | Claimed | Defined for its RKE setting | Endpoint token absent from discovery |
| Active chosen-ciphertext/tag resistance | RCCA target | Different security target | Discovery field has no endpoint semantics |
| Stateless endpoint during discovery | Yes in intended PKE interface | Not the intended use | Gateway registration required |
| Untrusted relay can transform without destination key | Intended | No | Relay replaces a non-semantic nonce |
| Operational trust shift | Cryptographic assumption | Ratcheted state | Private directory and rendezvous gateways |

## Conclusion

No reviewed concrete replacement was found that satisfies the exact Trahens interface while preserving the existing discovery design. The active protocol therefore adopts R1, a rendezvous-capability profile. C2 remains a research workstream and negative-control environment, not an active network suite.
