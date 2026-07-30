# Citation audit

This file records the external research and standards used by the current Trahens paper and specifications. It is intended to make every paper-derived claim traceable to a citation placed at the point where the claim is discussed.

## Citation policy

- The formal paper uses `\cite{...}` immediately in the paragraph, definition, limitation, or construction that depends on an external work.
- Specifications use local reference labels such as `[Wang2021]` next to the relevant statement and define those labels in the same file or link to this audit.
- Repository experiments, counterexamples, and design decisions are cited to repository artifacts rather than presented as results of the external papers.
- A citation to a paper does not imply that Trahens inherits the paper's security proof. The exact implementation assumptions and claim boundary are stated separately.

## Claim-to-source map

| Trahens topic | External basis | Point-of-use locations |
|---|---|---|
| Compact mix/onion packet formats | Sphinx | Paper: background and related work |
| Network-layer onion routing and stateless forwarding comparison | HORNET | Paper: background and related work |
| Constant-rate link padding and setup mixing comparison | TARANET | Paper: underlay assumptions, traffic-analysis limitations, timing profile |
| Poisson mixing and cover-traffic comparison | Loopix | Paper: related work and timing limitation |
| Universal public-key-free rerandomization baseline | Golle et al. | Paper: C1 negative-control construction and security limitation |
| Replayable chosen-ciphertext security | Canetti, Krawczyk, and Nielsen | Paper: C2 security contract and game definitions |
| Recipient/key privacy | Bellare et al. | Paper: receiver-anonymity motivation and C2-RA game |
| Smooth projective hash functions | Cramer and Shoup | Paper: C2 construction background |
| Rerandomizable RCCA encryption | Prabhakaran and Rosulek | Paper: C2 construction history and security target |
| First anonymous rerandomizable RCCA construction and concrete k-Lin transcription | Wang et al. | Paper: C2 target, concrete audit, source equations, finite-field limitation |
| Formal universal re-encryption security/composition treatment | Banfi, Maurer, and Ritsch | Paper: unlinkability claim boundary and composition requirements |
| HPKE composition reference | RFC 9180 | Paper: distinction between the custom reply KEM and standardized HPKE |
| Ristretto group encoding | RFC 9496 | Paper: C1 group operations and canonical encodings |
| HKDF | RFC 5869 | Paper: key derivation |
| ChaCha20-Poly1305 | RFC 8439 | Paper: adjacent-link and nested-candidate AEAD |
| Ed25519/EdDSA | RFC 8032 | Paper: candidate authentication |
| Normative requirement language | RFC 2119 and RFC 8174 | Paper: normative requirement appendix |

## Bibliography

### Wang2021

Yi Wang, Rongmao Chen, Guomin Yang, Xinyi Huang, Baosheng Wang, and Moti Yung, **“Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved,”** *Advances in Cryptology - CRYPTO 2021*, LNCS 12828, pp. 270-300. DOI: `10.1007/978-3-030-84259-8_10`. Full version: IACR ePrint `2021/862`, <https://eprint.iacr.org/2021/862>.

Trahens uses the paper for:

- the receiver-anonymous rerandomizable RCCA target;
- the generic Re-T-SPHF framework;
- the k-Lin concrete construction in Section 6.3 and Figure 6;
- the related quadratic-residue groups based on a length-three Cunningham chain;
- the literal finite-field statement that the inner tag uses `u mod q` and that modular reduction supplies the required homomorphism.

Trahens independently tests the last statement. The exact counterexample and deterministic witness are repository results, not claims made by Wang et al.

### Banfi2023

Florian Banfi, Ueli Maurer, and Simon Ritsch, **“On the Security of Universal Re-Encryption,”** Cryptology ePrint Archive, Paper `2023/1165`, <https://eprint.iacr.org/2023/1165>.

### PrabhakaranRosulek2007

Manoj Prabhakaran and Mike Rosulek, **“Rerandomizable RCCA Encryption,”** *Advances in Cryptology - CRYPTO 2007*, LNCS 4622, pp. 517-534.

### CanettiKrawczykNielsen2003

Ran Canetti, Hugo Krawczyk, and Jesper Buus Nielsen, **“Relaxing Chosen-Ciphertext Security,”** *Advances in Cryptology - CRYPTO 2003*, LNCS 2729.

### BellareEtAl2001

Mihir Bellare, Alexandra Boldyreva, Anand Desai, and David Pointcheval, **“Key-Privacy in Public-Key Encryption,”** *Advances in Cryptology - ASIACRYPT 2001*, LNCS 2248, pp. 566-582. DOI: `10.1007/3-540-45682-1_33`.

### CramerShoup2002

Ronald Cramer and Victor Shoup, **“Universal Hash Proofs and a Paradigm for Adaptive Chosen Ciphertext Secure Public-Key Encryption,”** *Advances in Cryptology - EUROCRYPT 2002*, LNCS 2332.

### GolleEtAl2004

Philippe Golle, Markus Jakobsson, Ari Juels, and Paul Syverson, **“Universal Re-encryption for Mixnets,”** *Topics in Cryptology - CT-RSA 2004*, LNCS 2964, pp. 163-178.

### Sphinx2009

George Danezis and Ian Goldberg, **“Sphinx: A Compact and Provably Secure Mix Format,”** *IEEE Symposium on Security and Privacy*, 2009.

### HORNET2015

Chen Chen, Daniele Enrico Asoni, David Barrera, George Danezis, and Adrian Perrig, **“HORNET: High-speed Onion Routing at the Network Layer,”** arXiv `1507.05724`, <https://arxiv.org/abs/1507.05724>.

### TARANET2018

Chen Chen, Daniele Enrico Asoni, Adrian Perrig, David Barrera, George Danezis, and Carmela Troncoso, **“TARANET: Traffic-Analysis Resistant Anonymity at the Network Layer,”** *IEEE European Symposium on Security and Privacy*, 2018, pp. 137-152.

### Loopix2017

Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, and George Danezis, **“The Loopix Anonymity System,”** *26th USENIX Security Symposium*, 2017, pp. 1199-1216, <https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska>.

### Standards

- RFC 2119, **“Key words for use in RFCs to Indicate Requirement Levels.”**
- RFC 8174, **“Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.”**
- RFC 9180, **“Hybrid Public Key Encryption.”**
- RFC 9496, **“The ristretto255 and decaf448 Groups.”**
- RFC 5869, **“HMAC-based Extract-and-Expand Key Derivation Function (HKDF).”**
- RFC 8439, **“ChaCha20 and Poly1305 for IETF Protocols.”**
- RFC 8032, **“Edwards-Curve Digital Signature Algorithm (EdDSA).”**
