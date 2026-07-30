# Trahens

Trahens is a research protocol for privacy-enabled route discovery in decentralized and path-aware networks. The repository develops a bounded, executable protocol core before attempting a complete routing architecture. Historical material is preserved separately for traceability and is not the current specification.

## Status

The active specification is **Trahens Core v0.9**, composed of:

- **U1** - conditional branch-local passive unlinkability;
- **E1** - deterministic event and route-state lifecycle;
- **C2** - receiver-anonymous rerandomizable RCCA eligibility contract;
- **M2** - suite-agile canonical variable-length logical messages;
- **W2** - fixed-size authenticated adjacent-link cells with bounded reassembly.

C2 is integrated through an executable ideal functionality for protocol composition and through a separate fail-closed `k = 2` arithmetic transcription audit of Wang et al.'s CRYPTO 2021 construction [Wang et al., 2021](https://doi.org/10.1007/978-3-030-84259-8_10). The audit fixes canonical dimensions and a 412-byte encoding and validates key generation, encryption, decryption, mutation rejection, and the linear strand equations. It also tests the paper's literal finite-field map `mu(u) = u mod q`: an exact counterexample shows that this map is not a multiplicative homomorphism from `QR*_p` to `Z_q` under ordinary group multiplication. Reserved suite `0x7f02` is therefore not a network suite and full concrete rerandomization is disabled. This blocks the audited finite-field instantiation; it does not refute the paper's generic framework or a corrected construction. Neither artifact is deployable. C1 remains executable as a negative-control eligibility suite and supplies the current reply-key, candidate-encryption, signature, transcript, KDF, and AEAD components.

## Current result

Every forwarded DISCOVER branch receives a fresh adjacent capability, a tweaked reply public key, a suite-selected rerandomized eligibility capsule, a new canonical M2 message, a fresh link-local W2 message identifier, new padding, and fresh adjacent-link ciphertexts. CANDIDATE returns through nested authenticated reply layers. COMMIT reserves the selected tentative route, READY activates it, and all state has a finite local deadline.

M2 separates semantic encoding from transport framing. Logical messages contain canonical fields and no semantic padding. W2 fragments a message into 992-byte payload fragments, pads each 1,024-byte cell plaintext, and emits 1,052-byte adjacent-link records. The number and timing of cells remain observable unless a separate scheduling profile conceals them.

The C1 negative-control experiment reproduces a persistent ratio tag across an honest rerandomizing relay. In the symbolic C2 experiment, an attacker-controlled marker mutation is rejected by the first honest transformation and no transformed tag reaches the separated colluder. This establishes that the C2-TAG game is correctly embedded in the lifecycle; it does not prove a concrete construction secure. The C2-K2 audit makes the remaining cryptographic question reproducible rather than silently accepting a partial implementation.

## Repository map

- `paper/legacy/` - preserved historical source material.
- `paper/rewrite/` - standalone current protocol paper with line numbers every five lines and no watermark.
- `docs/` - strategy, threat model, ADRs, research questions, and review logs.
- `spec/` - active and historical specifications, security games, transcripts, invariants, and vectors.
- `simulator/` - deterministic discovery and lifecycle models, M2/W2 codec, C1 code, C2 ideal functionality, and adversarial experiments.
- `implementation/` - requirements for a future user-space overlay prototype.
- `reports/` - reproducible experiment and conformance outputs.
- `tools/` - repository checks, vector generators, and experiment runners.

## Working method

1. Separate protocol claims by adversary and layer.
2. Define canonical encodings, state transitions, limits, and failure behavior before network implementation.
3. Keep negative constructions and attacks as mandatory regression tests.
4. Require executable vectors and malformed-input cases for every profile.
5. Quantify privacy, reliability, and abuse costs.
6. Block production claims on concrete cryptographic review, independent implementation, fuzzing, and measured traffic analysis.

## Quick start

```bash
make test
make crypto-vectors
make c2-symbolic-vectors
make c2-compare
make c2-k2-audit
make fragmentation-compare
make paper
make check
```

Start with [`spec/core-v0.9.md`](spec/core-v0.9.md), [`spec/crypto-profile-c2.md`](spec/crypto-profile-c2.md), [`spec/crypto-profile-c2-k2.md`](spec/crypto-profile-c2-k2.md), [`spec/active-unlinkability-games-c2.md`](spec/active-unlinkability-games-c2.md), [`spec/message-codec-m2.md`](spec/message-codec-m2.md), [`spec/wire-cell-w2.md`](spec/wire-cell-w2.md), [`spec/unlinkability-profile-u1.md`](spec/unlinkability-profile-u1.md), [`spec/event-lifecycle-profile-e1.md`](spec/event-lifecycle-profile-e1.md), [`docs/citation-audit.md`](docs/citation-audit.md), and [`docs/strategy.md`](docs/strategy.md).
