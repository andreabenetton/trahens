# Trahens

Trahens is a research project for privacy-enabled route discovery in decentralized and path-aware networks.

The repository develops a bounded, testable protocol core before attempting a complete network-layer architecture. Historical source material is retained separately for traceability.

## Status

Research design. The active specification is **Trahens Core v0.7**, composed of:

- the **U1** conditional non-adjacent message-unlinkability profile;
- the **E1** deterministic event-lifecycle profile;
- the **C1** concrete classical cryptographic research profile;
- the **M1** canonical variable-length logical-message profile;
- the **W2** constant-size authenticated adjacent-link cell profile.

M1 and W2 separate logical encoding from observable transport framing. Logical messages contain only their canonical fields and do not carry semantic padding. Each message is then fragmented into one or more 992-byte payload fragments, padded inside fixed 1,024-byte W2 plaintext cells, and protected as 1,052-byte adjacent-link records. The profiles have not received independent cryptographic review and are not suitable for production deployment.

## Current result

Core v0.7 uses independently transformed branch-local contexts. Every forwarded DISCOVER replaces its adjacent capability, additively tweaks the reply key, rerandomizes the eligibility capsule, reconstructs a canonical M1 message, assigns a fresh link-local W2 message identifier, and emits one or more independently authenticated fixed-size cells. CANDIDATE returns through nested authenticated C1 layers. COMMIT reserves the selected tentative route, READY activates it, and every state has a finite local deadline.

The integrated simulator performs actual `ristretto255` transformations, ChaCha20-Poly1305 link and candidate protection, Ed25519 responder authentication, COMMIT and READY proof checks, M1 encoding, W2 fragmentation and bounded reassembly, and deterministic cleanup. The tracked suite contains 61 tests.

The active-tagging analysis found a persistent ratio tag in the C1 URE consistency pair. A compromised relay can create a relation that survives honest rerandomization and can be recognized by a colluding downstream relay. Active-adversary message unlinkability is therefore explicitly not claimed. Passive wire-image and conditional batch-local properties remain separate research claims. W2 equalizes individual cell length, but the number and timing of cells remain observable unless a traffic-scheduling profile hides them.

## Repository map

- `paper/legacy/` - original source material, preserved without semantic edits.
- `paper/rewrite/` - standalone current protocol paper with five-line numbering and no watermark.
- `docs/` - assessment, strategy, threat model, research questions, ADRs, and review logs.
- `spec/` - active and historical protocol specifications, transcripts, invariants, and C1 vectors.
- `simulator/` - deterministic integrated lifecycle model, M1/W2 codec, C1 reference code, and attack experiments.
- `implementation/` - requirements for a future user-space overlay prototype.
- `reports/` - reproducible experiment and conformance outputs.
- `tools/` - repository checks, vector generation, and experiment runners.

## Working method

1. Preserve legacy material as evidence, not as the current specification.
2. Record architecture changes as ADRs.
3. Separate wire-image, batch-local, lifecycle, active-adversary, and traffic-flow claims.
4. Define exact encodings, transcripts, limits, state transitions, and failure behavior before network implementation.
5. Require executable vectors and negative tests for every cryptographic profile.
6. Quantify privacy and abuse costs rather than infer privacy from encryption alone.
7. Block production claims on independent review, implementation audit, and measured traffic analysis.

## Quick start

```bash
make test
make crypto-vectors
make fragmentation-compare
make unlinkability-compare
make lifecycle-compare
make tagging-compare
make paper
make check
```

Start with [`spec/core-v0.7.md`](spec/core-v0.7.md), [`spec/message-codec-m1.md`](spec/message-codec-m1.md), [`spec/wire-cell-w2.md`](spec/wire-cell-w2.md), [`spec/active-tagging-analysis.md`](spec/active-tagging-analysis.md), [`spec/crypto-profile-c1.md`](spec/crypto-profile-c1.md), [`spec/crypto-transcript-v0.2.md`](spec/crypto-transcript-v0.2.md), [`spec/unlinkability-profile-u1.md`](spec/unlinkability-profile-u1.md), [`spec/event-lifecycle-profile-e1.md`](spec/event-lifecycle-profile-e1.md), and [`docs/strategy.md`](docs/strategy.md).
