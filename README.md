# Trahens

Trahens is a research project for privacy-enabled route discovery in decentralized and path-aware networks.

The repository preserves the 2020 manuscript as historical evidence and develops a smaller, testable protocol core before attempting a complete network-layer architecture.

## Status

Research design. The active specification is **Trahens Core v0.5**, composed of:

- the **U1** conditional non-adjacent message-unlinkability profile;
- the **E1** deterministic event-lifecycle profile;
- the **C1** concrete classical cryptographic research profile.

C1 makes the previously abstract transformations executable and supplies canonical encodings, domain separation, deterministic vectors, and a reference implementation. It has not received independent cryptographic review and is not suitable for production deployment.

## Current result

Core v0.5 uses independently transformed branch-local contexts. Every forwarded DISCOVER replaces its adjacent capability, additively tweaks the branch reply key, universally rerandomizes the eligibility capsule, reconstructs the message body, and obtains fresh adjacent-link encryption. CANDIDATE returns through nested encrypted layers. COMMIT reserves the selected tentative route, READY activates it, and every state has a finite local deadline.

C1 instantiates the research model with `ristretto255`, a GJJS-style universal re-encryption construction, HKDF-SHA-256, ChaCha20-Poly1305, and Ed25519. The custom reply KEM is deliberately labeled `TR-KEM-R255`; it is HPKE-inspired but is not an RFC 9180 HPKE suite. The tracked test suite contains 45 deterministic tests, including malformed-input, transcript-binding, rerandomization, key-tweak, lifecycle, resource, and reproducibility checks.

The deterministic 500-node experiments remain model results rather than network benchmarks. They show that conservative expanding-ring policies can contain the amplification created by unlinkable branch contexts, while broad flooding and distributed fresh-branch attacks remain important open problems.

## Repository map

- `paper/legacy/` - original LaTeX source and rendered PDF, preserved without semantic edits.
- `paper/rewrite/` - formal Core v0.5 paper with five-line numbering and no watermark.
- `docs/` - assessment, strategy, threat model, research questions, ADRs, and review logs.
- `spec/` - active and historical protocol specifications, transcripts, invariants, and C1 vectors.
- `simulator/` - deterministic discovery/lifecycle models and the C1 reference code.
- `implementation/` - requirements for a future user-space overlay prototype.
- `reports/` - reproducible experiment and conformance outputs.
- `tools/` - repository checks, vector generation, and experiment runners.

## Working method

1. Preserve the legacy design as evidence, not as the current specification.
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
make unlinkability-compare
make lifecycle-compare
make paper
make check
```

Start with [`spec/core-v0.5.md`](spec/core-v0.5.md), [`spec/crypto-profile-c1.md`](spec/crypto-profile-c1.md), [`spec/crypto-transcript-v0.2.md`](spec/crypto-transcript-v0.2.md), [`spec/unlinkability-profile-u1.md`](spec/unlinkability-profile-u1.md), [`spec/event-lifecycle-profile-e1.md`](spec/event-lifecycle-profile-e1.md), and [`docs/strategy.md`](docs/strategy.md).
