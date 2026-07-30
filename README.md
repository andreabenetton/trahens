# Trahens

Trahens is a research project for privacy-preserving route discovery in decentralized and path-aware networks.

The repository preserves the 2020 confidential draft as historical evidence and develops a smaller, testable protocol core before attempting a complete network-layer architecture.

## Status

Research design. The active specification is **Trahens Core v0.3** with the conditional **U1 non-adjacent message unlinkability profile**. It is incomplete, has no production cryptographic suite, and is not suitable for deployment.

## Current result

Core v0.3 removes the attempt-wide identifier introduced in v0.2 and replaces it with independently transformed branch-local contexts. Every forwarded branch receives a new link-local token, a blinded reply key, a rerandomized eligibility capsule, fresh local capabilities, and a fresh adjacent-link ciphertext.

The simulator measures the resource cost of removing attempt-wide duplicate suppression. On the tracked 500-node, average-degree-8 model with 2% responders, hop limit 4, and fan-out 3, the U1 branch-local model used 4.26% more discovery transmissions and 15.60% more state than the identifier-based baseline. At hop limit 5 and fan-out 4, state grew by 180.88% and 91% of runs exhausted a configured budget. These are deterministic model results, not network benchmarks or a cryptographic proof.

The formal paper has been restored as a full research draft with definitions, algorithms, security assumptions, propositions, protocol tables, and experimental results.

## Repository map

- `paper/legacy/` - original LaTeX source and rendered PDF, preserved without semantic edits.
- `paper/rewrite/` - formal paper aligned with the active specification.
- `docs/` - assessment, strategy, threat model, research questions, ADRs, and review logs.
- `spec/` - active and historical protocol specifications, transcripts, and invariants.
- `simulator/` - deterministic identifier-based, expanding-ring, and U1 branch-local models.
- `implementation/` - requirements for a future overlay prototype.
- `reports/` - reproducible experiment outputs.
- `tools/` - repository checks and experiment runners.

## Working method

1. Preserve the legacy design as evidence, not as the current specification.
2. Record architecture changes as ADRs.
3. Separate wire-image, batch-local, and traffic-flow unlinkability.
4. Make security claims only against an explicit adversary and named deployment profile.
5. Define wire semantics, state machines, limits, and failure behavior before implementation.
6. Quantify the resource cost of privacy mechanisms in deterministic models.
7. Block production implementation on concrete cryptographic suites, test vectors, and independent review.

## Quick start

```bash
make test
make sweep
make policy-compare
make unlinkability-compare
make paper
# Reproduce all tracked reports and the paper:
make reproduce
```

Start with [`spec/core-v0.3.md`](spec/core-v0.3.md), [`spec/unlinkability-profile-u1.md`](spec/unlinkability-profile-u1.md), [`docs/strategy.md`](docs/strategy.md), and [`ROADMAP.md`](ROADMAP.md).
