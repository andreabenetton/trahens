# Trahens

Trahens is a research project for privacy-aware route discovery in decentralized and path-aware networks.

This repository preserves the 2020 confidential draft and develops a smaller, testable protocol core before attempting a complete network-layer architecture.

## Status

Research prototype. The active design draft is **Trahens Core v0.2**. It is incomplete and not suitable for production use.

## Current result

The simulator now compares fixed broad flooding with bounded expanding rings. In the current 500-node experiment with 2% responders, expanding rings retained 100% observed success across 100 deterministic runs while reducing mean DISCOVER transmissions from 895.12 to 157.65. This is a model result, not a network benchmark.

## Repository map

- `paper/legacy/` - original LaTeX source and rendered PDF, preserved without semantic edits.
- `paper/rewrite/` - a clean paper rewrite aligned with the evolving specification.
- `docs/` - assessment, strategy, threat model, research questions, ADRs, and review logs.
- `spec/` - active and historical protocol specifications and invariants.
- `simulator/` - deterministic fixed and expanding-ring discovery models.
- `implementation/` - future overlay implementation requirements.
- `reports/` - reproducible experiment outputs.
- `tools/` - repository checks and experiment runners.

## Working method

1. Preserve the legacy design as evidence, not as the current specification.
2. Record important decisions as ADRs.
3. Make security and privacy claims only when linked to an explicit adversary model and test.
4. Specify wire semantics, state machines, limits, and failure behavior before implementation.
5. Validate design choices in a deterministic simulator before building a network prototype.
6. Treat every retry policy as both a resource policy and a privacy-leakage surface.

## Quick start

```bash
make test
make sweep
make policy-compare
make paper
# or reproduce every tracked report and the paper
make reproduce
```

See [`spec/core-v0.2.md`](spec/core-v0.2.md), [`docs/strategy.md`](docs/strategy.md), and [`ROADMAP.md`](ROADMAP.md).
