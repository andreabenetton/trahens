# Trahens

Trahens is a research project for privacy-preserving route discovery in decentralized and path-aware networks.

This repository preserves the 2020 confidential draft and develops a smaller, testable protocol core before attempting a complete network-layer architecture.

## Status

Research prototype. The protocol is incomplete and is not suitable for production use.

## Repository map

- `paper/legacy/` - original LaTeX source and rendered PDF, preserved without semantic edits.
- `paper/rewrite/` - a clean paper rewrite aligned with the evolving specification.
- `docs/` - assessment, strategy, threat model, research questions, and ADRs.
- `spec/` - normative protocol specifications and invariants.
- `simulator/` - topology and adversary simulation plan.
- `implementation/` - future overlay implementation plan.
- `tools/` - repository checks.

## Working method

1. Preserve the legacy design as evidence, not as the current specification.
2. Record important decisions as ADRs.
3. Make security and privacy claims only when linked to an explicit adversary model and test.
4. Specify wire formats, state machines, limits, and failure behavior before implementation.
5. Validate the design in a deterministic simulator before building a network prototype.

See [`docs/strategy.md`](docs/strategy.md) and [`ROADMAP.md`](ROADMAP.md).
