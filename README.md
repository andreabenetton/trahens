# Trahens

Trahens is a research project for privacy-preserving route discovery in decentralized and path-aware networks.

The repository preserves the 2020 confidential draft as historical evidence and develops a smaller, testable protocol core before attempting a complete network-layer architecture.

## Status

Research design. The active specification is **Trahens Core v0.4** with the conditional **U1 non-adjacent message unlinkability profile** and the deterministic **E1 event lifecycle profile**. It has no production cryptographic suite and is not suitable for deployment.

## Current result

Core v0.4 retains independently transformed branch-local contexts and now defines event time, candidate windows, delayed candidates, cancellation races, tentative reverse mappings, forward COMMIT, reverse READY, expiry, exact duplication, loss, and malicious fresh-branch generation.

E1 uses half-open state deadlines. Expiry is processed before an equal-time message, while a candidate arriving exactly at a candidate-window deadline is eligible. COMMIT reserves `PENDING_READY` state; the initiator exposes a route to the data plane only after authenticating the final READY. Every state class has deterministic local cleanup.

The tracked 500-node event experiment produced 89% route-setup success on clean transport and 80% with 2% loss plus 5% exact duplication. A fresh-branch attack reduced success to 32% without ingress-peer buckets. A one-token bucket refilling every 10 ms raised success to 76%, reduced attack transmissions by 25.4%, and reduced attack branch allocations by 24.8%, but did not restore clean behavior. All four scenarios reached zero final branch, responder-offer, initiator-candidate, tentative, pending, and active state in every run. These are deterministic model results, not network benchmarks or a security proof.

## Repository map

- `paper/legacy/` - original LaTeX source and rendered PDF, preserved without semantic edits.
- `paper/rewrite/` - formal paper aligned with the active specification.
- `docs/` - assessment, strategy, threat model, research questions, ADRs, and review logs.
- `spec/` - active and historical protocol specifications, transcripts, and invariants.
- `simulator/` - deterministic discovery, U1 branch-local, and E1 event-lifecycle models.
- `implementation/` - requirements for a future overlay prototype.
- `reports/` - reproducible experiment outputs.
- `tools/` - repository checks and experiment runners.

## Working method

1. Preserve the legacy design as evidence, not as the current specification.
2. Record architecture changes as ADRs.
3. Separate wire-image, batch-local, lifecycle, and traffic-flow claims.
4. Make security claims only against an explicit adversary and named deployment profile.
5. Define wire semantics, event precedence, state machines, limits, and failure behavior before implementation.
6. Quantify privacy and abuse costs in deterministic models.
7. Block production implementation on concrete cryptographic suites, test vectors, and independent review.

## Quick start

```bash
make test
make unlinkability-compare
make lifecycle-compare
make paper
# Reproduce all tracked reports and the paper:
make reproduce
```

Start with [`spec/core-v0.4.md`](spec/core-v0.4.md), [`spec/unlinkability-profile-u1.md`](spec/unlinkability-profile-u1.md), [`spec/event-lifecycle-profile-e1.md`](spec/event-lifecycle-profile-e1.md), [`docs/strategy.md`](docs/strategy.md), and [`ROADMAP.md`](ROADMAP.md).
