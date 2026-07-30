# ADR-0030: Require multi-link route classification and active probing

- Status: Accepted
- Date: 2026-07-30

## Context

Per-link count correlation does not capture longer observation windows, route identity, correlated background traffic, or deliberate bandwidth perturbation.

## Decision

T3 defines a balanced four-class route dataset, transparent nearest-centroid baseline, independent and correlated background conditions, multiple observation windows, and a bounded known active-probe pattern. Every result reports random baseline, macro-F1, boundary alignment, cross-link correlation, budget equality, and cleanup.

## Consequences

The repository gains a reproducible falsification gate. Passing the simple classifier is not treated as resistance to deep-learning correlation, watermarking, open-world inference, or global traffic analysis.
