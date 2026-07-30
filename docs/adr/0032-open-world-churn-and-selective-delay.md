<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0032: Require open-world, route-churn, and selective-delay evaluation

- Status: Accepted
- Date: 2026-07-30

## Context

Closed-world route classification assumes every observed trace belongs to a known monitored class. It does not measure false positives on unseen routes. Stable-route tests also omit temporal topology changes. Passive classifiers do not evaluate an adversary that selectively delays traffic and tests for a downstream response.

## Decision

T4 reserves disjoint route sets for monitored classes, unknown calibration, and unknown testing. Feature normalization, centroid fitting, and rejection-threshold calibration use no test trace. Reports must include monitored true-positive rate, unknown false-positive rate, monitored precision, and macro-F1 rather than overall accuracy alone.

T4 also defines route-churn traces where only newly generated target traffic adopts a new path, and a bounded selective-delay experiment with a deterministic probe pattern, steady target workload, disjoint training/testing traces, and finite phase/lag search.

A negative result from the transparent reference detector is not treated as a security proof. A positive result rejects the evaluated claim.

## Consequences

- Unknown-route false positives become first-class metrics.
- Churn can be evaluated as a temporal privacy risk rather than a routing-only event.
- Selective-delay sensitivity is measured without adding a protocol-visible marker.
- Stronger open-world, learned, adaptive, and deployment-specific attacks remain future work.
