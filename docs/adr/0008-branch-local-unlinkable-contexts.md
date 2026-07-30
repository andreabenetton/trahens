<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0008: Replace wire attempt IDs with branch-local contexts

- Status: Accepted for Core v0.3 research draft
- Date: 2026-07-30

## Context

Core v0.2 used one random `attempt_id` across every message of a bounded flood. This supported first-parent duplicate suppression but created a deterministic equality test for any colluding relays observing the same attempt. Fresh IDs across rings did not restore unlinkability within one attempt.

The legacy draft intended non-adjacent messages to be unlinkable. That objective cannot coexist with an unchanged attempt identifier visible at every hop.

## Decision

Core v0.3 removes `attempt_id` from the wire protocol. Every forwarded copy is represented by an independent branch context identified only by a peer-bound random token. Relays replace tokens at every hop and reject only exact adjacent-link replays.

A branch that reaches the same physical relay through another peer or token is independent state. Immediate backtracking is excluded, while longer cycles are controlled by hard hop, fan-out, state, and transmission budgets.

## Consequences

Positive:

- no protocol identifier provides direct non-adjacent equality testing;
- branch and candidate capabilities become link-local;
- the design can state a conditional wire-image unlinkability property.

Negative:

- network-wide and attempt-wide duplicate suppression is lost;
- converging branches and loops allocate multiple contexts at one relay;
- resource accounting becomes a security dependency;
- simulation must quantify context amplification and budget exhaustion.

## Validation

The deterministic simulator includes a U1 branch-local mode and compares it with the v0.2 first-parent model in `reports/iteration-0004-unlinkability-comparison.csv`.
