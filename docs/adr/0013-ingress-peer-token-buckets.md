<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0013: Admit fresh branches through ingress-peer token buckets

- Status: Accepted with limitations
- Date: 2026-07-30

## Context

U1 deliberately removes an attempt-wide duplicate identifier. Exact adjacent-link replay protection rejects retransmission of one token but cannot reject a stream of syntactically valid fresh tokens. Such a stream can consume branch capacity and cryptographic work before global budgets stop it.

## Decision

Before expensive fresh-branch processing, each relay applies a token bucket scoped at least to `(link epoch, ingress peer, receiving node)`. One admitted fresh DISCOVER consumes one token. Exact replays are rejected before token consumption.

Token buckets are combined with per-node context limits, node-global capacities, propagation bounds, and cryptographic-work budgets. They are not treated as Sybil resistance.

## Consequences

- concentrated fresh-token floods are throttled before full allocation;
- legitimate branches sharing an ingress peer can also be delayed or rejected;
- distributed attackers can aggregate many independent buckets;
- bucket parameters are deployment policy and require success-versus-abuse measurement;
- node-global limits remain mandatory.

## Validation

In the tracked 500-node E1 experiment, a fresh-branch attack reduced route-setup success from 89 percent in the clean scenario to 32 percent without the bucket. A one-token bucket with one-token-per-10-ms refill raised success to 76 percent, reduced mean attack transmissions from 1,389.94 to 1,037.09, and reduced mean attack branch allocations from 1,116.61 to 839.36. The attack remained material, confirming that the bucket is mitigation rather than a complete defense.
