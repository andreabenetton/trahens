<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0006: Evaluate expanding-ring discovery before fixed broad flooding

- Status: Accepted
- Date: 2026-07-30

## Context

The first parameter sweep shows a steep trade-off between responder discovery and control traffic. In a 500-node, average-degree-8 model with 2 percent responders, hop limit 4 and fan-out 3 found at least one candidate in 95 percent of runs with about 116 transmissions on average. Increasing to hop limit 5 and fan-out 4 reached 100 percent success but used about 913 transmissions and produced about 486 duplicate deliveries on average.

A single fixed broad flood therefore spends high cost even when a nearby responder exists.

## Decision

Before adopting fixed broad flooding, evaluate an expanding-ring policy:

1. start with a small hop limit and fan-out;
2. wait for a bounded candidate window;
3. stop when selection policy has sufficient candidates;
4. otherwise retry with a larger ring and a fresh attempt context;
5. cap total attempts, total transmitted messages, and total state across all rings.

The design must also measure whether retry timing or reused identifiers increase linkability.

## Consequences

- Nearby responders may be found with substantially less traffic.
- Setup latency rises when multiple rings are required.
- Repeated attempts can create a new correlation signal.
- State accounting must span the entire logical discovery, not only one ring.

## Validation

Iteration 0003 implemented the policy and compared it with a fixed hop-5/fan-out-4 flood on 500-node, average-degree-8 graphs. At a 2 percent responder fraction, expanding rings retained 100 percent observed success while reducing mean DISCOVER transmissions from 895.12 to 157.65. The simulator also reports relay overlap across attempts as a correlation surface.

The decision is accepted for the active Core v0.2 draft. Ring parameters remain deployment policy and require further topology and adversary testing.
