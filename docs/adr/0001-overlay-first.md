<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0001: Develop an overlay before a new network layer

- Status: Accepted
- Date: 2026-07-30

## Context

The legacy draft depends on a new adjacent-link layer named Nexus and positions Trahens as part of a replacement layer-3 stack. This combines route-discovery research with link security, fragmentation, transport behavior, deployment, and hardware concerns.

## Decision

The first executable Trahens version will operate as an overlay over an existing authenticated transport. Underlay profiles may later describe QUIC, local secure links, or scheduled padded links. A new layer-2 or layer-3 stack is outside Core v0.1.

## Consequences

- Protocol state machines and privacy leakage can be studied without building an entire network stack.
- Some metadata protections cannot be claimed for the baseline overlay profile.
- The core remains reusable by stronger underlays later.

## Validation

The overlay prototype must establish and expire routes on a controlled multi-node testbed without depending on privileged kernel networking.
