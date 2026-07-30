<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0002: Separate bounded discovery from global resolution

- Status: Accepted
- Date: 2026-07-30

## Context

The legacy design includes local flooding, gateways, beacons, authorities, address-space masks, registration, propagation, and lookup. The long-range registration and lookup sections are incomplete, and their privacy properties differ from local route setup.

## Decision

Trahens Core v0.1 contains only bounded discovery, acknowledgement, confirmation, route-state lifecycle, and local candidate selection. Beacon and authority behavior will be specified as a separate directory protocol after Core is measurable.

## Consequences

- The first specification is smaller and independently testable.
- A deployment cannot perform global destination resolution using Core alone.
- Directory designs can be compared without changing local forwarding semantics.

## Validation

Core conformance tests must not require any beacon, authority, or global address-space partition.
