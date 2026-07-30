<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0026: Fixed schedule, interleaving, and chaff

- Status: Accepted as an experimental privacy profile
- Date: 2026-07-30

## Context

Equal cell length does not hide idle periods, fragment bursts, or message timing. A multi-cell candidate can remain distinguishable by the number and spacing of records even when every record is encrypted and padded.

## Decision

T1 fixed-schedule mode emits one complete record in every directed slot during a finite pre-existing schedule epoch. The encrypted scheduler class is selected in this order: due ACK, retransmission, round-robin new DATA, then CHAFF. Work-conserving mode remains available but makes no constant-trace claim.

The protocol claims only a link-local schedule-shape property: while the epoch and slot rate remain fixed and the queue does not overflow, public lengths and timestamps are independent of whether the slot contains DATA, ACK, or CHAFF.

## Consequences

- Active and empty traffic have identical modeled per-direction slot traces.
- Bandwidth overhead can be large and is reported explicitly.
- Schedule start, stop, rate, direction, topology, congestion changes, and global cross-link correlation remain observable.
- A deployment that cannot sustain its promised CHAFF reserve has exited the profile.

## Sources

TARANET motivates coordinated constant-rate transmission for traffic-analysis resistance. Loopix demonstrates a different design point based on Poisson mixing and cover traffic. T1 uses deterministic fixed slots and does not claim the Loopix statistical anonymity model.
