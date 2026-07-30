<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0027: Quantized adaptive scheduling at explicit epochs

- Status: Accepted
- Date: 2026-07-30

## Context

T1 fixed scheduling reserves a constant cell rate and can consume very large CHAFF bandwidth. Immediate work-conserving adaptation leaks exact demand and provides no overload contract.

## Decision

Add T2 with a finite rate menu, fixed-length epochs, one-class transitions, encrypted adjacent-link OFFER/ACCEPT frames, minimum hold time, and asymmetric queue-pressure hysteresis. The applied cadence remains public and is explicitly outside the fixed-trace privacy claim.

## Consequences

Bandwidth reservation can follow coarse sustained load, but rate-class transitions expose activity and can correlate across links. Fixed mode remains available when the deployment is willing to pay its reserve cost.
