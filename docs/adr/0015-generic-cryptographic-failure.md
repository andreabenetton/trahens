# ADR-0015: Normalize cryptographic failure behavior

- Status: Accepted
- Date: 2026-07-30

## Context

Different responses to malformed points, wrong eligibility keys, marker mismatches, AEAD failures, and signature failures can create decryption or eligibility oracles. Even when no explicit response is sent, divergent state allocation or amplified work may reveal the cause.

## Decision

All C1 cryptographic failures map to one state-machine result, `INVALID_CRYPTO`. The protocol sends no differentiated discovery or candidate error. Expensive work is preceded by record, replay, rate, and capacity checks. Any required logging is local and access-controlled.

## Consequences

- network behavior does not intentionally reveal the detailed failure cause;
- conformance tests can assert one external failure path;
- timing equalization remains an implementation obligation and is not proven by the reference code;
- operational diagnostics must not become protocol-visible.
