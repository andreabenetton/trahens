<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR-0018: Integrate C1, W1, and E1 in one event model

- Status: Accepted for research validation
- Date: 2026-07-30

## Context

The lifecycle model previously used abstract cryptographic success, while C1 conformance tests exercised primitives separately. That separation could conceal incorrect state transitions after malformed records, candidate-chain failures, or transcript mismatches. It also prevented measurement of exact wire bytes and cryptographic work.

## Decision

The reference event model executes the complete receive and send path:

1. encode or receive one 1,052-byte W1 record;
2. authenticate the adjacent link and parse canonical fields;
3. apply E1 replay, deadline, token-bucket, and capacity checks;
4. execute C1 eligibility, reply-key, nested candidate, signature, COMMIT, and READY operations;
5. transition state only after all required validation succeeds;
6. encode a fresh W1 record for every outgoing hop.

Fault injection includes adjacent-link tampering and compromised-relay ratio tagging. The model reports wire authentication, codec, cryptographic, route, state, and cleanup outcomes.

## Consequences

- codec and cryptographic failures are tested in their lifecycle positions;
- route activation cannot bypass candidate, COMMIT, or READY authentication;
- exact wire bytes and cryptographic transformations are measurable;
- the model remains deterministic and is not a network throughput benchmark;
- future transport and mixing implementations can use the integrated traces as a conformance oracle.
