<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0038: Reconciliations for completing the Rust implementation

## Status

Accepted for v1.5 (registry 1.5.1).

## Context

Closing the P1 acceptance gate requires implementing every normative MUST on
the mandatory path in Rust. Three places needed a decision rather than code
alone: two independent candidate-transcript formats exist, the W2 fragment
header is specified twice at different layers, and the E1 lifecycle names a
phase the Rust state machine lacks. Deciding these silently in code would
hide claim-boundary choices that the v1.6 external review must see.

## Decision

1. **Candidate transcripts.** The P1 `GatewayOffer` transcript
   (`implementation/rust/crates/node-runtime/src/p1.rs`, domain
   `Trahens-P1-gateway-offer-v1`) is normative for the R1 wire path. The C1
   responder-payload transcript (`simulator/trahens_crypto/candidate.py`,
   domain `candidate-transcript`) is normative only for the network-disabled
   C1 research suite and its published vectors. The Rust C1 work implements
   the C1 format as a library for vector agreement; it is never emitted on
   the P1 wire, and the two formats keep distinct domain separators by
   construction.

2. **W2 fragment header.** Under T1 — the only P1 transport — the W2 §4
   header is realized by the T1 DATA frame header, as now stated in
   `spec/wire-cell-w2.md` §4. The 32-byte W2 form is reserved for a future
   transport that runs W2 without T1 framing. P1 implementations MUST emit
   the T1 realization and MUST NOT emit both.

3. **PENDING_READY.** The Rust state machine gains a distinct
   `PendingReady` phase with a ready-hold deadline and data rejection,
   implementing `event-lifecycle-profile-e1.md` §6.1 as written. This is a
   code obligation; no spec text changes.

## Consequences

The C1 library in Rust checks the same vectors as the Python reference
without creating a second wire chain. Frozen vectors and the conformance
corpus remain valid because the T1 realization was already the encoded
form. The v1.6 review can audit each reconciliation as an explicit decision
with its alternatives stated here rather than reverse-engineering them from
code.
