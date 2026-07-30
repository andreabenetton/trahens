# ADR 0022: Bind cryptographic suites in M2 and W2

- Status: Accepted
- Date: 2026-07-30

## Context

M1 hard-coded the C1 suite and a fixed 128-byte eligibility capsule. C2 requires a different capsule representation and future concrete encodings may have different lengths. Suite selection must not become a cross-hop identifier, permit fragment splicing, or allow a message to change cryptographic interpretation after reassembly.

## Decision

M2 retains canonical variable-length logical messages and adds:

- a suite-agile two-byte suite identifier;
- a canonical length-delimited DISCOVER eligibility capsule;
- one immutable suite for the complete route-setup lifecycle.

W2 repeats the suite identifier inside every encrypted fragment header. The reassembly context binds the first admitted suite and rejects inconsistent fragments. After completion, the M2 suite must equal the W2 suite before semantic or cryptographic state is allocated.

## Consequences

- C1 and symbolic C2 messages can use the same W2 transport without ambiguous parsing.
- Cross-suite fragment substitution invalidates the entire reassembly context.
- A future concrete C2 encoding requires a reviewed suite identifier and exact canonical parser.
- Suite information remains adjacent-link encrypted, but a compromised relay naturally learns the suite it processes.
