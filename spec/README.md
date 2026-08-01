<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Specifications

## Active P1 profile (v1.6)

v1.6 is the profile the implementation speaks. `DISCOVER` differs by 32 bytes
from v1.5, so the two do not interoperate
(`../docs/adr/0040-routing-nonce-split.md`).

- [`core-v1.6.md`](core-v1.6.md) — mandatory interoperability semantics and evidence boundary.
- [`protocol-registry-v1.6.json`](protocol-registry-v1.6.json) — normative IDs, widths, limits, byte order, domains, and protection classes.
- [`protocol-registry-v1.6.md`](protocol-registry-v1.6.md) — generated human-readable registry.
- [`p1-prototype-profile-v1.6.md`](p1-prototype-profile-v1.6.md) — executables, Linux harness, fuzzing, metrics, and acceptance gate.
- [`messages-v1.6.md`](messages-v1.6.md), [`state-machines-v1.6.md`](state-machines-v1.6.md), [`invariants-v1.6.md`](invariants-v1.6.md), and [`resource-accounting-v1.6.md`](resource-accounting-v1.6.md) — P1 message roles, typed lifecycle, safety invariants, and concrete ceilings.
- `p1-conformance-vectors-v1.6.json` and `p1-conformance-corpus-v1.6.bin` — canonical and noncanonical encodings.

The mandatory v1.6 path is U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1. Adaptive
T2 and C1 eligibility are selectable experimental profiles with their own CI
gates and their own narrower claims. T3/T4 remain analysis profiles. D1 remains
a non-normative private-directory dependency.

## Component profiles

These filenames carry no revision, so each always describes the **active**
profile rather than the revision it was introduced in. A change here applies to
v1.6; the frozen v1.5 documents below are not retrospectively edited.

- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md), [`message-codec-m2.md`](message-codec-m2.md), [`wire-cell-w2.md`](wire-cell-w2.md), [`transport-profile-t1.md`](transport-profile-t1.md), [`transport-profile-t2.md`](transport-profile-t2.md), [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md), and [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md).

## Historical: v1.5 and earlier

**v1.5 is history.** Its files are retained and still regenerate from their own
generators, so anyone checking an implementation against that profile can, but
no binary in this repository speaks it.

- [`core-v1.5.md`](core-v1.5.md), [`messages-v1.5.md`](messages-v1.5.md), [`state-machines-v1.5.md`](state-machines-v1.5.md), [`invariants-v1.5.md`](invariants-v1.5.md), [`resource-accounting-v1.5.md`](resource-accounting-v1.5.md), [`p1-prototype-profile-v1.5.md`](p1-prototype-profile-v1.5.md).
- `protocol-registry-v1.5.json`, `protocol-registry-v1.5.md`, `p1-conformance-vectors-v1.5.json`, `p1-conformance-corpus-v1.5.bin`.
- Earlier revisions: `core-v1.4.1.md`, `core-v0.*.md`, and the other superseded documents in this directory.

## Cryptographic profiles

- [`crypto-profile-c1.md`](crypto-profile-c1.md) — C1 v2 research construction, suite `0x0003`, construction-wide v2 domains, multiplicative blinding, standard Extract-then-Expand, and recipient-bound commitment.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) — provider boundary.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) and [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) — symbolic research target.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) — disabled transcription audit.

C1 v1 suite `0x0001` is retired and MUST be rejected. Symbolic C2 `0x0002` is research-only. Disabled `0x7f02` MUST be rejected by network decoders. Active R1 is `0x0101`.

## Conformance vectors

- [`p1-conformance-vectors-v1.5.json`](p1-conformance-vectors-v1.5.json) and [`p1-conformance-corpus-v1.5.bin`](p1-conformance-corpus-v1.5.bin) — independently encoded positive/negative M2 corpus for every message type.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) — C1 v2 vectors.
- [`r1-test-vectors.json`](r1-test-vectors.json), [`t1-test-vectors.json`](t1-test-vectors.json), and [`t2-test-vectors.json`](t2-test-vectors.json) — component vectors.
- T3/T4 vectors remain analysis artifacts, not mandatory P1 interop material.

Earlier versioned specifications are retained for traceability and are not active.
