<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Specifications

## Active P1 profile: v1.6

v1.6 is the profile the implementation speaks. `DISCOVER` differs by 32 bytes
from v1.5, so the two do not interoperate
(`../docs/adr/0040-routing-nonce-split.md`).

- [`core-v1.6.md`](core-v1.6.md) — mandatory interoperability semantics and evidence boundary.
- [`protocol-registry-v1.6.json`](protocol-registry-v1.6.json) — normative IDs, widths, limits, byte order, domains, and protection classes; current registry version 1.6.1.
- [`protocol-registry-v1.6.md`](protocol-registry-v1.6.md) — generated human-readable registry.
- [`p1-prototype-profile-v1.6.md`](p1-prototype-profile-v1.6.md) — executables, Linux harness, fuzzing, metrics, and acceptance gate.
- [`messages-v1.6.md`](messages-v1.6.md), [`state-machines-v1.6.md`](state-machines-v1.6.md), [`invariants-v1.6.md`](invariants-v1.6.md), and [`resource-accounting-v1.6.md`](resource-accounting-v1.6.md) — message roles, typed lifecycle, safety invariants, and concrete ceilings.
- `p1-conformance-vectors-v1.6.json` and `p1-conformance-corpus-v1.6.bin` — active canonical and noncanonical encoding corpus.

The mandatory v1.6 path is U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1.
Adaptive T2 and C1 eligibility are selectable experimental profiles with their
own CI gates and narrower claims. T3 and T4 remain analysis profiles. D1 and B1
remain non-normative future architecture work.

## Component profiles

These filenames carry no Core revision, so each describes the **active** profile
unless its own status says otherwise. A change here applies to v1.6; frozen
historical documents are not retrospectively edited.

- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md) — mandatory generic gateway discovery and one-time redemption.
- [`message-codec-m2.md`](message-codec-m2.md) — canonical suite-agile logical messages.
- [`wire-cell-w2.md`](wire-cell-w2.md) — fixed-size adjacent-link records and fragmentation contract.
- [`transport-profile-t1.md`](transport-profile-t1.md) — hop-local loss recovery.
- [`transport-profile-t2.md`](transport-profile-t2.md) — fixed, adaptive, and work-conserving scheduling profiles.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) — event precedence, deadlines, and cleanup.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) — provider interface for R1 and experimental C1.

## Non-normative system dependencies and future work

- [`private-directory-d1.md`](private-directory-d1.md) — private descriptor-distribution strawman; not implemented or proven.
- [`network-bootstrap-b1.md`](network-bootstrap-b1.md) — future peer discovery, admission, authenticated adjacent-link establishment, gateway advertisement, and directory-root bootstrap. Core v1.6 still uses statically configured peers and base keys.

D1 answers how an authorized client might privately retrieve a destination
descriptor. B1 answers how nodes might form authenticated adjacent links and
learn system roots. Neither is part of P1 route discovery.

## Historical: v1.5 and earlier

**v1.5 is history.** Its files remain and still regenerate from their own
generators, so an implementation can be checked against that frozen profile,
but no current binary in this repository speaks it.

- [`core-v1.5.md`](core-v1.5.md), [`messages-v1.5.md`](messages-v1.5.md), [`state-machines-v1.5.md`](state-machines-v1.5.md), [`invariants-v1.5.md`](invariants-v1.5.md), [`resource-accounting-v1.5.md`](resource-accounting-v1.5.md), and [`p1-prototype-profile-v1.5.md`](p1-prototype-profile-v1.5.md).
- `protocol-registry-v1.5.json`, `protocol-registry-v1.5.md`, `p1-conformance-vectors-v1.5.json`, and `p1-conformance-corpus-v1.5.bin`.
- Earlier revisions: `core-v1.4.1.md`, `core-v0.*.md`, and the other superseded documents in this directory.

## Cryptographic profiles

- [`crypto-profile-c1.md`](crypto-profile-c1.md) — C1 v2 research construction, suite `0x0003`, selectable on the experimental profile.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) — provider boundary and role-specific operations.
- [`crypto-profile-c2.md`](crypto-profile-c2.md) and [`active-unlinkability-games-c2.md`](active-unlinkability-games-c2.md) — symbolic research target.
- [`crypto-profile-c2-k2.md`](crypto-profile-c2-k2.md) — disabled transcription audit.

C1 v1 suite `0x0001` is retired and MUST be rejected. Symbolic C2 `0x0002` is
research-only. Disabled `0x7f02` MUST be rejected by network decoders. Mandatory
R1 is `0x0101`.

## Conformance vectors

### Active v1.6

- `p1-conformance-vectors-v1.6.json` and `p1-conformance-corpus-v1.6.bin` — 32 independently encoded positive and negative M2 vectors for the active profile.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) — C1 v2 vectors.
- [`r1-test-vectors.json`](r1-test-vectors.json), [`t1-test-vectors.json`](t1-test-vectors.json), and [`t2-test-vectors.json`](t2-test-vectors.json) — component vectors.

### Historical v1.5

- `p1-conformance-vectors-v1.5.json` and `p1-conformance-corpus-v1.5.bin` — frozen historical corpus retained for reproducibility only.

T3 and T4 vectors remain analysis artifacts, not mandatory P1 interoperability
material.