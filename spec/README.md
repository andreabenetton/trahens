<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Specifications

## Active P1 profile: v1.8

v1.8 is the profile the implementation speaks. It replaces the pre-shared
adjacent-link key and configured epoch with the B1.1 authenticated handshake, so
every session derives its own directional keys and its own epoch. The protocol
version byte becomes `3`, so v1.7 and v1.8 do not interoperate, and a v1.7 node
cannot bring a link up at all (`../docs/adr/0043-b1.1-handshake-decisions.md`).

- [`core-v1.8.md`](core-v1.8.md) — mandatory interoperability semantics and evidence boundary.
- [`link-handshake-b1.md`](link-handshake-b1.md) — normative B1.1 adjacent-link handshake: Noise `XX`/`XXpsk0`, record encoding, negotiation, pinning, and derivation.
- [`protocol-registry-v1.8.json`](protocol-registry-v1.8.json) — normative IDs, widths, limits, byte order, domains, and protection classes; current registry version 1.8.0.
- [`protocol-registry-v1.8.md`](protocol-registry-v1.8.md) — generated human-readable registry.
- [`p1-prototype-profile-v1.8.md`](p1-prototype-profile-v1.8.md) — executables, Linux harness, fuzzing, metrics, and acceptance gate.
- [`messages-v1.8.md`](messages-v1.8.md), [`state-machines-v1.8.md`](state-machines-v1.8.md), [`invariants-v1.8.md`](invariants-v1.8.md), and [`resource-accounting-v1.8.md`](resource-accounting-v1.8.md) — message roles, typed lifecycle, safety invariants, and concrete ceilings.
- `p1-conformance-vectors-v1.8.json` and `p1-conformance-corpus-v1.8.bin` — active canonical and noncanonical encoding corpus.
- `b1-test-vectors.json` — handshake vectors, cross-checked against an independent Noise implementation.

The mandatory v1.8 path is B1.1 + U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1.
Adaptive T2 and C1 eligibility are selectable experimental profiles with their
own CI gates and narrower claims. T3 and T4 remain analysis profiles. D1, and
B1.2 onward, remain non-normative future architecture work.

## Component profiles

These filenames carry no Core revision, so each describes the **active** profile
unless its own status says otherwise. A change here applies to v1.8; frozen
historical documents are not retrospectively edited.

- [`link-handshake-b1.md`](link-handshake-b1.md) — mandatory authenticated adjacent-link establishment and rekey.
- [`rendezvous-capability-r1.md`](rendezvous-capability-r1.md) — mandatory generic gateway discovery and one-time redemption.
- [`message-codec-m2.md`](message-codec-m2.md) — canonical suite-agile logical messages.
- [`wire-cell-w2.md`](wire-cell-w2.md) — fixed-size adjacent-link records and fragmentation contract.
- [`transport-profile-t1.md`](transport-profile-t1.md) — hop-local loss recovery.
- [`transport-profile-t2.md`](transport-profile-t2.md) — fixed, adaptive, and work-conserving scheduling profiles.
- [`event-lifecycle-profile-e1.md`](event-lifecycle-profile-e1.md) — event precedence, deadlines, and cleanup.
- [`eligibility-suite-interface-v1.md`](eligibility-suite-interface-v1.md) — provider interface for R1 and experimental C1.

## Non-normative system dependencies and future work

- [`private-directory-d1.md`](private-directory-d1.md) — private descriptor-distribution strawman; not implemented or proven.
- [`network-bootstrap-b1.md`](network-bootstrap-b1.md) — the bootstrap architecture. Its B1.1 stage landed in v1.8 and is now normative in `link-handshake-b1.md`; stages B1.2 onward — peer discovery, admission, gateway advertisement, and directory-root bootstrap — remain future work. Core v1.8 still uses a statically configured peer list with pinned static keys.

D1 answers how an authorized client might privately retrieve a destination
descriptor. The remaining B1 stages answer how nodes might find one another and
learn system roots. Neither is part of P1 route discovery.

## Historical: v1.7 and earlier

**v1.7, v1.6 and v1.5 are history.** Their files remain and still regenerate
from their own generators, so an implementation can be checked against any
frozen profile, but no current binary in this repository speaks them.

- [`core-v1.7.md`](core-v1.7.md), [`messages-v1.7.md`](messages-v1.7.md), [`state-machines-v1.7.md`](state-machines-v1.7.md), [`invariants-v1.7.md`](invariants-v1.7.md), [`resource-accounting-v1.7.md`](resource-accounting-v1.7.md), and [`p1-prototype-profile-v1.7.md`](p1-prototype-profile-v1.7.md).
- `protocol-registry-v1.7.json`, `protocol-registry-v1.7.md`, `p1-conformance-vectors-v1.7.json`, and `p1-conformance-corpus-v1.7.bin`.
- [`core-v1.6.md`](core-v1.6.md), [`messages-v1.6.md`](messages-v1.6.md), [`state-machines-v1.6.md`](state-machines-v1.6.md), [`invariants-v1.6.md`](invariants-v1.6.md), [`resource-accounting-v1.6.md`](resource-accounting-v1.6.md), and [`p1-prototype-profile-v1.6.md`](p1-prototype-profile-v1.6.md).
- `protocol-registry-v1.6.json`, `protocol-registry-v1.6.md`, `p1-conformance-vectors-v1.6.json`, and `p1-conformance-corpus-v1.6.bin`.
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

### Active v1.8

- `p1-conformance-vectors-v1.8.json` and `p1-conformance-corpus-v1.8.bin` — 32 independently encoded positive and negative M2 vectors for the active profile.
- [`b1-test-vectors.json`](b1-test-vectors.json) — B1.1 handshake vectors for an initial exchange and a chained rekey, cross-checked against an independent Noise implementation.
- [`crypto-test-vectors-c1.json`](crypto-test-vectors-c1.json) — C1 v2 vectors.
- [`r1-test-vectors.json`](r1-test-vectors.json), [`t1-test-vectors.json`](t1-test-vectors.json), and [`t2-test-vectors.json`](t2-test-vectors.json) — component vectors.

### Historical v1.7, v1.6 and v1.5

- `p1-conformance-vectors-v1.7.json` and `p1-conformance-corpus-v1.7.bin` — frozen historical corpus retained for reproducibility only.
- `p1-conformance-vectors-v1.6.json` and `p1-conformance-corpus-v1.6.bin` — frozen historical corpus retained for reproducibility only.
- `p1-conformance-vectors-v1.5.json` and `p1-conformance-corpus-v1.5.bin` — frozen historical corpus retained for reproducibility only.

T3 and T4 vectors remain analysis artifacts, not mandatory P1 interoperability
material.