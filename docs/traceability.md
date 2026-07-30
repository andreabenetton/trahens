# Legacy-to-current traceability

| Legacy concept | Current treatment | Location |
|---|---|---|
| Nexus secure adjacent links | Replaced by a minimal underlay contract plus named privacy profiles | `spec/core-v0.7.md`, ADR-0001, ADR-0005 |
| T-FLOOD | Renamed DISCOVER with bounded propagation and complete per-hop transformation | `spec/core-v0.7.md`, `spec/messages-v0.7.md` |
| T-ACK-L | Reframed as nested CANDIDATE reverse propagation installing tentative mappings | `spec/core-v0.7.md`, `spec/crypto-transcript-v0.2.md` |
| T-ACK-R | Split into COMMIT and READY so selection, reservation, and activation are explicit | `spec/core-v0.7.md`, `spec/state-machines-v0.7.md` |
| Left and right labels | Replaced by direction-, peer-, generation-, and deadline-bound random capabilities | `spec/core-v0.7.md`, `spec/invariants-v0.7.md` |
| BIP32-like child keys | Replaced by an additive `ristretto255` reply-key chain and nested C1 return capsule | ADR-0003, ADR-0009, ADR-0014, `spec/crypto-profile-c1.md` |
| Unchanged hidden destination selector | Replaced by a 128-byte universally rerandomizable C1 eligibility capsule | ADR-0010, ADR-0014, `spec/crypto-profile-c1.md` |
| Abstract encryption/signature symbols | Replaced by exact C1 algorithms, encodings, transcripts, vectors, and generic failure | ADR-0014, ADR-0015, `spec/crypto-transcript-v0.2.md` |
| Obfuscated degree | Removed as a Core dependency | Core fan-out classes and ADR-0006 |
| One broad flood | Replaced by bounded initiator-local expanding rings | ADR-0006, Core v0.7 |
| Stable discovery or attempt context | Removed from the wire; only peer-bound branch contexts remain | ADR-0008, Core v0.7 |
| Gateway and Beacon discovery | Represented generically as eligible responders and service selectors | `spec/core-v0.7.md` |
| Beacon and Authority directory | Deferred into a separate future protocol | ADR-0002 |
| One padded control record | Replaced by canonical variable-length M1 logical messages carried in one or more fixed-size W2 encrypted cells with bounded reassembly | ADR-0019, ADR-0020, `spec/message-codec-m1.md`, `spec/wire-cell-w2.md` |
| Batch mixing and chaff | Required by U1 for batch-local unlinkability; scheduling remains a separate profile | ADR-0005, `spec/unlinkability-profile-u1.md` |
| Non-adjacent message unlinkability | Restored as a conditional U1 property; timing and active tagging are not claimed | `spec/unlinkability-profile-u1.md`, `docs/threat-model.md` |
