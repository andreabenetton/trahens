# Legacy-to-current traceability

| Legacy concept | Current treatment | Location |
|---|---|---|
| Nexus secure adjacent links | Replaced by a minimal underlay contract plus named privacy profiles | `spec/core-v0.3.md`, ADR-0001, ADR-0005 |
| T-FLOOD | Renamed DISCOVER with bounded propagation and complete per-hop transformation | `spec/core-v0.3.md`, `spec/messages-v0.3.md` |
| T-ACK-L | Reframed as nested CANDIDATE reverse propagation that installs tentative mappings | `spec/core-v0.3.md`, `spec/crypto-transcript-v0.1.md` |
| T-ACK-R | Split into COMMIT and READY so selection and activation are explicit | `spec/core-v0.3.md`, `spec/state-machines-v0.3.md` |
| Left and right labels | Replaced by direction-bound, peer-bound random local capabilities | `spec/core-v0.3.md`, `spec/invariants-v0.3.md` |
| BIP32-like child keys | Replaced in the research design by a blinded reply-key chain and nested return capsule | ADR-0003, ADR-0009, `spec/crypto-transcript-v0.1.md` |
| Unchanged hidden destination selector | Replaced by a rerandomizable eligibility capsule in U1 | ADR-0010, `spec/unlinkability-profile-u1.md` |
| Obfuscated degree | Removed as a Core dependency | Core fan-out classes and ADR-0006 |
| One broad flood | Replaced by bounded local policy; expanding rings remain initiator-local | ADR-0006, Core v0.3 |
| Stable discovery or attempt context | Removed from the wire; only peer-bound branch contexts remain | ADR-0008, Core v0.3 |
| Gateway and Beacon discovery | Represented generically as eligible responders and service selectors | `spec/core-v0.3.md` |
| Beacon and Authority directory | Deferred into a separate future protocol | ADR-0002 |
| Batch mixing and chaff | Required by U1 for batch-local unlinkability; traffic scheduling remains a separate profile | ADR-0005, `spec/unlinkability-profile-u1.md` |
| Unlinkability for non-adjacent messages | Restored as a conditional, explicitly scoped U1 property; global timing and active tagging are not claimed | `spec/unlinkability-profile-u1.md`, `docs/threat-model.md` |
