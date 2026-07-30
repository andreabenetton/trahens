# Legacy-to-current traceability

| Legacy concept | Current treatment | Location |
|---|---|---|
| Nexus secure adjacent links | Replaced by a minimal underlay contract and optional privacy profiles | `spec/core-v0.2.md`, ADR-0001, ADR-0005 |
| T-FLOOD | Renamed DISCOVER with explicit attempt, hop, fan-out, expiry, and resource limits | `spec/core-v0.2.md`, `spec/messages-v0.2.md` |
| T-ACK-L | Reframed as CANDIDATE reverse propagation that installs tentative forward mappings | `spec/core-v0.2.md` |
| T-ACK-R | Split into COMMIT and READY so selection and activation are explicit | `spec/core-v0.2.md` |
| Left and right labels | Replaced by direction-bound random hop labels | `spec/core-v0.2.md`, `spec/invariants-v0.2.md` |
| BIP32-like child keys | Rejected as a required routing mechanism; replacement profile remains proposed | ADR-0003 |
| Obfuscated degree | Removed as a Core dependency | Core fan-out rules and ADR-0006 |
| One broad flood | Replaced by a bounded expanding-ring policy baseline | ADR-0006, Core v0.2 |
| Stable discovery context | Split into local logical discovery and fresh per-ring attempt IDs | ADR-0007, Core v0.2 |
| Gateway and Beacon discovery | Represented generically as eligible responders and service selectors | `spec/core-v0.2.md` |
| Beacon and Authority directory | Deferred into a separate future protocol | ADR-0002 |
| Batch mixing and chaff | Moved into explicit privacy profiles | ADR-0005 |
| Unlinkability for non-adjacent messages | Treated as an unproven legacy claim; Core v0.2 explicitly does not satisfy it | `spec/invariants-v0.2.md`, `docs/threat-model.md` |
