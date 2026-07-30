# Legacy-to-current traceability

| Legacy concept | Current treatment | Location |
|---|---|---|
| Nexus secure adjacent links | Replaced by a minimal underlay contract and optional privacy profiles | `spec/core-v0.1.md`, ADR-0001, ADR-0005 |
| T-FLOOD | Renamed DISCOVER with explicit hop, fan-out, duplicate, expiry, and state limits | `spec/core-v0.1.md`, `spec/messages-v0.1.md` |
| T-ACK-L | Reframed as CANDIDATE reverse propagation that installs tentative forward mappings | `spec/core-v0.1.md` |
| T-ACK-R | Split into COMMIT and READY so selection and activation are explicit | `spec/core-v0.1.md` |
| Left and right labels | Replaced by direction-bound random hop labels | `spec/core-v0.1.md`, `spec/invariants.md` |
| BIP32-like child keys | Rejected as a required routing mechanism; replacement profile remains proposed | ADR-0003 |
| Obfuscated degree | Removed as a Core dependency | `docs/strategy.md`, Core fan-out rules |
| Gateway and Beacon discovery | Represented generically as eligible responders and service selectors | `spec/core-v0.1.md` |
| Beacon and Authority directory | Deferred into a separate future protocol | ADR-0002 |
| Batch mixing and chaff | Moved into explicit privacy profiles | ADR-0005 |
| Unlinkability for non-adjacent messages | Treated as an unproven legacy claim; Core v0.1 explicitly does not satisfy it | `spec/invariants.md`, `docs/threat-model.md` |
