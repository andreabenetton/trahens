# Design traceability

| Earlier concept | Current treatment | Active location |
|---|---|---|
| Broad local flooding | Bounded initiator-local expanding rings | `spec/core-v1.1.md` |
| Stable discovery context | Removed from the wire; peer-bound branch contexts only | U1, `spec/invariants-v1.1.md` |
| Forward endpoint selector | Removed from active DISCOVER; replaced by non-semantic R1 nonce | `spec/rendezvous-capability-r1.md` |
| Endpoint discovery ciphertext | Retained only in disabled/research C1 and C2 providers | `spec/eligibility-suite-interface-v1.md` |
| Gateway or responder discovery | Generic rendezvous gateway candidates with protected short-lived pseudonyms | `spec/core-v1.1.md` |
| Endpoint connection after discovery | Post-READY single-use capability redemption | `spec/rendezvous-capability-r1.md` |
| Reverse acknowledgement | Nested CANDIDATE return installing tentative state | `spec/messages-v1.1.md` |
| Final route acknowledgement | Split into COMMIT and READY | `spec/state-machines-v1.1.md` |
| Directional labels | Peer-, direction-, epoch-, generation-, and deadline-bound random capabilities | `spec/invariants-v1.1.md` |
| Deterministic child-key derivation | Additive `ristretto255` reply-key chain and nested return capsule | `spec/crypto-profile-c1.md` |
| One fixed logical record | Canonical variable-length M2 message carried in fixed W2 cells | `spec/message-codec-m2.md`, `spec/wire-cell-w2.md` |
| Padding inside semantic message | Removed; padding belongs to encrypted W2 cells | M2/W2 specs |
| Best-effort cleanup only | Independent local expiry plus advisory CANCEL/ABORT/CLOSE | E1 and v1.0 state machines |
| Unbounded convergence state | Explicit per-peer/global branch and reassembly budgets | `spec/resource-accounting-v1.1.md` |
| Implicit directory | Explicitly separate private descriptor profile, not yet specified | R1 limitations and roadmap |
| Unqualified unlinkability | Structural, batch-local, active-tag, directory, and traffic claims separated | `docs/threat-model.md`, paper |

| Fragment loss | Hop-local cumulative selective ACK and bounded missing-fragment recovery | `spec/transport-profile-t1.md` |
| Retry equality | Fresh sequence, padding, authentication tag, and ciphertext per emission | `spec/transport-profile-t1.md`, `spec/invariants-v1.1.md` |
| Fragment burst and idle leakage | Fixed directed slots with encrypted DATA/ACK/CHAFF class and explicit residual leakage | `spec/transport-profile-t1.md` |
