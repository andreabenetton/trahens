# Design traceability

| Earlier concern or mechanism | Current treatment | Authoritative artifact |
|---|---|---|
| Stable discovery identifier | Removed; branch-local capabilities and replacement nonces | `spec/unlinkability-profile-u1.md`, `spec/rendezvous-capability-r1.md` |
| Endpoint selector in exploration | Removed from active DISCOVER; capability used only after READY | `spec/rendezvous-capability-r1.md` |
| Implicit route activation | Tentative CANDIDATE, outward COMMIT, inward READY | `spec/state-machines-v1.4.md` |
| Directional labels | Peer-, direction-, epoch-, generation-, and deadline-bound random capabilities | `spec/invariants-v1.4.md` |
| Deterministic child-key derivation | Additive `ristretto255` reply-key chain and nested return capsule | `spec/crypto-profile-c1.md` |
| One fixed logical record | Canonical variable-length M2 message carried in fixed W2/T1/T2 cells | `spec/message-codec-m2.md`, `spec/wire-cell-w2.md` |
| Padding inside semantic message | Removed; padding belongs to encrypted adjacent-link cells | M2/W2/T1 specifications |
| Best-effort cleanup only | Independent local expiry plus advisory CANCEL/ABORT/CLOSE | E1 and v1.4 state machines |
| Unbounded convergence state | Explicit per-peer/global branch, reassembly, queue, and timer budgets | `spec/resource-accounting-v1.4.md` |
| Fragment loss | Hop-local cumulative selective ACK and bounded missing-fragment recovery | `spec/transport-profile-t1.md` |
| Retry equality | Fresh sequence, padding, authentication tag, and ciphertext per emission | T1 and v1.4 invariants |
| Fixed cadence under overload | Quantized rate classes, admission, and fail-closed maximum-class behavior | `spec/transport-profile-t2.md` |
| FIFO or equal-flow service | Weighted deficit round robin over fixed-size DATA cells | T2 and ADR-0028 |
| Hidden adaptive rate | Rejected; public class sequence is explicit leakage | T2 privacy boundary and paper |
| Loss modeled only as independent | Added two-state Gilbert-Elliott stress baseline | T2 reports |
| Single-link trace claim extrapolated globally | Prohibited; multi-link correlation measured separately | T2 report and threat model |
| Implicit directory | Separate private descriptor profile remains open | R1 limitations and roadmap |
| Unqualified unlinkability | Structural, batch-local, active-tag, directory, fixed-schedule, adaptive-rate, and global-traffic claims separated | threat model and paper |

| Equal-bandwidth traffic analysis | Exact per-link super-epoch budgets plus route classification and active probing | `spec/transport-profile-t3.md` |
