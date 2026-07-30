# v1.5 independent-review remediation

## Source

This revision addresses the 30 July 2026 independent re-review of v1.4.1 and carries its actionable findings into the P1 implementation baseline.

## Closed findings

| Review item | v1.5 action |
|---|---|
| C1 v2 prose/code domain mismatch | All C1 domains are construction-wide v2 values generated from one registry. |
| CI compared code-generated vectors only | Registry source now generates Python, Rust, and Markdown bindings; CI compares all outputs and runs independent malformed vectors. |
| Deterministic crypto helper shipped in package | Helpers moved to `tools/`; production functions no longer accept deterministic ephemeral values. |
| Missing `rg` silently disabled paper check | CI explicitly uses `rg` when present and a `grep -E` fallback otherwise. |
| Incompatible C1 versions shared suite ID | C1 v1 `0x0001` is retired; C1 v2 uses `0x0003`; decoders reject `0x0001`. |
| Non-committing reply AEAD | C1 v2 adds an independent 32-byte HMAC key commitment and uniform rejection. |
| No spec-to-code constant authority | `protocol-registry-v1.5.json` is normative and reproducibly generated into both implementations. |
| Post-quantum consequence undocumented | ADR 0036 records that reply-path migration requires redesign. |
| Prototype deferred too long | ADR 0037 and `implementation/rust/` establish the UDP P1 implementation and namespace harness. |

## Partially closed or intentionally open

- Reply key privacy now has a precise IK-CPA reduction sketch and robustness mechanism. Multi-user IK-CCA and the nested composition still require external review.
- R1 and E1 have executable bounded-state models and TLA+ specifications. These are not equivalent to an unbounded Tamarin/ProVerif proof.
- Entropy and effective-anonymity-set metrics are added to T3/T4 analysis. They remain model measurements, not deployment claims.
- D1 private directory implementation remains outside P1 and remains a system-level anonymity dependency.

## Validation boundary

Python conformance, registry generation, bounded models, vectors, and repository checks are executable in the current environment. Rust source and Linux CI are included, but local Rust compilation cannot be claimed on a host without a Rust toolchain. Namespace acceptance also requires Linux root or suitable user-namespace capabilities plus `ip`, `tc`, and a capture tool.
