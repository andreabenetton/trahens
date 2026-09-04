# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Trahens is a research protocol for privacy-enabled route discovery in decentralized path-aware networks. The active profile is **Core v1.6 (P1)**; v1.5 is history and its files are retained only so that profile stays reproducible. It is not a complete endpoint-anonymity system — private directory (D1), global-observer traffic-flow theorems, and production implementations are explicitly out of scope.

## Commands

See the `trahens-commands` skill for build/test/vector-regeneration commands (Python simulator and Rust implementation).

## Architecture

### Layered component model

The protocol is built from named profiles that stack on each other. Working top-down:

- **U1** — branch-local unlinkable context replacement (identifiers, nonces, keys replaced per hop)
- **E1** — deterministic event and route-state lifecycle (TLA+ in `formal/E1Lifecycle.tla`)
- **R1** — rendezvous-gateway discovery; post-`READY` one-time capability redemption (TLA+ in `formal/R1Capability.tla`)
- **M2** — suite-agile variable-length logical messages (`spec/message-codec-m2.md`, `simulator/trahens_codec/m2w2.py`)
- **W2** — fixed 992-byte authenticated wire fragments (`spec/wire-cell-w2.md`)
- **T1** — hop-local selective recovery with fresh retry ciphertexts (`spec/transport-profile-t1.md`)
- **T2** — fixed/adaptive schedule epochs, weighted DRR, chaff (`spec/transport-profile-t2.md`)
- **T3** — equal-budget multi-link traffic analysis model (`spec/transport-profile-t3.md`)
- **T4** — deterministic packet-event emulation with jitter, churn, open-world classification (`spec/transport-profile-t4.md`)

**Mandatory P1 path:** U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1. Adaptive T2, T3, and T4 are experimental analysis profiles; D1 is non-normative.

### Cryptographic profiles

- **C1 v2 (`0x0003`)** — active research control: ristretto255 blinding, ChaCha20-Poly1305, Ed25519 candidate auth, RFC 5869 KDF. Implemented in `simulator/trahens_crypto/c1.py` and `implementation/rust/crates/crypto/`.
- **Symbolic C2 (`0x0002`)** — ideal functionality for composition testing only (`simulator/trahens_crypto/c2_ideal.py`).
- **C2 k=2 audit (`0x7f02`)** — disabled transcription experiment; full rerandomization fails closed (`simulator/trahens_crypto/c2_klinear.py`).
- **C1 v1 (`0x0001`)** — retired; MUST be rejected.

Suite IDs and all numeric constants are generated from the single source of truth: `spec/protocol-registry-v1.6.json`. The v1.5 registry is historical and regenerates its own markdown only. Regenerate derived files with `make registry`.

### Repository layout

| Path | Role |
|---|---|
| `spec/core-v1.6.md` | Normative semantics and evidence boundary |
| `spec/protocol-registry-v1.6.json` | Single source of truth for all IDs, widths, and limits |
| `spec/p1-prototype-profile-v1.6.md` | P1 acceptance gate and claim boundary |
| `simulator/trahens_sim/` | Python deterministic protocol models |
| `simulator/trahens_crypto/` | Crypto providers (C1, C2-ideal, C2-k2, ristretto, tagging) |
| `simulator/trahens_codec/` | M2/W2, T1, T2 codecs |
| `simulator/trahens_spec/generated.py` | Auto-generated from registry — do not edit |
| `simulator/tests/` | All Python tests |
| `implementation/rust/crates/` | One crate per protocol layer |
| `implementation/rust/bins/` | `trahens-endpoint`, `trahens-relay`, `trahens-rendezvous` |
| `implementation/rust/crates/protocol-registry/src/generated.rs` | Auto-generated from registry — do not edit |
| `tools/` | Vector generators, experiment runners, repo integrity checks |
| `reports/` | Committed reproducible outputs from comparisons and audits |
| `formal/` | TLA+ models for E1 lifecycle and R1 capability redemption |
| `docs/adr/` | Architectural decision records |
| `paper/rewrite/main.tex` | Current standalone paper (no historical narration) |

### Generated files — never edit directly

Three files are mechanically derived from `spec/protocol-registry-v1.6.json` and must stay in sync:

1. `simulator/trahens_spec/generated.py`
2. `implementation/rust/crates/protocol-registry/src/generated.rs`
3. `spec/protocol-registry-v1.6.md`

After any registry change, run `make registry` and commit all three outputs together.

`spec/protocol-registry-v1.5.md` is also generated, from the historical v1.5
registry, and `check_repo.sh` still regenerates and compares it. Do not edit
either v1.5 artifact: that profile is history and its files exist so it stays
reproducible.

### `make check` integrity invariants

`tools/check_repo.sh` (called by `make check`) enforces:

- All required files exist and are committed
- Every vector file matches a fresh generator run (`cmp` on regenerated output)
- `simulator/trahens_spec/generated.py` and the Rust generated file match `make registry` output
- **Both** registries regenerate: v1.6 produces the bindings and its markdown, and the historical v1.5 registry still produces its own markdown
- P1 conformance vectors and corpus match `tools/generate_p1_conformance.py` for both v1.6 and v1.5
- Bounded state models and anonymity metrics match their generators
- `paper/rewrite/main.tex` contains no forbidden historical terms (`Nexus`, `2020`, `W1`, `M1`, `Core v0.*`, etc.)
- Python compiles cleanly; Rust tests pass if `cargo` is available

`make check` fails if any committed artifact diverges from its generator. Always run `make check` before committing changes to specs, models, or tools.

## Git discipline

After each logical unit of work:
- create a git commit
- push to the current branch

If push cannot be completed because of credentials, remote access, branch protection, or environment limits:
- say so explicitly
- do not claim the push succeeded

Commit messages must be short, specific, and scoped to the actual change.
Do not leave completed logical units of work uncommitted.
Do not add a "Co-Authored-By" trailer to any commit message.

### Multi-fix prompts

When a single prompt asks for **more than one unrelated fix** (different files, different bugs, different specs, different concerns — not the natural sub-tasks of one feature), do not bundle them into a single commit. Instead, for each fix in turn:

1. implement only that one fix
2. add or update only the tests directly related to it
3. run the impacted tests; verify they pass
4. create one commit scoped to that fix (with a commit message describing only it)
5. push, then move to the next fix

Each fix becomes one commit. Each commit is independently reviewable, revertable, and bisectable. A multi-fix prompt produces N commits, not one.

Related sub-tasks of the same fix (e.g., a spec change plus its vector update plus a doc cross-reference) belong in the same commit. The discriminator is whether the changes share a single root cause or feature; if yes, one commit; if no, separate commits.

Do not bundle "while I'm here" cleanups into a fix commit. If stale material is discovered mid-fix, either note it and defer it, or handle it as its own follow-up commit after the in-scope fix is committed.

### Debugging hygiene

When chasing a bug across multiple commits, **do not squash the chain into a single "fix X" commit**. Each independent root cause peeled back during the investigation deserves its own commit, even when the surface symptom is the same. Squashing distinct fixes into one commit loses bisectability and hides the diagnostic narrative.

What MUST be cleaned up before commit:

- Diagnostic instrumentation added while chasing the bug (temporary `print`/`eprintln` traces, one-off debug outputs).
- Throw-away one-shot fixtures or hardcoded test values pasted from a session.
- Commented-out code from earlier hypotheses.

What is NOT diagnostic noise (keep it):

- A warning log on a real fallback path the production code can take.
- A catch/error log of previously swallowed failures — the log is the fix.
- A structured info log on a one-shot startup path (fires once per run, not per call).

Either fold the cleanup into the same commit as the fix, or add a follow-up commit before pushing. Do not push diagnostic noise to main "to clean up later."

## Key constraints

- **Clippy `unwrap_used` and `expect_used` are denied** in Rust. Use `?` or explicit error handling.
- **`unsafe_op_in_unsafe_fn` is denied** — unsafe blocks must be explicitly marked.
- Python requires ≥3.11; only `cryptography>=43` is a runtime dependency.
- `docs/review-log/` is an internal reconstruction — it must not be cited as independent external review. The independent reviews are `docs/external-review-2026-07-30.md` (v1.4) and `docs/external-review-2026-09-04.md` (v1.6/P1). `docs/review-verification-2026-09-04.md` is an internal verification pass over the latter's P0 findings and is likewise not independent review.
- C1 v1 suite `0x0001`, symbolic C2 `0x0002`, and disabled C2 k=2 `0x7f02` must all be rejected by network decoders. The negative-control providers exist only in the simulator for measurement.
