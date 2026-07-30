<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Development record and evidentiary status

The repository contains versioned specifications, ADRs, deterministic reports, and files under `docs/review-log/`. These materials record a compressed reconstruction of design decisions and automated experiments. They are not evidence of fifteen independent external review rounds, nor do the Git timestamps establish an extended real-time development history.

The following distinctions are normative for project communications:

- **Git history** records changes to the artifact, not independent validation.
- **Review logs** are internal technical notes unless a named external reviewer, date, scope, and reviewed artifact are stated.
- **Automated tests** establish regression and conformance properties only.
- **Deterministic experiments** are falsification tools for the declared model, not deployment measurements.
- **External review** must be stored separately and must not be merged into the internal review-log count.
- **Cryptographic security** is claimed only where a proof or independently reviewed standard/construction applies to the actual composition.

The independent review dated 30 July 2026 is stored as `docs/external-review-2026-07-30.md`. The v1.4.1 remediation was created in response to that review.
