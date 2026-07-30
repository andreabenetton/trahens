<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0033: Remediate independent review before prototype work

## Status

Accepted.

## Context

An independent review of Core v1.4 verified the executable results but identified four load-bearing gaps: the custom additive reply-key composition, potentially misleading wording around the C2 transcription, the absence of a private-directory profile, and a fresh-clone repository-check failure. It also warned that the compressed version and review-log history must not be presented as independent scrutiny.

## Decision

Prototype work is postponed. Core v1.4.1:

- adopts multiplicative reply-key blinding;
- narrows the proved property to exact public-key distribution;
- standardizes the HKDF structure;
- removes deterministic ephemeral input from the production API;
- adds D1 as an explicit private-directory strawman;
- corrects C2 framing;
- fixes clean-checkout reproducibility;
- records the evidentiary status of internal history.

## Consequences

The protocol has a cleaner and more reviewable reply-key transform, but the full nested reply encryption remains conditional on a key-privacy and composition argument. System-level endpoint anonymity remains unavailable until a private-directory profile is implemented and reviewed.
