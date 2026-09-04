<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Verification of the 2026-09-04 external review — P0 findings only

**Status:** Internal verification pass. This document is **not** independent review and
MUST NOT be cited as such. The independent reviews are
`docs/external-review-2026-07-30.md` (v1.4) and `docs/external-review-2026-09-04.md`
(v1.6/P1). This file records only whether this repository's own code and specifications
substantiate that reviewer's P0 claims.

**Verified against:** working tree at `7a7eacc` (code identical at `ebd444e`, which changes
only `CLAUDE.md`).
**Date:** 4 September 2026
**Method:** direct reading of the cited Rust sources, TLA+ models, v1.6 specifications and
`paper/rewrite/main.tex`, with `grep` sweeps across `spec/` for the normative language the
review attributes to v1.6.

**Scope limit:** only the five P0 findings were verified. TR-02, TR-07, TR-08, TR-09,
TR-10, TR-11 and TR-12 were **not examined**. Their absence from this document is not
evidence for or against them.

---

## Verdict summary

| ID | Reviewer's claim | Verdict | Reclassification |
|---|---|---|---|
| TR-01 | End-to-end DATA has no replay protection | Confirmed | Specification gap, not a conformance violation; a dormant AAD defence exists |
| TR-03 | CANDIDATE semantic replay is not idempotent | Confirmed (behaviour) | Spec citation refuted — the quoted requirement is not in v1.6 |
| TR-04 | Capability is not globally one-time | Confirmed (mechanism) | Not an implementation bug; the spec conforms and the paper overclaims |
| TR-05 | `AtMostOnce` does not prove at-most-once | Confirmed | Mechanically worse than described; severity overstated for current state |
| TR-06 | Paper transcript ≠ signed transcript | Confirmed | Broader — no normative spec text arbitrates |

No P0 finding was refuted outright. No new exploit was identified.

---

## TR-01 — End-to-end DATA replay

**Confirmed.** All four route-channel sub-claims hold:

- `crates/crypto/src/lib.rs:670-679` — `route_key()` takes only `route_secret`, with no
  direction input; `route_seal` (`:686`) and `route_open` (`:703`) call it identically, so
  one key serves both directions.
- `:687`, `:690`, `:704-705` — a random 96-bit nonce is generated, prepended, and read back.
- `:695-707` — `route_open` is fully stateless: length check, key derivation, nonce split,
  `aead_open`. No replay state.
- `:674-678` — the key is `hmac_sha256(route_secret, DOMAIN_P1_ROUTE_KEY || route_secret)`;
  `route_secret` is both the HMAC key and part of the message, as the review describes.

Gateway path: `bins/trahens-rendezvous/src/main.rs:543-572` matches `direction: 0`, binds
`sequence` at `:547` and echoes it at `:568` with no window or set. The only gate is
`phase == Open` (`:551-555`). `crates/state-machine/src/lib.rs:271` accepts repeated
`DataAccepted` in `Open` unconditionally. The only replay window in the stack is W2's,
per-link (`crates/node-runtime/src/lib.rs:514`).

**Correction — a dormant defence exists.** `control_aad()`
(`crates/node-runtime/src/p1.rs:333-338`) binds `message_type` and `generation`, and the
rendezvous compares generations at `:384`. There are two counters. The state-machine
generation advances on every `DataAccepted` (`crates/state-machine/src/lib.rs:274`) but
never reaches the AAD. The wire-level `Route.generation` that *does* feed the AAD is
initialized to `0` (rendezvous `:343`, `:700`; endpoint `:240`) and is never mutated in
either binary, so the comparison at `:384` is a no-op and the AAD is constant for a route's
lifetime. The plumbing supports non-zero values — a unit test at rendezvous `:739` asserts
`generation == 11`. Wiring the advancing counter into the AAD may close the replay without
the directional key-schedule redesign the review proposes.

**Correction — direction.** Cross-direction reflection is already blocked: `direction` sits
in the authenticated plaintext and peers pattern-match opposite values. Only same-direction
replay works.

**Specification status.** v1.6 neither requires end-to-end DATA replay protection nor
excludes it from the claim boundary. Every normative replay clause is adjacent-link or
capability scoped (`spec/core-v1.6.md` §4:83-85, §8 items 5 and 8). Core `:170` requires
only that DATA be accepted in `OPEN`, which the code enforces. The P1 gate
(`spec/p1-prototype-profile-v1.6.md:70-84`) lists capability replay but no DATA-replay case.
Meanwhile `docs/threat-model.md:39` places A1 — an active relay that duplicates — inside the
adversary model, and `:25` assumes only an authenticated replay domain between honest
adjacent peers. The adversary is in scope while the countermeasure is unspecified.

---

## TR-03 — CANDIDATE semantic replay

**Confirmed as behaviour; the supporting spec citation is refuted.**

Relay ordering in `bins/trahens-relay/src/main.rs`:

1. `:812` `candidate_token` read; `:820` `labels.get(&candidate_token).copied()` — resolved
   by copy, and no path in this arm removes the binding.
2. `:869` `wrap_candidate(...)` — nested public-key wrapping.
3. `:885` `states.apply(parent_label, Event::CandidateAccepted, ...)`.
4. `:900-903` `offer_label(...)` → `ERROR_RESOURCE_EXHAUSTED "offer_response_limit"`.
5. `:906` `offers_forwarded += 1`; `:913` `tentatives.insert`; `:925` `labels.insert`.

The 64-response quota is enforced inside `offer_label`
(`crates/node-runtime/src/p1.rs:91-93`, `LIMIT_MAX_CANDIDATE_RESPONSES_PER_DISCOVERY`,
`generated.rs:120`) — two steps after the wrap and one step after the state transition. The
child-facing offer label is never consumed, so the same `candidate_token` resolves
indefinitely.

`crates/state-machine/src/lib.rs:257` — `(Phase::Candidate, Event::CandidateAccepted) => {}`
falls through to the unconditional tail at `:272-273`, which increments `generation` and
resets `expires_at_ms`. Every duplicate renews the deadline. The comment at `:251-256`
states the case is "stored idempotently and renews the offer deadline"; those clauses
contradict each other, since renewing a deadline is itself a protocol effect.

Endpoint: `bins/trahens-endpoint/src/main.rs:492` authenticates, and the result feeds
`held.push(...)` at `:518` with no comparison against already-held offers; `:537` closes the
window on `held.len() >= candidate_threshold`. Deduplicating on `selector` would not help,
because the first relay mints the tentative selector (`:913`) and can mint a fresh one per
duplicate. Only dedup on the authenticated offer is sound.

**Refutation.** The review attributes to E1 the requirements "reject exact replays
idempotently" and that duplicated complete logical messages must not create new protocol
effects. Neither sentence exists in v1.6. `grep -rn "idempotent" spec/` returns hits only in
retired profiles — `state-machines-v0.1.md:86`, `v0.6.md:140`, `v0.7.md:203`,
`core-v0.6.md:278`, `core-v0.8.md:129`, `messages-v0.3.md:124`, `v1.0.md:161`,
`v1.3.md:62`, `v1.4.1.md:62`. v1.6's only duplicate rule is fragment-level
(`state-machines-v1.6.md:54`), and its replay requirements are explicitly W2 link-layer
(`core-v1.6.md:83-84`, `:186`; `invariants-v1.6.md:7`). The relay section
(`state-machines-v1.6.md:42`) is silent on duplicate CANDIDATE.

The idempotency requirement was dropped when v0.6 was superseded and never carried into
v1.6. The behaviour is therefore a **specification gap**, not a conformance violation.

The review's point that W2/T1 correctly treat each replay as new link traffic, and are
therefore not the applicable control, is correct.

---

## TR-04 — R1 capability one-time semantics

**Confirmed as mechanism; misclassified as an implementation bug.**

`crates/rendezvous-r1/src/lib.rs:57` — `records: HashMap<(u32, [u8; 32]), Registration>`.
The duplicate check at `:136-139` is `contains_key(&(gateway_id, digest))`, so the same
digest at a different gateway is admitted. `:190` and `:213` remove only that gateway's
record. No `redeemed` set exists anywhere in the Rust implementation.

**The specification already specifies this behaviour.** Every normative sentence in
`spec/rendezvous-capability-r1.md` is gateway-local: `:30` ("one or more gateways"), `:45`
("removed atomically on successful redemption"), `:87` ("looks up the registration …
atomically removes the record"), `:131` ("the correct gateway redeems once"). The
implementation conforms.

**The paper overclaims.** `paper/rewrite/main.tex:459` and `:469` establish one capability
hash registered at *k* gateways. `:549-550` then states the property "Single successful
redemption" scoped over *one capability commitment*, not over a gateway's registry. As
literally written this is false across the *k* registrations the same page defines. The
spec's own framing at `:97-98` ("the one-time capability", "capability replay is rejected by
atomic redemption") is unqualified and should carry the gateway scope explicitly.

**No Python/Rust divergence, but the bounded checker is weaker than it looks.**
`tools/check_state_models.py:38-42` rejects only `digest == d and gateway == g`; `:44-59`
removes one record and adds the digest to a `redeemed` set. That set is never read as a
guard by `register` or `redeem` — it is observational only (`:133`). The explorer does sweep
both gateways (`:121`), but the replay assertion at `:132` re-redeems against the same
gateway, and the closing assertions (`:150-153`) are existence-only. The checker permits the
same double redemption and would not flag it.

---

## TR-05 — The `AtMostOnce` formal property

**Confirmed, and mechanically worse than described.**

`formal/R1Capability.tla:47`:

```
AtMostOnce == \A c \in Capabilities : registrations[c].live \in BOOLEAN
```

`TypeOK` (`:10-11`) already declares `live : BOOLEAN`, so the invariant is implied by the
type invariant and cannot fail in any well-typed state. It is vacuous.

Beyond the review's account: `Register` (`:18`) is guarded only by `~registrations[c].live`,
and no history is retained (`vars == <<registrations>>`, `:8`). The trace
`Register → Redeem → Register → Redeem` is therefore legal, and the model permits unbounded
redemptions of one capability. A *correct* `AtMostOnce` would be **violated** by this model
as written — repairing the property alone would expose a defect in the transition relation.
Both need work.

The review is also right that the model binds each capability to exactly one gateway
(`:10-11`), so it cannot express the multi-gateway condition central to TR-04.

**Severity correction.** The model is not cited as security evidence anywhere.
`paper/rewrite/main.tex` contains no occurrence of `AtMostOnce`, `TLA`, `model check` or
`machine-checked`. The only reference in the repository is a bare pointer under "Formal
models:" at `spec/state-machines-v1.6.md:8`, with no claim attached. Nor is the model ever
executed: `formal/` contains only the two `.tla` files with no TLC `.cfg`; no workflow in
`.github/workflows/` references TLC; and `tools/check_repo.sh:43-44` lists the files only in
its required-files-exist set.

The defect is real and should be fixed, but it is currently a latent trap for the first
person to cite the model rather than an active overclaim. "High assurance defect" is
accurate the moment the model is cited and overstated until then.

---

## TR-06 — Signed transcript versus the paper

**Confirmed, and broader than stated.**

Actually signed (`crates/node-runtime/src/p1.rs:113-131`): the ASCII prefix
`Trahens-P1-gateway-offer-v1`, then u16-BE length-prefixed `gateway_id`, `expires_at_ms`,
`gateway_pseudonym`, `route_secret`, `commit_challenge`, `routing_nonce`, `signing_public`.
The review's field list matches exactly, in order.

Paper claim at `main.tex:1415`, supported by the equation at `:682`.

| Paper field | Present in the signed transcript? |
|---|---|
| protocol domain | as the literal prefix only, not a length-prefixed field |
| version | absent (only the domain's own `-v1`) |
| suite | absent |
| gateway pseudonym | yes (field 3) |
| offer deadline | yes, as `expires_at_ms`, but ordered before the pseudonym |
| final reply public key | absent |
| commit challenge | yes (field 5) |
| candidate nonce | yes, as `routing_nonce` |
| selected parameter digest | absent |

Signed but undocumented: `gateway_id`, `route_secret`, `signing_public`.

`route_secret` is **not** the final reply public key under another name — `crates/crypto/src/lib.rs:670-679`
feeds it to `route_key()` as key material. `recipient_public` is a parameter of
`seal_gateway_offer` (`p1.rs:143`) but is never passed to `offer_transcript`.

**Mitigation not noted in the review:** the recipient key *is* bound inside the reply-KEM
context (`crates/crypto/src/lib.rs:555`), so the seal is recipient-bound even though the
signature does not cover it. However `main.tex:717` instructs the initiator to verify the
"final reply key" via the transcript, which the transcript cannot supply.

**The review's suite-downgrade retraction is correct.** `crates/node-runtime/src/lib.rs:719-737`
delivers only when `envelope.suite_id == suite`, otherwise `ERROR_UNSUPPORTED_SUITE` with
detail `"m2_suite_mismatch"`. No downgrade follows from the missing suite field.

**Reply KDF (review §7): confirmed.** `crates/crypto/src/lib.rs:560` expands 76 bytes, split
32 key / 12 nonce / 32 commitment key (`:564-566`); the ciphertext is
`encapsulation(32) || ct || commitment(32)` (`:619-622`). `main.tex:1405` still describes a
44-byte expansion into key and nonce only, and the word "commitment" never appears in the
reply-KEM sense, so the paper also understates the ciphertext layout by 32 bytes.

**No normative arbiter.** `grep -rln "gateway-offer-v1" spec/` returns no hits. Neither
`spec/core-v1.6.md` nor `spec/rendezvous-capability-r1.md` contains "transcript", and the R1
spec contains no "sign" or "Ed25519". The signed transcript is normative only via ADR 0038
(`docs/adr/0038-rust-completion-reconciliations.md:20-28`) plus the code.

---

## Cross-cutting observation

TR-01, TR-03 and TR-06 share a single root cause: **the v1.6 normative spec layer is silent
where the paper and the code both speak.** The v0.6 → v1.6 rewrite dropped the CANDIDATE
idempotency requirement, end-to-end DATA replay was never specified in either direction, and
the R1 signed transcript was only ever pinned in an ADR. Most of the P0 work is therefore
deciding what v1.6 should require, then bringing paper and code into agreement with it —
rather than five independent defect fixes.
