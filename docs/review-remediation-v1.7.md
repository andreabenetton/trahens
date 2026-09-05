<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Remediation of the 2026-09-04 external review

**Review:** `docs/external-review-2026-09-04.md` (Core v1.6 / P1 at `7a7eacc`)
**Verification of its P0 findings:** `docs/review-verification-2026-09-04.md`
**Outcome:** Core v1.7, registry 1.7.0. v1.6 joins v1.5 as retained history.

Only the five P0 findings were independently verified before work began. TR-02
and TR-07 through TR-12 were acted on from the review's own account, except
where noted below.

---

## Addressed

| ID | Finding | Resolution |
|---|---|---|
| TR-01 | No end-to-end DATA replay protection | Directional HKDF route keys bound to the offer transcript, counter nonces, bounded per-direction replay window committed after authentication (v1.7, ADR 0041) |
| TR-03 | CANDIDATE semantic replay | Idempotency requirement restored to v1.6 spec, then implemented: relay consumes the candidate label and accounts for the response quota before wrapping; endpoint counts one candidate per authenticated offer |
| TR-04 | "One-time" capability not global | Not a code defect — the spec already specifies per-gateway semantics and the implementation conforms. The paper's global claim was narrowed and the behaviour pinned by test |
| TR-05 | `AtMostOnce` proves nothing | Property rewritten to count redemptions per (capability, gateway); model rekeyed to match R1's multi-gateway registration; `Register` refuses a spent pair. Executable for the first time, and now run in CI |
| TR-06 | Paper transcript ≠ signed transcript | `GatewayOfferTranscriptV2` binds version, suite, reply key and parameter digest; its domain moved into the registry; paper corrected to the implemented field set |
| TR-07 | Descriptor pseudonyms unchecked | Endpoint accepts only descriptor-authorized pseudonyms; gateway can advertise a configured one. Separately, a wrong pseudonym no longer consumes the registration |
| TR-08 | Gateway crypto before admission | `states.begin()` moved ahead of `seal_gateway_offer()`, with the reservation released on the sealing and label failure paths |
| TR-09 | Reply key reused across rings | Reply root moved into `RingContext`; each ring's DISCOVER carries a fresh key |
| TR-12 | Stale descriptions | Paper KDF corrected to 76 bytes with the commitment key; C1 comments in three binaries and the crypto crate corrected to match the selectable experimental profile |
| §19 | Missing adversarial tests | Route-record replay, cross-direction reflection, transcript binding, window reordering, per-gateway redemption, and a `unauthorized-pseudonym` harness scenario gated in CI |

## Not addressed, and why

**TR-02 — W2 restart safety.** Unresolved and unresolvable within P1. The
prototype receives a base key and epoch statically, so nothing in it can
guarantee a restart does not reuse an epoch. The fix is fresh AKE-derived
traffic keys per process session, which is B1. This remains a deployment
precondition the prototype cannot enforce, and it should be stated as such
wherever P1 is operated.

**TR-10 — reply encryption proof obligation.** No code change can discharge
this. It needs either a game-based proof of this construction in the
multi-user, multiplicatively-related-key setting, or a reduction to a
recognised key-private KEM. The repository already scopes the claim
conditionally; that scoping is unchanged and still correct.

**TR-11 — B1 and D1.** Two missing subsystems, deliberately scoped as future
work. Implementing either is a research programme, not a remediation.

**Global one-time capabilities.** Not pursued. R1 specifies per-gateway
semantics, the implementation conforms, and the global property is a
distributed double-spend problem requiring cross-gateway state. The paper now
says so rather than implying otherwise.

## What v1.7 costs

The protocol version byte is `2`, so v1.6 and v1.7 do not interoperate and
every P1 binary must be upgraded together.

The route nonce is a counter rather than random, so a relay that decrypts the
link layer learns the direction and a per-route record count where it
previously learned nothing. This is a deliberate exchange, recorded in
`field_protection`, invariant 16, ADR 0041 and the paper. It is the only place
in this series where a fix cost privacy rather than adding it.
