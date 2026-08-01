<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0040: Separate the routing nonce from the eligibility field

## Status

Accepted for v1.6 (registry 1.6.0). Supersedes ADR 0038 decision 1 in part:
C1 is no longer barred from the wire by construction, only by profile.

## Context

Until v1.6 one 32-byte value in `DISCOVER` did three jobs at once:

1. the active suite's eligibility field;
2. the binding of each link in the returned candidate chain, which is what
   proves an offer came back along the branch the initiator opened;
3. the key per-offer labels are derived from (ADR 0039).

Because job 1 belonged to the suite and jobs 2 and 3 belonged to route
discovery, every suite was forced to be exactly 32 bytes. R1 is; C1 v2 is a
128-byte universal re-encryption capsule and symbolic C2 is 640 bytes.

M2 was never the obstacle, and earlier documents in this repository said
otherwise. `message-codec-m2.md` already gives `discovery_field` a length
prefix and already fixes all three widths, so the envelope could always carry
a capsule. What could not move was everything above M2.

Those documents also said P1 "carries a 32-byte nonce end to end". It does
not, and never did: each hop replaces it independently, which is the U1
property. What every hop shared was the width, and all three jobs assumed it.

## Decision

1. **`DISCOVER` carries two fields.** A suite-independent 32-byte
   `routing_nonce`, replaced with fresh randomness at every hop, and an
   `eligibility_field` whose width the suite fixes.

2. **Route discovery uses only the routing nonce.** The candidate chain binds
   parent and child routing nonces, and `offer_label` keys on the routing
   nonce. `P1Payload::RelayLayer` therefore carries routing nonces at the same
   32 bytes it previously carried discovery nonces, so **candidate layers do
   not grow**. That was the main cost anticipated for enabling C1, and the
   separate-nonce design avoids it; deriving offer labels from the capsule
   instead would have needed a new derivation and a new security argument.

3. **The two replacements are independent.** A relay draws a fresh routing
   nonce per child and separately asks the suite to transform the eligibility
   field. Previously the nonce replacement *was* the suite transform, which is
   why the two could not have different widths.

4. **The candidate chain no longer covers the eligibility field.** This is the
   consequence worth stating plainly rather than leaving implicit, because it
   removes coverage that used to exist as a side effect.

   It is defensible: the field is hop-local, replaced or rerandomised at every
   hop, and integrity-protected by W2 on the adjacent link it crosses. The
   chain binding exists to prove the candidate returned along the branch the
   initiator opened, and the routing nonce still proves exactly that. An
   attacker who substitutes an eligibility field on a link they already
   control learns nothing they did not already have, and cannot redirect the
   candidate, because the routing chain is what the initiator verifies.

   A suite whose eligibility field must be end-to-end authentic would need its
   own binding. R1's is not — it carries no endpoint-specific material — and
   C1's capsule is authenticated by its own construction to its recipient.

## Consequences

Any suite can now be selected without changing route discovery, which is what
made C1 activatable at all.

The v1.5 profile is superseded rather than amended: `DISCOVER` gains 32 bytes,
so v1.5 encodings do not decode under v1.6. v1.5's registry, vectors, and
corpus are retained and still regenerate from their own generators, so the
frozen profile remains reproducible and checkable. It does **not** remain
speakable: the binaries implement v1.6 only, and a dual-stack implementation
is out of scope.

`tools/check_repo.sh` regenerates and byte-compares both profiles, so neither
can drift.
