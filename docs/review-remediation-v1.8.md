<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# What Core v1.8 addressed from the 2026-09-04 external review

**Review:** `docs/external-review-2026-09-04.md` (Core v1.6 / P1 at `7a7eacc`)
**Previous round:** `docs/review-remediation-v1.7.md`
**Outcome:** Core v1.8, registry 1.8.0. v1.7 joins v1.6 and v1.5 as retained
history.

v1.7 closed nine of the review's findings and left three open. This records what
v1.8 did to the remaining three. It supersedes the "Not addressed, and why"
section of the v1.7 document, which is now stale on two of them and should be
read only as the record of where v1.7 stopped.

---

## TR-02 — W2 restart safety: now addressed

The review's own prescription was: *"For production I would require fresh
AKE-derived traffic keys per process session. Epoch uniqueness then becomes
defense-in-depth rather than the only thing preventing nonce-space
resurrection."*

That is what B1.1 does. `LinkConfig` no longer has a `base_key` or an `epoch`
field to receive. Both directional keys and the epoch come out of a handshake
whose transcript includes both ends' fresh ephemerals, so a restarted pair
cannot reuse an epoch: neither end chooses one. The hazard is gone structurally
rather than documented as an operator obligation.

`implementation/harness/netns-restart.sh` is the falsification test. It runs the
same topology twice with the same static keys and the same peer list, and
requires the two sets of observed link epochs to be disjoint. The epoch is the
one W2 field in the clear, so packet captures are sufficient to check it. It
runs in CI.

**Verified first-hand** rather than taken from the review's account: the absence
of the configured key and epoch was read in the code, the derivation was
followed through `handshake::directional`, and the restart harness was executed
(3 and 3 epochs, none shared).

What did not change is that a node's **static** handshake key and its peer
manifest remain operator responsibilities. A node whose static key is disclosed
can be impersonated; a node given the wrong pinned key for a peer will refuse to
talk to it. Neither is a key-reuse hazard, and neither is what TR-02 was about,
but both are real key management and are stated in
`spec/p1-prototype-profile-v1.8.md`.

## TR-11 — B1 and D1: half addressed

TR-11 named two missing subsystems: *"Private directory and authenticated
bootstrap/rekey are not implemented."*

**Authenticated bootstrap and rekey are now implemented**, as B1.1
(`spec/link-handshake-b1.md`): a Noise `XXpsk0` handshake that authenticates
both peers against a manifest, negotiates the profile set inside the
authenticated transcript, derives the directional keys and the epoch from the
finished exchange, and rekeys in band on a live link. Its records are pinned by
`spec/b1-test-vectors.json` and cross-checked against an independent Noise
implementation; the rekey generation overlap is modelled in
`formal/B1Rekey.tla`.

**The private directory (D1) is not implemented** and remains out of scope, as
`docs/d1-evaluation-plan.md` and the P1 profile both say. So TR-11 is reduced,
not closed, and should stay open in any tracking of this review until D1 exists.

Two limits of what B1.1 delivers, both stated in `link-handshake-b1.md`
section 8 rather than left implied:

- an authenticated peer — a compromised neighbour, or anyone holding a static
  key — can still open exchanges and spend a responder's bounded per-attempt
  work; the registry bounds are what cap that;
- a deployment that must accept handshakes from peers it has no manifest entry
  for cannot use B1.1's first-message authentication at all, because it has no
  static-static value to derive from. That is B1.2.

## TR-10 — reply encryption proof obligation: unchanged

No code change can discharge this, and none was attempted. It still needs either
a game-based proof of the construction in the multi-user,
multiplicatively-related-key setting, or a reduction to a recognised key-private
KEM. The repository scopes the claim conditionally and that scoping remains
correct.

---

## What v1.8 costs

The protocol version byte is `3`, so v1.7 and v1.8 do not interoperate and a
v1.7 node cannot bring a link up at all.

The handshake changed twice within v1.8. It shipped using Noise `XX` for the
initial exchange, and was later amended so that both exchanges use `XXpsk0`
with a static-static pre-shared key
(`docs/adr/0044-authenticating-the-first-handshake-message.md`), which closed a
responder exposure the profile had recorded as inherent. That amendment was made
in place rather than as a new profile, so the B1.1 vectors were regenerated and
any handshake capture recorded against the earlier v1.8 handshake is no longer
reproducible from the tree. The P1 conformance vectors and corpus cover M2 and
W2 and were unaffected.

## Scope of this document

This is an internal record of remediation, not independent review. The only
independent reviews of this repository are
`docs/external-review-2026-07-30.md` (v1.4) and
`docs/external-review-2026-09-04.md` (v1.6/P1). Nothing in v1.8 has been
externally reviewed, and the `XXpsk0` construction in particular was designed
and landed without external scrutiny; it belongs in the scope of the next
review.
