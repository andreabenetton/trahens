<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0046: Invitation scoping and revocation ownership

## Status

Accepted, 6 September 2026. Extends ADR 0045 with two decisions its D1 and D2
implied but did not settle. Implementation has not started.

## Context

ADR 0045 chose the invitation model and decided that the invitation keys the
`psk0` handshake. That is enough to know the first-message defence survives into
B1.2, and not enough to implement it.

The gap matters because the invitation case moves what the pre-shared key is
*for*. Under a manifest (ADR 0044) the key is a pre-filter and the pin on the
presented static key is what authenticates. Under an invitation there is no
manifest entry to pin against, so **the pre-shared key becomes the
authentication**. How an invitation is scoped therefore decides who can
impersonate whom, and until that is fixed the derivation cannot be written.

## Decisions

**D8 — invitations are per-joiner, single-use, and promote on success.**

Each joiner receives its own invitation secret out of band. On a handshake that
completes, the inviter records the static key the joiner presented and marks the
invitation spent. Later sessions between those two peers use the manifest path
of ADR 0044 and its stronger property.

Two joiners never share a secret, so one cannot impersonate another, and the
window in which an invitation is worth stealing closes at its first use. A
shared network invitation was rejected for the opposite reason: every holder
could impersonate every other holder to the inviter, and nothing on the wire
would distinguish them. A reusable per-joiner invitation was rejected because a
leak permits permanent impersonation of that joiner with nothing to withdraw but
the invitation.

The costs are accepted and are real: invitations are distributed per joiner, and
the inviter must persist spent invitations and pinned keys across restarts. A
spent-invitation list that does not survive a restart re-opens every invitation
it was holding.

*Consequence, decided by implication.* A responder must know which invitation to
derive `psk0` from before it can decrypt the first message. Trial-decrypting
against every live invitation makes that work linear in the number outstanding,
which is exactly the exhaustion the cookie exists to bound and would make an
admitting node cheaper to attack the more joiners it expects. So the first
message carries an invitation identifier in the clear, and the responder's work
stays constant.

That identifier is an identifier on an unauthenticated datagram, which
`network-bootstrap-b1.md` section 6 warns against. It is acceptable here only
because it is random, per-invitation, and consumed at first use, so it is not a
durable correlation handle for the joiner. If a later design makes invitations
reusable, this reasoning lapses with them.

**D9 — minimal revocation lands in B1.2.**

Promotion creates a pinned static key, which is the first thing in this system
there has ever been to withdraw. The stage that first admits a peer nobody named
also ships the means to un-admit one.

Minimal means two things and no more: a spent-invitation list, so an invitation
cannot be replayed into a second admission, and removal of a pinned key from the
manifest, so a removed peer cannot complete a further handshake.

It explicitly does not include revocation propagation between nodes: removing a
key at one node says nothing to any other, and a deployment that needs
network-wide withdrawal needs signed revocation documents, which belong with
B1.3's signed roots. Nor does removal tear down a live link. A link already
established keeps running until it stops on its own terms; making removal
terminate live sessions is a separate decision about whether revocation is
immediate or eventual, and B1.2 takes the eventual reading because the immediate
one needs a way to reach every node that is exactly the propagation this defers.

## Consequences

The B1.2 scope's list of what it leaves open loses revocation and keeps
everything else. `docs/b1.2-scope.md` and `ROADMAP.md` are updated to match.

An admitted peer is now withdrawable at the node that admitted it, and only
there. That is a smaller claim than "revocation" unqualified, and the evidence
boundary should say so rather than let the word do work the mechanism does not.

The invitation identifier is a new field on an unauthenticated datagram and
belongs in the discovery encoding of D4, whose fixed-width padding already
covers it. It is the first thing in that datagram whose privacy argument rests
on single use rather than on being unlinkable, so it is worth naming in review.
