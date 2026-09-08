<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0050: Where a joiner learns a candidate from

## Status

Accepted, 8 September 2026. Settles the shape of the signed seed manifest that
`network-bootstrap-b1.md` section 14 puts in B1.2 and that
`docs/b1.2-scope.md` lists in group 3.

## Context

B1.2's admission path is built: a joiner with an invitation is challenged,
admitted and recorded, over a listening socket, against an adversary. What it
cannot do is find anybody. A joiner is handed an address on its command line,
which is the configuration duplication B1 exists to remove, and the candidate
cache — bounded, per-source accounted, and fed only by discovery — has exactly
one thing that can fill it: an advertisement that has to arrive from a peer the
joiner is already talking to.

That is the remaining circularity. A seed manifest breaks it by naming
candidates a joiner has not met.

Two nearby things it is not. B1.0's static manifest is the *peer* manifest:
configured peers with pinned static keys, which a node treats as already
trusted. A seed manifest names peers a node has **not** decided to trust and
may never reach. Conflating them would be easy and would quietly turn a hint
into a pin.

## Decisions

**D17 — a seed manifest names advertisement keys and addresses, and is signed by
a key the joiner holds out of band.**

```text
version(1) issued_ms(8) expiry_ms(8) count(1)
  entry * count:
    advertisement_key(32) family(1) address(4 or 16) port(2)
signature(64)
```

The signature covers a domain separator and the whole body, `count` and every
entry included, so an entry cannot be added, removed or reordered.

Each entry carries an **advertisement key**, not a static admission key. That is
what makes the manifest checkable rather than merely followed: ADR 0049 binds an
advertisement key to whoever completes an admission exchange, so a joiner that
reaches an address the manifest named can confirm afterwards that the node
answering is the one the manifest meant. Naming a static admission key instead
would put admission identities in a file that circulates, which is the stable
network-wide identifier section 6 objects to, and would pin a peer the joiner
has not decided to trust.

The signing key is configuration. A joiner is given it the way it is given an
invitation, and this ADR does not say how — that is a deployment question and
the same one B1.0's manifest has.

**D18 — it is an out-of-band file, not a datagram, and is not padded to a fixed
width.**

Nothing sends a seed manifest over a Trahens socket, so it takes no first-byte
discriminator and none of the reserved range. It is variable length, and
deliberately: the advertisement is padded to exactly one cell because it is a
datagram whose length would otherwise distinguish it, and a file that is read
from disk has no such observer. Copying the advertisement's fixed width here
would cost bytes and buy nothing, and the reason it exists there would not
survive being restated here.

Bounded before it is parsed: `max_seed_entries` caps `count`, so a manifest
cannot make a reader allocate for a number it chose. An entry's address is 4 or
16 bytes by family and nothing else is accepted.

**D19 — verifying a seed manifest establishes who wrote it, and nothing about
the peers it names.**

A verified manifest says the seed key signed this list before its expiry. It
does not say those peers exist, will answer, will admit the joiner, or are
honest. Entries go into the same bounded candidate cache that advertisements go
into, and are consumed by the same separate step (ADR 0045 D6). A seed entry is
a hint with a signature on it.

*Amended 8 September 2026, while implementing this.* This first read "under the
same per-source accounting", and that is wrong in a way the arithmetic makes
obvious: `max_seed_entries` is 32 and `max_candidate_peers_per_source` is 8, so
a full manifest would have had three quarters of its entries silently dropped.
The bound it would have been applying also answers a threat a manifest does not
present. The per-source cap exists because advertisement keys are free to
generate and an unauthenticated source can invent as many as it likes; a
manifest is signed by a key the operator chose, is capped by its own parser
before anything is allocated, and an attacker holding that key has better
options than filling a cache.

Seeded entries are therefore accounted against the seed key that signed them
rather than against a network source, and the bound on them is the manifest's
own. What still applies, and is the protection that matters, is the global
`max_candidate_peers`: a manifest contributes at most 32 of 256 and can displace
nothing, because a full cache refuses rather than evicting.

*Consequence.* The seed key is a trust root, and a deployment that accepts one
has accepted that whoever holds it chooses which peers its joiners try first.
That is a real concession and the reason `network-bootstrap-b1.md` section 12
lists malicious seeds and seed-server observation as threats. What this ADR
bounds is the damage: a malicious seed can waste a joiner's attempts and can
watch which of them it fetches a manifest from, and cannot admit itself in place
of anyone, because admission still needs an invitation and the transition still
has to check out.

## Consequences

`spec/seed-manifest-b12.md` is new and normative, with published vectors,
because two implementations must parse the same file identically. The registry
gains `max_seed_entries`, `seed_manifest_ttl_ms`, the widths the encoding needs
and a `b12_seed_manifest` domain separator.

`netns-admission.sh` gains a malicious-seed arm, which was waiting for seed
manifests to exist: a manifest naming an address that answers with a different
advertisement key must leave the joiner unadmitted and must not be treated as
having named that node.

An expiry is carried and enforced, so a manifest cannot be replayed
indefinitely, and `seed_manifest_ttl_ms` bounds how far ahead of `issued_ms` an
expiry may sit — otherwise an issuer could write one that never lapses and the
field would be decoration.

This does not give a joiner a way to *fetch* a manifest. Delivery is out of
band, exactly as an invitation is, and a seed **server** — with the observation
that comes with it — is B1.3's problem and is not made easier or harder here.
