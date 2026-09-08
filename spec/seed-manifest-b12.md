<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.2 signed seed manifest

> Normative for the file format. Decisions in
> `docs/adr/0050-seed-manifest.md`.

## 1. Purpose

A joiner has to learn a candidate from somewhere. Without this, the bounded
candidate cache of `discovery-advertisement-b12.md` section 4 can be filled only
by an advertisement from a peer the joiner is already talking to, and a joiner
with no peers is handed an address by configuration — the duplication B1 exists
to remove.

A seed manifest names candidates a joiner has not met. It is delivered out of
band, exactly as an invitation is, and this document does not say how. Fetching
one from a seed server, and the observation of joining nodes that comes with it,
is B1.3's concern and section 12's threat.

**This is not B1.0's static manifest.** That one names peers already trusted,
with pinned static keys. This one names peers a node has not decided to trust
and may never reach.

## 2. Shape

```text
body:
  version(1)
  issued_ms(8)
  expiry_ms(8)
  count(1)
  entry * count:
    advertisement_key(32)
    family(1)              4 or 6
    address(4 | 16)        by family
    port(2)
document = body || Ed25519-Sign(seed_secret, b12_seed_manifest || body)(64)
```

All integers big-endian. The signature covers the whole body, `count` and every
entry included, so an entry cannot be added, removed or reordered.

Each entry carries an **advertisement key**, not a static admission key. That is
what makes a manifest checkable rather than merely followed: `link-handshake-b1.md`
section 4.1 binds an advertisement key to whoever completes an admission
exchange, so a joiner that reaches a named address can confirm afterwards that
the node answering is the one the manifest meant. A static admission key here
would put admission identities into a circulating file, which is the stable
network-wide identifier `network-bootstrap-b1.md` section 6 forbids, and would
pin a peer the joiner has not decided to trust.

**A manifest is not padded to a fixed width.** A discovery advertisement is one
cell wide because it is a datagram whose length would otherwise distinguish it
on the wire; a file read from disk has no such observer, so the reason does not
carry over. It also takes no first-byte discriminator and spends none of the
range section 3 reserves, because nothing sends it over a Trahens socket.

## 3. Reading one

A reader MUST, in this order:

1. verify the signature against the seed key it holds out of band;
2. refuse a `version` it does not implement;
3. refuse `count` of zero or above `max_seed_entries`, **before parsing any
   entry** — the count is attacker-chosen, and a reader must not be made to work
   for a number it was handed;
4. refuse `expiry_ms` at or before `issued_ms`, or more than
   `seed_manifest_ttl_ms` after it, so an issuer cannot write a manifest that
   never lapses and leave the field as decoration;
5. refuse a manifest whose expiry has passed;
6. refuse an unknown address family, and an address whose width does not match
   the family;
7. refuse any byte following the entries `count` declared.

The expiry check comes **after** the signature. An expired manifest is a real
manifest that has lapsed, and answering before verifying would answer for
documents nobody signed.

Every refusal is one outcome. A reader does not report which check refused a
manifest.

## 4. What verifying one establishes

That the seed key signed this list, and nothing else. Not that those peers
exist, will answer, will admit the joiner, or are honest.

Entries enter the same bounded candidate cache that advertisements enter, under
the same per-source accounting, and are consumed by the same separate step that
`discovery-advertisement-b12.md` section 4 describes. A seed entry is a hint
with a signature on it.

The seed key is a trust root. A deployment that accepts one has accepted that
whoever holds it chooses which peers its joiners try first. What bounds the
damage is that a malicious seed can waste a joiner's attempts and can watch which
of them fetch from it, and cannot admit itself in place of anyone: admission
still needs an invitation, and the transition of section 4.1 still has to check
out against the key the manifest named.

## 5. Conformance

`b12-seed-manifest-vectors.json` fixes two documents: one entry over IPv4, and
three entries across both families so the list encoding is exercised beyond a
single element and the variable-width address is exercised at all. The generator
refuses to publish if any two are byte-identical.

An implementation MUST reproduce each document byte for byte and MUST refuse a
document whose signature, count, family, lifetime or trailing bytes have been
altered.
