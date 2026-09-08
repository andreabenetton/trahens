<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0049: Binding an advertisement to the identity that answers

## Status

Accepted, 8 September 2026. Implements ADR 0045 D5, which decided that a
short-lived advertisement key needs a signed transition to the admission
identity and did not say what the transition is.

## Context

`discovery-advertisement-b12.md` section 3 states the gap plainly: verifying an
advertisement shows that the advertiser holds the short-lived key and that the
fields are intact, and **that is all**. Nothing binds that key to the identity
the advertiser later admits under, so a reader MUST NOT treat a verified
advertisement as evidence of who will answer.

ADR 0045 D5 called the transition "the part most likely to be got wrong": it
must bind the short-lived key to the admission identity in a transcript the
handshake then covers, or the two halves can be attacked separately.

It is worth being exact about what this does and does not buy, because the
invitation model already covers more than it first appears. Under ADR 0046 D8 a
joiner pins the inviter: the invitation arrives out of band and carries the
inviter's static key, so a joiner that reaches the wrong node fails the pin
check regardless of any advertisement. The transition therefore does **not**
authenticate admission — the invitation does that, and did before this ADR.

What it buys is the candidate cache. An advertisement carries a capacity class,
authentication modes and profile lists, and a joiner chooses among candidates on
those. Without a transition, none of it describes whoever eventually answers:
anyone can copy a verified advertisement and attract joiners to an address they
control, and the joiner discovers the mismatch only after spending an exchange.
With one, a completed handshake says which advertisement it belongs to.

It also matters more later than now. B1-Opportunistic is deferred (D1), and if
it is ever taken the invitation disappears and the advertisement becomes the
only thing a joiner has. A transition retrofitted then would have to be
negotiated; one that exists first does not.

## Decisions

**D15 — the responder signs the transcript with its advertisement key, inside
the admission exchange's second message.**

```text
transition = Ed25519-Sign(advertisement_secret,
                          b1_transition || h)
```

`h` is the handshake hash at the moment the second message's payload is about to
be encrypted. That hash already covers the protocol name, the prologue, the
pre-shared key, the cleartext admission header, both ephemerals and the
responder's static key, so a signature over it binds the advertisement key to
this responder, this joiner and this exchange at once. It is the same value the
AEAD uses as associated data for that payload, so both sides hold it at the same
point and neither has to carry a second transcript.

Signing the transcript rather than the static key is what stops the two halves
being attacked separately. A signature over the static key alone would be a
standing certificate: replayable into any exchange, by anyone who saw it once.

The payload becomes `selection || advertisement_key(32) || signature(64)`.

*Consequence.* The initiator verifies the signature against the key the payload
carries, always. That proves whoever completed the handshake holds that
advertisement key. Comparing it against a **cached** advertisement is a separate
step and is what turns the proof into a statement about the candidate the joiner
chose — a joiner that reached this node without an advertisement simply has
nothing to compare, and is no worse off than before.

**D16 — the transition is unconditional on the admission path and absent
everywhere else.**

Only the admission exchange carries it. The manifest and rekey exchanges are
byte-identical to what v1.8 already publishes, so ADR 0045 D7 holds without
qualification: a node with discovery disabled speaks exactly what a v1.8 node
speaks, and the published B1.1 vectors do not move.

Within the admission path it is unconditional. An optional field would need a
presence flag, which is a branch a sender can steer and a second shape every
reader must handle; and it would let a responder decline to bind itself, which
is exactly the case the joiner cannot distinguish from an attack. An admitting
node therefore holds an advertisement key whether or not it has advertised
recently. That key is cheap — it is short-lived by design — and a node that has
never advertised simply signs with one nobody has seen, which costs a signature
and tells a joiner nothing it did not already know.

Rejected: a new record type for the admission respond. The first message needed
one because a responder must read its cleartext header before it has any state;
the second message is already inside a transcript both sides agree on, and the
mode is known to both, so the payload can differ by mode without a discriminator
and without spending one of the reserved bytes from section 3.

## Consequences

`b1_transition` is a new domain separator, and it is the only registry addition:
no width changes. The second message's payload is framed as a two-byte length, a
body and zero padding to `b1_respond_payload` (954), and a selection plus 96
bytes of transition is nowhere near that, so the record stays one cell and the
width it frames to is the one it already used. The admission path differs in
what the body contains, not in how much room it has.

`link-handshake-b1.md` gains the payload shape in section 4.1, and
`discovery-advertisement-b12.md` section 3 stops saying that nothing binds an
advertisement to the identity that answers, because something now does.

The advertisement's `cookie` field remains without a specified use. ADR 0048
left it that way and this does not change it.

An advertiser's short-lived key is now visible to any joiner that completes an
exchange with it, where before it was visible to anyone who received the
advertisement. That is not a new exposure. What is new is that the key and the
static identity appear together, to the joiner, inside an encrypted payload —
which is where section 6's objection to a stable identifier in an
unauthenticated datagram does not reach.

This does not make an advertisement trustworthy before an exchange. A joiner
still learns whether an advertisement described the truth only by completing a
handshake with the advertiser, so the candidate cache remains a set of hints
that are checkable after the fact rather than before it. Making them checkable
before would need the advertiser's admission identity in the datagram, which
section 6 forbids for the reason D5 exists.
