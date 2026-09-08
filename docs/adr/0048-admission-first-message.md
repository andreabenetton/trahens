<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0048: How an admission handshake begins

## Status

Accepted, 8 September 2026. Settles two things ADR 0046 D8 and
`admission-cookie-b12.md` each assumed the other had decided. Implementation has
not started.

## Context

ADR 0046 D8 decided that a responder must know which invitation to derive `psk0`
from before it can decrypt the first message, and that the invitation identifier
therefore travels in the clear. It did not say where in the message.

`admission-cookie-b12.md` specifies how a cookie is constructed and requires it
to be checked before a handshake context is allocated. It does not say how the
cookie reaches the sender that must echo it.

Between them these leave the admission exchange unable to start. Writing the
listening socket's receive decision made that concrete: a handshake record from a
source the node was never configured with has no path at all, and the
implementation refuses it before any state rather than pretending otherwise.

There appeared to be an answer already in the tree. The discovery advertisement
of `discovery-advertisement-b12.md` carries an optional cookie field, which reads
like the intended delivery mechanism. **It cannot be.** An advertisement is
produced before the advertiser has observed any source address, so a cookie
inside one is bound to no source. Any holder could echo it from any address, and
it would demonstrate exactly nothing about where the sender receives datagrams —
which is the only thing a cookie is for. The field is not a delivery mechanism
and this ADR does not make it one; what to do with it is left open below.

## Decisions

**D13 — a responder challenges rather than requiring a cookie it never sent.**

A joiner sends its admission initiate with no valid cookie, because it has none.
The responder allocates nothing, performs no Diffie-Hellman, and replies with a
cookie bound to the observed source. The joiner resends the same initiate
carrying it, and only then does the responder allocate a handshake context.

```text
joiner    -> admission_initiate  (cookie field zero)
responder -> cookie_challenge    (cookie bound to the observed source)
joiner    -> admission_initiate  (cookie)
responder -> handshake_respond   (allocates here, and not before)
```

This is the shape DTLS uses for `HelloVerifyRequest` and QUIC for Retry, chosen
because it is reviewed rather than because it is novel, and it is what B1 section
7's "validated before expensive cryptographic work" already describes. It costs
one extra round trip on first contact and none thereafter.

*Consequence, decided by implication.* A responder needs no way to tell an absent
cookie from a wrong one. Both fail verification, and failing verification means
one thing: challenge. There is exactly one behaviour, so there is no branch a
sender can steer and no state to hold for a first attempt.

*Consequence.* The challenge is the same 1,052 bytes as the message that provoked
it, so a responder that answers a spoofed source amplifies by a factor of one. A
reflector gains nothing it would not gain by sending to the victim directly. This
is the same argument QUIC Retry rests on, and it is why no separate bound on
challenge issuance is introduced here: there would be nothing for it to prevent
that sending directly does not already achieve.

The challenge echoes the invitation identifier so a joiner with more than one
attempt outstanding can match it. That puts the identifier in the clear a second
time, on the same path, in front of the same observer that already saw it in the
initiate. D8's argument — random, per-invitation, consumed at first use — is what
carries it, and this does not weaken that argument, but it does depend on it: if
invitations ever become reusable, this echo lapses with the rest of D8.

A forged challenge makes a joiner echo a cookie that will not verify and be
challenged again. That is a denial of service against a joiner by an attacker who
can already reach it, which is not a new capability.

**D14 — the admission initiate is a handshake record type, not a new datagram
kind.**

`b1_record_types` gains `admission_initiate` and `cookie_challenge`. Both keep
the `0x00` first byte, so `link-handshake-b1.md` section 3's allocation is
unchanged, the receive path's classification needs no new arm, and a reader
branches on the second byte as it already does for six record types.

```text
admission_initiate  0x00 type  id(16) cookie(32)  e(32)  enc(payload)
cookie_challenge    0x00 type  id(16) cookie(32)  padding
```

The cleartext header costs 48 bytes, so the admission initiate's framed payload
is narrower than `b1_initiate_payload_psk`. It gets its own width rather than
reusing one.

Rejected: a distinct first byte from the range section 3 reserves. It would make
the two paths separable in a capture without parsing, which is a small
diagnostic convenience, and it would spend a reserved byte on something that is
already a handshake record by every other measure — same width, same framing,
same reader, same state machine. The reserved range is better kept for datagrams
that are not handshake records at all.

*Consequence.* The cookie's `offer` input, which
`admission-cookie-b12.md` defines as the parameter set offered so far, is the
cleartext admission header for this exchange: the invitation identifier. That is
everything the sender has offered in the clear at the moment the cookie is
issued, and binding it means a cookie issued for one invitation cannot be spent
on another from the same address.

## Consequences

`link-handshake-b1.md` gains the two record types, their widths, and the
exchange; `admission-cookie-b12.md` gains what `offer` means on this path and
loses the implication that an advertisement delivers cookies.

The advertisement's `cookie` field now has no specified use. It is left in place
rather than removed in the same change that decides this, because removing a
field from a signed datagram moves published vectors and belongs in its own
commit with its own argument. Whoever takes it should either give it a purpose
that survives not being bound to a source, or delete it.

*Resolved 8 September 2026: deleted.* No purpose survived. The obvious candidate
— a flag saying this node requires a cookie — would be true of every node,
because D13 has a responder challenge any first message whose cookie does not
verify, so there is nothing optional to advertise. The field is gone from
`discovery-advertisement-b12.md` section 2 and from the published vectors, and
the body now has no optional fields at all: for a given set of list lengths its
shape is fixed, so a decoder has no branch a sender can steer.

This does not settle D5's signed transition. An admitted joiner still has no
binding from the short-lived advertisement key to the identity it admits under,
and nothing here creates one.

The first message of an admission exchange remains the only unauthenticated
1,052-byte record a node will parse from a stranger. What bounds that is the gate
of `link-handshake-b1.md` section 8, and what makes it cheap is that a cookie
that does not verify costs one HMAC and produces one datagram.
