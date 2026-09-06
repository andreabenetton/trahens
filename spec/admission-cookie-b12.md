<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.2 stateless admission cookie

- Status: Normative for the construction. B1.2 is not implemented; this fixes
  the cookie so the rest of the stage can be built against it.
- Decisions: `docs/adr/0045-b1.2-scope-decisions.md`, D3
- Scope: `docs/b1.2-scope.md`
- Parent: `spec/network-bootstrap-b1.md` section 7
- Reference: `simulator/trahens_crypto/cookie.py`; vectors in
  `b12-cookie-test-vectors.json`

## 1. Purpose

Before allocating a handshake context, a responder may require the sender to
echo a cookie the responder itself issued. The cookie demonstrates return
routability from the observed source and nothing else.

It is a denial-of-service control and **not** an identity proof. A sender that
presents a valid cookie has shown only that it receives datagrams at the
address it claims. ADR 0045 records the cookie as the floor beneath whichever
identity model is selected, not as the mechanism that authenticates: under the
invitation model of D1 that is the pre-shared key, and under an opportunistic
model there is nothing, which is why that model is deferred.

## 2. Construction

```text
cookie = HMAC-SHA256(k = responder_secret,
                     m = b12_cookie
                      || len16(source) || source
                      || u16be(port)
                      || u64be(window)
                      || len16(offer) || offer)
```

truncated to `b12_cookie` (32) bytes, which for SHA-256 is no truncation.

`source` is the observed source address as it appears on the wire, 4 bytes for
IPv4 and 16 for IPv6. `offer` is the parameter set the sender offered so far.
`responder_secret` is 32 bytes and is never transmitted.

Every variable-length field is length-prefixed. Without that a source address
and an offer could be split differently and produce the same message, so a
cookie issued for one pair would verify for another.

The window is inside the MAC rather than carried beside it. A cookie therefore
cannot be replayed into a later window, and no per-cookie state has to be
retained for that to hold.

## 3. Windows and rotation

`window = floor(now_ms / cookie_window_ms)`, computed from absolute time so
that two responders agree on which window a moment falls in regardless of
uptime.

A responder holds `cookie_windows_accepted` (2) secrets: the current one and
the immediately previous. It MUST verify against each in turn, computing the
candidate window as `current - index`, and MUST evaluate every candidate rather
than returning on the first match, so the time taken does not reveal which
window a cookie came from. Comparison MUST be constant time.

Retaining more than one secret is what stops every rotation rejecting senders
mid-exchange: a cookie issued just before a boundary must still verify just
after it. On rotation the oldest secret is zeroized, so a cookie under a retired
secret stops verifying even inside a window that is otherwise still accepted.

`cookie_window_ms` (2,000) and `cookie_windows_accepted` (2) bound a cookie's
life at between two and four seconds. Both are registry values rather than
local choices.

## 4. What this does not provide

A cookie bound to a source address is a correlation handle for as long as it is
valid. It is not reusable across windows, and its lifetime is the argument that
it is not a durable tracking token; a deployment that lengthens the window
weakens that argument and owes a new one.

Nothing here resists an attacker that can receive at the address it claims.
Such an attacker obtains cookies freely, and what bounds it is the registry's
handshake-context and public-key-operation limits — which
`link-handshake-b1.md` section 8 records as unenforced today, and which B1.2
must implement, because a listening socket is what makes them reachable.

Underlays where a source address is not meaningful need an equivalent bounded
return-routability mechanism; this construction assumes one exists.

## 5. Conformance

`b12-cookie-test-vectors.json` fixes the cookie for a set of inputs that differ
in exactly one field each: window, secret, port, address family, and an empty
offer. The generator refuses to publish if any two collide, so the vectors also
witness that each field is bound. An implementation MUST reproduce every cookie
byte for byte.
