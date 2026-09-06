<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.2 discovery advertisement

- Status: Normative for the encoding. B1.2 is not implemented; this fixes the
  datagram so the rest of the stage can be built against it.
- Decisions: `docs/adr/0045-b1.2-scope-decisions.md`, D4 and D5
- Parent: `spec/network-bootstrap-b1.md` section 6
- Reference: `simulator/trahens_crypto/advertisement.py`; vectors in
  `b12-advertisement-test-vectors.json`

## 1. Shape

Exactly `b12_advertisement` (1,052) bytes — one cell — because discovery
precedes any link and there is no encryption to hide a length under. A
variable-length advertisement would leak its shape on the wire and would make
captures non-uniform, which the harness's fixed-record assertion relies on.

```text
0x01              1     b12_datagram_types.advertisement
framed body     987     len16 || body || zero padding
signature        64     Ed25519 over b12_advertisement || the 988 bytes above
```

The first byte is a discriminator from the range `link-handshake-b1.md`
section 3 reserves: a handshake record begins `0x00` and a W2 cell `0x80` or
above, so `0x01`–`0x7f` is reachable by neither. A receiver MUST test this
range **before** attempting to open the datagram as a cell, or its own
advertisements are consumed by the W2 path and counted as malformed.

The signature covers the discriminator and the whole framed region, padding
included, so neither the type byte nor the padding can be altered undetected.
A receiver MUST reject non-zero padding and MUST reject trailing bytes after
the declared length.

## 2. Body

```text
version(1) || key(32) || expiry_ms(8) || capacity_class(1) || auth_modes(1)
  || n || w2 profile ids (n)
  || n || t1 profile ids (n)
  || n || t2 profile ids (n)
  || n || suite ids (2n)
  || cookie_present(1) || [cookie(32)]
```

Each `n` is at least 1 and at most `max_offered_profiles_per_class`. The cookie
flag MUST be 0 or 1; any other value is refused rather than treated as present.

`key` is the short-lived advertisement key of D5, and is the only identity the
datagram carries. Section 6's exclusions hold: no descriptor, no capability, no
route label, and no stable network-wide identifier.

## 3. What an advertisement establishes, and what it does not

Verifying one shows that the advertiser holds the short-lived key and that the
fields have not been altered. That is all.

It carries **no binding from the short-lived key to the admission identity**
the advertiser will later use. That binding is D5's signed transition, and it
cannot live here: putting an admission static key in an unauthenticated
datagram is exactly the stable network-wide identifier section 6 forbids, and
exactly what advertising under a long-term key was rejected for. The transition
therefore belongs inside the handshake transcript, where it is protected, and
is specified with the admission exchange rather than here.

Until that exists, an advertisement is a hint about where to try, not a
statement about who will answer. A reader MUST NOT treat a verified
advertisement as evidence of the advertiser's admission identity.

## 4. Conformance

`b12-advertisement-test-vectors.json` fixes three datagrams: a minimal one, one
carrying a cookie, and one with several profiles per class so the list encoding
is exercised beyond a single entry. The generator refuses to publish if any two
collide. An implementation MUST reproduce each datagram byte for byte and MUST
refuse a datagram whose signature, padding, width, or discriminator has been
altered.
