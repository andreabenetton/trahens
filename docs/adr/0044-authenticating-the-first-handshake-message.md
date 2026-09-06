<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0044: Authenticating the first B1.1 handshake message

- Status: Accepted
- Supersedes part of `0043-b1.1-handshake-decisions.md` (decision D1)
- Spec: `spec/link-handshake-b1.md` sections 2, 3 and 8

## Context

B1.1 chose Noise `XX` for the initial handshake, with `XXpsk0` used only for
rekeys. `XX` leaves its first message unencrypted and unauthenticated, which
had two consequences the profile recorded but did not fix:

- a responder answered any well-formed first message with two Diffie-Hellman
  operations plus an ephemeral key generation, before it knew who sent it;
- that reply disclosed the responder's static key to whoever asked.

Both were written down as inherent to the pattern and deferred to B1.2. They
are not inherent. B1.1 already requires each peer to hold the other's static
public key in a manifest — the pin in section 4 refuses anything else, and
trust on first use is explicitly not a B1.1 behaviour — so both ends can
compute a shared secret before any message exists.

## Decision

Both exchanges use `Noise_XXpsk0_25519_ChaChaPoly_SHA256`. They differ only in
where the pre-shared key comes from:

- a rekey chains to the session it replaces, through its export key, as before;
- an initial handshake uses `HMAC-SHA256(k = X25519(s, rs), m = b1_static_psk)`,
  the static-static Diffie-Hellman between the two manifest identities.

Nothing carries that value and no exchange establishes it; both peers derive it
offline from what the manifest already gives them.

## Consequences

A first message now decrypts only for a sender holding the manifest identity.
A forgery fails at the first AEAD open, before any Diffie-Hellman, and draws no
reply, so an unauthenticated prober gets neither the work nor the responder's
static key.

Three smaller effects follow, and each is a behaviour change worth naming:

- **A wrong manifest pin now fails at the first record rather than the second.**
  The static-static value is computed against the pinned key, so a mismatch
  produces a first message the peer cannot decrypt. The section 4 manifest
  check still exists and is still what authenticates — the pre-filter is not a
  substitute for it, and a test holds it separately — but a wrong pin no longer
  reaches it.
- **Tampering with the first record is refused where it arrives**, rather than
  surfacing two messages later as a transcript mismatch.
- **The registry loses `b1_initiate_payload` and `b1_noise_protocol_rekey`.**
  Both exchanges now encrypt the first payload, so there is one width; both use
  one protocol name, and are separated by their prologue and their pre-shared
  key. A retained width nothing reads is the drift the registry exists to
  prevent.

The forward-secrecy story is unchanged. The pre-shared key is static, but it is
mixed alongside the ephemeral `ee`, `es` and `se` Diffie-Hellman rather than in
place of them, so session keys still depend on fresh ephemerals. Someone
holding the static-static value alone completes nothing.

## Why not KK

`KK` was the original recommendation for B1.1 and was rejected in ADR 0043. It
would not have fixed this. `KK`'s first message is `e, es, ss`, so a responder
must perform two Diffie-Hellman operations to process it and can only reject a
forgery afterwards — it hides the responder's static key, which `XXpsk0` also
does, but it leaves exactly the computational exposure that was the more
serious half. A precomputable pre-shared key is strictly better here, because
rejecting costs a hash and a failed decryption.

Keeping the pattern as `XX` also leaves the smaller step available: a profile
that must accept peers it has no manifest entry for drops the pre-shared key
rather than changing pattern. It will need a different first-message defence,
which is B1.2's problem.

## Wire compatibility

This changes the handshake records. A node on the previous v1.8 handshake and
one on this cannot bring a link up. The change was made in place rather than as
a new profile, so v1.8 handshake artifacts recorded before it — the B1.1
vectors and any capture of a handshake — are not reproducible from the current
tree. The P1 conformance vectors and corpus are unaffected: they cover M2 and
W2, which this does not touch.
