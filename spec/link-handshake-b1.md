<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.1 authenticated adjacent-link handshake

- Status: Normative candidate for Core v1.8. Not yet the active profile.
- Decisions: `docs/adr/0043-b1.1-handshake-decisions.md`
- Scope: `docs/b1.1-scope.md`
- Registry: `protocol-registry-v1.8.json` (draft)
- Reference: `simulator/trahens_crypto/b1.py`; vectors in `b1-test-vectors.json`

## 1. Purpose

B1.1 replaces the pre-shared W2 base key and configured epoch with a handshake
that authenticates both peers, negotiates the profile set inside the
authenticated transcript, and derives the directional W2 keys, the epoch, and
an export key from the finished exchange. Every process session therefore has
its own keys, and the restart hazard recorded in `p1-prototype-profile-v1.7.md`
ceases to exist rather than being an operator obligation.

Peers remain manually named. What each peer knows in advance is the other's
peer id, address, and expected static public key, from a manifest.

## 2. Construction

An initial handshake is Noise revision 34, pattern `XX`, instantiated as
`Noise_XX_25519_ChaChaPoly_SHA256`. A rekey is the same pattern under the
`psk0` modifier, `Noise_XXpsk0_25519_ChaChaPoly_SHA256`. The protocol name is
the registry domain `b1_noise_protocol` or `b1_noise_protocol_rekey` and MUST
match that string exactly, because it is the initial hash and chaining key.

```text
-> e
<- e, ee, s, es
-> s, se
```

The prologue is domain separation only: `b1_prologue` for an initial handshake,
`b1_rekey_chain` for a rekey. The previous session's export key is **not**
carried in the prologue. A prologue reaches only the handshake hash, so binding
the chain that way would prevent an unrelated exchange being spliced in as a
rekey while leaving the traffic keys unchained — with the same ephemerals a
rekey would derive the very keys it replaced, because `Split()` reads the
chaining key. The export key therefore enters as the `psk0` pre-shared key,
through `MixKeyAndHash`, which reaches the chaining key as well.

Static handshake keys are X25519 keys used for nothing else. A node's Ed25519
signing key is not converted into its handshake identity.

## 3. Records

Every handshake record is exactly `b1_record` (1,052) bytes, so invariant 1
holds from the first record on a link. A record begins with a two-byte prefix:
a zero byte, then the record type from `b1_record_types`. Derived epochs always
have their top bit set (section 6), so a receiver distinguishes a handshake
record from a W2 cell by its first byte, with no trial decryption.

```text
initiate  0x00 type  e(32)                       payload(1018)
respond   0x00 type  e(32)  enc(s)(48)           enc(payload)(970)
finish    0x00 type         enc(s)(48)           enc(payload)(1002)
```

Each payload is a two-byte big-endian length, the body, and zero padding to a
fixed width. The padding is inside the region Noise hashes and, where a key
exists, encrypts, so it is authenticated. A receiver MUST reject non-zero
padding. The finish payload is empty.

The framed widths are `b1_initiate_payload`, `b1_respond_payload` and
`b1_finish_payload`, except that a rekey's first message uses
`b1_initiate_payload_psk`: under `psk0` a key exists from the start, so that
payload is encrypted and its ciphertext carries a 16-byte tag. The record is
one cell in both cases; only the framed body region differs.

In a rekey, every `e` token also mixes the public ephemeral into the chaining
key, not only into the hash, as Noise section 9 requires of a PSK handshake.
Without it the ephemeral would contribute nothing to the key for the first
message, since under `psk0` a key already exists before any Diffie-Hellman.

In an initial handshake the first message's payload is transmitted in the
clear, because `XX` has no encryption key at that point. It is still mixed into
the transcript hash, so altering it fails authentication of the second message:
the offered profile set is public but not forgeable. In a rekey it is
encrypted, and a chain mismatch is therefore refused on the first record,
before the responder performs any Diffie-Hellman.

## 4. Message processing

Both sides follow the Noise `XX` token sequence exactly as the reference does.
Two checks are added, in this order, at the point the peer's static key has
been decrypted and authenticated:

1. The presented static key MUST equal the manifest entry for this peer id.
   A mismatch aborts. Trust on first use is not a B1.1 behaviour.
2. The responder's selection MUST be within the initiator's offer
   (section 5). Either side aborts otherwise.

No key is derived and no W2 or P1 state is allocated until the third message
has authenticated. Every failure is one generic outcome to the peer: the
receiver does not say why.

## 5. Negotiation

The initiator's offer is:

```text
version(1) || n || w2 profile ids (n bytes)
           || n || t1 profile ids
           || n || t2 profile ids
           || n || suite ids (2n bytes)
           || resource class(1)
```

Each `n` is at least 1 and at most `max_offered_profiles_per_class`. The
version MUST equal the registry's protocol version. A suite the registry marks
retired or disabled, or the symbolic C2 control, MUST be rejected at parse; it
cannot be offered, so it cannot be selected.

The responder's selection is:

```text
version(1) || w2(1) || t1(1) || t2(1) || suite(2) || resource class(1)
```

It MUST name one value from each offered list and the same version and
resource class. Because both payloads are transcript-bound, a peer that strips
a stronger profile from the offer, or substitutes a suite, causes the handshake
to fail rather than to succeed on the weaker set. There is no pre-shared-key
path to fall back to.

## 6. Derivation

After the third message, with `ck` the final chaining key and `h` the
handshake hash, using the Noise HKDF:

```text
(k_i2r, k_r2i) = HKDF(ck, "", 2)                    -- Noise Split
export_key     = HKDF(ck, b1_export || h, 1)[0]
epoch          = HKDF(ck, b1_epoch  || h, 1)[0][0..4] with byte 0 |= 0x80
```

`k_i2r` is the initiator's W2 send key and the responder's receive key;
`k_r2i` the reverse. The epoch is the W2 epoch for both directions. Its top bit
is forced set so that no derived epoch begins with a zero byte, which is what
section 3 relies on.

Uniqueness of the epoch follows from both ephemeral contributions being fresh,
not from any stored counter. `docs/adr/0042-link-epoch-strategy.md` records why
the alternatives were rejected.

## 7. Rekey

A rekey is a complete new handshake on the established link, using the
`rekey_*` record types and the `psk0` instantiation, with the previous
session's export key as the pre-shared key. A responder that receives a
`rekey_initiate` record MUST run the handshake with the export key of the
session it currently holds; an initiator chained to any other session produces
a first message the responder cannot decrypt. This is what prevents an
unrelated handshake from being spliced in as a rekey, and because the export
key reaches the chaining key, it also means a rekey's traffic keys differ from
the replaced session's even if every ephemeral were to repeat.

Only the initiator opens a rekey, by the same lower-identifier rule that decides
who opens the initial handshake, so two ends cannot rekey past each other. A
rekey is carried in band on a link that is already passing traffic: records are
distinguished from cells by the leading zero byte, the outstanding record is
resent on a timer until the peer answers, and normal traffic continues under the
current keys throughout.

The initiator MUST rekey before `rekey_after_cells` cells have been sent in
either direction or `rekey_after_ms` has elapsed, whichever comes first. Those
registry values are ceilings, not mandates: an implementation MAY rekey sooner,
and a conformance run is expected to, because no realistic run reaches the
ceiling. On
completion each side switches its send key immediately and zeroizes the old
one; it keeps the old receive key for at most `rekey_overlap_ms`, then zeroizes
it. A record that authenticates under neither key is rejected.

## 8. Bounds and failure

A node MUST bound, from the registry: outstanding handshake contexts
(`max_handshake_contexts`); public-key operations per source per interval
(`handshake_pubkey_ops_per_interval`, `handshake_interval_ms`); handshake
duration (`handshake_timeout_ms`) and retransmissions
(`max_handshake_retransmits`); and consecutive failures before backing off a
source (`max_failed_handshakes_before_backoff`, `handshake_backoff_ms`).

Under `XX` a responder performs Diffie-Hellman work to answer any well-formed
first message, before it knows who sent it, and its reply discloses its static
key to that sender. The bounds cap the cost; nothing in B1.1 eliminates it, and
nothing in this pattern hides the responder's identity from an active probe. A
deployment that needs either belongs to B1.2.

## 9. Conformance

`b1-test-vectors.json` fixes, for an initial handshake and a chained rekey,
every key, both negotiation payloads, all three records, the handshake hash,
both directional keys, the epoch, and the export key. An implementation MUST
reproduce every record byte for byte and derive identical outputs.

Both exchanges are additionally replayed through an independent Noise
implementation, which is given the same statics, ephemerals, prologue, chained
key and payloads and must produce the same message bytes and the same handshake
hash (`implementation/rust/crates/link-handshake-b1/tests/cross_check_snow.rs`).
That check is what makes the reference trustworthy rather than merely
self-consistent: it found a real defect in the `psk0` path, where the reference
had omitted the `MixKey(e.public_key)` that Noise section 9 requires of an `e`
token in a PSK handshake.
