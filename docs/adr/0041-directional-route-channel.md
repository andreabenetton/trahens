<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0041: Directional route channel and gateway offer transcript v2

## Status

Accepted for v1.7 (registry 1.7.0). Supersedes the v1 route key schedule and
the `Trahens-P1-gateway-offer-v1` transcript established by ADR 0038. v1.6 is
retained frozen and reproducible; the two profiles do not interoperate.

## Context

The independent review of 4 September 2026
(`docs/external-review-2026-09-04.md`) raised two protocol defects that a
documentation change could not resolve. Both were verified against the
implementation before this decision was taken
(`docs/review-verification-2026-09-04.md`).

### The route channel had no end-to-end replay protection

`route_key()` derived a single key from the route secret and served both
directions with it. `route_seal()` generated a random 96-bit nonce and
prepended it; `route_open()` authenticated the record and kept no state at all.
The DATA payload carried a `sequence` field, but nothing compared it against
anything.

The threat model already admits A1, an active relay that duplicates traffic.
Such a relay cannot read a protected body, but it can retain one and re-send it
later inside a newly generated T1 transmission of its own. That duplicate
carries a fresh W2 sequence, a fresh link ciphertext and a fresh tag, so the
adjacent-link replay window correctly regards it as new link traffic and admits
it. The gateway then decrypted a body it had already acted on, and the route
phase machine accepts repeated `DataAccepted` while Open.

Hop-by-hop replay protection is structurally incapable of covering this. The
countermeasure has to live in the layer whose key spans the two endpoints.

A latent partial defence existed and was inert. `control_aad()` binds a
`generation` counter, and the gateway compares generations on receipt, but the
state machine's counter — which does advance on every accepted DATA — was never
wired to the wire-level `Route.generation` that feeds the AAD. That field was
initialized to zero and never mutated in either binary, so the comparison was a
no-op for a route's whole lifetime.

### The signed offer transcript was narrower than the security argument

ADR 0038 made `Trahens-P1-gateway-offer-v1` normative. It signs `gateway_id`,
`expires_at_ms`, `gateway_pseudonym`, `route_secret`, `commit_challenge`,
`routing_nonce` and `signing_public`.

The paper's gateway-authentication argument reasons over a different field set,
including the protocol version, the suite, the final reply public key and a
selected parameter digest. None of those four are signed. No normative spec text
arbitrated between the two descriptions: `grep -rln "gateway-offer-v1" spec/`
returns nothing, and the R1 specification contains no signature language at all.

This did not yield a suite-downgrade exploit, because `node-runtime` refuses a
decoded M2 envelope whose `suite_id` differs from the configured link suite
before the protocol ever sees it. The defect is that a published security
argument described a construction the implementation does not build, which is
precisely how implementations and their proofs drift apart.

## Decision

Introduce Core v1.7 rather than amend v1.6.

The repository's existing discipline is that a wire change produces a new
profile and the old one is retained verbatim so it stays byte-reproducible;
v1.5 exists for exactly this reason. Editing v1.6 in place would have broken
that contract for v1.6 itself and left the two reviews now filed in `docs/`
describing an artifact that no longer exists.

### Route channel

- Derive two keys, not one. `HKDF-Extract` over
  `Trahens-P1-route-extract-v2 || route_secret`, then one `HKDF-Expand` per
  direction under `Trahens-P1-route-key-e2g-v2` and
  `Trahens-P1-route-key-g2e-v2`.
- Bind the selected offer. The v2 transcript hash is part of the expansion
  info, so a route secret presented under any other offer derives different
  keys and fails closed.
- Replace the random nonce with a counter: a 32-bit direction code followed by
  a 64-bit sequence, filling the 96-bit AEAD nonce exactly. One key therefore
  never repeats a nonce, and the receiver can bound what it has already
  accepted. Exhaustion of the sequence space is an error, not a wrap.
- Keep a bounded per-direction replay window, sized by
  `limits.route_replay_window`, committed only after the record authenticates —
  the same ordering W2 already uses, so a forged sequence cannot burn a slot.
- The direction code is checked before the AEAD call and selects the key, so a
  reflected record cannot open even before authentication.

### Offer transcript

`Trahens-P1-gateway-offer-v2` moves into the registry as
`domain_separators.p1_gateway_offer` and binds, in order: protocol version,
suite, gateway id, gateway pseudonym, offer deadline, the reply public key the
offer was sealed to, route secret, commit challenge, routing nonce, gateway
signing key, and a digest of the profile parameters both ends must already
agree on.

`seal_gateway_offer` returns the transcript hash alongside the sealed blob, and
`OpenedOffer` carries the hash the initiator recomputed, because that hash is
the binding the route keys derive against. The initiator can recompute the
recipient key because the gateway sealed to the blinded reply key that reached
it, which is the public counterpart of the secret that opened the layer.

## Consequences

The protocol version byte becomes `2`. A v1.6 encoding does not decode under
v1.7, the conformance corpus regenerates, and every P1 binary must be upgraded
together.

**The route nonce is now visible to an on-path relay where a random one was
not.** A relay that decrypts the link layer sees the protected body's leading
12 bytes and therefore learns the direction and a per-route message counter. It
could already count records and infer direction from the way they travel, so
the marginal disclosure is small, but it is real and it is a change in what the
wire exposes. `field_protection` classifies the route nonce as
`link-encrypted` accordingly. This is the deliberate price of end-to-end replay
protection: a construction that hides the counter from relays while still
letting the receiver derive the nonce would require either strict in-order
delivery, which T1 does not promise, or an additional encrypted header.

The redundant `direction` and `sequence` fields inside the DATA payload are now
superseded by the authenticated nonce. They are retained in the v1.7 payload
encoding to keep this change to the key schedule rather than the message
format; the nonce is authoritative. Removing them is deferred.

Retaining v1.6 costs one more registry, spec set, corpus and markdown
regeneration in `check_repo.sh`, which now loops over both retired series.

## Alternatives considered

**Wire the existing generation counter into the AAD instead.** The plumbing
exists and a unit test already asserts a non-zero generation, so this was the
cheapest possible fix. It was rejected as the whole answer: the generation
advances per accepted event rather than per record, it is a `u32` on a channel
with no rekey, and it leaves the single bidirectional key and the random nonce
in place. It closes the specific replay while leaving the construction that
produced it.

**Amend v1.6 in place.** Rejected for the reproducibility reason above.

**Global one-time capabilities (review TR-04).** Out of scope here. The
verification found that the R1 specification already specifies per-gateway
one-shot semantics and the implementation conforms; the defect is a paper
overclaim, which is a documentation fix rather than a protocol change.
