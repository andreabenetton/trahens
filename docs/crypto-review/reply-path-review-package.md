<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Reply-path review package

- Status: brief for an external cryptographic reviewer. Asserts no new result.
- Companion to [`reply-path-security.md`](reply-path-security.md), which holds
  the construction, the games, and the one proposition established so far.
- Registry: 1.5.1. Suite R1 `0x0101` is the network suite; C1 v2 `0x0003` is
  research-only and never emitted on the P1 wire (ADR 0038).

## What is being asked

One question decides whether the reply-path privacy claim can stop being
conditional:

> Does the multiplicatively blinded reply-key chain compose securely with a
> concrete key-private, chosen-ciphertext-secure reply KEM under related-key
> evolution, in the multi-user setting, against an adversary that supplies the
> keys and the blinding factors?

Everything below exists to let that question be answered without reading the
implementation first.

Three outcomes are all useful, and the third is not a failure of the review:

1. a reduction to a standard assumption or an already-analysed construction;
2. a concrete attack, which retires the construction;
3. a demonstration that the composition is unprovable as stated, which is a
   reason to replace the custom seal with a standard anonymous PKE.

## What is already established

`reply-path-security.md` proves one thing exactly, and it is worth being
precise about how little it covers:

**Proposition 1.** For any adversarially chosen non-identity `X` in the
prime-order group, `bX` for uniform `b` in `Z_q^*` is uniform on the
non-identity elements. So a single blinding step is a perfect one-time
disguise of the public key.

That is a statement about **one step, in isolation, about the public key
alone**. It says nothing about a chain of steps, nothing about the ciphertexts
encrypted under those keys, and nothing about an adversary who sees several
users' chains at once. The gap between Proposition 1 and the question above is
the entire review.

## The construction in one page

Initiator samples `x0` in `Z_q^*`, publishes `X0 = x0·B` in the DISCOVER.

Each honest relay, per forwarded child, samples independent `b_i` in `Z_q^*`
and sets `X_{i+1} = b_i·X_i`, keeping `x_{i+1} = b_i·x_i (mod q)` recoverable
by the initiator. The relay places `b_i` inside the authenticated reverse layer
encrypted **to `X_i`**, so the initiator peels layer `i`, learns `b_i`, derives
`x_{i+1}`, and continues inward.

The gateway seals its offer to the final blinded key. Each relay adds one
authenticated layer. The C1 v2 reply ciphertext is

```text
32-byte encapsulation || AEAD ciphertext and tag || 32-byte recipient-bound commitment
```

with commitment and AEAD failures collapsing to one external
authentication-failure class.

Two properties a reviewer should note as intended, and check are actually
delivered:

- **Related keys are not independent.** `x_{i+1} = b_i·x_i` is a multiplicative
  relation the adversary partly controls when a relay on the path is
  compromised. The security notion needed is therefore related-key, not the
  textbook independent-key IK-CCA.
- **The blinding factor is transported under the key it blinds.** `b_i` travels
  encrypted to `X_i`, so confidentiality of the chain and confidentiality of
  the factors are not separable.

## The six obligations, as questions

Restated from `reply-path-security.md` with the artifact that answers each.

1. **Key-private CCA reply KEM, multi-user.** Is the C1 v2 seal IK-CCA in the
   multi-user setting? Code: `implementation/rust/crates/crypto/src/lib.rs`
   (`reply_seal`, `reply_open`), `spec/crypto-profile-c1.md`. Vectors:
   `spec/crypto-test-vectors-c1.json`.
2. **Malicious keys and factors.** A compromised relay chooses `b_i`, and a
   malicious peer chooses `X`. What survives when neither is honest? Point
   validation is in the ristretto helpers; the chain check is
   `open_candidate_chain` in `crates/node-runtime/src/p1.rs`.
3. **Transcript binding.** Are route, suite, direction, layer, and expiry all
   bound? The transcript is `offer_transcript`, domain
   `Trahens-P1-gateway-offer-v1`, and the per-layer AAD is
   `candidate_context(layer)`. ADR 0038 records why this transcript, not the
   Python C1 one, is normative on the wire.
4. **Failure uniformity.** Does timing or resource use distinguish decryption
   failures? Relevant: the single external authentication-failure class, and
   the drop counters in `RemoteInputDrops`, which are local-only by design.
5. **Standard anonymous PKE instead.** Could a standard construction replace
   the custom seal, and at what size and route-depth cost? Assessment started
   in [`alternative-primitive-assessment.md`](alternative-primitive-assessment.md).
6. **Independent review before any production profile.** This document exists
   to make that cheap; it does not discharge it.

## Where a reviewer should start

Reading order that reaches the question fastest:

1. This document, then `reply-path-security.md` for the games.
2. `spec/crypto-profile-c1.md` for the concrete seal.
3. `crates/crypto/src/lib.rs`: `reply_seal`, `reply_open`, `blind_public`,
   `blind_secret`.
4. `crates/node-runtime/src/p1.rs`: `open_candidate_chain`, which is where the
   chain, the transcript, and the expiry check meet.

`spec/crypto-test-vectors-c1.json` lets a reviewer's own implementation agree
with ours before either is trusted.

## What is claimed, and what is not

Claimed: one blinding step perfectly disguises the public key (Proposition 1);
the construction uses standard primitives rather than an exotic one; the
implementation agrees with the published vectors.

**Not claimed**, and the reply-path privacy claim stays conditional until an
independent review says otherwise: that the nested composition is IK-CCA in the
multi-user setting; that it is secure under adversarially chosen keys and
factors; that failure behaviour is indistinguishable; that any of this holds
against an adversary observing multiple users concurrently.

Nothing in the repository should be read as asserting the second list. Where
prose elsewhere is less careful than this, this document is correct and the
prose is a defect worth reporting.

## Scope boundary

This is the reply path only. It is not a system-level anonymity argument:
endpoint anonymity additionally depends on a private directory that does not
yet exist (`spec/private-directory-d1.md`), and on traffic analysis, for which
Core v1.5 makes no global-observer claim.
