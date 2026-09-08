<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens B1.1 handshake and P1 route channel — external cryptographic review

**Scope reviewed:** the B1.1 handshake, the node runtime and W2, the route
channel implementation, and the associated ADR and specification text, against
Noise rev34, RFC 5869, RFC 7748 and RFC 8439.
**Reviewed at:** Core v1.8 / P1, before commit `4d11f79`.
**Review date:** 8 September 2026.
**Provenance:** supplied by the maintainer. The reviewer is not named here. This
is external in the sense that matters — it was not produced by anyone working on
the tree — but it did not come through the same commissioning route as
`docs/external-review-2026-07-30.md` and `docs/external-review-2026-09-04.md`,
and a reader weighing independence should know that.

Unlike the earlier rounds this document carries its own disposition rather than
a separate `review-remediation-*` file. The findings were acted on inside v1.8
rather than driving a version bump, and a second "v1.8 remediation" document
would be read as a companion to `docs/review-remediation-v1.8.md`, which answers
the 2026-09-04 review and has nothing to do with this one.

---

## Overall assessment, in the reviewer's terms

> I do not see an immediate break of the completed B1 transport keys or of the
> P1 AEAD under the intended healthy-RNG/fresh-key assumptions. But Construction
> 1 currently makes several security claims that are stronger than what the
> construction actually provides.

Specifically: the first-message defence is replayable, the implementation
performs public-key work before authenticating message 1, and deriving the PSK
from the same Noise static keys puts the construction outside Noise's clean
security model. Construction 2 — the route channel — was found substantially
more conventional, with one critical invariant: a route key must never survive a
reset of its send sequence and replay state.

No finding was a break. Most were claims that outran the construction, which is
why most of the remediation is specification text rather than code.

---

## Findings and disposition

| ID | Finding | Disposition |
|---|---|---|
| **B1-A** | Message 1 is replayable: a captured `handshake_initiate` wins the race on a later link establishment, and the responder answers and waits for a finish nobody can produce | **Documented, not remedied.** Spec §4.2 |
| **B1-B** | "No DH before auth" is false: every responder attempt computes the static-static PSK and both of its own public keys before reading message 1 | **Documented, not remedied.** Spec §8 |
| **B1-C** | The PSK is a bearer pre-authentication credential: a holder without the pinned static private key can elicit and decrypt the responder's static key | **Documented, not remedied.** Spec §4.2, `73f2260` |
| **B1-D** | Using the Noise static key outside Noise to derive a correlated PSK leaves Noise's proof assumptions | **Not taken.** See below |
| **B1-E** | The PSK KDF is non-standard and binds no public keys | **Fixed** — `4d11f79` |
| **B1-F** | Ephemeral freshness is an assumption, not "fails closed" | **Fixed** — `4997002` |
| **B1-G** | Specification drift: the first message described as both encrypted and unencrypted | **Fixed** — `cdc89ba` |
| **P1-A** | The same route key with a reset sequencer repeats nonces | **Fixed** — `57a7593` |
| **P1-B** | The replay window permits deliberate aging-out by reordering | **Not taken.** See below |
| **P1-C** | The HKDF domain is in the IKM rather than the salt | **Fixed** — `ff455c0` |

Two further points from the body of the review, outside its own table:

| Point | Finding | Disposition |
|---|---|---|
| §3 | The prologue reaches only `MixHash`, so it does not separate `Split()` keys; initial and rekey are separated only by their PSK sources | **Fixed** — `773d696` derives the rekey PSK under its own domain rather than feeding the export key in unchanged |
| §4 | The epoch carries 31 bits, not 32; independent sessions collide around 55,000 | **Fixed** — spec §6 states it, and states that nonce uniqueness rests on key freshness rather than epoch distinctness |

---

## What was fixed

**B1-E — the static pre-shared key derivation.** Was `HMAC-SHA256(k = ss, m =
b1_static_psk)`. The review's two objections: RFC 5869 puts a domain in the
salt, not HMAC's message field; and RFC 7748 recommends binding both public keys
into the derivation, warning that X25519 has publicly computable equivalent
public keys, so knowledge of a raw shared secret is not proof of public-key
ownership. The derivation is now HKDF-Extract with `SHA-256(domain)` as salt and
the shared secret as IKM, then HKDF-Expand over `domain || initiator_static ||
responder_static`. Keys are ordered by protocol role, as the review specified —
not sorted, which would hide the asymmetry the exchange already has. Domain
bumped to `-v2`; `spec/b1-test-vectors.json` moved.

**§3 — rekey phase separation.** The review's observation is exact: with an
identical protocol name, PSK, static keys and ephemerals, the two prologues
produce the same `ck` and therefore the same `Split()` keys. The prologue
separates `h`, not the traffic keys. Adequate today only because the two PSK
sources differ — which made the export key both a session output and a handshake
input. It now goes through one HKDF step under `b1_rekey_psk` before use.

**P1-C — HKDF domain placement.** The extract step took
`p1_route_extract || route_secret` under a zero salt. It now takes the route
secret as IKM with `SHA-256(p1_route_extract)` as salt. Domain bumped to `-v3`;
`spec/route-channel-test-vectors.json` moved. The review called this standards
alignment rather than an emergency, and it is.

**P1-A, B1-F, B1-G** were the earlier three corrections: the key-and-sequence
invariant is now normative in Core v1.8 §7.1 with a test that documents the
forbidden state by demonstrating its consequence; ADR 0042's "fails closed" is
separated into an RNG API error (which does) and repeated RNG output (which does
not, and is security-critical); and the stale "first message is unencrypted"
text is gone with two lints holding it gone.

---

## What was not taken, and why

**B1-D — a separate pre-authentication keypair.** The review is right that
Trahens uses a Noise static private key outside the Noise state machine to build
a correlated PSK, that Noise rev34 warns against exactly this, and that `snow`
cannot validate the composition because to `snow` the PSK is 32 opaque bytes.
The cross-check therefore establishes implementation correspondence and not the
compositional security claim.

The remedy — a dedicated X25519 keypair for pre-authentication — was not taken.
It changes the manifest format, the provisioning story and the admission path,
and it buys a cleaner proof rather than a defended attack: the review itself
says "no direct exploit follows automatically". That is a real cost against a
real but non-urgent benefit, and it is a decision for whoever owns the claim
boundary rather than one to make while fixing KDFs. What must not happen in the
meantime is the tree claiming to inherit Noise's analysis. It does not, and this
document is where that is recorded.

**P1-B — replay-window aging-out.** Hold record `n`, deliver `n+1 … n+64`,
release `n`; it is refused although authentic and never seen. The review
classifies this correctly as availability and ordering, not confidentiality or
authentication, and notes an attacker with reorder and delay capability could
usually just drop `n`. It matters only for a threat model granting reorder and
delay but not deletion. Left open deliberately; a wider window trades memory for
a property this profile does not claim.

**The §3 falsification test** — force identical PSK and keypairs into an initial
and a rekey exchange and assert their `Split()` keys differ, which would fail —
was not added. The derivation change makes the two PSK sources structurally
distinct, and a test asserting a property the construction no longer relies on
would encode the old worry rather than a current invariant.

**The B1-A and B1-B remedies** — responder freshness on the manifest path, and
deferring the responder's public-key work until message 1 authenticates — were
not taken either. Both are real improvements. B1-A's remedy already exists on the
admission path, where ADR 0048 D13's cookie challenge is precisely the responder
freshness the manifest path lacks; extending it to the manifest path is a
protocol change with its own round-trip cost. B1-B's is a straightforward
refactor of `Responder::new`. Both are recorded here rather than silently
carried, and the specification no longer claims either property.

---

## The reviewer's closing prescription, for the record

> For B1, I would first fix the security specification, not merely code. Define
> msg1 as a replayable bearer-PSK prefilter, not proof that the current sender
> possesses the static identity.

That is done. The remaining items in that paragraph — caching the pair PSK
outside handshake attempts, deferring responder ephemeral generation, and using
a separate pre-authentication key — are the open ones above.

> That is already evidence that the specification/test suite needs adversarial
> property tests, not more byte-for-byte agreement tests.

Worth keeping in view. The three fixes here each moved published vectors, and
byte-for-byte agreement is what proved the two implementations still match; it
is not what found any of these. The findings came from reading the construction
against the RFCs.
