<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Briefs for work that cannot be done inside this repository

Four pieces of work are outstanding that no amount of implementation here can
supply, because what they need is an *independent* party. Two are review, one is
measurement, one is research. Each brief below is written to be handed to
someone — or pasted into a capable model — without further explanation, and each
says what has already been done so the effort is not spent twice.

A note on using a language model for these. Briefs 1 and 4 are the ones a model
can genuinely help with: they are argument, and a wrong argument is detectable by
reading it. Brief 2 needs someone to *write code from a specification*, and a
model that has read this repository's implementation is no longer independent —
if you use one, give it the specs and vectors and withhold the implementation.
Brief 3 needs a network and cannot be simulated into existence.

---

## Brief 1 — TR-10: the reply layer's proof obligation

**Status.** The 2026-09-04 external review found no algebraic break and declined
to clear it anyway. Its words: "no demonstrated cryptographic break, but still an
external-review blocker for a production anonymity claim."

**The construction.** Every forwarding relay multiplies the reply public key by a
random Ristretto255 scalar; the matching secret is multiplied by the same scalar
so decryption survives. The obvious attack is related-key retargeting — given
`X' = bX`, transform `R' = b⁻¹R` so `DH(R', X') = DH(R, X)` — and it does not work
here, because the KDF context takes in the encapsulated point and the recipient
public key as well as the DH output, so preserving the group element while
changing `(R, X)` changes the derived key. There is also an explicit
recipient/ciphertext commitment.

**What is missing.** The setting is multi-user with *multiplicatively related
recipient keys*, and the property wanted is stronger than IND-CCA: it is
ciphertext unlinkability. The existing argument establishes real structural facts
about the public-key distribution but makes full unlinkability conditional on
key-privacy and composition assumptions it does not discharge.

**What would count as an answer**, in descending order of value:

1. A game-based proof of *this* construction under stated assumptions, with the
   related-key structure in the model rather than assumed away.
2. A reduction to a recognised anonymous / key-private KEM or PKE, plus an
   argument that the reduction survives the per-hop rerandomisation.
3. A concrete attack, which is worth more than either.
4. A reasoned statement that the property is not achievable in this shape, which
   would be worth more than another conditional argument.

Please say explicitly which assumptions you are importing and where each is used.
An argument that quietly needs a random oracle, or key-privacy of the underlying
KEM, is useful only if it says so.

**Attach:** `spec/crypto-profile-c1.md`, `docs/crypto-review/reply-path-security.md`,
`docs/crypto-review/reply-key-privacy-v1.5.md`, `spec/crypto-test-vectors-c1.json`,
and section 11 of `docs/external-review-2026-09-04.md`.

---

## Brief 2 — an independent implementation, for interoperability

**Status.** There are two implementations, a Python reference and a Rust one, and
they agree. That is worth less than it sounds: they were written by the same
hand from the same reading of the same specification, so agreement between them
is evidence about the specification's *determinism*, not about its clarity. The
B1.1 handshake is additionally cross-checked against `snow`, an independent Noise
implementation, which is the one place that argument does not apply.

**The task.** Implement, from the specifications and published vectors alone, one
or more of:

- the W2 wire cell and M2 message codec (the smallest useful target);
- the B1.1 handshake, including the `XXpsk0` rekey chain;
- the B1.2 admission exchange: cookie, invitation-keyed `psk0`, the
  challenge-and-retry first message, and the advertisement transition.

Reproduce the published vectors byte for byte, then interoperate with the Rust
binaries over a socket.

**What is actually being measured** is not whether you succeed but *where you had
to guess*. Every place the specification underdetermined the bytes, or where you
reached for the reference implementation to resolve an ambiguity, is a finding —
please record those as you go rather than reconstructing them afterwards. A
report that says "it worked" is much less useful than one that says "section 4.1
does not say whether the padding is inside the signed region; I guessed, and I
was wrong."

**Attach:** `spec/` in full, and nothing from `implementation/` or `simulator/`.

---

## Brief 3 — evidence from a real network

**Status.** Every measurement in this repository comes from Linux network
namespaces on one host: `implementation/harness/netns-p1.sh` and
`netns-admission.sh`. Latency, loss and jitter are injected with `netem`, so the
distributions are the ones we chose.

**Why that matters here specifically.** The fixed-T2 claim is a claim about a
*constant cadence*: that a link's packet trace is the same whether it is carrying
traffic or not. On a single host with synthetic delay, holding that cadence is
easy. The interesting question is whether it survives real scheduling, real
clock drift between hosts, real queueing, and a real path.

**The task.** Run the P1 harness across at least three physical hosts on a
network you do not control end to end, and report:

- the per-link slot jitter distribution, not just its maximum, against the
  12,500 µs slot;
- how often a slot is missed outright, and what caused it;
- whether an observer on one link can distinguish a loaded node from an idle one
  by timing alone, which is the property the fixed schedule exists to provide;
- route setup latency and its variance, which the netns runs measure at a few
  hundred milliseconds and which is the number most likely to be optimistic.

**What would count as a finding.** Any of: the cadence does not hold off one
host; it holds but the residual timing signal is exploitable; or it holds and the
claim is stronger than the repository currently states, which is also worth
knowing.

**Attach:** `implementation/harness/`, `spec/transport-profile-t2.md`,
`spec/p1-prototype-profile-v1.8.md`.

---

## Brief 4 — the two research questions

These are open problems, not defects. They are stated here because the
repository's claim boundary depends on them staying open, and a reader deserves
to know what would close them.

### 4a. A private directory that is actually private (D1)

R1 deliberately removes endpoint-specific selectors from mandatory discovery, so
a destination is never named in a DISCOVER. That pushes the problem somewhere
else rather than solving it: something has to map a human-meaningful destination
to a reachable gateway, and whatever does that learns who is looking for whom.

`spec/private-directory-d1.md` is non-normative and unimplemented. The question:
what construction lets an endpoint resolve a destination descriptor without the
resolver learning the pair, at a cost a prototype could bear? Private information
retrieval is the obvious family and its costs are the obvious objection. An
answer that says "PIR, at this concrete cost, for a directory of this size" is
worth as much as a novel construction.

This is half of the review's TR-11; the other half — authenticated bootstrap —
has since been built as B1.1 and B1.2.

### 4b. Traffic-flow unlinkability against a global observer

`spec/core-v1.8.md` excludes this explicitly and repeatedly, and the exclusion is
load-bearing: fixed-schedule T2 defeats a *local* observer by making one link's
trace constant, and says nothing about an adversary who sees every link at once.
T3 models an equal-budget multi-link adversary and T4 an open-world classifier,
both as analysis profiles rather than as claims.

The question is whether a fixed-schedule design of this shape can offer anything
against a global observer beyond what its total bandwidth budget buys, and if
not, what the honest statement of the residual is. A negative result here would
be directly useful: it would let the repository state a bound instead of an
exclusion.

**Attach:** `spec/transport-profile-t3.md`, `spec/transport-profile-t4.md`,
`spec/private-directory-d1.md`, `reports/v1.5-t3-anonymity-metrics.json`.

---

## What not to spend effort on

The 2026-09-04 review's P0 findings are closed and verified; TR-01's end-to-end
replay in particular is fixed and has a route-channel replay window with
published vectors. The B1.1 handshake and the B1.2 admission path are
implemented, cross-checked and exercised against an adversary in namespace
scenarios. `docs/review-log/` is an internal reconstruction and is not
independent review; the two independent reviews are
`docs/external-review-2026-07-30.md` and `docs/external-review-2026-09-04.md`.
