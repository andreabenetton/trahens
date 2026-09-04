<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.6 / P1 — Independent Review

**Artifact reviewed:** `paper-pdf` artifact 9946057450 from GitHub Actions run 33896591192, cross-checked against the normative v1.6 specifications and the Rust implementation at commit `7a7eacc5080797fa168873ab480752c14f692dc9`
**Review date:** 4 September 2026
**Method:** read the paper against the v1.6 normative specs and the Rust implementation; traced the route channel, R1 rendezvous, candidate lifecycle and W2 link layer through the code; tested the blinded reply construction for related-key retargeting; audited the TLA+ models and CI acceptance gate.

---

## Overall assessment

**Trahens is a serious research protocol with several well-designed components, but I would not approve the current v1.6/P1 implementation for production anonymity or security use.**

I did **not** find an immediate catastrophic break in Ristretto255, the reply DH construction, HKDF, Ed25519, or ChaCha20-Poly1305. In particular, the obvious related-key retargeting attack against the blinded reply keys appears blocked by recipient/encapsulation binding in the KDF.

I did find:

| ID    | Severity                      | Finding                                                                                                  |
| ----- | ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| TR-01 | **High**                      | End-to-end protected DATA has no end-to-end replay protection                                            |
| TR-02 | **High deployment risk**      | Restarting W2 with the same key+epoch re-enables old ciphertexts and risks nonce reuse                   |
| TR-03 | **Medium–High**               | CANDIDATE semantic replay can exhaust candidate budgets, renew state and bias selection                  |
| TR-04 | **Medium–High**               | "One-time" R1 capability is not globally one-time when the same `tau` is registered at multiple gateways |
| TR-05 | **High assurance defect**     | The TLA+ `AtMostOnce` property does not actually prove at-most-once redemption                           |
| TR-06 | **Medium–High**               | Paper's signed-candidate transcript does not match the normative R1 transcript                           |
| TR-07 | **Medium**                    | Descriptor-authorized gateway pseudonyms are not checked by the P1 endpoint                              |
| TR-08 | **Medium**                    | Gateway performs relatively expensive candidate crypto before its route/admission check                  |
| TR-09 | **Medium**                    | Reply key is reused across expanding rings despite Core's fresh-DISCOVER requirement                     |
| TR-10 | **Assurance blocker**         | Custom reply encryption still lacks a convincing multi-user, related-key, key-private CCA argument       |
| TR-11 | **System blocker**            | Private directory and authenticated bootstrap/rekey are not implemented                                  |
| TR-12 | **Documentation/conformance** | Several paper/spec/code descriptions are stale or mutually inconsistent                                  |

The strongest parts are **W2 inside a single correctly managed epoch**, bounded resource accounting, canonical parsing, secret destruction, the R1 separation of destination capability from DISCOVER, and the generally disciplined treatment of claim boundaries.

---

## 1. TR-01 — End-to-end DATA replay

This is the most important concrete protocol flaw I found.

Once the route is established, `route_seal()` derives one route key from `route_secret`, generates a random 96-bit ChaCha20-Poly1305 nonce, and prepends it to the ciphertext. `route_open()` authenticates the ciphertext but keeps **no replay state**.

DATA plaintext itself contains:

`direction || sequence || payload`

but the gateway does not maintain an accepted-sequence window. When it decrypts a valid endpoint→gateway DATA message, it checks `direction == 0`, accepts whatever `sequence` is present, processes the DATA, and sends it back with `direction == 1`.

That defeats neither recording nor replay by a compromised relay. The threat model explicitly permits a relay to duplicate traffic.

### Concrete attack

Assume:

`Endpoint → R1 → malicious R2 → Gateway`

Endpoint sends an encrypted application operation, for example conceptually:

`DATA(seq=57, "transfer/action/request")`

R2 cannot decrypt it. But it can retain the opaque `protected_body`.

Later R2 sends that **same protected body** again toward the gateway, encapsulated inside a newly generated legitimate R2→Gateway W2/T1 transmission.

Adjacent-link replay protection does not help:

* the new W2 sequence is fresh;
* the link ciphertext/tag is fresh;
* W2 correctly considers it new traffic;
* the gateway subsequently decrypts the old end-to-end `protected_body`;
* there is no route-level replay cache;
* the application DATA is delivered again.

This is precisely why hop-by-hop replay protection is not a substitute for end-to-end replay protection.

The state machine explicitly accepts repeated `DataAccepted` events while Open.

### Fix

I would redesign the route channel around two independent directions:

```text
PRK   = HKDF-Extract(route_salt, route_secret)

K_EG  = HKDF-Expand(PRK, "Trahens/route/e2g" || transcript_hash, 32)
K_GE  = HKDF-Expand(PRK, "Trahens/route/g2e" || transcript_hash, 32)
```

Then use monotonically increasing 64-bit sequence numbers. A nonce can safely be deterministic, for example:

```text
nonce = direction_domain_32 || sequence_64
```

Authenticate at least:

```text
protocol version
route/profile identifier
selected-offer transcript hash
message type
route generation
direction
sequence
```

Both endpoints need a bounded replay window per direction.

The existing `sequence` field is already available; it should become a cryptographic anti-replay field instead of effectively informational data.

### Related issue: random route nonces

Using random 96-bit AEAD nonces with a long-lived key is also inferior to deterministic per-direction counters. At a stringent nonce-collision target of about \(2^{-64}\), a 96-bit random nonce space reaches that risk after only roughly **93,000 encryptions**. This is not an immediate practical break at prototype rates, but it is unnecessary risk.

I would also replace the unusual:

`HMAC(route_secret, DOMAIN || route_secret)`

route-key construction with a conventional HKDF key schedule.

---

## 2. TR-02 — W2 restart safety is currently operational, not cryptographic

W2 itself is one of the best-designed parts of Trahens.

It derives different directional keys, encodes `(epoch, sequence)` into the nonce/AAD, authenticates before advancing the replay window, and uses fixed-size cells.

The problem appears on process restart.

`LinkConfig` receives a raw 32-byte base key and a 32-bit epoch externally.

At startup, the sender chooses a new random **32-bit** starting value and promotes it to a 64-bit sequence; the receiver creates a fresh replay window for the supplied epoch.

Suppose yesterday:

```text
key   = K
epoch = 17
sequence = 0x23145678 ...
```

An attacker records valid cells.

Both daemons restart today with:

```text
key   = K
epoch = 17
```

The new replay window has forgotten yesterday. A previously recorded authenticated W2 record can therefore be presented again and can authenticate.

Worse, if the new sender eventually emits a sequence previously used under the same `(directional key, epoch)`, ChaCha20-Poly1305 sees a repeated nonce under the same key.

The repository is aware of this requirement: B1 explicitly says restart must not reuse old key/epoch/sequence state.

But B1 is future work, while P1 receives the values statically.

So this is not a flaw in the W2 cryptographic design itself. It is a **hard deployment precondition that the prototype currently cannot enforce**.

For production I would require fresh AKE-derived traffic keys per process session. Epoch uniqueness then becomes defense-in-depth rather than the only thing preventing nonce-space resurrection.

---

## 3. TR-03 — CANDIDATE replay is not idempotent

This one is subtle and quite important.

E1 explicitly requires a relay traversed by a CANDIDATE to:

> reject exact replays idempotently

and says duplicated complete logical messages must not create new protocol effects.

The Rust relay currently does not implement that semantic property.

When a child CANDIDATE arrives, the relay:

1. resolves `candidate_token`;
2. finds the corresponding child;
3. cryptographically wraps the candidate;
4. calls `CandidateAccepted`;
5. allocates another tentative offer selector;
6. forwards another CANDIDATE upstream.

The used child-facing candidate label is not consumed before another logically identical CANDIDATE can use it.

More seriously, the candidate response limit is checked **after** expensive wrapping and after `CandidateAccepted`.

`CandidateAccepted` while already in Candidate state is explicitly accepted and renews the state deadline.

Therefore a malicious child relay can repeatedly transmit:

```text
same candidate token
same candidate blob
fresh T1 transmission
fresh W2 sequence/ciphertext
```

The W2 replay window quite correctly regards these as new link messages.

The semantic protocol layer does not.

### Consequences

A malicious child can consume the branch's 64-offer response budget, crowd out candidates from honest sibling branches, force repeated public-key wrapping work, grow tentative mapping activity, and repeatedly renew candidate state.

Even after the 64-response quota is exhausted, the implementation performs the wrapping and state transition before discovering that it has no next offer label.

There is also an initiator-side variation. The endpoint pushes every successfully decrypted candidate into `held`, and closes its candidate window when `held.len()` reaches `candidate_threshold`; there is no authenticated-offer deduplication before that count.

A malicious adjacent first relay that has obtained one legitimate candidate can therefore duplicate it and influence a threshold-based selection policy without forging any gateway signature.

### Fix

Candidate identities should be deduplicated semantically, not by W2/T1 transmission identifiers.

A useful candidate identifier is something derived from the authenticated gateway offer, for example:

```text
candidate_id = H(canonical_signed_gateway_offer)
```

The initiator should count each candidate ID once.

At a relay, a child candidate capability should be **consumed or marked seen on successful admission**, and the quota/work reservation check must occur before nested public-key wrapping.

If multipath legitimately permits several different offers from one gateway, deduplicate the signed offer, not merely the gateway identity.

---

## 4. TR-04 — R1's "one-time capability" needs its semantics clarified

R1 says an endpoint generates a capability `tau` and may register it at **one or more gateways**.

The implementation indexes records as:

```text
(gateway_id, H(tau))
```

and redemption deletes only that record. Registration explicitly permits the same digest at another gateway.

Therefore:

```text
register tau at G1
register tau at G2

redeem tau at G1  -> success
redeem tau at G2  -> success
```

Nothing cryptographically prevents it.

So there are two possible specifications.

If **one-time means per gateway registration**, implementation behavior is reasonable, but the paper's global-sounding statements need to be narrowed.

If **one-time means one successful use of the descriptor capability anywhere**, the current protocol does not implement that property.

The paper presently says atomic lookup/deletion enforces at most one successful redemption.

That is only true within one gateway's local registry.

### Architectural choice

Global one-shot semantics across independent gateways are effectively a small distributed double-spend problem. You need either shared spent-token state/consensus, a single authoritative gateway, or another common redemption authority.

A simpler design is to generate independent per-gateway tokens:

```text
tau_G1
tau_G2
tau_G3
```

and explicitly call them **one-time per-gateway rendezvous capabilities**.

That removes semantic ambiguity, although it still permits the descriptor as a whole to be used once at each gateway.

---

## 5. TR-05 — The formal `AtMostOnce` property does not prove at-most-once

This should be corrected before citing the TLA+ model as security evidence.

Current `R1Capability.tla` defines:

```text
AtMostOnce ==
    \A c \in Capabilities :
        registrations[c].live \in BOOLEAN
```

That says only that `live` is a Boolean. It does not count redemptions or retain any history of redeemed capabilities.

Furthermore, the model maps each capability to exactly **one gateway**, so it cannot express the normative multi-gateway registration condition in the first place. And once `live` becomes false, `Register` permits that capability to become live again.

So `AtMostOnce` is not merely weak—it is not the claimed invariant.

The bounded Python checker is better: it permits `(digest,gateway)` records and retains a `redeemed` set. But registration does not reject a digest because it is in `redeemed`, and the tests verify an immediate replay against the same gateway rather than proving global non-redeemability across gateways.

A real property should contain historical state, conceptually:

```text
RedeemCount[c] <= 1
```

or, for per-gateway semantics:

```text
RedeemCount[c,g] <= 1
```

and the model must match whichever semantics the protocol actually chooses.

---

## 6. TR-06 — The paper describes a stronger signed transcript than R1 implements

This is a significant paper/specification fidelity problem.

The paper says the signed candidate transcript includes, in fixed order:

> protocol domain, version, suite, gateway pseudonym, offer deadline, final reply public key, commit challenge, candidate nonce, selected parameter digest.

But ADR 0038 explicitly establishes `Trahens-P1-gateway-offer-v1` as the **normative R1 wire transcript**.

The Rust implementation signs:

```text
gateway_id
expires_at_ms
gateway_pseudonym
route_secret
commit_challenge
routing_nonce
signing_public
```

under the `Trahens-P1-gateway-offer-v1` domain.

It does **not** explicitly include:

```text
Core/protocol version
network suite ID
final reply public key
parameter digest
```

This does not automatically imply a practical suite-downgrade exploit. In fact, I specifically checked this: `node-runtime` rejects a decoded M2 envelope unless `envelope.suite_id` equals the configured link suite before handing it to the protocol.

So my earlier tentative suite-rewrite concern is not a valid finding.

The problem is instead that the **security argument in the paper is reasoning about a transcript different from the normative R1 transcript**.

For a cryptographic protocol, that needs to be eliminated completely.

I would define exactly one canonical `GatewayOfferTranscriptV2`, freeze test vectors for it, and derive both signature and selected-route context from its hash.

---

## 7. The paper's reply-KDF description is also stale

The current cryptographic profile and implementation derive **76 bytes** of HKDF output:

```text
32 bytes AEAD key
12 bytes nonce
32 bytes commitment key
```

The paper still contains prose describing a **44-byte** expansion into only key+nonce.

The code is actually the stronger version here, since it adds an explicit recipient/ciphertext key commitment.

But publication and normative implementation must describe the same cryptosystem.

---

## 8. TR-07 — Descriptor pseudonym authorization is not enforced by the endpoint prototype

R1 requires the descriptor to contain acceptable gateway pseudonyms and requires the initiator to accept only authorized candidates.

The Rust endpoint currently receives an expected gateway verification key and the bearer capability, but `open_candidate_chain()` returns the signed `gateway_pseudonym` without comparing it against an accepted descriptor pseudonym set. The endpoint subsequently places that candidate into its selection set.

The signature proves:

> this pseudonym was asserted by this gateway key.

It does not prove:

> this is one of the descriptor instances I intended to use.

That distinction matters for stale descriptor epochs and capability registrations.

Because `redeem_for_pseudonym()` removes a registration even when the presented pseudonym is wrong, selecting a same-key but unauthorized/stale pseudonym can consume the capability registration and produce a denial of service.

The P1 CLI should ideally consume a parsed descriptor object and validate:

```text
gateway verification key
gateway pseudonym
descriptor expiration
suite/profile
endpoint authentication policy
```

before the candidate enters `held`.

---

## 9. TR-08 — Gateway cryptographic work occurs before gateway admission

The resource specification has a good admission philosophy: bound work/state before expensive protocol operations.

The paper similarly says cheap checks and token buckets precede expensive group/signature/decryption work.

The relay implements an `IngressAdmission` token bucket.

The gateway currently does not.

For a valid R1 DISCOVER it generates route/challenge randomness and constructs `seal_gateway_offer()`—which includes public-key operations, KDF/AEAD and a signature—before attempting `states.begin()` and discovering whether route-state capacity is available.

This does not yield an unbounded memory attack, and fixed T2 substantially limits one link's request rate. But it lets an authenticated hostile peer spend gateway crypto even when later-stage capacity is already exhausted.

Reserve the bounded gateway-offer/work slot first, perform cryptography second, and release the reservation on failure.

---

## 10. TR-09 — The endpoint reuses one reply root across expanding rings

Core describes a DISCOVER containing a fresh non-identity reply public key.

The endpoint instead generates:

```text
root_secret
reply_public_key
```

once before the ring loop, and every `open_ring()` sends that same `reply_public_key`.

Therefore the endpoint's adjacent relay can trivially recognize successive expanding-ring attempts by equality of the initial reply key.

This does **not** invalidate the narrow U1 theorem because U1 explicitly excludes origin adjacency across local rings from its claim boundary.

But it is still a conformance/privacy mismatch that is cheap to remove.

Store a fresh reply secret/public pair in every `RingContext`.

---

## 11. Custom reply encryption: I do not see an obvious algebraic break

The reply scheme deserves separate treatment because it is custom cryptography.

Every forwarding relay multiplies the reply public key by a random Ristretto scalar. The corresponding secret can be multiplied by the same scalar to preserve decryption.

A first attack to test is related-key retargeting.

Given:

```text
X' = bX
```

an attacker who knows `b` might transform:

```text
R' = b^-1 R
```

so that:

```text
DH(R', X') = DH(R, X)
```

That sort of transformation is dangerous in schemes that derive the AEAD key from the DH point alone.

Trahens does not.

Its KDF context additionally incorporates the encapsulated point and recipient public key. Consequently preserving the DH group element while changing `(R,X)` changes the KDF transcript and therefore the derived AEAD key/nonce/commitment key.

The explicit recipient/ciphertext commitment provides another useful barrier.

I therefore did **not** find a simple ciphertext retargeting attack.

### But the proof obligation remains substantial

The repository itself correctly identifies the unresolved question: nested reply encryption is used in a **multi-user, multiplicatively related-recipient-key** setting, and the desired privacy property is stronger than ordinary IND-CCA confidentiality.

The existing argument proves useful structural facts about the public key distribution but treats full ciphertext unlinkability conditionally on stronger key-privacy/composition assumptions.

I would therefore label this:

**no demonstrated cryptographic break, but still an external-review blocker for a production anonymity claim.**

Ideally the reply layer should eventually be reduced to a recognized anonymous/key-private KEM/PKE construction with a proof fitting the related-key structure, or receive a proper game-based proof of this exact construction.

---

## 12. R1 is a bearer-capability system

This is not a hidden bug; the protocol states the limitation.

Anyone who obtains `tau` before first use can race the legitimate owner. R1 does not cryptographically bind possession of `tau` to a client identity.

In the current gateway executable, `endpoint_handshake` is received and logged as local rendezvous input, but P1 does not perform a cryptographic client proof-of-possession over it.

For production I would bind the descriptor to a client public key and require something resembling:

```text
Sig_client(
    protocol_domain ||
    selected_offer_hash ||
    H(tau) ||
    client_nonce ||
    expiration ||
    endpoint_handshake_hash
)
```

Then theft of the capability alone is insufficient.

Whether you want that property depends on whether `tau` is deliberately meant to behave like a bearer invitation.

---

## 13. Adjacent-link/W2 design is otherwise strong

Within its stated session assumptions I consider W2 well structured.

Independent directional keys are used. The nonce derives exactly from epoch and sequence rather than randomness. The same values are authenticated. Replay is prechecked but is not committed until AEAD authentication succeeds. Fixed record size avoids trivial message-length exposure.

T1 then retransmits lost fragments with new W2 sequences rather than repeating ciphertexts.

The implementation also explicitly zeroizes send keys, receive keys and the configured base key on shutdown.

This is considerably cleaner than the current end-to-end route channel.

---

## 14. Privacy properties: narrow but mostly stated honestly

The R1 architectural change is a good one.

The forward DISCOVER no longer carries an endpoint capability or endpoint-specific selector. The R1 eligibility field is just a fresh random nonce, independently replaced by every relay.

This eliminates an important class of obvious equality handles.

But it does **not** make Trahens a complete anonymous communication system.

U1 excludes, among other things, global timing correlation, origin adjacency across rings, route depth, gateway choice and traffic-flow properties.

T2 also explicitly limits what padding can prove. Fixed-rate behavior is the meaningful privacy profile; adaptive scheduling leaks activity by design.

The project's own T3 measurements reinforce this. Its 4-class nearest-centroid result is approximately random-chance under fixed scheduling (`0.25`) but about `0.854` under adaptive scheduling, with the latter estimated at roughly `1.31` bits of leakage in that experiment.

That is useful falsification evidence, but it is not evidence against a sophisticated global passive adversary.

---

## 15. D1 is essential, not optional polish

The most important architecture-level privacy statement in the repository may be in D1:

> a complete system cannot claim meaningful endpoint anonymity until private directory lookup or an equivalent mechanism exists.

D1 is currently a non-normative strawman.

That is correct.

If a client retrieves:

```text
destination -> tau + gateway pseudonyms + authentication material
```

through an observable destination-specific directory lookup, excellent anonymity properties in the subsequent routing protocol may not matter.

For a deployable anonymous system, directory privacy and gateway-discovery privacy must be analyzed together with the routing protocol.

---

## 16. B1 is equally important for authentication and rekey

P1 assumes the adjacent graph and symmetric keys already exist.

It does not currently define:

```text
peer identity enrollment
authenticated neighbor discovery
AKE
rekey
revocation
persistent epoch management
Sybil policy
```

The prototype profile explicitly says so.

B1 has the right general direction, especially its prohibition on key/epoch reuse, but is non-normative future architecture.

Until that is implemented, the secure-channel assumptions below P1 are supplied by configuration rather than by Trahens.

---

## 17. Availability against malicious gateways/Sybils remains limited

R1 intentionally lets every generic rendezvous gateway respond to a valid DISCOVER.

That removes destination-specific information from forward discovery, but also means the system needs strong operational defenses against candidate flooding and malicious gateways.

The protocol contains good local bounds: branch limits, route limits, 64 candidate responses per discovery, fanout limits, queue limits and token buckets.

Those prevent unbounded local state.

They do not solve distributed Sybil admission. A population of malicious registered peers can still consume its legitimate share of discovery and candidate work. B1 presently does not supply that admission architecture.

This is primarily an availability/system-design issue rather than a cryptographic break.

---

## 18. Formal assurance is presently much weaker than the protocol

`E1Lifecycle.tla` is essentially a small phase-transition skeleton:

```text
ABSENT
DISCOVERING
CANDIDATE
COMMITTED
READY
OPEN
```

It does not model the difficult parts of E1: timers, event ordering, duplicates, generations, candidate fan-out, capacity limits, replay windows or protected DATA.

That is fine as a sanity model.

It should not be described as formal verification of the complete lifecycle protocol.

The bounded Python checker is more useful operationally, and the Rust/state-machine tests are useful conformance evidence, but a security paper should be precise about the difference between:

```text
model checked simplified state machine
bounded exhaustive implementation-independent checker
tests/fuzzing
cryptographic proof
network experiments
```

Those are very different forms of evidence.

---

## 19. CI quality is good, but the missing adversarial tests explain several findings

The linked workflow passed the full reference/spec checks, Rust tests/clippy, decoder fuzzing and Linux interoperability.

The namespace tests are particularly useful: deep paths, 5% loss, retry exhaustion, capability replay, expiry, fanout selection, cleanup and experimental C1 controls are all better than the test coverage of most early research protocols.

But the current acceptance gate does not appear to contain the adversarial cases that expose the issues above:

```text
fresh-W2 replay of an old end-to-end DATA body
same valid CANDIDATE retransmitted as a new logical message
candidate duplication before threshold counting
same tau registered and redeemed at two gateways
restart with identical base key and epoch
same signing key but descriptor-unauthorized pseudonym
```

Those should become regression tests.

---

## 20. Specification hygiene needs tightening

Crypto protocols are unusually intolerant of parallel descriptions.

There are currently several signs of version drift: current v1.6 documents still contain older applicability labels, old candidate transcript material coexists with the ADR-selected R1 transcript, and implementation comments around C1 still describe states that have since changed.

One example is C1. Current v1.6 makes C1 eligibility a selectable experimental live profile.

But some implementation commentary still describes C1 as never appearing on P1, while newer code explicitly supports it experimentally.

Similarly, the endpoint comments say C1 requires "two explicit choices", yet the code derives `Profile::Experimental` automatically when `--eligibility-suite c1` is selected.

These are not severe cryptographic flaws individually, but this is exactly how cryptographic implementations and security arguments gradually diverge.

I would generate a single machine-readable protocol manifest containing all suite IDs, domains, transcript schemas, field order, key schedules and versions, and generate both documentation tables and test vectors from it.

---

## Recommended remediation order

**P0 should be protocol correctness.** Add end-to-end directional sequence/replay protection; fix semantic CANDIDATE replay and quota ordering; decide whether R1 capability consumption is global or per registration; replace the misleading `AtMostOnce` formal property; and synchronize the paper's signed transcript with the actual normative R1 transcript.

**P1 should be cryptographic hardening.** Replace the route channel with a directional HKDF schedule and counter nonces; bind the complete selected-offer transcript into route keys; enforce descriptor pseudonym authorization; generate a fresh reply root for every DISCOVER/ring; and obtain an independent review/proof of the related-key reply-encryption construction.

**P2 is what turns P1 into a deployable system.** Implement B1 or an equivalent authenticated AKE/rekey/epoch mechanism, implement a private-directory architecture such as D1, add client proof-of-possession if stolen bearer capabilities are unacceptable, establish Sybil/admission policy, and decide whether post-quantum protection is part of the threat model.

---

## Bottom line

The **basic Trahens idea survives this review**. In particular, I do not see a fatal flaw in the central concept of replacing link-local routing handles and using multiplicatively transformed ephemeral reply keys to return an encrypted candidate chain. R1's removal of endpoint-specific material from forward DISCOVER is also a meaningful improvement.

But there are enough concrete issues that I would currently characterize v1.6 as:

**a promising, unusually well-instrumented research prototype with credible local unlinkability mechanisms, but not yet a production-secure anonymous routing protocol.**

The most urgent actual protocol defect is the **missing end-to-end replay layer**. The most urgent discovery-lifecycle defect is **semantic CANDIDATE replay**. The most serious assurance error is the current **R1 `AtMostOnce` formal model**, and the most important publication issue is the **paper describing a signed transcript that the normative R1 implementation does not actually sign**.
