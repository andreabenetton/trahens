<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.7 invariants

- Status: Normative P1 safety and conformance invariants

## Encoding and wire

1. Every emitted UDP protocol record is exactly 1,052 bytes.
2. Only W2 epoch and sequence are public; T1 class and all M2 fields are link-encrypted.
3. All fixed-width integers are unsigned big-endian.
4. Varuints are minimal, bounded, and consume no trailing bytes.
5. Retired C1 v1 `0x0001`, disabled `0x7f02`, unknown suites, versions, and profiles are rejected.
6. One registry is the source of all identifiers, widths, limits, and C1 v2 domains.

## Authentication and replay

7. Replay state changes only after complete W2 authentication.
8. Every retransmission has a fresh sequence, padding, tag, and ciphertext.
9. Remote malformed, commitment, signature, and AEAD failures map to a uniform security event/error class.
10. No route or reassembly state is allocated from an unauthenticated or noncanonical message.

## Unlinkability structure

11. Branch token, candidate token, route label, discovery nonce, and T1 transmission ID are hop-local.
12. Every forwarded DISCOVER replaces token and nonce and blinds the reply public key with a non-zero scalar.
13. Parent/child discovery nonces are linked only inside reply-encrypted candidate layers.
14. Queue, retry, replay, scheduling, and route-map state never enters outgoing M2 semantics.
15. The protocol makes no claim that fixed-size cells alone hide link activity or route timing.

## Lifecycle and cleanup

16. Only typed valid events change route phase.
17. RENDEZVOUS_OPEN and DATA are rejected before Ready/Open respectively.
18. One capability can succeed at most once and only before expiry at its registered gateway.
19. CLOSE, CANCEL, ABORT, timeout, peer loss, and retry exhaustion reclaim all associated remote state.
20. Secret wrappers are zeroized when released.
21. A duplicate complete logical message creates no new protocol effect: it allocates no label, forwards nothing, counts toward no threshold, and renews no deadline.

## Bounds

22. Every route, peer, reassembly, sender, queue, fragment, retry, replay, and candidate-layer count is bounded by the registry.
23. Reassembly reserves bytes before storing a new fragment and releases them on every terminal path.
24. The fixed T2 scheduler emits exactly 16 slots per 200 ms epoch while active.
25. Queue or retry exhaustion fails closed; it never expands cadence or memory.
26. Logs contain stable event data but no capability, route secret, private scalar, link key, or route mapping.

## Evidence boundary

27. Passing vectors and namespace tests establishes conformance only for the frozen profile and tested faults.
28. Reply-public-key distributional unlinkability does not imply key privacy of reply ciphertexts.
29. D1 and adaptive T2/T3/T4 are not mandatory P1 interoperability properties.
