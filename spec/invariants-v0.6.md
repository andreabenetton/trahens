# Trahens Core v0.6 invariants

## Routing and activation

1. A relay never requires a complete source route.
2. Every forwarding capability is bound to peer, direction, route generation, and deadline.
3. CANDIDATE creates only tentative route state.
4. COMMIT changes tentative state only to `PENDING_READY`; it does not authorize application data.
5. READY changes matching pending state to `ACTIVE`.
6. The initiator exposes a route to the data plane only after authenticating the final READY.
7. A route-generation transcript mismatch fails closed.

## Event time

8. Every branch, offer, tentative, pending, active, replay, and initiator transaction state has a finite local deadline.
9. State is valid on `[created, expiry)` and invalid at `expiry`.
10. Expiry is processed before a message assigned the same local timestamp.
11. Candidate delivery is processed before closure of a candidate window assigned the same timestamp.
12. An expired or cancelled state is never recreated by a delayed message.
13. A stale expiry event cannot shorten a state deadline that was validly replaced during a state transition.
14. Cleanup does not require remote cooperation.

## Candidate windows and races

15. Ring schedule, ring number, retry count, and logical-discovery identity remain initiator-local.
16. A delayed candidate from an earlier ring may remain eligible until a route decision, subject to its offer and tentative deadlines.
17. Route selection is immutable after the decision boundary.
18. A late candidate cannot replace or modify the selected route.
19. CANCEL is advisory; expiry is authoritative.
20. If CANCEL precedes CANDIDATE at a required context, the candidate is discarded.
21. If CANDIDATE precedes CANCEL, any created tentative state remains bounded by its independent deadline or later abort.
22. CANCEL traverses stored adjacent mappings and is scoped to branches of the initiating logical discovery; unrelated or attacker-created contexts are not remotely reclaimed by that initiator.

## Unlinkability structure

23. No network-wide discovery, attempt, ring, candidate, or route identifier is forwarded unchanged.
24. Every outgoing branch has a fresh branch token, reply-key transformation, eligibility-capsule rerandomization, padding, and link ciphertext.
25. Candidate and route capabilities are replaced at every hop.
26. Exact replay detection is scoped to one adjacent-link epoch and does not create a cross-hop equality handle.
27. E1 event timing does not itself provide traffic-flow unlinkability; timing claims require a separate scheduling profile.

## Resource safety

28. Exact replay rejection precedes token-bucket consumption and expensive cryptography.
29. Fresh branches consume an ingress-peer token before full allocation.
30. Every node enforces per-peer, per-node, node-global, and time-window limits.
31. Candidate, tentative, pending, and active capacities are independently bounded.
32. No invalid input causes an unbounded or larger error response.
33. Per-peer token buckets mitigate concentrated fresh-token floods but are not treated as Sybil or distributed-denial resistance.
34. Experiments report peak concurrent state in addition to cumulative allocations.
35. A completed bounded simulation reports final state and whether cleanup reached zero.

## Authentication and cryptography

36. Responder authentication and service parameters are protected end to end inside the candidate transcript.
37. COMMIT proves knowledge of the responder-provided challenge.
38. READY authenticates the selected transcript and route limits.
39. C1 fixes the URE and reply-key algorithms, canonical encodings, domain separation, generic failure result, and deterministic vectors.
40. C1 point inputs decode canonically; public keys and KEM encapsulations reject the identity.
41. C1 reply tweaks satisfy `X_(i+1) = X_i + delta_i B` and `x_(i+1) = x_i + delta_i mod q`.
42. C1 URE decryption accepts only when the consistency pair decrypts to the identity and the message equals the fixed eligibility marker.
43. A C1 deterministic test scalar or seed is never used as an operational key.
44. Malformed ciphertext and transcript errors do not produce distinguishable amplified network behavior.

## Claim discipline

45. Wire-image unlinkability, batch-local message unlinkability, lifecycle correctness, and traffic-flow unlinkability are separate claims.
46. Core v0.6 with U1, E1, C1, and W1 claims deterministic bounded lifecycle behavior under the modeled events; it does not claim global timing resistance or active-tagging resistance.


## W1 wire invariants

47. Every reference control record is exactly 1,052 bytes: 12 public header bytes, 1,024 encrypted plaintext bytes, and a 16-byte authentication tag.
48. Message type, protocol and profile identifiers, suite identifier, logical fields, and padding are inside the encrypted plaintext.
49. Reserved bytes are zero and all integer, point, scalar, and nested-length encodings are canonical.
50. Every outgoing hop reconstructs a fresh plaintext body, regenerates padding, and uses a unique adjacent-link nonce.
51. A length, link-authentication, or codec failure allocates no protocol state.
52. W1 length equality does not imply timing, direction, or traffic-volume unlinkability.

## Integrated C1 and E1 invariants

53. The responder candidate payload has one exact 256-byte canonical encoding before relay wrapping.
54. Each reverse relay layer is authenticated to its current reply key and contains the next reply-key tweak and local capabilities.
55. The initiator authenticates the responder payload and every nested layer before selecting a candidate.
56. COMMIT and READY proofs are bound to the candidate challenge and endpoint address.
57. A route is never ACTIVE after any candidate, COMMIT, READY, link, or codec authentication failure.
58. Exact wire bytes, cryptographic transformations, candidate layers, and failure classes are accounted separately from abstract protocol transmissions.

## Active-security boundary

59. A compromised relay is allowed to originate a new valid adjacent-link ciphertext; adjacent-link integrity therefore does not imply honest relay transformation.
60. The C1 consistency pair admits a persistent ratio-tag experiment that survives honest rerandomization.
61. The protocol does not claim active-adversary message unlinkability while that experiment remains distinguishable.
62. Endpoint rejection of a tagged capsule is normalized with other invalid-cryptographic outcomes and does not produce an amplified diagnostic response.
