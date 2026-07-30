# Trahens Core v0.7 invariants

## Routing and activation

1. A relay never requires a complete source route.
2. Every forwarding capability is bound to peer, direction, route generation, and deadline.
3. CANDIDATE creates only tentative route state.
4. COMMIT changes tentative state only to `PENDING_READY`; it does not authorize application data.
5. READY changes matching pending state to `ACTIVE`.
6. The initiator exposes a route to the data plane only after authenticating the final READY.
7. A route-generation transcript mismatch fails closed.

## Event time

8. Every reassembly, branch, offer, tentative, pending, active, replay, and initiator transaction state has a finite local deadline.
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
21. If CANDIDATE precedes CANCEL, created tentative state remains bounded by its independent deadline or later abort.
22. CANCEL traverses stored adjacent mappings and cannot remotely reclaim unrelated or attacker-created contexts.

## Unlinkability structure

23. No network-wide discovery, attempt, ring, candidate, or route identifier is forwarded unchanged.
24. Every outgoing branch has a fresh branch token, reply-key transformation, eligibility-capsule rerandomization, M1 encoding, W2 message-local identifier, cell padding, and link ciphertext.
25. Candidate and route capabilities are replaced at every hop.
26. Exact replay detection is scoped to one adjacent-link epoch and does not create a cross-hop equality handle.
27. A W2 message-local identifier is meaningful only on one authenticated link direction and is replaced after relay transformation.
28. E1 event timing and W2 cell equality do not by themselves provide traffic-flow unlinkability.

## M1 canonical-message invariants

29. An M1 message contains no semantic padding.
30. The complete M1 message is between 1 and 16,384 bytes.
31. Every M1 variable integer is minimal and field-bounded.
32. The declared M1 body length exactly consumes the containing message; trailing bytes are rejected.
33. Message-specific nested lengths are exact and do not overlap or exceed their containing body.
34. Semantic and C1 processing begins only after complete W2 reassembly and successful M1 parsing.

## W2 cell and reassembly invariants

35. Every W2 adjacent-link record is exactly 1,052 bytes: 12 public header bytes, 1,024 encrypted cell bytes, and a 16-byte authentication tag.
36. Every encrypted cell carries at most 992 M1 bytes and fresh padding to 1,024 bytes.
37. For M1 length `L`, fragment count is exactly `ceil(L / 992)`.
38. Every non-final fragment has length 992; the final fragment has the exact remainder.
39. One M1 message uses at most 17 W2 cells.
40. Reassembly is keyed by authenticated link direction and a non-zero 128-bit message-local identifier.
41. Reassembly metadata is immutable after the first accepted fragment.
42. Exact duplicate fragments are idempotent; conflicting duplicates invalidate the context.
43. Incomplete contexts are bounded by count, aggregate reserved bytes, and deadline.
44. Incomplete or invalid reassembly allocates no branch, candidate, tentative, pending, or active route state.
45. A relay discards incoming fragments and padding after reassembly and emits newly encoded and padded cells.
46. Equal cell length does not conceal fragment count or cell timing without a separate scheduling profile.

## Resource safety

47. Authenticated exact link replay rejection precedes reassembly admission and expensive route cryptography. Unauthenticated input never advances the replay window.
48. Reassembly admission precedes M1 and C1 work and enforces peer and node-global byte budgets.
49. Fresh branches consume an ingress-peer token before full route-protocol allocation.
50. Every node enforces per-peer, per-node, node-global, and time-window limits.
51. Candidate, tentative, pending, active, and reassembly capacities are independently bounded.
52. No invalid input causes an unbounded or larger error response.
53. Per-peer token buckets mitigate concentrated fresh-token floods but are not treated as Sybil resistance.
54. Experiments report peak concurrent route state and peak reserved reassembly bytes.
55. A completed bounded simulation reports final route and reassembly state and whether cleanup reached zero.

## Authentication and cryptography

56. Responder authentication and service parameters are protected end to end inside the candidate transcript.
57. COMMIT proves knowledge of the responder-provided challenge.
58. READY authenticates the selected transcript and route limits.
59. C1 fixes URE and reply-key algorithms, canonical encodings, domain separation, generic failure, and deterministic vectors.
60. C1 point inputs decode canonically; public keys and KEM encapsulations reject the identity.
61. C1 reply tweaks satisfy `X_(i+1) = X_i + delta_i B` and `x_(i+1) = x_i + delta_i mod q`.
62. C1 URE decryption accepts only when the consistency pair decrypts to the identity and the message equals the fixed eligibility marker.
63. A deterministic test scalar or seed is never used as an operational key.
64. Malformed ciphertext and transcript errors do not produce distinguishable amplified network behavior.

## Integrated lifecycle invariants

65. The responder candidate payload has one exact 256-byte canonical encoding before relay wrapping.
66. Each reverse relay layer is authenticated to its current reply key and contains the next reply-key tweak and local capabilities.
67. The initiator authenticates the responder payload and every nested layer before selecting a candidate.
68. COMMIT and READY proofs are bound to the candidate challenge and endpoint address.
69. A route is never ACTIVE after any candidate, COMMIT, READY, link, cell, reassembly, M1, or C1 authentication failure.
70. Exact cell bytes, logical-message bytes, cryptographic transformations, candidate layers, and failure classes are accounted separately.

## Claim discipline and active-security boundary

71. Cell-length equality, wire-image unlinkability, batch-local message unlinkability, lifecycle correctness, message-size concealment, and traffic-flow unlinkability are separate claims.
72. Core v0.7 claims deterministic bounded lifecycle and reassembly behavior under the modeled events; it does not claim global timing resistance.
73. A compromised relay may originate a new valid adjacent-link ciphertext; adjacent-link integrity does not imply honest relay transformation.
74. The C1 consistency pair admits a persistent ratio-tag experiment that survives honest rerandomization.
75. The protocol does not claim active-adversary message unlinkability while that experiment remains distinguishable.
76. Endpoint rejection of a tagged capsule is normalized with other invalid-cryptographic outcomes and does not produce an amplified diagnostic response.
