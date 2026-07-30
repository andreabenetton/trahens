# Trahens Core v0.2 invariants

The simulator, conformance tests, and implementations must check these invariants.

## Routing

1. **Local-label scope**: a route label is accepted only from its bound adjacent peer and direction.
2. **No complete route object**: no relay state contains the full ordered path.
3. **Tentative isolation**: application data never traverses tentative state.
4. **Commit consistency**: active forward and reverse mappings refer to the same route generation and limits.
5. **Idempotent setup**: duplicate CANDIDATE, COMMIT, READY, ABORT, or CLOSE messages do not allocate additional route state.

## Attempt separation

6. **Local logical ID**: the logical-discovery ID never appears on the wire.
7. **Fresh attempt ID**: each ring uses a unique unpredictable attempt ID.
8. **No retry marker**: a message does not expose a previous attempt ID, ring index, or retry count.
9. **Attempt-local deduplication**: duplicate suppression keys do not span attempts.
10. **Candidate deduplication**: equivalent authenticated responders occupy at most one logical candidate slot.

## Lifecycle

11. **Finite state lifetime**: every attempt, replay, tentative, and active record has a finite local expiration.
12. **Local cleanup**: remote cooperation is not required to remove expired state.
13. **No resurrection**: an expired candidate or route cannot be reactivated by a delayed message.
14. **Monotonic setup**: state cannot transition from ACTIVE back to TENTATIVE.
15. **Late-attempt isolation**: cancellation or expiration of one attempt does not alter a later attempt.

## Resource safety

16. **Bounded ring schedule**: one logical discovery has a finite number of attempts and a finite overall deadline.
17. **Bounded fan-out**: one accepted DISCOVER creates at most the configured outgoing messages.
18. **Cumulative transmission bound**: all attempts together remain within the logical transmission budget.
19. **Cumulative allocation bound**: all attempts together remain within the logical state-allocation budget at the initiator model.
20. **Relay-local enforcement**: relays independently enforce peer, attempt, time-window, and global limits.
21. **Bounded candidates**: one logical discovery stores at most the configured unique candidates.
22. **Budget-before-crypto**: budget checks occur before expensive public-key operations whenever the format permits.
23. **No error amplification**: an error response is bounded by a configured constant relative to the request.
24. **Pressure priority**: uncommitted state is evicted before active state unless local safety policy requires otherwise.

## Authentication and replay

25. **Transcript binding**: authentication covers version, suite, message type, attempt or route context, role, direction, expiry, and critical options.
26. **Context binding**: material valid for one hop, direction, attempt, or route is invalid in another context.
27. **Freshness**: replayed setup messages cannot extend state lifetime without a new authenticated exchange.
28. **Downgrade resistance**: suite or privacy-profile changes are authenticated and cannot be silently rewritten.

## Privacy accounting

29. **Explicit leakage**: every profile documents identifiers, sizes, timing, peer relationships, and service selectors visible to each adversary.
30. **Cross-attempt overlap metric**: experiments report relays observing more than one attempt and repeated relay observations.
31. **Claim scoping**: a privacy claim names the adversary class and deployment profile.
32. **No identifier-only unlinkability claim**: fresh attempt IDs alone are not evidence that attempts are unlinkable.
33. **Legacy claim quarantine**: the legacy non-adjacent-message unlinkability statement remains unproven.
