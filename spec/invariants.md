# Protocol invariants

The simulator, conformance tests, and implementations must check these invariants.

## Routing

1. **Local-label scope**: a route label is accepted only from its bound adjacent peer and direction.
2. **No complete route object**: no relay state contains the full ordered path.
3. **Tentative isolation**: application data never traverses tentative state.
4. **Commit consistency**: an active forward mapping and its reverse mapping refer to the same route generation and limits.
5. **Idempotent setup**: duplicate CANDIDATE, COMMIT, READY, ABORT, or CLOSE messages do not allocate additional route state.

## Lifecycle

6. **Finite state lifetime**: every discovery, replay, tentative, and active record has a finite local expiration.
7. **Local cleanup**: remote cooperation is not required to remove expired state.
8. **No resurrection**: an expired candidate or route cannot be reactivated by a delayed message.
9. **Monotonic setup**: state cannot transition from ACTIVE back to TENTATIVE.

## Resource safety

10. **Bounded fan-out**: one accepted DISCOVER creates at most the configured number of outgoing DISCOVER messages.
11. **Bounded candidates**: one discovery creates at most the configured candidate state per node.
12. **Budget-before-crypto**: peer and global budget checks occur before expensive public-key operations whenever the message format permits.
13. **No error amplification**: an error response is not larger or more expensive than the rejected request by more than a configured constant factor.
14. **Pressure priority**: uncommitted state is evicted before active state unless local safety policy requires otherwise.

## Authentication and replay

15. **Transcript binding**: authentication covers version, suite, message type, discovery or route context, role, direction, expiry, and critical options.
16. **Context binding**: material valid for one hop, direction, discovery, or route is invalid in another context.
17. **Freshness**: replayed setup messages cannot extend state lifetime without a new authenticated exchange.
18. **Downgrade resistance**: suite or privacy-profile changes are authenticated and cannot be silently rewritten.

## Privacy accounting

19. **Explicit leakage**: every profile documents visible identifiers, sizes, timing, peer relationships, and service selectors.
20. **Claim scoping**: a privacy claim names the adversary class and deployment profile under which it is evaluated.
21. **Legacy claim quarantine**: the legacy statement of unlinkability is not treated as satisfied by Core v0.1.
