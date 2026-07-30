# Open questions

## R1 descriptor and gateway design

- How are descriptors queried without revealing the destination to the directory?
- How are clients authorized without making queries or descriptors linkable?
- Should capability commitments be replicated, threshold-shared, or registered at multiple independent gateways?
- How are gateway pseudonyms authenticated, rotated, revoked, and protected from enumeration?
- Can a client-bound handshake reduce the race created by a stolen capability?
- How can selective gateway denial be measured or audited without exposing users?

## Retained cryptography

- Can the additive reply-key chain and custom KEM be proved secure under related-key evolution?
- Which transcript fields and key-confirmation step are necessary to prevent substitution?
- How should malformed-input and timing behavior be normalized without creating a denial-of-service primitive?
- Does an author-confirmed interpretation repair the disabled C2 k=2 transcription?
- Which future endpoint-specific primitive could satisfy the source-independent provider interface?
- What post-quantum construction can preserve acceptable candidate size and route depth?

## Reliability and W2

- Which acknowledgement and retransmission scheme avoids stable cross-hop identifiers?
- Should recovery operate per cell, per logical message, or through bounded erasure coding?
- How should retry state interact with E1 deadlines and cancellation?
- Should the 16,384-byte message ceiling and 17-cell limit remain fixed?
- Which deterministic eviction policy resists fragment sprays without giving the attacker control over surviving contexts?

## Scheduling and traffic privacy

- Which interleaving, batching, release, and chaff policy provides a useful anonymity set at acceptable latency?
- How should candidate cell count be padded without excessive amplification?
- Can queue fairness be preserved under low load and attack traffic?
- Which classifiers and statistical tests define acceptable timing-linkability evidence?

## Protocol lifecycle and routes

- How should route diversity be measured without revealing topology?
- How are active routes repaired without repeating full discovery?
- Are active labels flow-scoped, route-scoped, or reusable until expiry?
- How should gateway handoff or endpoint mobility interact with one-time capabilities?

## Governance and deployment

- Which organization allocates protocol and suite identifiers?
- What evidence is required before a research profile becomes operationally enabled?
- How are relay and gateway admission, Sybil resistance, incentives, and abuse handled?
- When is the licensing position of preserved historical material resolved?
