# Research questions

## Privacy

- What route-position information is learned by one relay, two adjacent colluding relays, and non-adjacent colluding relays?
- In the U1 challenge game, how close does matching success remain to the inverse batch size under realistic message mixes?
- Which mutable or opaque fields survive transformation and accidentally partition the anonymity set?
- How accurately can observers correlate local ring attempts through timing, origin adjacency, record class, and relay overlap even without an attempt ID?
- Does scheduling jitter reduce correlation enough to justify added discovery latency?
- Does returning multiple candidates improve route privacy or merely add distinguishable traffic?
- Can endpoint lookup avoid a stable directory query token?

## Cryptography

- Which URE construction provides ciphertext anonymity, rerandomization indistinguishability, integrity, and acceptable performance?
- Does the additive reply-key tweak construction provide the required key privacy and CCA security under a concrete KEM?
- Can an active relay tag a rerandomized selector or nested candidate capsule and recognize it later?
- How can route depth be hidden without imposing an impractical maximum-size candidate record?
- How should post-quantum migration avoid suite fingerprinting and downgrade?

## Scalability

- How does branch-context amplification grow with degree distribution, hop limit, fan-out, cyclic structure, and responder density?
- Which expanding-ring schedule minimizes expected work under a required success target when branch-local contexts replace duplicate suppression?
- What relay state is necessary for reverse and forward routing, and what can be reconstructed or removed?
- Which path-diversity target provides useful resilience without excessive control traffic?
- How should initiator-local cumulative budgets relate to independent relay-local limits?

## Security

- How are long-term endpoint identities or anonymous credentials bound to responder ephemeral keys inside CANDIDATE?
- What is the minimum information required to reject fresh-branch floods, exact replays, and malformed messages before public-key work?
- How does the protocol behave when a relay selectively delays candidates or installs inconsistent labels?
- Can an attacker force deterministic eviction of a chosen route by controlling branch timing?
- What is the recovery behavior after relay compromise and state disclosure?

## Simulation

- How do candidate-window length, packet loss, delayed responses, and cancellation races change policy performance?
- How should late candidates from an earlier local ring be handled when a later ring is active?
- What metrics distinguish cumulative allocation from peak concurrent state?
- Which topology families expose loop and convergence costs hidden by the random connected graph?
- How does active adversarial branch generation interact with per-peer and per-node token buckets?

## Deployment

- Which properties require fixed-size mixed links, and which survive ordinary encrypted transports?
- Can the protocol operate over QUIC, local mesh links, and mixnet-style scheduled links using separate profiles?
- What operational incentive causes independent nodes to relay, store state, or run directory services?
