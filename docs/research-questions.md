# Research questions

## Privacy

- What route-position information is learned by one relay, two adjacent colluding relays, and non-adjacent colluding relays?
- In the U1 challenge game, how close does matching success remain to the inverse batch size under realistic cell mixes?
- Which mutable or opaque fields survive transformation and accidentally partition the anonymity set?
- How accurately can observers correlate local ring attempts through timing, origin adjacency, W2 cell count, and relay overlap even without an attempt ID?
- Does scheduling jitter reduce correlation enough to justify added discovery latency?
- Does returning multiple candidates improve route privacy or merely add distinguishable multi-cell traffic?
- Can endpoint lookup avoid a stable directory query token?

## Cryptography

- Which URE construction provides ciphertext anonymity, rerandomization indistinguishability, active-tag resistance, integrity, and acceptable performance?
- Does the additive reply-key tweak construction provide the required key privacy and CCA security under a concrete KEM?
- Can an active relay tag a rerandomized selector or nested candidate capsule and recognize it later?
- Can route depth be hidden through candidate representation or cell scheduling without impractical overhead?
- How should post-quantum migration avoid suite fingerprinting and downgrade?

## Message and cell framing

- Are M1 minimal-varint rules sufficient for deterministic cross-language interoperability?
- What malformed W2 fragment patterns are most effective at exhausting parsing or reassembly resources?
- Which fragment conflict, timeout, and eviction rules are least observable and most robust?
- What cell-count padding distribution provides useful ambiguity for candidate depth?
- Can multi-cell messages be retransmitted or repaired without revealing logical-message identity beyond one link?

## Scalability

- How does branch-context amplification grow with degree distribution, hop limit, fan-out, cyclic structure, responder density, and fragment count?
- Which expanding-ring schedule minimizes expected work under a required success target when branch-local contexts replace duplicate suppression?
- What relay state is necessary for reverse and forward routing, and what can be reconstructed or removed?
- Which path-diversity target provides useful resilience without excessive control traffic?
- How should initiator-local cumulative budgets relate to independent relay-local and reassembly limits?

## Security

- How are long-term endpoint identities or anonymous credentials bound to responder ephemeral keys inside CANDIDATE?
- What is the minimum information required to reject fresh-branch floods, exact cell replays, malformed fragments, and malformed messages before public-key work?
- How does the protocol behave when a relay selectively delays fragments, candidates, or installs inconsistent labels?
- Can an attacker force deterministic eviction of a chosen route or reassembly by controlling branch and fragment timing?
- What is the recovery behavior after relay compromise and state disclosure?

## Simulation

- How do candidate-window length, cell loss, delayed fragments, and cancellation races change policy performance?
- How should late candidates from an earlier local ring be handled when a later ring is active?
- What metrics distinguish cumulative allocation from peak concurrent branch and reassembly state?
- Which topology families expose loop and convergence costs hidden by the random connected graph?
- How does active adversarial branch generation interact with per-peer token buckets and fragment-spray pressure?

## Deployment

- Which properties require fixed-size mixed cells, and which survive ordinary encrypted transports?
- Can the protocol operate over QUIC, local mesh links, and mixnet-style scheduled links using separate profiles?
- What scheduler can interleave fragments while meeting W2 reassembly deadlines and fairness requirements?
- What operational incentive causes independent nodes to relay, store state, or run directory services?
