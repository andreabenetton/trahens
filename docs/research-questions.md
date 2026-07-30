# Research questions

## Privacy

- What route-position information is learned by one relay, two adjacent colluding relays, and non-adjacent colluding relays?
- How accurately can observers correlate fresh-ID ring attempts from timing, origin adjacency, service metadata, and relay overlap?
- Does scheduling jitter reduce correlation enough to justify added discovery latency?
- Does returning multiple candidates increase route privacy or only add distinguishable traffic?
- Can an endpoint address be queried without giving the directory a stable lookup token?

## Scalability

- How does discovery cost grow with degree distribution, ring schedule, responder density, churn, and duplicate suppression?
- Which expanding-ring schedule minimizes expected work under a required success target?
- What relay state is necessary for reverse and forward routing, and what can be reconstructed or removed?
- Which path-diversity target provides useful resilience without excessive control traffic?
- How should cumulative logical-discovery budgets relate to independent relay-local limits?

## Security

- How are long-term endpoint identities bound to attempt-scoped setup keys?
- What is the minimum information required to reject fresh-attempt floods, replays, and malformed messages before public-key operations?
- How does the protocol behave when a relay selectively delays candidates or installs inconsistent labels?
- Can an attacker force deterministic eviction of a chosen route by controlling attempt timing?
- What is the recovery behavior after relay compromise and state disclosure?

## Simulation

- How do candidate-window length, packet loss, delayed responses, and cancellation races change policy performance?
- How should late candidates from an earlier ring be handled when a later ring is active?
- What metrics distinguish cumulative work from peak concurrent state?
- Which topology families expose failure modes hidden by the current random connected graph?

## Deployment

- Which properties require constant-rate links, and which survive ordinary encrypted transports?
- Can the protocol operate over QUIC, local mesh links, and mixnet-style scheduled links using separate profiles?
- What operational incentive causes independent nodes to relay, store state, or run directory services?
