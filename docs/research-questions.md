# Research questions

## Privacy

- What route-position information is learned by one relay, two adjacent colluding relays, and non-adjacent colluding relays?
- Under which padding and scheduling profiles can a passive observer correlate discovery with acknowledgement traffic?
- Does returning multiple candidates increase route privacy or only add distinguishable traffic?
- Can an endpoint address be queried without giving the directory a stable lookup token?

## Scalability

- How does discovery cost grow with degree distribution, hop limit, churn, and duplicate suppression?
- What relay state is necessary for reverse and forward routing, and what can be reconstructed or removed?
- Can route discovery avoid dependence on an obfuscated next-hop degree?
- Which path-diversity target provides useful resilience without excessive control traffic?

## Security

- How are long-term endpoint identities bound to ephemeral route setup keys?
- What is the minimum information required to reject replays and malformed floods before public-key operations?
- How does the protocol behave when a relay selectively delays acknowledgements or installs inconsistent labels?
- What is the recovery behavior after relay compromise and state disclosure?

## Deployment

- Which properties require constant-rate links, and which survive ordinary encrypted transports?
- Can the protocol operate over QUIC, local mesh links, and mixnet-style scheduled links using separate profiles?
- What operational incentive causes independent nodes to relay, store state, or run directory services?
