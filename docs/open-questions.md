# Open questions

## R1 descriptor and gateway design

- How are descriptors queried without revealing the destination to the directory?
- How are clients authorized without making queries or descriptors linkable?
- Should commitments be replicated, threshold-shared, or registered at independent gateways?
- How are gateway pseudonyms authenticated, rotated, revoked, and protected from enumeration?
- Can a client-bound handshake reduce the race created by a stolen capability?
- How can selective gateway denial be measured or audited without exposing users?

## Retained cryptography

- Can the additive reply-key chain and custom KEM be proved secure under related-key evolution?
- Which transcript fields and key-confirmation step prevent substitution?
- How should malformed-input and timing behavior be normalized without creating a denial-of-service primitive?
- Does an author-confirmed interpretation repair the disabled C2 k=2 transcription?
- Which post-quantum construction preserves acceptable candidate size and route depth?

## T1 recovery

- Should bounded redundancy supplement retransmission for multi-cell candidates?
- How should adversarial ACK suppression, ACK spoofing after peer compromise, and delayed ACKs affect route deadlines?
- Which receiver feedback may influence admission without creating a cross-hop handle?
- Should the 16,384-byte message ceiling and 17-cell limit remain fixed?
- Which eviction policy resists fragment sprays without giving an attacker control over survivors?

## T2 congestion and scheduling

- How are simultaneous OFFERs, lost ACCEPTs, epoch restart, and peer disagreement resolved without cadence ambiguity?
- Can randomized or differentially private class transitions reduce activity leakage at acceptable queue and CHAFF cost?
- How should T2 share capacity between route setup, route maintenance, and future data-plane traffic?
- Which weights are administratively safe, and how are they protected from abuse by authenticated peers?
- What queue-pressure or receiver-feedback signal is robust to burst loss and malicious dropping?
- Can a fixed profile survive overload without visible schedule breaks or unbounded admission delay?
- How should schedule lifetime and rate be established without making the protected activity itself trigger the epoch?

## Multi-link traffic privacy

- Which classifiers and statistical tests define unacceptable linkability evidence?
- How do propagation delay, clock noise, mixed traffic, route churn, shared bottlenecks, and heterogeneous rates change correlation?
- Can fragment-count padding be combined with T2 without excessive amplification?
- Does independent per-link adaptation decorrelate traces or create a new route fingerprint?

## Protocol lifecycle and routes

- How should route diversity be measured without revealing topology?
- How are active routes repaired without repeating full discovery?
- Are active labels flow-scoped, route-scoped, or reusable until expiry?
- How should gateway handoff or endpoint mobility interact with one-time capabilities?

## Governance and deployment

- Which organization allocates protocol, profile, and suite identifiers?
- What evidence is required before a research profile becomes operationally enabled?
- How are relay and gateway admission, Sybil resistance, incentives, and abuse handled?
- When is the licensing position of preserved historical material resolved?
