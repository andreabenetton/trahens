# Open questions

## Cryptographic review

- Which exact modern URE security definition is sufficient for the C1 eligibility use case?
- What replacement eligibility construction prevents the demonstrated persistent ratio tag and selective-failure linking?
- Can `TR-KEM-R255` be proved secure under its additive related-key evolution, or should it be replaced?
- How should malformed-ciphertext timing be equalized without creating a denial-of-service primitive?
- What hybrid or post-quantum construction can preserve universal rerandomization?
- Which independent implementation should cross-check the C1 vectors?

## M1/W2 codec and reassembly

- Which machine-readable schema can generate memory-safe M1 and W2 parsers in two independent implementations?
- Should the 16,384-byte logical-message ceiling and 17-cell limit remain fixed or become negotiated profile parameters?
- How should fragment retransmission work without introducing stable cross-hop identifiers or amplification?
- Which timeout and aggregate-byte policy best resists fragment sprays without penalizing delayed links?
- Should a conflicting duplicate invalidate the complete reassembly context or only the conflicting fragment?
- How should version and suite negotiation avoid downgrade and fingerprinting?

## Cell-count and depth hiding

- Which candidate depths map to one, two, or more W2 cells under realistic descriptors and application offers?
- Should a scheduling profile pad message cell counts to powers of two, fixed transaction classes, or a probabilistic distribution?
- Can fragments be interleaved with CHAFF and unrelated traffic without making reassembly deadlines or fairness impractical?
- Can the nested candidate representation be made sublinear in route depth?

## Protocol lifecycle

- What candidate-window duration minimizes cost without discarding useful delayed candidates?
- How should route diversity be defined without exposing topology?
- How are routes repaired without repeating a complete discovery?
- Are active route labels single-use, flow-scoped, or reusable until expiry?
- Which bounded acknowledgment scheme is appropriate for multi-cell control messages?

## Resource safety

- Which quotas best resist Sybil, rotating-peer, candidate-spam, fragment-spray, and distributed fresh-branch attacks?
- What deterministic eviction policy avoids giving an attacker control over surviving routes or reassemblies?
- Can rejection remain non-amplifying without becoming a capacity oracle?
- At what hop/fan-out settings does branch-context and fragment amplification become impractical by topology family?

## Traffic privacy

- What minimum mixing batch and release policy gives useful matching resistance at acceptable latency?
- Which observable message sizes, cell counts, and timing patterns partition the anonymity set?
- Can batching and chaff avoid exposing queue occupancy under low load?
- What classifier and statistical tests should define traffic-flow unlinkability evidence?

## Identity and directory

- How is a descriptor distributed and refreshed without exposing deterministic lookup tokens?
- How can lookup provide poisoning resistance, replication, selective-denial evidence, and private queries?
- How is long-term eligibility-key rotation represented without making historical destinations linkable?

## Governance

- When will the confidential-versus-CC-BY licensing conflict be resolved?
- Which organization owns protocol identifiers and version allocation?
- What evidence and review process is required before a research claim becomes a deployment claim?
