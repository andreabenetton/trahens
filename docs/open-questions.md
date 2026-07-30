# Open questions

## Cryptographic review

- Which exact modern URE security definition is sufficient for the C1 eligibility use case?
- Does the GJJS-style construction remain unlinkable under the active modifications available to compromised relays?
- Can `TR-KEM-R255` be proved secure under its additive related-key evolution, or should it be replaced?
- How should malformed-ciphertext timing be equalized without creating a denial-of-service primitive?
- What hybrid or post-quantum construction can preserve universal rerandomization?
- Which independent implementation should cross-check the C1 vectors?

## Codec and depth hiding

- What constant-size CANDIDATE classes support useful maximum depths without excessive padding?
- Should nested candidate layers use one maximum-depth envelope or a small declared class set?
- Which schema language can generate memory-safe parsers in two independent implementations?
- How should version and suite negotiation avoid downgrade and fingerprinting?

## Protocol lifecycle

- What candidate-window duration minimizes cost without discarding useful delayed candidates?
- How should route diversity be defined without exposing topology?
- How are routes repaired without repeating a complete discovery?
- Are active route labels single-use, flow-scoped, or reusable until expiry?

## Resource safety

- Which quotas best resist Sybil, rotating-peer, candidate-spam, and distributed fresh-branch attacks?
- What deterministic eviction policy avoids giving an attacker control over surviving routes?
- Can rejection remain non-amplifying without becoming a capacity oracle?
- At what hop/fan-out settings does branch-context amplification become impractical by topology family?

## Traffic privacy

- What minimum mixing batch and release policy gives useful matching resistance at acceptable latency?
- Which observable classes partition the anonymity set?
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
