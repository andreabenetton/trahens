# Open questions

## Protocol lifecycle

- What candidate-window duration minimizes cost without discarding useful delayed candidates?
- Should a later local ring cancel earlier branch state or permit bounded overlap until the logical deadline?
- How should late CANDIDATE messages be handled after a route has been committed?
- How is route diversity defined without exposing more topology?
- How are routes repaired without repeating a full discovery?
- Are route labels single-use, flow-scoped, or reusable until expiration?

## Unlinkability and cryptography

- Which universally rerandomizable encryption construction satisfies U1, including malformed-ciphertext and active-tagging behavior?
- Can the reply-key blinding chain be instantiated with a reviewed CCA-secure KEM-DEM construction and a compact proof?
- How is nested candidate return padded without revealing route depth or creating a size class per depth?
- Can exact replay rejection remain link-local without introducing a transferable tag?
- What minimum mixing batch and release policy gives useful matching resistance at acceptable latency?
- Which fields remain observable classes and therefore part of the anonymity-set partition?

## Resource safety

- Which peer and link quotas best resist Sybil and rotating-peer attacks?
- How should relays estimate the cost of tentative state before responder authentication completes?
- What deterministic eviction policy avoids giving an attacker control over which active routes survive?
- Can rejection behavior remain non-amplifying without becoming a capacity oracle?
- At what hop/fan-out settings does branch-context amplification make U1 impractical on each topology family?

## Underlay and traffic profile

- What minimum adjacent-link properties belong to Core?
- Which traffic-analysis defenses are optional profiles rather than mandatory assumptions?
- How are asymmetric and intermittently available links represented?
- Can batching and chaff be coordinated without exposing queue occupancy or creating deadlock under low load?

## Identity and directory

- Is the endpoint address self-certifying, human-resolvable, or both?
- How can a responder prove control of the requested identity without exposing it to every relay?
- Which long-range resolution design avoids stable deterministic lookup tokens?

## Governance

- When will the confidential-versus-CC-BY licensing conflict be resolved?
- Which organization owns protocol identifiers and version allocation?
- What evidence and review process is required before a privacy statement changes from research hypothesis to guarantee?
