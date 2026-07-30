# Open questions

## Protocol

- What candidate-window duration minimizes cost without discarding useful delayed candidates?
- Should a later ring cancel earlier relay state or permit bounded overlap until the logical deadline?
- How is route diversity defined without exposing more topology?
- How are routes repaired without repeating a full discovery?
- Are route labels single-use, flow-scoped, or reusable until expiration?
- Should equal-size rings be repeated with fresh randomness before increasing hop limit?

## Resource safety

- Which peer/session quotas best resist Sybil and rotating-peer attacks?
- How should relays estimate the cost of tentative state before responder authentication completes?
- What deterministic eviction policy avoids giving an attacker control over which active routes survive?
- Can rejection behavior remain non-amplifying without becoming a capacity oracle?

## Privacy

- How accurately can relays correlate fresh-ID attempts using timing and overlapping peer sets?
- Can attempt scheduling add jitter without making setup latency unacceptable?
- Is per-hop transformed duplicate suppression practical, or is strict bounded propagation preferable?
- Which service-selector construction avoids exposing a stable destination class to every relay?

## Underlay

- What minimum adjacent-link properties belong to Core?
- Which traffic-analysis defenses are optional profiles rather than mandatory assumptions?
- How are asymmetric and intermittently available links represented?

## Identity and directory

- Is the endpoint address self-certifying, human-resolvable, or both?
- How can a responder prove control of the requested identity without exposing it to every relay?
- Which long-range resolution design avoids stable deterministic lookup tokens?

## Governance

- When will the confidential-versus-CC-BY licensing conflict be resolved?
- Which organization owns protocol identifiers and version allocation?
- What review process is required before a security claim changes from hypothesis to guarantee?
