# Open questions

## Protocol

- Should a relay create a random hop label or derive it from an ephemeral public key?
- Is one acknowledgement enough, or should the initiator collect a bounded set of diverse candidates?
- How is route diversity defined without exposing more topology?
- How are routes repaired without repeating a full discovery?
- Are route labels single-use, flow-scoped, or reusable until expiration?

## Underlay

- What minimum adjacent-link properties belong to Core?
- Which traffic-analysis defenses are optional profiles rather than mandatory assumptions?
- How are asymmetric and intermittently available links represented?

## Identity and directory

- Is the endpoint address self-certifying, human-resolvable, or both?
- How can a responder prove control of the requested identity without exposing it to every relay?
- Which long-range resolution design avoids stable deterministic lookup tokens?

## Governance

- When will the confidential versus CC BY licensing conflict be resolved?
- Which organization owns protocol identifiers and version allocation?
- What review process is required before a security claim changes from hypothesis to guarantee?
