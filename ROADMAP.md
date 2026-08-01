# Roadmap

| Revision | Purpose | Gate | State |
|---|---|---|---|
| v1.4.1 | independent review remediation | cryptographic construction and evidence boundaries corrected | Complete |
| v1.5 | first P1 interoperable user-space prototype | Rust nodes, frozen registry/vectors, namespace faults, cleanup | Complete and historical; artifacts remain reproducible |
| v1.6 | active profile with selectable experimental paths | routing nonce separated from eligibility; C1 and adaptive T2 selectable with separate gates | Profiles landed; independent review planned |
| v1.7 | real multi-host deployment | independently operated nodes interoperate across real networks using a reproducible B1.0 static bootstrap manifest | Planned |
| v1.8 | captured-traffic evaluation | performance and traffic-analysis experiments use real packet traces | Planned |
| v1.9 | bootstrap and directory integration research | reviewed adjacent-link bootstrap, gateway advertisements, and authenticated directory roots are tested without changing P1 semantics | Planned; design starts in B1/D1 |
| v2.0 | reviewed stable protocol | wire protocol and security model survive implementation, independent review, multi-host measurement, and explicit deployment assumptions | Blocked on v1.6–v1.9 |

## Active v1.6 focus

Core v1.6 is the profile the current binaries speak. It supersedes v1.5 by
separating the suite-independent 32-byte routing nonce from the suite-sized
eligibility field. The wire change adds 32 bytes to `DISCOVER`; v1.5 peers do
not interoperate with v1.6.

The mandatory path remains U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1.
Adaptive T2 and C1 eligibility are selectable experimental profiles with their
own narrower CI gates. Neither may be cited as evidence for a mandatory gate
line.

The active acceptance checklist is normative in
`spec/p1-prototype-profile-v1.6.md`. Source presence is not equivalent to
passing the runtime gate. `docs/p1-acceptance-evidence.md` maps each gate line
to the job or harness arm that executes it.

Completed protocol-engineering items include:

- bounded route and branch lifecycle with monotonic local deadlines;
- hop-local T1 recovery and failure isolation;
- cell-based queue admission and fair fragment service;
- exact fan-out candidate selection and losing-subtree cancellation;
- route-capacity exhaustion handled as admission pressure rather than a process failure;
- separate route and branch counters;
- adjacent T2 rate-class transitions;
- zeroization of route, candidate, routing-nonce, and reply-key material;
- fixed-schedule missed-slot detection;
- separate mandatory fixed-T2, experimental adaptive-T2, and experimental C1 gates.

## Security work retained for v1.6 review

1. obtain an independent multi-user IK-CCA/key-privacy review of reply sealing and nested blinding composition;
2. review the recipient-bound commitment and failure/resource uniformity;
3. translate or extend the bounded R1/E1 models into an adversarial symbolic proof where appropriate;
4. review capability atomicity, replay/expiry, T1 recovery, and fixed-T2 claim boundaries;
5. decide whether C1 should be retained, replaced with a standard anonymous public-key encryption construction, or remain only a research control;
6. keep post-quantum migration classified as a reply-path redesign, not a primitive substitution;
7. obtain a second independent implementation against the v1.6 registry and corpus.

## Future network-bootstrap track: B1

P1 currently starts over an already configured graph. The prototype is given
adjacent peer addresses, node IDs, link epochs, and symmetric base keys. It
therefore demonstrates **route bootstrap**, not autonomous network bootstrap.

`spec/network-bootstrap-b1.md` records the non-normative future architecture.
The work is deliberately separated from P1 because peer identity, admission,
Sybil resistance, and underlay discovery are deployment and governance choices
with their own privacy consequences.

The proposed stages are:

### B1.0 — Reproducible static manifest

Replace duplicated command-line topology and key configuration with a signed
manifest format covering peers, addresses, pinned keys or base keys, epochs,
selected profiles, and resource ceilings.

B1.0 is sufficient for v1.7 multi-host measurement. It makes the existing
assumption explicit and reproducible without pretending the graph is discovered
autonomously.

### B1.1 — Authenticated adjacent-link establishment

Keep peers manually named, but replace pre-shared W2 base keys with a reviewed
authenticated key exchange. Bind version and profile negotiation into the
transcript; derive independent directional keys and a fresh replay epoch; test
restart, rekey, downgrade, replay, and resource exhaustion.

### B1.2 — Bounded peer discovery

Add signed seed manifests and optional local-link or underlay-native discovery.
Discovery must feed a bounded candidate cache and remain separate from
admission. Stateless return-routability cookies should precede expensive
cryptographic state.

### B1.3 — Gateway and directory bootstrap

Define short-lived generic gateway-service advertisements and authenticated D1
root documents. Neither may enumerate destinations. Private descriptor lookup
remains D1's responsibility.

### B1.4 — Adversarial and privacy evaluation

Measure Sybil floods, malicious seeds, downgrade, spoofing, restart/replay,
address mobility, gateway enumeration, stable-identity correlation, and
collusion among bootstrap, directory, and gateway operators on real networks.

A reviewed stable deployment must state its selected B1 identity and admission
model. Authenticated bootstrap is not automatically anonymous bootstrap.

## D1 private-directory track

R1 deliberately removes endpoint-specific selectors from mandatory discovery,
but an authorized initiator still needs a private descriptor. D1 remains a
non-normative strawman and must eventually define:

- the concrete PIR or oblivious-query construction;
- replica and relay independence assumptions;
- fixed descriptor and query sizes;
- publication, lookup, and epoch timing leakage;
- authorization, sharing, revocation, and recovery;
- signed directory-root and equivocation handling;
- directory/gateway collusion experiments.

B1 may authenticate and distribute directory roots, but it must not absorb the
private lookup protocol itself.

## Strategic scope

Trahens is evaluated as privacy-oriented route discovery for decentralized and
path-aware networks such as mesh, delay-tolerant, and policy-aware fabrics. It
is not positioned as a replacement for mature anonymity overlays that already
assume an IP substrate and a public relay directory.

Feature growth on the mandatory P1 path should remain frozen while the project
concentrates on independent implementation, cryptographic review, real
multi-host evidence, D1, and the explicit B1 deployment boundary.