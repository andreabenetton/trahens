# Roadmap

| Revision | Purpose | Gate | State |
|---|---|---|---|
| v1.4.1 | independent review remediation | cryptographic construction and evidence boundaries corrected | Complete |
| v1.5 | first P1 interoperable user-space prototype | Rust nodes, frozen registry/vectors, namespace faults, cleanup | Complete and historical; artifacts remain reproducible |
| v1.6 | selectable experimental paths | routing nonce separated from eligibility; C1 and adaptive T2 selectable with separate gates | Complete and historical; artifacts remain reproducible |
| v1.7 | end-to-end channel and offer hardening | directional route key schedule with counter nonces and per-direction replay window; gateway offer signed over a transcript binding version, suite, reply key, and parameter digest | Complete and historical; artifacts remain reproducible |
| v1.8 | active profile; authenticated adjacent-link establishment | B1.1 Noise `XXpsk0` handshake over X25519 with manifest-pinned static keys, transcript-bound profile negotiation, session-derived directional keys and epoch; rekey chained through an export key, initial handshake keyed from the static-static value | Landed |
| v1.9 | real multi-host deployment | independently operated nodes interoperate across real networks | Planned |
| v1.10 | captured-traffic evaluation | performance and traffic-analysis experiments use real packet traces | Planned |
| v1.11 | discovery and directory integration research | bounded peer discovery, gateway advertisements, and authenticated directory roots are tested without changing P1 semantics | Planned; design starts in B1.2/D1 |
| v2.0 | reviewed stable protocol | wire protocol and security model survive implementation, independent review, multi-host measurement, and explicit deployment assumptions | Blocked on v1.8–v1.11 |

## Active v1.8 focus

Core v1.8 is the profile the current binaries speak. It supersedes v1.7 by
replacing the pre-shared adjacent-link key and configured epoch with the B1.1
handshake: a Noise `XXpsk0` exchange over X25519 between peers that pin each
other's static key, with the profile set negotiated inside the authenticated
transcript. Both directional W2 keys and the link epoch are derived per session,
so the restart hazard v1.7 could only state as an operator obligation is gone —
a node cannot reuse an epoch because it no longer chooses one. A rekey chains
through the previous session's export key; an initial handshake keys the same
modifier from the static-static value the manifest already implies, so a first
message from a sender without that identity is refused before any
Diffie-Hellman and draws no reply.

The protocol version byte becomes `3`. v1.7 peers do not interoperate with
v1.8, and a v1.7 node cannot bring a link up at all, having no handshake to
offer.

v1.7 had itself superseded v1.6 by rebuilding the end-to-end route channel on a
directional key schedule and signing the gateway offer over a transcript binding
version, suite, reply key, and parameter digest. v1.6 had superseded v1.5 by
separating the suite-independent 32-byte routing nonce from the suite-sized
eligibility field, adding 32 bytes to `DISCOVER`. v1.8 keeps both unchanged.

The mandatory path is now B1.1 + U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1.
Adaptive T2 and C1 eligibility are selectable experimental profiles with their
own narrower CI gates. Neither may be cited as evidence for a mandatory gate
line.

The active acceptance checklist is normative in
`spec/p1-prototype-profile-v1.8.md`. Source presence is not equivalent to
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

## Security work retained for v1.8 review

1. obtain an independent multi-user IK-CCA/key-privacy review of reply sealing and nested blinding composition;
2. review the recipient-bound commitment and failure/resource uniformity;
3. translate or extend the bounded R1/E1 models into an adversarial symbolic proof where appropriate;
4. review capability atomicity, replay/expiry, T1 recovery, and fixed-T2 claim boundaries;
5. decide whether C1 should be retained, replaced with a standard anonymous public-key encryption construction, or remain only a research control;
6. keep post-quantum migration classified as a reply-path redesign, not a primitive substitution;
7. obtain a second independent implementation against the v1.8 registry, corpus, and handshake vectors;
8. obtain independent review of the B1.1 instantiation, including the `XXpsk0` rekey chain and the identity exposure inherent in `XX`.

## Network-bootstrap track: B1

P1 starts over a named peer set. Adjacent-link authentication is no longer part
of that assumption — B1.1 landed in v1.8 — but the prototype is still given the
peer list itself: addresses, node IDs, and each peer's pinned static public key.
It therefore demonstrates **route bootstrap over a named peer set**, not
autonomous network bootstrap.

`spec/network-bootstrap-b1.md` records the architecture. The remaining work is
deliberately separated from P1 because peer identity, admission, Sybil
resistance, and underlay discovery are deployment and governance choices with
their own privacy consequences.

The stages are:

### B1.0 — Reproducible static manifest

Replace duplicated command-line topology and key configuration with a signed
manifest format covering peers, addresses, pinned static keys, selected
profiles, and resource ceilings. Partially subsumed by B1.1, which already
requires each peer's pinned static key; what remains is the signed file format.

### B1.1 — Authenticated adjacent-link establishment — **delivered in v1.8**

Noise `XXpsk0` over X25519 between manually named peers, with the presented
static key pinned against the manifest, version and profile negotiation bound
into the transcript, and session-derived directional keys and epoch. A rekey
chains through the previous session's export key; an initial handshake keys the
same modifier from the static-static value the manifest already implies.
`spec/link-handshake-b1.md` is normative;
`docs/adr/0043-b1.1-handshake-decisions.md` records the original decisions,
`docs/adr/0044-authenticating-the-first-handshake-message.md` the later move to
`psk0`, and `docs/b1.1-scope.md` the scope.

Not addressed by B1.1: an authenticated peer — a compromised neighbour, or
anyone holding a static key — can still open exchanges and spend a responder's
bounded per-attempt work, which is what the registry limits cap. And a
deployment that must accept handshakes from peers it has no manifest entry for
cannot use this first-message defence at all, having no static-static value to
key from. B1.2's cookie gate is what covers that case.

### B1.2 — Bounded peer discovery

Add signed seed manifests and optional local-link or underlay-native discovery.
Discovery must feed a bounded candidate cache and remain separate from
admission. Stateless return-routability cookies should precede expensive
cryptographic state.

`docs/b1.2-scope.md` scopes this stage. Two of its findings are worth reading
before the work is planned rather than after. ADR 0044's first-message defence
cannot follow B1.2 unchanged: it rests on a value both peers hold in advance,
and an unknown peer supplies none — so the scope recommends targeting the
invitation model first, where an invitation secret can key it. And four
registry bounds that `link-handshake-b1.md` section 8 records as satisfied by
the topology stop being free the moment a listening socket exists; the scope
puts enforcing them in the first group, ahead of any discovery code.

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