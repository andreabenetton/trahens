<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# B1 network-bootstrap architecture

## Status

B1 is a **non-normative future architecture profile**. It has no wire identifier
and is not implemented by Core v1.6.

Core P1 starts only after an authenticated graph of adjacent peers already
exists. The current prototype obtains peer addresses, node identifiers, link
epochs, and 32-byte adjacent-link base keys from command-line configuration.
That is a valid test and early-deployment mechanism, but it is static
configuration rather than autonomous Trahens network bootstrap.

B1 records the work required to remove that assumption without expanding P1
itself into a topology, identity, and governance protocol.

## 1. Scope

B1 should define how a node moves from having an underlay network interface to
having one or more authenticated Trahens adjacent links ready for W2, T1, and
T2 traffic.

The intended boundary is:

```text
underlay connectivity
    -> candidate peer discovery
    -> admission and authenticated key exchange
    -> profile and limit negotiation
    -> directional link-key derivation
    -> W2 link ready
    -> P1 route discovery may begin
```

B1 is not the route-discovery protocol. It must not carry endpoint descriptors,
rendezvous capabilities, route labels, or P1 candidate state.

## 2. Goals

A future B1 profile should provide:

1. bounded discovery of candidate adjacent peers;
2. authentication appropriate to the deployment model;
3. replay- and downgrade-resistant link establishment;
4. negotiation of compatible wire, transport, scheduling, and eligibility profiles;
5. derivation of independent directional keys and an initial replay epoch;
6. admission control before expensive state is allocated;
7. explicit rekey, expiry, revocation, and link-teardown behavior;
8. a way to obtain short-lived gateway-service advertisements;
9. a way to obtain authenticated private-directory bootstrap roots;
10. evidence boundaries that distinguish link authentication from anonymity.

## 3. Non-goals

B1 should not claim to:

- hide the physical or underlay adjacency graph;
- solve private descriptor lookup, which remains D1's responsibility;
- provide global Sybil resistance without an explicit trust or economic model;
- make stable public relay identities unlinkable if a deployment chooses them;
- replace IP address assignment, Wi-Fi association, radio neighbor discovery,
  NAT traversal, or other underlay-specific functions;
- establish P1 route anonymity merely because the first link is authenticated.

## 4. Bootstrap inputs

A node must begin with at least one trust or reachability input. B1 should allow
several deployment-specific methods rather than pretending one mechanism fits
all networks:

- a static signed peer manifest;
- one or more DNS or HTTPS seed records;
- a QR code or invitation containing a peer key and address;
- local-link multicast or broadcast discovery;
- a mesh or radio underlay's native neighbor table;
- a federation membership document;
- an operator certificate or pinned trust root.

Each method must state what an observer learns and who can add, remove, or
replace entries.

## 5. Identity and admission models

The identity model is a deployment decision and should be a selectable B1
profile rather than an implicit global assumption.

### B1-Federated

Relays and gateways possess certificates under one or more federation roots.
This gives clear admission and revocation but creates visible administrative
domains and trust anchors.

### B1-Invitation

A joining node proves possession of a short-lived invitation or pairing secret.
This is suitable for private meshes and small overlays but requires secure
out-of-band invitation delivery.

### B1-Opportunistic

A node accepts previously unknown peers under strict rate, resource, and policy
limits. This is the most open model and the most exposed to Sybil and resource
exhaustion attacks. It cannot claim meaningful Sybil resistance without an
additional cost or reputation mechanism.

A deployment may support more than one model, but the selected model and its
trust assumptions must be explicit.

## 6. Candidate-peer discovery

Peer-discovery messages should be small, stateless where possible, and
rate-limited before public-key operations or link allocation occur.

A discovery advertisement may contain:

```text
bootstrap protocol version
short-lived node or service key
supported B1 authentication modes
supported Core and W2/T1/T2 profiles
coarse capacity class
expiry
signature or invitation proof
optional return cookie
```

It must not contain destination descriptors, capabilities, active route labels,
or a stable network-wide discovery identifier.

Stable long-term node identifiers should not be copied into every unauthenticated
advertisement unless the deployment explicitly accepts that correlation.
Short-lived advertisement keys can reduce passive linkability, but they require
a signed or otherwise authenticated transition to the identity used for
admission.

## 7. Stateless admission front end

Before allocating a handshake object, a responder should be able to require a
stateless cookie bound to the observed source address, transport tuple, time
window, and offered parameters.

The cookie is a denial-of-service control, not an identity proof. It should:

- expire quickly;
- be authenticated under a responder secret;
- bind the negotiation transcript offered so far;
- reveal no responder long-term secret;
- avoid creating a reusable tracking token;
- be validated before expensive cryptographic work.

Underlays where source addresses are not meaningful need an equivalent bounded
return-routability mechanism.

## 8. Authenticated adjacent-link handshake

B1 should reuse a reviewed authenticated key-exchange framework, such as an
appropriate Noise pattern or a TLS-derived construction, rather than inventing
a new Diffie-Hellman protocol.

The handshake transcript should bind:

- both presented identities or invitation proofs;
- all supported and selected protocol versions;
- selected W2, T1, T2, and eligibility profiles;
- public resource ceilings and rate classes;
- both nonces and ephemeral key shares;
- the underlay endpoints when the deployment treats them as authenticated;
- the initial link epoch;
- any gateway-service role advertisement.

Negotiation must be downgrade resistant. An attacker must not be able to remove
a stronger supported profile or substitute a retired suite without causing
transcript authentication to fail.

The output should include independently domain-separated keys for:

```text
A -> B W2 encryption/authentication
B -> A W2 encryption/authentication
bootstrap transcript/export authentication
future rekey chaining
stateless reset or authenticated teardown, if defined
```

No P1 route state may be allocated until the adjacent-link handshake and
profile validation complete.

## 9. Link epochs, rekey, and restart

B1 must define how the W2 epoch is chosen and advanced.

At minimum:

- an epoch must not repeat under the same directional key;
- process restart must not silently reuse an old key/epoch/sequence tuple;
- rekey must create fresh directional keys before sequence exhaustion;
- replay windows must reset only when the authenticated epoch transition is accepted;
- old keys and handshake secrets must be zeroized after a bounded overlap;
- failed rekey must fail closed without preserving half-negotiated state indefinitely.

Persistent counters, random epochs, and key-derived epochs each have different
failure modes and must be evaluated explicitly.

## 10. Gateway-service discovery

P1 discovers generic rendezvous gateways through the existing graph, but a
network still needs a way to recognize which peers are willing and authorized
to provide that service.

A B1 gateway advertisement should be short-lived and should contain only
service-level information, such as:

- rendezvous service class;
- short-lived gateway authentication key or pseudonym key;
- supported active and experimental profiles;
- coarse load or capacity class;
- validity interval;
- operator authorization or federation proof.

It must not enumerate registered destinations or capability commitments.
Advertisement rotation must be designed so that it does not accidentally
create a more stable correlation handle than the P1 gateway pseudonym.

## 11. Directory bootstrap

D1 assumes that clients know the directory replicas, their authentication keys,
the current epoch, and the independence assumptions among operators.

B1 should define only how those bootstrap roots are authenticated and updated,
not how private descriptor lookup works. A signed directory-root document may
contain:

```text
document version and validity
replica addresses and public keys
OHTTP relay addresses and keys, where used
current and overlapping directory epochs
supported D1 modes
operator and non-collusion declarations
revocation and next-root information
```

The document itself can reveal which directory federation a client uses. B1
must state that leakage rather than treating authenticated discovery as private
discovery.

## 12. Privacy and security risks

B1 introduces metadata that P1 currently avoids specifying. Evaluation must
include at least:

- correlation through stable node certificates or advertisement keys;
- seed-server observation of joining nodes;
- downgrade and version fingerprinting;
- Sybil saturation of candidate-peer lists;
- resource exhaustion before authentication;
- gateway-advertisement enumeration;
- directory-root substitution and rollback;
- cross-link correlation caused by key or epoch reuse;
- address mobility and NAT rebinding;
- restart behavior and replay after state loss;
- collusion among seeds, relays, gateways, and directory operators.

Authenticated bootstrap does not imply anonymous bootstrap. Some deployment
models may deliberately choose accountability over membership privacy.

## 13. Required bounds

A normative B1 profile must put registry limits on at least:

- unauthenticated advertisements per peer and interval;
- outstanding cookies and handshake contexts;
- public-key operations per source and global interval;
- candidate peers retained;
- simultaneous adjacent links;
- certificate, invitation, and advertisement sizes;
- handshake duration and retransmissions;
- failed authentication attempts;
- rekey overlap and old-key retention;
- gateway advertisements and directory roots retained.

All failure paths must reclaim state without remote cooperation.

## 14. Proposed implementation stages

### B1.0 — Static manifest

Formalize the current prototype inputs as a signed configuration format:
peer IDs, addresses, base keys or pinned peer keys, epochs, profiles, and
resource ceilings. This does not add autonomous discovery, but it removes
ad-hoc command-line duplication and gives multi-host tests one reproducible
bootstrap artifact.

### B1.1 — Authenticated link establishment

Keep peers manually named, but replace pre-shared W2 base keys with a reviewed
authenticated key exchange and explicit profile negotiation. Add restart,
rekey, replay, downgrade, and exhaustion tests.

### B1.2 — Seeded peer discovery

Add signed seed manifests and optional local-link discovery, both feeding the
same bounded candidate-peer cache. Do not mix discovery with admission.

### B1.3 — Gateway and directory roots

Add short-lived gateway-service advertisements and authenticated D1 root
documents. Keep endpoint descriptor lookup outside B1.

### B1.4 — Adversarial evaluation

Test Sybil floods, source spoofing, cookie exhaustion, downgrade, replay,
restart, mobility, malicious seeds, gateway enumeration, and colluding
bootstrap infrastructure on real multi-host networks.

## 15. Relationship to the roadmap

The planned v1.7 multi-host work can start with B1.0 static manifests; dynamic
peer discovery should not block measuring P1 across independently operated
hosts. A reviewed stable protocol, however, should not claim deployable network
bootstrap while relying only on manually copied addresses and symmetric keys.

B1 should remain separate from Core until its identity, admission, and privacy
models have been selected and independently reviewed.