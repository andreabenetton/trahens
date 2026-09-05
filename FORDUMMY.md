<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens, explained in plain language

This document explains **Trahens Core v1.8 and its P1 prototype** without
requiring the reader to begin with cryptographic notation, packet layouts, or
state-machine specifications.

Trahens is still a research project. The most accurate short description is:

> **Trahens is a privacy-oriented rendezvous route-discovery and control-plane
> protocol for decentralized, path-aware networks.**

It is not a complete anonymous communication network, and it is not a
replacement for Tor, I2P, or a mixnet.

---

## 1. What problem is Trahens trying to solve?

Before two machines can communicate, a network normally has to discover where
the destination is and how to reach it.

That discovery process can leak information such as:

- who is looking for whom;
- where a destination is located;
- which relays form the path;
- identifiers copied across several links;
- timing and traffic patterns that allow different links to be correlated.

Trahens tries to construct a route without putting a destination address or
another stable destination-specific selector into the mandatory active
`DISCOVER` message.

The basic objective is:

> Find a usable path to a rendezvous gateway while ensuring that every relay
> sees only the information required for its own adjacent links.

The endpoint-specific operation happens only after one route has been selected
and authenticated.

---

## 2. What must already exist?

Trahens P1 does **not** currently create a network from nothing.

Before P1 starts, the following must already exist:

- UDP or equivalent underlay connectivity between adjacent nodes;
- the address of each adjacent peer, and that peer's public identity key;
- a configured graph of endpoints, relays, and gateways;
- a destination registration at one or more gateways;
- a private descriptor known to the authorized initiator.

Adjacent-link keys are **not** on that list any more. Since v1.8 the two ends of
a link run an authenticated handshake and derive their own keys from it, so
nothing has to be installed in advance except each side's knowledge of the
other's public identity key. This is what B1.1 added, and it means a node cannot
accidentally restart onto keys it has already used.

The current Rust prototype still receives peer addresses, node IDs, and pinned
peer identity keys from command-line configuration. The test harness creates the
network namespaces, veth links, routes, and identity keys before starting the
nodes.

That is **static network configuration**, not autonomous Trahens network
bootstrap. Knowing which peers exist is still someone else's job.

A future non-normative design, [`spec/network-bootstrap-b1.md`](spec/network-bootstrap-b1.md),
records how peer discovery, admission, gateway-service advertisement, and
directory-root discovery could be added without mixing them into P1. Its
adjacent-link stage is already done; what remains is stage B1.2 onward.

The intended separation is:

```text
underlay connectivity and a known peer set
                    ↓
      B1.1 authenticated adjacent links
                    ↓
          Trahens P1 route discovery
                    ↓
       rendezvous and protected data use
```

---

## 3. The main participants

### Initiator

The node that wants to establish a route.

### Relay

An intermediate node that forwards discovery and control messages. A relay
knows its adjacent peers and its own local mappings, but should not learn the
complete route.

### Rendezvous gateway

A gateway that can return a route candidate and, after route activation, accept
a valid one-time capability for a destination-side rendezvous.

### Destination

The endpoint or service the initiator ultimately wants to reach.

Before discovery, the destination creates short-lived capability material and
registers commitments at selected gateways.

### Private directory

A mechanism through which an authorized initiator obtains the private
descriptor needed to contact the destination.

This is a necessary part of a complete system, but it is not yet implemented as
a production component. D1 is only a non-normative design direction.

---

## 4. A postal analogy

Imagine that Alice wants to reach Bob without writing “Bob” on a postcard that
every sorting office can read.

Instead:

1. Bob privately gives Alice a short-lived, single-use collection ticket.
2. Bob arranges for selected collection offices to recognize a commitment to
   that ticket.
3. Alice sends a bounded request asking which suitable office can help.
4. Every sorting office replaces its local tracking information before
   forwarding the request.
5. Several collection offices may return sealed offers.
6. Alice checks the offers, selects one exact path, and cancels the others.
7. Only after that path is ready does Alice present Bob's ticket inside the
   protected route.
8. The selected collection office consumes the ticket once and begins the final
   rendezvous.

The analogy is incomplete because real observers can also study timing,
direction, congestion, packet counts, and who is physically adjacent. Trahens
does not claim that sealed envelopes hide all of those signals.

---

## 5. What the destination prepares

Before the initiator starts P1 discovery, the destination:

1. creates a random, short-lived, one-time capability;
2. registers a commitment to it at one or more rendezvous gateways;
3. privately gives an authorized initiator a descriptor.

Under the mandatory R1 profile, the descriptor contains the capability,
acceptable short-lived gateway pseudonyms, expiry information, and endpoint
authentication material.

The raw capability does not appear in `DISCOVER`, `CANDIDATE`, `COMMIT`, or
`READY`.

This means P1 discovers a **gateway route** first. It does not directly search
for the destination.

---

## 6. Step 1: the initiator sends `DISCOVER`

The initiator creates a bounded discovery branch and sends `DISCOVER` to one
adjacent relay.

A v1.8 `DISCOVER` contains two different per-hop values:

### Routing nonce

A fresh non-zero 32-byte value used by route discovery itself.

It:

- binds the returned candidate chain to the branch;
- is replaced independently at every relay;
- is used as secret input for deriving per-offer labels.

### Eligibility field

A separate value controlled by the selected eligibility suite.

- Under mandatory **R1**, it is another fresh, non-semantic nonce.
- Under experimental **C1 v2**, it is a 128-byte rerandomizable capsule intended
  for a particular recipient.

The routing nonce and eligibility field were one coupled value in v1.5. Core
v1.6 separated them so route discovery always uses the fixed 32-byte routing
nonce while an eligibility suite can use its own field width.

The mandatory R1 `DISCOVER` contains no destination address, endpoint key,
capability, capability commitment, or endpoint handle.

---

## 7. Step 2: every relay replaces local representations

When a relay forwards a discovery to a child, it does not copy all incoming
identifiers unchanged.

For every child, it independently changes:

- the branch token;
- the routing nonce;
- the adjacent-link transmission identifier;
- the reply-key representation, using a fresh blinding factor;
- the eligibility field according to the selected suite;
- link padding, sequence number, authentication tag, and ciphertext.

For R1, the relay replaces the eligibility nonce with fresh randomness. For C1,
it rerandomizes the capsule without deciding whether the gateway is the
intended recipient.

The relay keeps only a bounded local mapping needed for the return path.

```text
Initiator -- label A --> Relay 1 -- label B --> Relay 2 -- label C --> Gateway
```

`A`, `B`, and `C` are not one network-wide route identifier. Each label is
meaningful only on one adjacent hop.

---

## 8. Step 3: discovery may fan out

A relay may forward a discovery to several children, within strict limits.

```text
                         -> Gateway 1
Initiator -> Relay -> Relay
                         -> Gateway 2
```

Several candidate routes may therefore return.

Fan-out is bounded by registry limits so that a malicious peer cannot create
unlimited branches, queue work, or route state.

---

## 9. Step 4: gateways return `CANDIDATE` offers

A suitable rendezvous gateway creates a candidate offer.

The protected gateway offer includes information such as:

- gateway identity and short-lived pseudonym;
- expiry time;
- route secret;
- commit challenge;
- final routing nonce;
- signing public key and signature.

The gateway encrypts the offer to the final blinded reply key.

As the candidate travels back, every relay wraps it in another authenticated
encrypted layer. Each layer records the parent and child routing nonces and the
reply-key transformation for that hop.

The initiator can verify the complete chain. Intermediate relays cannot open
the final gateway offer.

The v1.8 candidate chain binds the **routing nonce chain**. It does not bind the
eligibility field end to end; that field is transformed hop by hop and protected
on each adjacent W2 link. A future eligibility suite requiring end-to-end field
binding must define it itself.

---

## 10. Step 5: the initiator validates and selects one candidate

For every candidate, the initiator checks:

- the number and order of layers;
- continuity of the routing-nonce replacements;
- the reply-key blinding chain;
- the gateway signature;
- expiry;
- canonical encoding and absence of extra data;
- whether the gateway pseudonym is acceptable under the private descriptor.

The initiator chooses one candidate according to local policy.

Every returned offer has a distinct label derived from the child routing nonce.
This allows `COMMIT` to name one exact route chain even when several offers came
back through the same larger branch.

---

## 11. Step 6: the initiator sends `COMMIT`

The initiator sends `COMMIT` using the selected offer label.

The message proves possession of the route secret and challenge contained in
the protected gateway offer.

Every relay:

1. resolves the offer label to one child;
2. activates that child as the selected path;
3. forwards the commit using the child's local selector;
4. sends `CANCEL` to losing sibling subtrees.

A losing subtree exits cleanly instead of running until expiry.

If a relay cannot honor a commit because state or capacity has disappeared, it
returns `ABORT` rather than silently making the initiator wait for a timeout.

---

## 12. Step 7: the gateway sends `READY`

After validating the commit, the gateway returns an authenticated `READY`.

The route is now selected and authenticated, but the destination capability has
still not been presented.

The simplified lifecycle is:

```text
DISCOVERING -> CANDIDATE -> COMMITTED -> READY -> OPEN -> RECLAIMED
```

Only defined events can move a route between phases.

---

## 13. Step 8: the initiator presents the one-time capability

After `READY`, the initiator sends the destination capability through the
active protected route.

The gateway checks that it is:

- registered at this gateway;
- valid for the expected pseudonym;
- not expired;
- not previously used.

Capability consumption is atomic: at most one redemption succeeds.

After successful redemption, the route enters `OPEN`, and the gateway starts
the destination-side rendezvous procedure.

---

## 14. Step 9: data exchange and cleanup

The P1 prototype can exchange protected data over the open route.

When communication finishes, `CLOSE` reclaims the route. State is also
reclaimed after:

- cancellation;
- abort;
- timeout;
- retry exhaustion;
- peer or transport failure;
- process shutdown.

Cleanup is local and does not require the remote peer to cooperate.

---

## 15. How messages travel between adjacent nodes

Trahens separates the meaning of a message from how that message appears on one
physical link.

### B1.1: bringing the link up

Before any of the machinery below can run, the two ends of a link must agree on
keys. They do this with a short authenticated exchange — three messages, each
padded to the same 1,052-byte size as every other record, so the handshake is
not distinguishable by length from ordinary traffic.

Each side already knows the other's public identity key from configuration.
During the exchange each proves it holds the matching private key, and either
side aborts if the key it is shown is not the one it expected. Both ends then
derive, from the exchange itself:

- one encryption key for each direction;
- the link epoch, a number that separates this session from every previous one;
- a chaining key used if the link later needs fresh keys.

Deriving the epoch rather than configuring it is what makes restart safe. In
earlier versions an operator had to remember to change the epoch whenever a node
restarted, and nothing checked it; now neither side chooses the epoch, so
neither can repeat one.

Two honest caveats. A node answers the first handshake message before it knows
who sent it, which costs it some work — bounded, but not free. And its reply
contains its own identity key, so anyone who can send a first message can learn
which node is listening. Hiding that is a later stage's job.

### M2: logical messages

M2 defines canonical encodings for operations such as:

- `DISCOVER`;
- `CANDIDATE`;
- `COMMIT`;
- `READY`;
- `RENDEZVOUS_OPEN` and its result;
- `DATA`;
- `CLOSE`, `CANCEL`, and `ABORT`.

Canonical means there is one permitted byte encoding for each value. Ambiguous,
oversized, nonminimal, malformed, or trailing encodings are rejected.

### W2: fixed-size link records

Every P1 UDP datagram emitted on an adjacent link is exactly **1,052 bytes**.

Only the link epoch and sequence number are public. The rest of the record is
encrypted and authenticated between adjacent peers.

An observer can still see that a record was sent, when it was sent, its
direction, and the adjacent nodes involved. The observer should not distinguish
DATA, ACK, schedule control, and chaff merely from packet length.

### T1: hop-local fragmentation and recovery

A logical M2 message may require several cells. T1 fragments it and recovers
loss independently on each adjacent link.

T1 uses:

- selective acknowledgements;
- retransmission of only missing fragments;
- bounded retry rounds;
- interleaving between transmissions;
- fresh sequence numbers, padding, tags, and ciphertext for every retry.

Transmission identifiers and recovery state are not copied end to end.

### T2: scheduling and chaff

The mandatory profile uses a fixed schedule:

```text
16 cells every 200 milliseconds
one cell every 12.5 milliseconds
```

When no real cell is ready, the sender emits `CHAFF` so the scheduled position
is still occupied.

This supports a narrow claim: within an already established, non-overloaded
fixed schedule, every slot is occupied regardless of whether it carries data,
ACK, control, or chaff.

Experimental adaptive T2 can negotiate a neighboring rate class at epoch
boundaries. It reduces chaff under changing load, but visible cadence changes
reveal coarse queue activity. It therefore makes no fixed-trace or
activity-presence claim.

---

## 16. What privacy mechanisms are used?

### No stable cross-hop route label

Each relay creates local labels and mappings instead of forwarding one global
route identifier.

### Routing nonces are replaced at every hop

The child routing nonce is independent of the parent routing nonce. The return
chain proves that the candidate followed the branch opened by the initiator.

### Reply keys are blinded

Every relay changes the reply public key using fresh multiplicative blinding.
Only the initiator can open the complete nested return chain.

### Eligibility is separated from routing

The eligibility suite can replace an R1 nonce or rerandomize a C1 capsule without
changing the routing-nonce machinery.

### Destination-specific capability use is delayed

The mandatory discovery flood looks for generic rendezvous gateways. The
one-time destination capability is presented only after `READY`.

### Fixed-size records and optional fixed cadence

DATA, ACK, schedule control, and chaff use the same outer size. The mandatory
fixed profile also fills idle schedule positions.

### Bounded local state

Every branch, route, candidate, fragment context, queue reservation, retry,
timer, capability, and failed-redemption budget is finite.

A privacy mechanism that permits unlimited remote allocation would become a
denial-of-service mechanism.

---

## 17. What Trahens does not hide

Trahens does not claim to make communication invisible.

Depending on the observer, the following may remain visible or inferable:

- physical or underlay adjacency;
- packet timing and direction;
- schedule start and stop;
- fixed or adaptive cadence;
- route setup completion;
- congestion, loss, retries, or overload;
- correlations caused by propagation delay and shared bottlenecks;
- gateway registration and redemption timing at a compromised gateway;
- private-directory publication and lookup timing;
- bootstrap seed access and node admission events;
- stable node identities chosen by a future bootstrap profile.

A global observer may correlate traffic across several links. Fixed-size cells,
local labels, and nonce replacement do not by themselves defeat that attack.

Trahens makes **no global traffic-flow unlinkability claim**.

---

## 18. Why the private directory is still important

Removing the destination from mandatory `DISCOVER` does not remove the need for
an authorized initiator to learn about the destination.

A complete directory design must answer questions such as:

- Can descriptors be enumerated?
- Can a directory correlate a client with a lookup?
- What happens when directory and gateway operators collude?
- How are clients authorized without static public handles?
- How are gateway pseudonyms rotated and revoked?
- How are directory roots discovered and authenticated?

D1 sketches PIR and oblivious-relay approaches but remains non-normative and
unimplemented.

---

## 19. Mandatory and experimental parts

### Mandatory v1.8 interoperability path

- **B1.1** — authenticated adjacent-link establishment with session-derived keys and epoch;
- **U1** — branch-local representation replacement;
- **E1** — route lifecycle and cleanup;
- **R1** — generic gateway discovery and capability redemption;
- **M2** — canonical logical messages;
- **W2** — fixed-size authenticated adjacent-link records;
- **T1** — hop-local fragmentation and selective recovery;
- **fixed T2** — constant scheduled cell positions with chaff.

### Selectable experimental profiles

- adaptive T2 scheduling;
- C1 v2 eligibility.

C1 is now a live experimental path in v1.8. It requires an explicit
experimental profile and an explicit suite choice. It must not be cited as
proof of endpoint anonymity, and its algebraic tagging negative control remains
relevant.

### Analysis and future profiles

- T3 and T4 traffic-analysis experiments;
- D1 private-directory design;
- B1.2 onward: peer discovery and admission design;
- symbolic and disabled C2 research constructions.

---

## 20. How strong is the current evidence?

The repository includes:

- a normative v1.8 registry;
- canonical and noncanonical conformance vectors;
- Rust endpoint, relay, and rendezvous executables;
- fuzz targets;
- Linux network-namespace topologies;
- loss, delay, reordering, duplication, and burst-loss tests;
- packet-capture validation;
- fan-out selection and cancellation tests;
- separate fixed, adaptive, and C1 test arms;
- multi-host and external-implementation harness entry points;
- measurements for queues, retries, cleanup, schedules, and state ceilings.

This shows implementation coherence under the tested conditions. It does not
prove:

- anonymity;
- security against every traffic-analysis attack;
- resistance to a global observer;
- private-directory security;
- autonomous or private network bootstrap;
- production performance and operations;
- security of the complete cryptographic composition.

Independent implementation, independent cryptographic review, real multi-host
measurement, D1, and a reviewed B1 profile remain important milestones.

---

## 21. Compact end-to-end picture

```text
Before P1
---------
Operator                         : configure peer addresses and pinned keys
Adjacent peers (B1.1)            : authenticate and derive link keys
Destination -> selected gateways : register capability commitments
Destination -> Initiator         : privately deliver descriptor/capability

Route discovery
---------------
Initiator -> Relays -> Gateways   : DISCOVER
Relays                            : replace labels, routing nonces, reply keys,
                                    link IDs and eligibility representations
Gateways -> Relays -> Initiator   : signed, nested CANDIDATE offers
Initiator                         : validate and select one exact chain
Initiator -> selected path        : COMMIT
Relays -> losing subtrees         : CANCEL
Gateway -> Initiator              : READY

Rendezvous and use
------------------
Initiator -> Gateway              : present one-time capability
Gateway                           : atomically redeem and open route
Initiator <-> Gateway/path        : protected data exchange
Either side                       : CLOSE and reclaim all state
```

---

## 22. The simplest accurate description

Trahens attempts to make route discovery more private and more disciplined by
ensuring that:

- mandatory discovery is aimed at generic rendezvous gateways rather than a
  named destination;
- each relay replaces routing and transport representations locally;
- routing state is separated from suite-specific eligibility information;
- the initiator validates and selects one exact returned chain;
- endpoint-specific capability use happens only after that route is ready;
- adjacent-link records have a fixed outer size and can follow a fixed cadence;
- reliability, state, and cleanup remain local and bounded;
- the protocol states which privacy, directory, bootstrap, and cryptographic
  questions remain unresolved.

That is the current contribution of Trahens Core v1.8.

---

## Further reading

1. [`README.md`](README.md) — current status and claim boundary.
2. [`spec/core-v1.8.md`](spec/core-v1.8.md) — active interoperability profile.
3. [`spec/link-handshake-b1.md`](spec/link-handshake-b1.md) — mandatory adjacent-link handshake.
4. [`spec/p1-prototype-profile-v1.8.md`](spec/p1-prototype-profile-v1.8.md) — runtime acceptance gate.
5. [`docs/implementing-trahens-p1.md`](docs/implementing-trahens-p1.md) — second-implementation guide.
6. [`docs/threat-model.md`](docs/threat-model.md) — adversaries and exclusions.
7. [`spec/rendezvous-capability-r1.md`](spec/rendezvous-capability-r1.md) — mandatory rendezvous model.
8. [`spec/private-directory-d1.md`](spec/private-directory-d1.md) — directory strawman.
9. [`spec/network-bootstrap-b1.md`](spec/network-bootstrap-b1.md) — remaining bootstrap architecture (B1.2 onward).
10. [`spec/transport-profile-t1.md`](spec/transport-profile-t1.md) and
   [`spec/transport-profile-t2.md`](spec/transport-profile-t2.md) — recovery and scheduling.