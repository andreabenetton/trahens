<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens, explained in plain language

This document gives a high-level explanation of **Trahens Core v1.5 and its P1 prototype**. It is intended for readers who understand ordinary networking ideas but do not want to begin with cryptographic notation, packet layouts, or state-machine specifications.

Trahens is still a research project. It is best described as:

> **A privacy-oriented rendezvous route-discovery and control-plane protocol for decentralized, path-aware networks.**

It is **not** a complete anonymous communication network, and it is not a replacement for Tor, I2P, or a mixnet.

---

## 1. What problem is Trahens trying to solve?

Before two machines can communicate, the network must normally discover where the destination is and how to reach it.

That discovery process can leak important information:

- who is looking for whom;
- where a destination is located in the network;
- which intermediate nodes form the route;
- identifiers that remain the same across several links;
- timing and traffic patterns that help an observer correlate the route.

Trahens tries to build a route without putting a destination address or another stable destination-specific selector into the active discovery message.

The basic objective is:

> Find a usable path to a rendezvous gateway while ensuring that each relay sees only the information it needs for its own adjacent links.

The endpoint-specific operation happens later, after the route has been selected and authenticated.

---

## 2. The main participants

### Initiator

The node that wants to establish a route.

### Relay

An intermediate node that forwards discovery and control messages. A relay knows its adjacent peers and its own local mapping, but should not learn the complete route.

### Rendezvous gateway

A gateway that can accept a valid one-time capability and begin the destination-side rendezvous procedure.

The discovery process searches for suitable gateways rather than directly searching for the destination.

### Destination

The endpoint or service the initiator ultimately wants to reach.

Before discovery, the destination prepares short-lived capability material and registers commitments at selected rendezvous gateways.

### Private directory

A mechanism through which an authorized initiator obtains the private descriptor needed to contact the destination.

This is a critical part of a complete system, but it is **not yet implemented as a production component**. The experimental D1 document describes a possible direction and makes the missing assumptions explicit.

---

## 3. A postal analogy

Imagine that Alice wants to reach Bob without writing “Bob” on a postcard that every sorting office can read.

Instead:

1. Bob privately gives Alice a short-lived, single-use collection ticket.
2. Bob has previously arranged for selected collection offices to recognize a commitment to that ticket.
3. Alice sends a generic request asking, “Which collection office can help me?”
4. Each sorting office replaces the local tracking number before forwarding the request.
5. Several collection offices may return sealed offers.
6. Alice checks the offers, chooses one exact route, and cancels the others.
7. Only after the chosen route is active does Alice present Bob's private ticket inside the protected route.
8. The collection office consumes the ticket once and begins the final rendezvous procedure.

The analogy is incomplete because real network observers can also study timing, direction, congestion, and packet counts. Trahens explicitly does not claim that the envelope analogy hides all of those signals.

---

## 4. The protocol, step by step

## Step 0: The destination prepares rendezvous material

Before the initiator starts route discovery, the destination:

1. creates a random, short-lived, one-time capability;
2. registers a commitment to that capability at one or more rendezvous gateways;
3. privately gives an authorized initiator a descriptor containing the information needed later.

The active route-discovery message does not contain the capability, its commitment, the destination address, or an endpoint handle.

This separation is important: Trahens P1 discovers a **gateway route**, while the private descriptor identifies the destination relationship outside the active discovery flood.

## Step 1: The initiator sends `DISCOVER`

The initiator opens a discovery branch and sends a `DISCOVER` message to an adjacent relay.

The active R1 discovery contains, among other bounded fields:

- a temporary branch token;
- limits for hop count, fan-out, and lifetime;
- a temporary reply public key;
- a fresh 32-byte discovery nonce.

It does **not** contain destination-specific material.

## Step 2: Every relay replaces the local representation

When a relay forwards the discovery to a child link, it does not simply copy the incoming identifiers.

For every forwarded child, it independently replaces:

- the branch token;
- the discovery nonce;
- the adjacent-link transmission identifier;
- the reply-key representation, by applying a fresh blinding factor.

The relay keeps only a bounded local mapping that lets it reverse the path later.

A simplified view is:

```text
Initiator -- label A --> Relay 1 -- label B --> Relay 2 -- label C --> Gateway
```

`A`, `B`, and `C` are not one globally visible route identifier. Each is meaningful only on its local hop.

The same principle applies to transport recovery: fragment identifiers, ACK state, retry counters, and timers terminate at each adjacent link.

## Step 3: Discovery may fan out

A relay can forward a discovery to several children, within strict limits.

```text
                         -> Gateway 1
Initiator -> Relay -> Relay
                         -> Gateway 2
```

This can produce several candidate routes. Fan-out is bounded so a malicious peer cannot create unlimited branches or state.

## Step 4: Gateways return `CANDIDATE` offers

A rendezvous gateway that accepts the generic discovery creates a candidate offer.

The offer includes protected information such as:

- gateway identity and pseudonym;
- expiry time;
- a route secret;
- a commit challenge;
- the final discovery nonce;
- a signing key and signature.

The gateway encrypts the offer to the final blinded reply key.

As the candidate travels back, every relay adds its own encrypted layer. These layers let the initiator verify that the nonce and reply-key transformations form one continuous route.

An intermediate relay cannot open the complete end-to-end gateway offer.

## Step 5: The initiator validates and selects one candidate

The initiator opens the nested candidate layers and checks:

- that the number and order of layers are valid;
- that every discovery-nonce replacement connects correctly to the next layer;
- that the reply-key blinding chain is valid;
- that the gateway signature is valid;
- that the offer has not expired;
- that no unexpected or noncanonical data is present.

The initiator can receive several valid candidates and choose one according to local policy.

Trahens uses a distinct derived offer label for each returned candidate. This matters under fan-out: `COMMIT` must identify the exact candidate chain selected by the initiator, not merely the larger branch through which several candidates arrived.

## Step 6: The initiator sends `COMMIT`

The initiator sends a `COMMIT` addressed to the selected offer label.

The commit proves possession of the route secret and commit challenge contained in the protected gateway offer.

Each relay:

1. resolves the incoming offer label to one child;
2. activates that child as the selected path;
3. forwards the commit using the child's local label;
4. sends `CANCEL` to losing sibling subtrees.

The losing branches stop rather than remaining active until timeout.

## Step 7: The gateway sends `READY`

After validating the commit, the rendezvous gateway returns an authenticated `READY` message.

The route is now committed and authenticated, but endpoint-specific capability use still has not occurred.

The simplified lifecycle is:

```text
DISCOVERING -> CANDIDATE -> COMMITTED -> READY -> OPEN -> RECLAIMED
```

Only defined events can move a route from one phase to another.

## Step 8: The initiator presents the one-time capability

After `READY`, the initiator sends the destination capability through the active protected route.

The gateway checks that the capability is:

- valid for this gateway and pseudonym;
- not expired;
- not previously used;
- associated with a registered commitment.

Capability consumption is atomic: at most one redemption succeeds.

After successful redemption, the route enters `OPEN`, and the gateway starts the local rendezvous procedure.

## Step 9: Data exchange and cleanup

The P1 prototype can exchange protected data through the active route. When the exchange finishes, `CLOSE` reclaims the route.

The route is also reclaimed after:

- cancellation;
- abort;
- timeout;
- retry exhaustion;
- peer or transport failure;
- process shutdown.

Cleanup is local and does not require the remote peer to cooperate.

---

## 5. How packets travel between adjacent nodes

Trahens separates the meaning of a message from how it appears on one physical link.

### M2: logical messages

M2 defines canonical encodings for messages such as:

- `DISCOVER`;
- `CANDIDATE`;
- `COMMIT`;
- `READY`;
- capability presentation and rendezvous opening;
- `DATA`;
- `CLOSE`, `CANCEL`, and `ABORT`.

“Canonical” means there is one valid byte encoding for a value. Alternative, ambiguous, oversized, or malformed encodings are rejected.

### W2: fixed-size adjacent-link records

Every P1 UDP datagram emitted on an adjacent link is exactly **1,052 bytes**.

Only the link epoch and sequence number are public. The rest of the record is encrypted and authenticated between adjacent peers.

A passive observer can still see that a record was sent, when it was sent, in which direction, and between which adjacent nodes. The observer should not be able to distinguish whether the encrypted record contains data, an ACK, a schedule control, or chaff merely from its size.

### T1: hop-local fragmentation and recovery

A logical M2 message may require several cells. T1 fragments it and recovers loss separately on each adjacent link.

T1 uses:

- selective acknowledgements;
- retransmission of only missing fragments;
- bounded retry rounds;
- interleaving between transmissions;
- fresh sequence numbers, padding, authentication tags, and ciphertext for retries.

An end-to-end transmission identifier is not copied across relays. Each hop has its own recovery state.

### T2: scheduling and chaff

The mandatory P1 profile uses a fixed schedule:

```text
16 cells every 200 milliseconds
one cell every 12.5 milliseconds
```

If no real cell is ready, the sender emits `CHAFF` so the scheduled position is still occupied.

This supports a narrow claim: inside an already established, non-overloaded fixed schedule, an observer sees the same cell positions whether a slot carries data, ACK, control, or chaff.

Adaptive T2 is implemented as an experimental mode. It can negotiate a higher or lower rate by one adjacent rate class at an epoch boundary. It saves chaff under variable load, but the visible rate changes reveal coarse queue activity. Adaptive mode therefore makes no activity-presence privacy claim.

---

## 6. What privacy mechanisms are being used?

### No stable cross-hop routing label

A route is not represented by one identifier repeated on every link. Each relay creates local labels and mappings.

### Discovery nonces are replaced at every hop

The nonce sent to a child is independent of the nonce received from the parent. The candidate return proves that the replacement chain is internally consistent.

### Reply keys are blinded

Each relay changes the reply public key using fresh multiplicative blinding. Candidate layers are encrypted so only the initiator can open the full return chain.

### Destination-specific material is delayed

The discovery flood searches for generic rendezvous gateways. The one-time destination capability is presented only after the selected route reaches `READY`.

### Fixed-size records

DATA, ACK, schedule control, and chaff use the same outer record size.

### Optional fixed cadence

The mandatory profile fills idle schedule positions with chaff, preventing the mere presence of a cell in a scheduled position from proving that real traffic existed.

### Bounded local state

Every branch, route, fragment context, queue reservation, retry sequence, timer, and capability has a finite limit and lifetime.

Resource safety is part of the security design: a privacy mechanism that allows unlimited remote allocation would become a denial-of-service mechanism.

---

## 7. What Trahens does not hide

Trahens does not claim to make communication invisible.

Depending on the observer, the following may still be visible or inferable:

- which nodes are adjacent;
- packet direction and timing;
- schedule start and stop;
- fixed or adaptive public cadence;
- route setup completion;
- congestion, loss, retries, or overload failure;
- correlations caused by propagation delay or shared bottlenecks;
- gateway registration and redemption timing at a compromised gateway;
- private-directory lookups at a compromised directory.

A global observer that sees many links may correlate timing and volume across the route. Fixed-size cells and local label replacement do not by themselves defeat that attack.

Trahens therefore makes **no global traffic-flow unlinkability claim**.

---

## 8. Why the private directory is important

Removing the destination from `DISCOVER` does not remove the need for the initiator to learn something about the destination.

That information must arrive through a private descriptor-distribution mechanism. A complete system must answer questions such as:

- Can an attacker enumerate descriptors?
- Can the directory correlate a user with a lookup?
- What happens if a directory and a gateway collude?
- How are clients authorized without creating stable identifiers?
- How are gateway pseudonyms rotated and revoked?

Until D1 or another independently reviewed directory design exists, Trahens should not be described as a complete endpoint-anonymity system.

---

## 9. What is mandatory and what is experimental?

### Frozen P1 interoperability path

The mandatory v1.5 path contains:

- **U1** — local representation replacement;
- **E1** — route lifecycle and cleanup;
- **R1** — generic gateway discovery and one-time capability redemption;
- **M2** — canonical logical messages;
- **W2** — fixed-size authenticated adjacent-link records;
- **T1** — hop-local fragmentation and selective recovery;
- **fixed T2** — constant scheduled cell positions with chaff.

### Experimental or analytical work

The following are not required for v1.5 interoperability:

- adaptive T2 scheduling;
- T3 multi-link count-trace analysis;
- T4 packet-event and active-probe analysis;
- D1 private-directory design;
- C1 and C2 research cryptographic providers.

C1 is implemented for research and vector comparison but is deliberately blocked from the live P1 network path. The active P1 discovery semantics are built around R1's 32-byte nonce and cannot be converted to C1 by changing a configuration flag.

---

## 10. How strong is the current evidence?

The repository includes:

- a normative protocol registry;
- independently generated positive and negative message vectors;
- Rust implementations of endpoint, relay, and rendezvous gateway;
- fuzz targets;
- Linux network-namespace topologies;
- packet loss, delay, reordering, and burst-loss tests;
- packet capture validation;
- fan-out candidate-selection and cancellation tests;
- measurements for queues, retries, cleanup, schedule timing, and state limits.

This evidence demonstrates that the tested implementation can interoperate and fail in bounded ways under the tested conditions.

It does **not** prove:

- anonymity;
- resistance to every traffic-analysis technique;
- security against a global observer;
- security of the complete directory and gateway system;
- production performance or deployment stability;
- security of the complete cryptographic composition.

Independent implementations, cryptographic review, a concrete private directory, real multi-host testing, and independent traffic-analysis evaluation remain important milestones.

---

## 11. A compact end-to-end picture

```text
Before discovery
----------------
Destination -> selected gateways : register capability commitments
Destination -> Initiator         : privately deliver descriptor/capability

Route discovery
---------------
Initiator -> Relays -> Gateways  : generic DISCOVER, no destination selector
Gateways  -> Relays -> Initiator : signed, nested CANDIDATE offers
Initiator                         : validate offers and select one
Initiator -> selected path       : COMMIT
Relays    -> losing subtrees     : CANCEL
Gateway   -> Initiator           : READY

Rendezvous and use
------------------
Initiator -> Gateway             : present one-time capability
Gateway                           : atomically redeem and open route
Initiator <-> Gateway/path       : protected data exchange
Either side                      : CLOSE and reclaim all state
```

---

## 12. The simplest accurate description

Trahens does not attempt to hide every aspect of communication.

It attempts to make route discovery more private and more disciplined by ensuring that:

- discovery is aimed at generic rendezvous gateways rather than a named destination;
- each relay replaces identifiers and cryptographic representations locally;
- the initiator selects and authenticates one exact returned route;
- endpoint-specific capability use happens only after that route is ready;
- packets have a fixed outer size and can follow a fixed cadence;
- transport recovery and state remain local, finite, and reclaimable;
- the protocol states clearly which anonymity problems remain unsolved.

That is the current contribution of Trahens Core v1.5.

---

## Further reading

Start with these documents after this overview:

1. [`README.md`](README.md) — project status and evidence boundary.
2. [`spec/core-v1.5.md`](spec/core-v1.5.md) — frozen interoperability profile.
3. [`spec/p1-prototype-profile-v1.5.md`](spec/p1-prototype-profile-v1.5.md) — executable P1 acceptance profile.
4. [`docs/threat-model.md`](docs/threat-model.md) — adversaries, claims, and exclusions.
5. [`spec/rendezvous-capability-r1.md`](spec/rendezvous-capability-r1.md) — gateway discovery and capability redemption.
6. [`spec/private-directory-d1.md`](spec/private-directory-d1.md) — non-normative private-directory direction.
7. [`spec/transport-profile-t1.md`](spec/transport-profile-t1.md) and [`spec/transport-profile-t2.md`](spec/transport-profile-t2.md) — recovery, scheduling, and overload behavior.
