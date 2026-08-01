<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# D1 evaluation plan

- Status: turns the eight required-evaluation items in
  [`spec/private-directory-d1.md`](../spec/private-directory-d1.md) into
  concrete decisions and experiments. Design and plan only.
- D1 remains non-normative and outside P1. Nothing here changes the frozen
  profile, and no P1 node gains a directory dependency.

## Why this is the load-bearing gap

R1 removes endpoint-specific selectors from active discovery, which is a real
property and is tested. It does not make an endpoint anonymous: an authorized
initiator still has to learn a descriptor, and every question that makes
endpoint anonymity hard moves into that lookup — enumeration, query
linkability, authorization without identification, and collusion between the
directory and the rendezvous gateway.

So Trahens today relocates the hardest part of endpoint discovery rather than
solving it. That is a defensible staging decision, and it is the reason the
project describes itself as a route-discovery and control plane rather than an
anonymity network. It stops being defensible if D1 is deferred indefinitely,
because the unsolved part is the part that carries the anonymity claim.

## Decisions

The strawman lists what a report MUST state. Each item below is the proposed
answer, and the alternative that was rejected.

### 1. Construction and assumption

**Proposal: multi-server information-theoretic PIR over a replicated handle
table, with `k = 2` non-colluding replicas as the baseline and `k = 3`
supported.**

The database is small — one entry per live publisher per epoch — which is the
regime where multi-server IT-PIR is cheapest and where its assumption is the
most honest one available: security rests on non-collusion, which is an
operational property that can be reasoned about and audited, not a
computational assumption that might be revised.

Rejected: single-server computational PIR. It removes the non-collusion
assumption, which is attractive, but its per-query cost over a small database
is dominated by the homomorphic work, and the assumption it substitutes is
harder for an operator to reason about. Revisit if the table grows past the
crossover, which the experiment in item 6 should measure rather than assume.

Rejected as the sole mechanism: OHTTP. It separates source address from
content under a non-collusion assumption but leaves the *query* visible to the
directory. It is retained as a complementary source-address protection, not as
the query-privacy mechanism.

### 2. Replica count and independence

Baseline `k = 2`, with `k = 3` for deployments that want to tolerate one
compromised replica.

Independence must be stated as an operational requirement and, more usefully,
be **checkable**: distinct legal operators, distinct hosting providers,
distinct network origin, and published operator identities. An unverifiable
non-collusion claim is worth nothing, so the report must say how a client can
tell that replicas are independent rather than being asked to assume it.

Failure mode to state plainly: with all replicas colluding, IT-PIR provides no
query privacy at all. This is a cliff, not a gradient.

### 3. Descriptor size, padding, cadence, retention

- Fixed descriptor size per service class, padded. A variable size is a
  selector.
- One epoch length for all publishers. A publisher-specific cadence identifies
  the publisher.
- Publication in padded batches at fixed times, so publication timing does not
  identify who published.
- Retention exactly one epoch past `not-after`, so the table size tracks live
  publishers and nothing else.

The concrete numbers are to be chosen from the measured cost in item 6, not
picked in advance.

### 4. Query and publication timing leakage

The experiment must measure, not argue:

- correlation between a publisher's registration and a client's later lookup;
- whether lookup timing correlates with subsequent R1 discovery on the wire —
  this is the one that ties D1 to the rest of the protocol, because a lookup
  immediately followed by a `DISCOVER` links the two even under perfect PIR;
- whether epoch boundaries create a distinguishable burst.

The third is a known weakness of epoch-based designs and the padded-batch
decision in item 3 exists to address it. It must be verified, not assumed.

### 5. Authorization, revocation, compromise

Authorization is the `K_auth` secret already in the strawman. Three properties
to specify and test:

- **Revocation** is per epoch by non-republication. There is no revocation
  list, because a revocation list is an enumeration surface.
- **Compromise of `K_auth`** gives an adversary every future handle for that
  publisher until it rotates. State the rotation procedure and its cost.
- **Recovery** uses the optional next-epoch data already in the descriptor,
  which must not be usable to link consecutive epochs by an observer who sees
  both ciphertexts.

### 6. Directory–gateway collusion experiment

The decisive one, and the protocol makes no privacy claim against it today.

Setup: a directory replica set and a rendezvous gateway operated by one
adversary, with honest publishers and clients. The adversary sees every
registration and every redemption, plus whatever the PIR scheme leaks.

Measure: how well the adversary links a publisher to the client that reached
it, as a classification problem against a stated base rate, exactly as the
existing T3/T4 evaluations do. Report the classifier and the assumptions; a
transparent classifier that fails is a rejection tool, not evidence of
anonymity.

Expected result, stated in advance so the experiment cannot be read
selectively: **collusion is expected to be devastating.** The gateway learns
which capability was redeemed and when; the directory learns which handle was
fetched and when. The purpose of the experiment is to quantify how much
independence is worth, and to establish whether padding and batching move the
number at all.

### 7. Enumeration, replay, rollback, equivocation, denial of service

- **Enumeration**: handles are HKDF outputs over a secret, so the table is not
  walkable, but its *size* leaks the live publisher count. Decide whether to
  pad the table itself.
- **Equivocation**: replicas serving different tables to different clients
  breaks IT-PIR silently. Requires a consistency mechanism — a signed table
  digest per epoch is the cheapest — and this is currently unspecified.
- **Rollback**: a replica serving a stale epoch must be detectable by the same
  digest.
- **Denial of service**: per-client query budgets, which interact with query
  privacy because a budget is per-identity and identity is what D1 hides. This
  tension needs resolving, not noting.

### 8. Source-address and connection linkability

OHTTP or an equivalent oblivious relay for every query, with the relay
operated independently of every replica. Without it, the replica sees the
client's address and the PIR guarantee is irrelevant.

## What has to be built

In dependency order, none of it inside P1:

1. Handle and descriptor derivation with vectors, mirroring how every other
   Trahens component is pinned.
2. A replicated table with a signed per-epoch digest (item 7).
3. A `k = 2` IT-PIR client and replica.
4. The collusion experiment (item 6) as a committed, reproducible report.
5. Cost measurement (item 3) feeding the padding and cadence numbers.

## Honest statement of the outcome

Completing this plan does not make Trahens an anonymity network. It makes the
endpoint-discovery assumptions explicit, measured, and falsifiable, and it
replaces "depends on a private directory that does not exist" with a directory
whose failure modes are known and quantified.

The two questions that would remain, and they are the two the protocol has
always named: resistance to realistic cross-link and global traffic analysis,
and the reply-path composition in
[`crypto-review/reply-path-review-package.md`](crypto-review/reply-path-review-package.md).
