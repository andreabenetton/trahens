<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0042: Link epoch strategy across restarts

## Status

Accepted in part, amended by ADR 0043. The key-derived epoch (option C) stands
as the mechanism. The persistent high-water check (option A as a detector) is
**dropped**: once every session derives its own keys, a repeated epoch under
different keys is harmless, and a repeated epoch under the same keys requires
the same ephemerals, which is an RNG failure that now fails closed. A detector
would guard against nothing the keys do not already cover.

Originally proposed to supply the explicit evaluation
`network-bootstrap-b1.md` section 9 requires before B1.1 can specify an epoch
mechanism.

## Context

W2's construction is sound within one correctly managed epoch. Its guarantees
rest on one precondition: `(directional key, epoch, sequence)` never repeats.

P1 cannot enforce that. `LinkConfig` receives a base key and a 32-bit epoch from
configuration, the receiver builds a fresh `ReplayWindow` for whatever epoch it
is handed, and the sender picks a random 32-bit starting sequence. Restarting
two nodes on the same key and epoch therefore resurrects a replay window that
has forgotten everything, and gives the sender a fresh draw from a sequence
space it has already used part of. The external review raised this as TR-02, and
`p1-prototype-profile-v1.7.md` now states it as an operating precondition that
nothing checks.

Two facts constrain the options.

The epoch is 4 bytes and public: it is the first field of every cell header, so
it is visible to any observer of the link, and its width is fixed by the
registry (`widths_bytes.link_epoch`). Changing that width is a wire change.

The starting sequence is drawn from the low 32 bits, deliberately, to leave
headroom below the wrap guard. So within one epoch two runs can overlap in
sequence space with probability far above negligible — birthday collisions over
2^32 with a few thousand cells per run are not remote. The epoch, not the random
start, is what is supposed to separate runs.

B1 section 9 names three candidate mechanisms and requires each to be evaluated.

## Options

### A. Persistent counter

Each node stores the highest epoch it has used per peer and increments on
start.

*Failure modes.* Requires durable storage on a path that currently has none,
which is a new dependency for a prototype whose whole point is that it runs from
configuration. Storage loss, rollback from a snapshot or backup, container
images started from the same base layer, and cloned VMs all silently reintroduce
the reuse this is meant to prevent — and do so in exactly the deployments most
likely to be automated. A corrupted or unwritable counter needs a fail-closed
path of its own, or it degrades to the current behaviour.

*Strengths.* Monotonic by construction when the storage assumption holds, and
cheap to verify locally. It is the only option that can also detect the hazard
rather than merely making it unlikely: a node can refuse to start into an epoch
at or below its recorded high-water mark.

### B. Random epoch

Each node draws a fresh 32-bit epoch per session.

*Failure modes.* 32 bits is too narrow to rely on. At a few hundred sessions the
birthday probability of a repeat is already around 10^-5 and grows quadratically;
for a long-lived deployment with automated restarts this is not a margin, it is
a schedule. Worse, a repeat is silent and indistinguishable from normal
operation, so nothing surfaces it. And because both ends must agree on the
epoch, a randomly drawn one has to be negotiated, which means it cannot be
established before the handshake that the epoch is supposed to protect.

*Strengths.* No persistent state. Acceptable only if the epoch width grows,
which is a wire change.

### C. Key-derived epoch

Derive the epoch from the session key material established by the B1 handshake,
e.g. truncating a KDF output over the handshake transcript.

*Failure modes.* Only as unique as the handshake transcript. A handshake that
can be replayed, or that admits a fixed nonce, produces a repeated epoch — so
this option moves the uniqueness obligation into the AKE rather than discharging
it. Truncation to 32 bits reintroduces the birthday bound of option B unless the
transcript already guarantees freshness, in which case the epoch is carrying no
weight of its own.

*Strengths.* No persistent state, no separate negotiation, and it binds the
epoch to the session that owns it. If the handshake guarantees a fresh
contributory transcript, epoch uniqueness follows from handshake freshness
rather than being an independent assumption.

## Recommendation

**Adopt C as the mechanism and A as the check**, once B1.1 exists.

The epoch should be derived from the B1 handshake transcript, so uniqueness
follows from a property the AKE already has to provide, rather than from durable
storage the prototype does not have. Fresh traffic keys per session are what
actually retires this hazard: once every session derives its own directional
keys, epoch uniqueness becomes defence in depth rather than the only thing
standing between a restart and nonce reuse. That is the framing the review
reached and it is the right one.

Option A is still worth implementing, but as a detector rather than the
mechanism: a node that records its high-water epoch per peer can refuse to start
into a used one and say why. Storage loss then degrades to today's behaviour
instead of to something worse, which is an acceptable failure mode for a check
that is not load-bearing.

Option B is rejected at the current width. It would need a wider epoch field,
which is a wire change, and it would still fail silently.

## Consequences

Nothing changes until B1.1 specifies the handshake, because C depends on a
transcript that does not exist yet. Until then the precondition in
`p1-prototype-profile-v1.7.md` stands, and it is an operator obligation.

This ADR deliberately does not implement option A now. A high-water check would
close part of the gap, but adding durable per-peer state to the prototype ahead
of the handshake that will supersede it risks building a mechanism whose failure
modes then have to be maintained alongside the real one. If the hazard needs
mitigating before B1.1 lands, that is a separate decision and this ADR should be
superseded rather than quietly extended.

One related defect was fixed independently of this choice: the sender's starting
sequence fell back to zero when randomness was unavailable, which turned an RNG
failure into guaranteed nonce reuse. It now fails closed.
