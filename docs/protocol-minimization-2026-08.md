<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Protocol minimization review, August 2026

- Scope: the mandatory P1 path (U1 + E1 + R1 + M2 + W2 + T1 + fixed T2/P1)
- Question asked of every mechanism: what breaks if it is **deleted**?
- Standing constraint: this review proposes no new mechanism, and no change
  that would alter a frozen vector or the v1.5 registry is taken here.

## Why this exists

An assessment of v1.5 judged the combined state space large enough to be a
risk in itself: interoperability divergence, unexpected event ordering, side
channels, and audit cost all grow with it, and every component has a
defensible individual justification. The recommendation was to freeze feature
growth. This is the complement of that: an attempt to shrink.

Verdicts are **Remove** (no wire or registry impact, actionable now),
**Defer** (justified, but needs a registry or wire revision, so v1.6), or
**Keep** (load-bearing, with the reason).

## Findings

### 1. `state_machine::Action` — Remove

`RouteTable::apply` computes a six-variant `Action` and returns it. No caller
outside the crate ever reads it: all three binaries call `apply` and test only
`.is_err()`. The enum is constructed, returned, and dropped on every state
transition in the system.

What breaks: nothing on the wire or in the registry. The crate's own tests
assert on `Action` values and would move to asserting on `Phase` instead.

The one real loss is documentary. `StoreCandidate`, `ReserveRoute`,
`ActivateRoute`, `OpenRendezvous`, `DeliverData`, and `ReclaimState` are the
names E1 gives the effects of each transition, so the enum reads as an
executable restatement of the specification. That is worth something — but it
is worth it only if something executes it, and nothing does. A comment on each
transition arm carries the same information without a public type that implies
callers are expected to dispatch on it.

**Action: remove, and simplify `apply` to `Result<(), StateError>`.**

### 2. Five error identifiers that no node emits — Defer to v1.6

`ERROR_UNSUPPORTED_VERSION`, `ERROR_UNSUPPORTED_PROFILE`, `ERROR_REPLAY`,
`ERROR_EXPIRED`, and `ERROR_CANCELLED` appear nowhere outside the generated
registry. The conditions they name are all detected — they are simply reported
as something else: a replay increments `replay_rejections` with no identifier,
and a version or profile mismatch becomes `Malformed` inside `decode_frame`.

So the registry defines a failure taxonomy the implementation does not honour.
That is worse than an unused constant, because the taxonomy is what an
operator or a second implementer would reasonably code against.

This cannot be settled here: error identifiers reach the wire through
`RendezvousResult.status`, so removing five of them is a registry revision,
and wiring them up changes what a node reports. Both are v1.6 decisions.

**Recommendation: in v1.6, either emit them or delete them. Do not leave a
declared taxonomy unhonoured.** — **done**, by emitting them. No registry
change was needed: the identifiers stay local, since Core section 8 requires
externally uniform failure behaviour and `RendezvousResult.status` remains the
only place one crosses a link.

### 3. `MessageType::Abort` — Defer to v1.6

No node emits `ABORT`. Every handler that accepts it treats it exactly as
`CANCEL`, mapping both to `Event::CancelAccepted`, in all three binaries and in
the event-precedence table. It costs a wire code point and a set of match arms
that our own nodes can never exercise.

Either `ABORT` means something `CANCEL` does not — an unrecoverable teardown
distinct from an orderly one, which would need distinct handling and a reason
code — or it should be merged into `CANCEL`. Today it is a synonym.

**Recommendation: merge into `CANCEL` in the next wire revision unless a
distinct semantic is defined and implemented.** — **superseded, and this
finding was wrong.** Checking the spec before acting on it shows the condition
is met: `messages-v1.5.md` separates CANCEL as advisory, CLOSE as orderly, and
ABORT as failure teardown, and E1 has a relay that cannot reserve capacity
release what it holds by abort. ABORT is not a synonym by design; it was a
synonym because it was never implemented. It now is, and a relay that cannot
honour a COMMIT returns it instead of dropping the message.

### 4. `expiry_class` — Defer to v1.6, and it is the most interesting one

Every P1 control message carries `expiry_class`. Both the Rust codec and the
Python reference validate exactly one property: that it is non-zero. Nothing
then reads it. Deadlines come from `Phase::lifetime_ms()` and the registry's
per-class TTLs, not from the wire.

So it is remote-supplied input that is parsed, bounded only away from zero,
and ignored. That is not a vulnerability — an ignored field cannot do harm —
but it is precisely the shape a minimization review should surface: a field
whose only current function is to be present.

Two coherent futures, and the present state is neither:

- **It means something.** Then P1 must map each class to a deadline, bound the
  set, and reject unknown classes.
- **It does not.** Then P1 should pin it to 1 and reject anything else, which
  costs one comparison and removes an unvalidated degree of freedom.

Pinning it is a validation tightening rather than a format change, but it
would reject encodings the current reference accepts, so it needs the
conformance corpus regenerated and both codecs changed together.

**Recommendation: pin to 1 for P1 in v1.6 unless a second class is
specified.** — **done**, registry 1.5.2. `limits.expiry_class_p1` is the single
source, both codecs reject anything else, `spec/message-codec-m2.md` states it,
and ten new negative corpus vectors cover it. Regenerating found that
`generate_t1_vectors.py` had been emitting a CANDIDATE with class 3: a
published vector encoding a message no conforming node may send, which is the
incoherence the pin removes.

### 5. `Discover.options` — rename, do not delete

`options` carries the hop depth and is used as such (`depth =
options.saturating_add(1)`). The field is needed; the name suggests a bitfield
and mismatches every use. This is a documentation defect that will mislead a
second implementer.

**Recommendation: rename to `depth` in the next registry revision.** —
**done**, and no registry revision was needed: `options` was never a registry
key, only a struct field and a spec table row. The byte layout is unchanged.

### 6. Fixed-T2 ACK and retransmit reserves — Keep

Both are read on every slot decision and both are load-bearing: without them
ACKs drain unconditionally and starve DATA, which is the behaviour that
predated the current slot selector.

### 7. `Phase` and `Event` variants — Keep

All five phases and all eight events are reachable, exercised, and covered by
tests. `PendingReady` earns its place specifically: it is what makes a relay
refuse application data between `COMMIT` and `READY`.

### 8. `RemoteInputDrops` detail labels — Keep

Local telemetry strings, not protocol surface. They cost nothing at the wire
and are the only thing that makes a drop diagnosable.

## Surface added by the July 2026 fix series

A minimization review that only examines other people's mechanisms is not
worth much. The fan-out correction added three lookup maps to the relay:

- `reverse: label -> parent branch`
- `tentatives: our selector -> (parent, child, child selector)`
- `incoming: reserved offer label -> (parent, child, index)`

`incoming` is a strict superset of what `reverse` provides for the keys they
share, and the two are consulted in sequence on adjacent code paths. The key
sets differ today — `reverse` holds child labels minted at `DISCOVER` and
child selectors learned when an offer returns, `incoming` holds labels derived
from the child discovery nonce — so they are not trivially interchangeable.

**Recommendation: consolidate into one map from label to a
`Child | Offer` enum.** — **done**. One `labels` map holds a `LabelBinding`
that is either `Branch` or `Offer`; three call sites lost an argument and the
candidate path stopped registering a label it had just resolved out of the
other map. The fan-out arm ran 8/8.

## What was considered and left alone

Fan-out itself, the offer-label window, per-transmission retry state, and the
cell budget were all examined for removal. Each is the direct fix for a
defect an external review found, each has a CI arm or test that fails without
it, and none is redundant with another mechanism. Removing them would restore
known bugs.

## Summary

| # | Candidate | Verdict |
|---|---|---|
| 1 | `state_machine::Action` | Remove now |
| 2 | Five never-emitted error identifiers | **Done** — emitted, locally |
| 3 | `MessageType::Abort` | **Done** — implemented; the finding was wrong |
| 4 | `expiry_class` | **Done** — pinned to 1, registry 1.5.2 |
| 5 | `Discover.options` | **Done** — renamed |
| 6 | Fixed-T2 reserves | Keep |
| 7 | `Phase` / `Event` variants | Keep |
| 8 | `RemoteInputDrops` labels | Keep |
| 9 | Relay `reverse` / `incoming` maps | **Done** — one `labels` map |

All nine are now settled. Six changed the code; three were Keep verdicts
confirmed rather than assumed.

The three deferred as "wire decisions needing a v1.6 revision" turned out not
to need one. Emitting the error identifiers keeps them local, implementing
ABORT uses a code point that already exists, and `options` was never a registry
key. Only the `expiry_class` pin cost a revision, to 1.5.2, and only because
tightening validation rejects encodings the old reference accepted.

The lesson worth keeping is that "this needs a wire revision" was an assumption
about the *deletion* branch of each finding. Two of the three were better
served by the other branch — honour it, implement it — and those cost nothing.
A review that only asks what to remove will misjudge which things are surface
and which are unfinished.
