<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# ADR 0047: Durable node state for admission

## Status

Accepted, 7 September 2026. Extends ADR 0046, whose D8 and D9 need state that
outlives a process. Implementation has not started.

## Context

Nothing in this codebase has ever persisted anything. Every node takes its peer
set from the command line and keeps nothing across a restart, which is why the
restart harness works by comparing two independent runs rather than by checking
what a node remembered.

ADR 0046 changed that requirement without meeting it. D8 makes an invitation
single-use, which needs a record of what has been spent; D9 promotes a learned
static key into the manifest and allows its removal, which needs a record of
what has been pinned. The ADR named the failure and left it: *a spent-invitation
list that does not survive a restart re-opens every invitation it was holding.*

That is the shape of TR-02 — a property that holds only while an operator keeps
something true, with nothing enforcing it — which B1.1 was built to eliminate
for link keys. Reintroducing it for admission would be a step backwards taken
deliberately.

## Decisions

**D10 — an append-only log, one record per change, flushed before the change
takes effect.**

Each admission or revocation appends one record and the append is flushed to
disk *before* the handshake it belongs to completes. **The ordering is the
security property, not the format.** A spent marker written after the handshake
completes is a marker a crash can lose, and losing it re-opens the invitation
the handshake just consumed. Any storage shape has to obey that rule; this one
makes it cheap, because appending and flushing one record is the whole write.

Records are length-framed and checksummed so a torn write is recognisable. A
partial record at the tail is what a crash during append looks like, and it is
discarded on load — the change it represents did not take effect, because the
flush had not returned. Damage anywhere before the tail is not a crash artifact
and is handled by D11.

An atomic snapshot rewrite would satisfy the same ordering rule and was
rejected only as the more expensive way to obtain it: every change would cost a
rewrite of the whole store. An embedded key-value store was rejected for
dependency posture — the workspace is libsodium-only against a 1.82 floor, and
the crosscheck crate already had to be moved outside it over exactly that.

Growth is real and unowned: the log grows with admissions and needs compaction
eventually. Prototype scale does not reach it, and a compaction that rewrites
the log has to obey the same ordering rule, so it is deferred rather than
hand-waved.

**D11 — an absent store starts empty; a damaged one fails closed.**

A first run has no store and must work, so absence is not an error. A store
that exists and does not parse means something is wrong that a node cannot
reason about: it does not know what it already spent, and admitting on that
basis is how an invitation gets used twice. It refuses to start and puts the
decision with an operator.

The distinction from D10 matters. A torn record *at the tail* is expected — it
is what a crash during append looks like — and is discarded. A record that
fails its checksum *before* the tail is not explicable that way, and is damage.

Always failing closed, including on absence, was rejected as ceremony that
protects nothing extra. Always starting empty was rejected because it silently
re-opens every invitation an unreadable store was holding, which is the exact
failure this storage exists to prevent.

**D12 — the store path is required for any node that can admit.**

A node offering admission must be given a path and refuses to start without
one. A node that only speaks to manifest peers needs none and is unchanged.

Making it optional with an in-memory default would let a node run admission
with no durable store at all — a precondition nobody enforces, which is what
TR-02 was. Requiring it also means the harness must supply one, so CI exercises
persistence instead of leaving it untested. That matters more than it sounds:
the section 8 exhaustion bounds went untested for as long as they did precisely
because nothing in the harness could reach them.

## Consequences

**The store holds secrets, and not only public values.** Spent invitation
identifiers and pinned static keys are both public — the identifiers are
consumed and the keys are public keys — so that part could be inspected or
backed up freely. But an inviter must retain the secret of every invitation it
has issued and not yet seen used, in order to derive the pre-shared key when
the joiner arrives. Live invitations are therefore secret material at rest, and
the implementation must either hold them in a separate store with its own
handling or treat the whole file as sensitive. This is the first secret this
system writes to disk, and it should not acquire that property by accident.

**A full or unwritable disk becomes a security-relevant failure.** If the
append cannot be flushed, the handshake it belongs to must not complete. An
implementation that logs the write failure and proceeds has re-created the lost
marker this decision exists to prevent.

**The harness and CI grow a store path per admitting node**, and the restart
scenario acquires a second thing to check: not only that epochs differ across
runs, but that a spent invitation is still spent in the second run.

**Compaction is owned by nobody**, as noted in D10. So is what happens when two
processes are pointed at one store; the prototype has no locking, and the
answer for now is that they must not be.
