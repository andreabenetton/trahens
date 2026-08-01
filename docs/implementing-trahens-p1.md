<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Implementing Trahens P1

This is a route map for a second implementation, not a specification. Every
normative statement lives in `spec/`; where this document and a spec disagree,
the spec wins. Its purpose is to make the order of work obvious and to point at
the artifact that settles each question, so that a second implementer spends
their time on the protocol rather than on discovering which file is
authoritative.

A second implementation is the single most valuable thing that can happen to
this protocol right now. One implementation cannot distinguish "the protocol
says this" from "our code happens to do this", and several of the defects
fixed in July 2026 were exactly that confusion.

## The one rule

`spec/protocol-registry-v1.5.json` is the only source of identifiers, widths,
limits, and domain separators. Do not copy constants out of prose, out of this
document, or out of our Rust. Generate them, as we do — `make registry` emits
Python, Rust, and Markdown from that one file, and `tools/check_repo.sh` fails
if any of the three drifts.

## Order of work

Each step is independently testable. Do not proceed until the current step's
vectors pass; every one of them exists so a mistake surfaces before it becomes
a wire problem.

### 1. Registry and codecs, no network

Read `spec/message-codec-m2.md` and `spec/wire-cell-w2.md`. Implement M2
encode/decode and W2 fragmentation.

Check against `spec/p1-conformance-vectors-v1.5.json` and the binary corpus
`spec/p1-conformance-corpus-v1.5.bin` (22 vectors, 1,991 bytes, format
described below). Canonical encodings must round-trip; **noncanonical ones must
be rejected**, and that half matters more. A decoder that accepts a
noncanonical encoding is the classic source of cross-implementation
divergence, and it will not show up in interoperability testing against a
correct peer.

### 2. Transport

`spec/transport-profile-t1.md` and `spec/transport-profile-t2.md`. Fragment
framing, selective ACK, retransmission, and the fixed schedule.

Check against `spec/t1-test-vectors.json` and `spec/t2-test-vectors.json`. Note
what those vectors do *not* pin: the random privacy padding is drawn from the
Python reference's seeded Mersenne Twister, so the recorded body and record
digests test that PRNG, not the protocol. Assert the 32-byte headers, which are
fully determined, and ignore the digests. Our Rust says so at the assertion
site; do the same.

Three T1 behaviours are easy to get subtly wrong, and each caused a real defect
here:

- A duplicate DATA fragment arriving after the message completed must be
  re-acknowledged and **not** redelivered. Without a completion cache, an
  upstream duplicate becomes an invalid lifecycle transition.
- A recovery round is one RTO period, not one poll. Track fragment state
  explicitly; a fragment queued for retransmission but not yet emitted is not
  overdue, or a congested link spends its whole retry budget without putting a
  cell on the wire.
- Retry exhaustion belongs to one transmission. Failing the whole link takes
  down unrelated routes that were making progress.

### 3. Crypto

`spec/crypto-profile-c1.md` and `spec/rendezvous-capability-r1.md`. Check
against `spec/crypto-test-vectors-c1.json` and `spec/r1-test-vectors.json`.

R1 is the mandatory suite. C1 is a network-disabled research suite: implement
it only for vector agreement, and refuse to select it for a live node. See ADR
0038.

### 4. Lifecycle and discovery

`spec/state-machines-v1.5.md`, `spec/invariants-v1.5.md`, and
`spec/event-lifecycle-profile-e1.md`.

Time is a **monotonically increasing local clock**. Use wall clock only for the
three values another process compares: the sealed gateway offer's expiry, the
capability validity interval, and the R1 registration TTLs. Everything else —
branch, offer, ready-hold, and route deadlines — is local and monotonic.

Expiry must run before you process events, not only when your event source
falls idle. Otherwise a peer that keeps sending keeps your expired state alive.

### 5. Resource bounds

`spec/resource-accounting-v1.5.md`. Every ceiling is in the registry.

Count queued **cells**, not messages: the sender ceiling and the fragment
ceiling multiply, so a per-message count does not bound anything. Track branch
and route ceilings separately, or the smaller one silently becomes the only
one that applies.

Remote input must never terminate your node. Malformed, unauthenticated,
over-limit, and invalid-state input are counted drops. Only local I/O, a broken
invariant, or a cryptographic subsystem failure is fatal.

### 6. Fan-out and offer labels

Read `docs/adr/0039-offer-label-derivation.md` before implementing a relay with
more than one child. Each returned offer travels under a label derived from the
child discovery nonce, so a `COMMIT` names one chain rather than a branch. The
nonce is key material as a result: confidential to its hop, never reused.

## Corpus format

`spec/p1-conformance-corpus-v1.5.bin` is:

```text
"TP15"                     magic
u16                        vector count, big endian
  per vector:
    u8                     1 canonical, 0 noncanonical
    u8                     name length
    bytes                  name, ASCII
    u16                    encoding length, big endian
    bytes                  the encoding
```

Every integer is big endian, as everywhere else in this protocol, and the
cursor must land exactly on the end of the file. `tools/generate_p1_conformance.py`
is the generator and `implementation/rust/crates/conformance` the reference
consumer; either settles an ambiguity.

## Proving it works

Run your node against ours, in namespaces on one Linux host:

```bash
cargo build --release --manifest-path implementation/rust/Cargo.toml --locked
sudo implementation/harness/netns-p1.sh --relays 2 \
  --external-endpoint "<your initiator command>"
```

Your command receives exactly the arguments our own endpoint does — see the
launch block in `implementation/harness/netns-p1.sh` for the contract. The run
asserts that every node reclaimed its state, that the exchange completed, and
that every captured packet is a 1,052-byte record.

You are not required to emit our metrics JSON; a node that emits none simply
is not counted. Every node that does emit one must show no leaked state.

Confirm the harness can fail before you trust it passing: point it at a stub
that accepts the arguments and speaks nothing, and check it exits non-zero.

## Acceptance

`spec/p1-prototype-profile-v1.5.md` holds the gate.
`docs/p1-acceptance-evidence.md` maps each line to the job or harness arm that
executes it here, and states what remains open. Source presence is not passing;
the gate is a runtime gate.

## What to tell us

Divergences are the point. Where our implementation and yours disagree, the
spec decides; where the spec is silent, that silence is the finding, and it is
worth more to this protocol than either implementation.
