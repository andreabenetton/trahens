<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens v1.7 P1 prototype profile

## Executables

```text
trahens-endpoint
trahens-relay
trahens-rendezvous
```

All use ordinary connected UDP sockets. QUIC and TCP are outside P1 because
they would replace or conceal T1 recovery and scheduling behavior.

## Bootstrap boundary

P1 begins after the adjacent graph already exists. Every process is given its
adjacent peer addresses, node identifiers, link epoch, and 32-byte link base
keys by configuration or by the harness.

P1 does not define:

- peer or neighbor discovery;
- node identity enrollment and admission;
- authenticated adjacent-link key exchange;
- link rekey and revocation;
- gateway-service advertisement;
- private-directory root discovery.

The current prototype therefore demonstrates **route bootstrap over a configured
graph**, not autonomous network bootstrap. `network-bootstrap-b1.md` records a
non-normative future architecture. B1 work is not part of the v1.7 acceptance
gate.

### Operating precondition: never restart into a used epoch

Because the link base key and epoch arrive by configuration, W2's guarantees
hold only for as long as the operator keeps `(base key, epoch)` unique across
process lifetimes. A pair of nodes restarted on the same key and epoch begins
with an empty replay window and a freshly chosen starting sequence, so
previously recorded records can authenticate again and a later record can repeat
a nonce under a key that has already used it. Neither is a defect in W2, whose
construction is sound within one correctly managed epoch; both follow from P1
having no mechanism of its own to enforce the precondition.

Until B1 supplies AKE-derived traffic keys per process session, an operator MUST
advance the epoch on every restart, or provision a fresh base key, and MUST NOT
treat epoch uniqueness as something the implementation checks. Nothing in the
acceptance gate detects a violation.

## Interoperability path

The minimum harness is:

```text
Endpoint -> Relay 1 -> Relay 2 -> Rendezvous
```

A successful run verifies discovery, candidate return, COMMIT, READY,
capability redemption, data in both directions, CLOSE, and complete state
cleanup.

## Linux harness

`implementation/harness/netns-p1.sh` creates one namespace per process, veth
links, addresses and routes, configurable MTU, configurable independent
loss/delay/jitter/duplication/reordering, packet capture on every link, optional
per-process clock offsets, and one aggregate JSON report. It rejects any
captured UDP payload that is not exactly 1,052 bytes.

The harness supplies static peer and key configuration before starting the
processes. A multi-host harness may distribute the same static information to
independent hosts; doing so does not change the bootstrap boundary.

## Fuzzing

The repository supplies independent positive and negative M2 vectors,
deterministic mutation smoke tests in the Rust conformance crate, and
`cargo-fuzz` targets for M2 and W2. Fuzz inputs MUST be processed under bounded
input and allocation limits; crashes, panics in production decoding, hangs, and
unbounded allocation are failures.

## Mandatory acceptance gate

P1 is complete for one revision only when CI or an equivalent Linux test host
demonstrates:

- separately started processes interoperate using the active v1.7 specification;
- all canonical vectors pass and noncanonical encodings fail;
- decoder fuzzing completes without crash or unbounded allocation;
- a 12-relay namespace path establishes, exchanges data, closes, and cleans up;
- 5% independent packet loss is recovered;
- configured burst loss reaches retry exhaustion cleanly;
- capability replay, wrong-gateway use, and expiry are rejected;
- success, cancellation, timeout, and transport failure reclaim all remote state;
- packet captures contain only 1,052-byte W2 records;
- Linux CI builds and tests without manual repository edits;
- a fanned-out branch commits the exact chain selected by the initiator and releases the others;
- every fixed-profile link reports a valid slot-occupancy trace, zero missed slots, zero rate changes, and zero SCHEDULE cells.

The mandatory gate is the fixed-T2, R1 profile.

## Selectable experimental gates

Two profiles are selectable but make narrower claims:

- **adaptive T2** — selected by `--schedule-profile adaptive`; negotiation
  occurs on a live link, transitions are adjacent, stale or unanswered
  negotiations leave the rate unchanged, and no fixed-trace claim is made;
- **C1 eligibility** — selected by `--eligibility-suite c1` on the experimental
  profile; a recipient serves a discovery addressed to it and declines one
  addressed elsewhere, while relays rerandomize without deciding.

Neither experimental profile may be cited as evidence for a mandatory gate line
and neither replaces a mandatory arm.

A source-only revision that has not executed the Rust and namespace jobs MUST
report runtime gates as pending rather than passed.

## Measurements

The harness records setup latency, successful cells and bytes,
retransmissions, peak queue occupancy, process CPU, maximum resident memory,
memory per active route where measurable, redemption latency, cleanup time,
chaff-to-real ratio, malformed and refused traffic outcomes, fixed-schedule
jitter and missed slots, adaptive negotiation, and topology/fault parameters.

Divergence from deterministic model results is a specification-review trigger,
not an invitation to tune parameters until the result disappears.