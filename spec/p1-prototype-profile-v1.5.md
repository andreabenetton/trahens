# Trahens v1.5 P1 prototype profile

## Executables

```text
trahens-endpoint
trahens-relay
trahens-rendezvous
```

All use ordinary connected UDP sockets. QUIC and TCP are outside P1 because they would replace or conceal T1 recovery and scheduling behavior.

## Interoperability path

The minimum harness is Endpoint -> Relay 1 -> Relay 2 -> Rendezvous. A successful run verifies discovery, candidate return, COMMIT, READY, capability redemption, data in both directions, CLOSE, and complete state cleanup.

## Linux harness

`implementation/harness/netns-p1.sh` creates one namespace per process, veth links, addresses and routes, configurable MTU, configurable independent loss/delay/jitter/duplication/reordering, packet capture on every link, optional per-process clock offsets, and one aggregate JSON report. It rejects any captured UDP payload that is not exactly 1,052 bytes.

## Fuzzing

The repository supplies independent positive/negative M2 vectors, deterministic mutation smoke tests in the Rust conformance crate, and `cargo-fuzz` targets for M2 and W2. Fuzz inputs MUST be processed under bounded input and allocation limits; crashes, panics in production decoding, hangs, and unbounded allocation are failures.

## Acceptance gate

P1 is complete only when CI or an equivalent Linux test host demonstrates:

- separately started processes interoperate using the frozen specification;
- all canonical vectors pass and noncanonical encodings fail;
- decoder fuzzing completes without crash or unbounded allocation;
- a 12-relay namespace path establishes, exchanges data, closes, and cleans up;
- 5% independent packet loss is recovered;
- configured burst loss reaches retry exhaustion cleanly;
- capability replay, wrong-gateway use, and expiry are rejected;
- success, cancellation, timeout, and transport failure reclaim all remote state;
- packet captures contain only 1,052-byte W2 records;
- Linux CI builds and tests without manual repository edits.

A source-only revision that has not executed the Rust and namespace jobs MUST report those gates as pending rather than passed.

## Measurements

The harness records setup latency, successful cells/bytes, retransmissions, peak queue, process CPU, maximum resident memory, memory per active route where measurable, redemption latency, cleanup time, chaff-to-real ratio, malformed traffic outcomes, and topology/fault parameters. Divergence from simulator results is a specification-review trigger.
