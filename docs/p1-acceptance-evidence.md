<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# P1 acceptance evidence

- Status: Evidence map for the acceptance gate in `spec/p1-prototype-profile-v1.5.md`
- Registry: 1.5.1

The profile requires that a source-only revision report its gates as pending
rather than passed. Every line below now names the CI job or harness arm that
executes it, so the claim rests on execution rather than on source presence.

## Gate lines

| Gate line | Evidence |
|---|---|
| separately started processes interoperate using the frozen specification | `linux-interop`, direct arm (`--relays 0`) |
| all canonical vectors pass and noncanonical encodings fail | `reference-and-spec` (`check_repo.sh` regenerates and byte-compares every vector) and the `conformance` crate over the 22-vector corpus, plus Rust consumption of the T1, T2, R1, and C1 vectors |
| decoder fuzzing completes without crash or unbounded allocation | `fuzz-run`, both `cargo-fuzz` targets for 120 s each with `-max_len=2048 -rss_limit_mb=2048` |
| a 12-relay namespace path establishes, exchanges data, closes, and cleans up | `linux-interop`, twelve-relay arm |
| 5% independent packet loss is recovered | `linux-interop`, two-relay and five-relay arms. The five-relay arm is the one that matters: the CANDIDATE blob crosses the 992-byte fragment payload only from about four relays, so below that every message is a single fragment and selective-ACK recovery of a partial fragment set is never exercised |
| configured burst loss reaches retry exhaustion cleanly | `linux-interop`, burst-loss arm using netem Gilbert-Elliott `20,20`; asserts a node reported exhaustion and that all state was reclaimed |
| capability replay, wrong-gateway use, and expiry are rejected | `linux-interop`, replay, unregistered-capability, and expired-capability arms, plus the R1 vector tests in `rendezvous-r1` |
| success, cancellation, timeout, and transport failure reclaim all remote state | `linux-interop`: the direct arm for success, the NO_CANDIDATE arm for cancellation, the expired-capability arm for timeout, and the transport-failure arm for T1 exhaustion. Every arm asserts `live_routes == 0` on every node. The fan-out arm covers cancellation of a subtree the initiator did not select |
| packet captures contain only 1,052-byte W2 records | `tools/check_pcap_cells.py` runs in every arm, including the fan-out topology |
| a fanned-out branch commits the chain the initiator selected | `linux-interop`, fan-out arm: two gateways answer through one relay, the initiator selects one, and the arm asserts the relay released the other subtree and that its gateway observed the cancellation |
| Linux CI builds and tests without manual repository edits | all seven jobs green at head |
| the schedule shape claimed by the fixed profile actually held | every arm reports `fixed_trace_valid` per link, which goes false if any slot was missed |

## Known gaps

These are recorded rather than claimed as passing.

1. **Adaptive T2 is codec-only.** The SCHEDULE frame, the rate menu, and
   weighted DRR are implemented and tested as libraries, but no node
   negotiates a rate class and the live slot selector still runs the fixed
   profile, so the P1 fixed-trace claim is unchanged. The cell budget is no
   longer in this category: every link now reserves a transmission's whole
   fragment set against the per-peer and node-global ceilings before its first
   emission.
2. **C1 is library-only.** The URE capsule, endpoint identity, and eligibility
   provider exist so the published C1 vectors can be checked from Rust and so
   the suite interface has a second provider. C1 remains network-disabled per
   ADR 0038 and is never emitted on the P1 wire.

## Closed since the first revision

**Off-route subtree cancellation under fan-out** was recorded here as an open
gap, on the reasoning that COMMIT named the branch but not which child
answered and that `open_candidate_chain` already computed
`first_forward_label` for the purpose. That second claim was wrong: a relay
passes its own parent label as `forward_label`, so the field only ever held
the initiator's own branch token and could not have disambiguated anything. It
has been removed.

Each returned offer now travels under a label derived from the discovery nonce
the parent replaced for that child, which both ends can compute and no
observer can link. COMMIT therefore names one chain, the relay activates that
child and cancels its siblings, and `netns-fanout.sh` asserts it. The
derivation, and the confidentiality and freshness the nonce must now have as
key material, are recorded in `docs/adr/0039-offer-label-derivation.md`.

## Measurement coverage

Each node reports, per link: cells and bytes, malformed and replay counts,
logical messages, transmission failures, dropped and coalesced ACKs, peak queue
depth, fixed-schedule slot classes and overrun (late slots, missed slots,
worst lateness, and whether the fixed-trace claim still holds),
chaff-to-real ratio, transmissions refused for want of queue cells, dropped
lifecycle and telemetry events, and the ADR-0020 reassembly counters. Each node additionally reports remote-input drops keyed by
registry error identifier, peak occupancy of every bounded state class, and
cleanup latency. The initiator reports candidate count, late candidates,
candidate drops, branches cancelled, and rings opened.
