<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# P1 acceptance evidence

- Status: Evidence map for the acceptance gate in `spec/p1-prototype-profile-v1.5.md`
- Registry: 1.6.0 (v1.5 retained; see the note on what that does and does not mean)

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
| the schedule shape claimed by the fixed profile actually held | every arm reports `fixed_trace_valid` per link. It is a slot-occupancy claim with one slot interval as the stated tolerance: no position passed empty and none was filled late enough to displace its successor. Sub-slot lateness is real and reported separately as `worst_jitter_us`, so a tighter tolerance can be judged from the same run |

## Known gaps

These are recorded rather than claimed as passing.

1. **Adaptive T2 is off the mandatory path by choice, not by omission.**
   Nodes do negotiate a rate class when started with `--adaptive-t2`: one end
   of each link proposes, steps are adjacent, hysteresis damps oscillation, and
   the accepted class changes the live slot cadence. A local two-relay run
   negotiates on every link and reports it as `schedule_cells` and
   `rate_class_changes`.

   It is off by default, and it does not run in the mandatory jobs: the P1
   fixed-trace claim is a claim about a constant cadence, so an adaptive run
   must never be cited as evidence for it. That is a statement about which
   *job* may claim what, not a reason to keep adaptation out of CI — an earlier
   version of this document conflated the two. Adaptation has its own job with
   adaptation-specific assertions and no fixed-trace claim, and the harness
   refuses to assert the fixed trace when the adaptive profile is selected, so
   neither job can silently make the other's claim.

   On the mandatory path every link still reports zero SCHEDULE cells, zero
   rate changes, and a valid fixed trace, and those are now asserted rather
   than merely reported. Weighted DRR remains library-only: the fixed profile
   has one DATA class to serve.
2. **C1 is selectable, on the experimental profile only.** The v1.6
   routing-nonce split removed the structural obstacle, and C1 is now wired end
   to end: an initiator encrypts an eligibility marker to a recipient's key,
   relays rerandomise the capsule without learning anything, and only the
   recipient can tell a discovery is for it. Two CI arms cover it — one where
   the gateway is the intended recipient and serves the route, one where it is
   not and declines.

   It is not on the mandatory path and is not claimed to make endpoints
   anonymous. `require_provider` gates on the profile as well as the suite, so
   reaching C1 takes two explicit choices, and the retired C1 v1 and disabled
   C2 k=2 suites stay refused on every profile.

## What retaining v1.5 does and does not mean

The binaries implement **v1.6 only**. `DISCOVER` gained a 32-byte routing
nonce, so a v1.5 encoding does not decode here and a v1.5 peer will not
interoperate.

v1.5's registry, vectors, corpus and markdown are retained, and
`tools/check_repo.sh` regenerates and byte-compares both profiles, so neither
can drift. That makes the frozen v1.5 profile **reproducible** — its artifacts
still follow from their generators — and it does not make it **speakable** by
this code. A dual-stack implementation is out of scope. Anyone checking a
second implementation against v1.5 is checking it against those artifacts, not
against these binaries.

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
worst lateness, worst sub-slot jitter, and whether the fixed-trace claim still
holds),
chaff-to-real ratio, transmissions refused for want of queue cells, dropped
lifecycle and telemetry events, and the ADR-0020 reassembly counters. Each node additionally reports remote-input drops keyed by
registry error identifier, peak occupancy of every bounded state class, and
cleanup latency. The initiator reports candidate count, late candidates,
candidate drops, branches cancelled, and rings opened.
