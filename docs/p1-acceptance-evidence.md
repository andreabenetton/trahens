<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# P1 acceptance evidence

- Status: Evidence map for the acceptance gate in `spec/p1-prototype-profile-v1.7.md`
- Registry: 1.7.0
- Historical registries: v1.6 and v1.5 retained only for reproducibility

The profile requires a source-only revision to report runtime gates as pending
until its Rust and Linux jobs execute. Every gate line below names the job or
harness arm intended to execute it, so source presence is never treated as a
passing result.

## Mandatory gate lines

| Gate line | Evidence |
|---|---|
| separately started processes interoperate using the active specification | `linux-interop`, direct arm (`--relays 0`) |
| all canonical vectors pass and noncanonical encodings fail | `reference-and-spec`: `check_repo.sh` regenerates and byte-compares the 32-vector v1.7 corpus; the Rust `conformance` crate consumes it; Rust also consumes T1, T2, R1, and C1 component vectors |
| decoder fuzzing completes without crash or unbounded allocation | `fuzz-run`, both `cargo-fuzz` targets for 120 seconds with bounded input and RSS |
| a 12-relay namespace path establishes, exchanges data, closes, and cleans up | `linux-interop`, twelve-relay arm |
| 5% independent packet loss is recovered | `linux-interop`, two-relay and five-relay arms; the five-relay arm exercises selective recovery of a fragmented candidate blob |
| configured burst loss reaches retry exhaustion cleanly | `linux-interop`, burst-loss arm; asserts exhaustion occurred and all state was reclaimed |
| capability replay, wrong-gateway use, and expiry are rejected | `linux-interop`, replay, unregistered-capability, and expired-capability arms, plus R1 vector tests |
| success, cancellation, timeout, and transport failure reclaim all remote state | direct, no-candidate, expired-capability, transport-failure, and fan-out arms; every arm asserts `live_routes == 0` on all nodes |
| packet captures contain only 1,052-byte W2 records | `tools/check_pcap_cells.py` in every network arm |
| a fanned-out branch commits the exact chain the initiator selected | fan-out arm: two gateways answer through one relay; the selected chain commits and the other subtree receives cancellation |
| the fixed schedule shape actually held | every mandatory arm requires `fixed_trace_valid`, zero missed slots, zero rate changes, and zero SCHEDULE cells on every link |
| Linux CI builds and tests without manual repository edits | all required jobs must be green for the commit being cited; a source branch is pending until those jobs finish |

The fixed-trace assertion is a slot-occupancy claim with one slot interval as
the declared tolerance: no scheduled position may remain empty or be emitted so
late that it displaces its successor. Sub-slot lateness is separately reported
as `worst_jitter_us`.

## Selectable experimental gates

### Adaptive T2

Adaptive scheduling is selected with:

```text
--schedule-profile adaptive
```

Its CI arm must establish that:

- negotiation occurs on at least one live adjacent link;
- accepted transitions move by one adjacent rate class;
- a stale, rejected, or unanswered negotiation leaves the rate unchanged;
- the selected rate changes the live slot cadence;
- every emitted record remains 1,052 bytes;
- queue, retry, route, and cleanup bounds still hold.

The harness refuses to assert the fixed trace when adaptive scheduling is
selected. An adaptive run therefore cannot be cited as evidence for the
mandatory constant-cadence claim.

Weighted DRR remains primarily a library-level mechanism on the mandatory
fixed path because that path has one new-DATA service class.

### C1 eligibility

C1 v2 is selected with an explicit experimental eligibility choice:

```text
--eligibility-suite c1
```

The positive arm establishes a complete route when the gateway possesses the
intended recipient key. The negative arm gives the initiator another recipient
key and requires the gateway to decline as `not_eligible`, rather than accepting
or treating the well-formed capsule as malformed.

Relays rerandomize the C1 capsule without deciding eligibility. C1 remains an
experimental profile and is not evidence of complete endpoint anonymity. The
retired C1 v1 and disabled C2 k=2 suite must be refused on every live profile.

## Routing-nonce split

The active v1.7 `DISCOVER` carries, unchanged from v1.6:

- one suite-independent 32-byte `routing_nonce`;
- one suite-sized `eligibility_field`.

The routing nonce binds the candidate chain and is the key from which per-offer
labels are derived. The eligibility suite independently replaces an R1 nonce or
rerandomizes a C1 capsule.

Every returned offer travels under a label derived from the child routing nonce.
`COMMIT` therefore names one exact chain rather than only the larger branch
through which several offers may have returned. The nonce is confidential
hop-local key material, never reused, not cloned with route objects, and wiped
when the branch ends.

The candidate chain covers the routing-nonce replacements. It does not cover
the eligibility field end to end; the active core specification states that
boundary explicitly.

## What retaining v1.6 and v1.5 means

The binaries implement **v1.7 only**. The protocol version byte is now `2`, so
v1.6 and v1.7 do not interoperate; v1.6 had already broken with v1.5 when
`DISCOVER` gained the separate 32-byte routing nonce.

The v1.6 and v1.5 registries, vectors, corpora, and generated Markdown remain in
the repository and `tools/check_repo.sh` regenerates and byte-compares them.
This keeps the historical profiles reproducible. It does not make the current
code dual-stack or capable of speaking either.

## Known system-level gaps

The following are recorded rather than claimed as passing:

1. **Independent implementation.** The repository supplies an external codec
   checker and external-endpoint harness path, but a separately developed full
   implementation has not yet established interoperability.
2. **Independent cryptographic review.** Reply-path key privacy and the nested
   multi-user composition remain conditional.
3. **Private directory.** D1 remains non-normative and unimplemented; directory
   enumeration, lookup correlation, and directory-gateway collusion remain
   load-bearing problems.
4. **Autonomous network bootstrap.** P1 starts over manually configured adjacent
   peers and preinstalled link keys. Peer discovery, node admission,
   authenticated key exchange, gateway-service advertisements, and directory
   root discovery belong to the future B1 profile.
5. **Real-network evidence.** Namespace tests execute on one kernel. The
   multi-host harness exists, but independently operated real-network results
   are still required.
6. **Global traffic analysis.** Fixed-size cells and local replacement do not
   establish global traffic-flow unlinkability.

## Measurement coverage

Each node reports, per link:

- cells and bytes;
- malformed, authentication, profile, version, and replay outcomes;
- logical messages and transmission failures;
- dropped and coalesced ACKs;
- peak queue depth and refused reservations;
- fixed-schedule slot classes, late slots, missed slots, worst lateness,
  sub-slot jitter, and fixed-trace validity;
- SCHEDULE cells and rate-class changes;
- chaff-to-real ratio;
- dropped lifecycle and telemetry events;
- reassembly allocations, completions, expiry, overlap, and limit failures.

Each node also reports remote-input drops by stable registry error identifier,
peak occupancy of bounded state classes, and cleanup latency. The initiator
reports candidate count, late and dropped candidates, selected branch, cancelled
branches, and rings opened.

These measurements support implementation and resource claims. They are not an
anonymity proof.