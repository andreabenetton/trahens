<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Review 0012 - T1 reliability and scheduled cells

- Date: 2026-07-30
- Scope: hop-local recovery, fixed-size ACK and CHAFF frames, retry privacy, scheduler trace, formal paper
- Result: active experimental baseline accepted for Core v1.1

## Changes

1. Added a concrete T1 codec with equal-size encrypted DATA, ACK, and CHAFF records.
2. Added a cumulative 32-bit selective ACK bitmap for the current maximum of 17 fragments.
3. Added bounded RTO estimation, Karn-style RTT sampling, exponential backoff, and finite recovery rounds.
4. Required new link sequence numbers, random padding, tags, and ciphertexts for every retry.
5. Added round-robin fragment interleaving and fixed-schedule or work-conserving release.
6. Added a deterministic route-setup model covering DISCOVER, CANDIDATE, COMMIT, and READY across 2, 5, 8, and 12 hops.
7. Added fixed-schedule trace-equivalence experiments and explicit CHAFF bandwidth accounting.
8. Added Core v1.1, T1, message, state-machine, invariant, resource, ADR, threat-model, and traceability updates.
9. Added deterministic T1 DATA, retry, selective-ACK, and CHAFF conformance vectors.
10. Expanded the paper with point-of-use citations to RFC 6298, RFC 6675, RFC 9002, TARANET, and Loopix.

## Reliability result

Each row in `reports/iteration-0012-t1-reliability.csv` contains 30 deterministic runs. Under two percent independent cell loss:

| Hops | W2 without recovery | T1 selective recovery | T1 fixed schedule |
|---:|---:|---:|---:|
| 2 | 83.3% | 100% | 100% |
| 5 | 60.0% | 100% | 100% |
| 8 | 63.3% | 100% | 100% |
| 12 | 26.7% | 100% | 100% |

At five percent loss, unrecovered W2 reached 0% at twelve hops, while both T1 modes reached 100%. At ten percent loss, T1 selective recovery reached 96.7% at twelve hops and fixed scheduling reached 93.3%; all shorter tested paths reached 100%. Three recovery rounds were permitted.

The W2 and T1 latency models use different release rules, so cross-profile latency is not treated as a direct performance comparison. T1 results are used to assess delivery, retry amplification, cleanup, and schedule cost.

## Scheduling result

For every tested route depth, active and empty fixed-schedule runs had:

- identical per-direction cell counts;
- zero inter-arrival coefficient of variation;
- the same 1,052-byte record size.

The schedule cost is substantial. For the 12-hop fixed epoch, active route setup used 106 real DATA/ACK cells and 14,798 CHAFF cells in the zero-loss trace-equivalence run. This is an explicit bandwidth reservation, not a free privacy property.

## Security interpretation

- Passive ciphertext equality does not reveal retries because each emission has a new sequence, padding, tag, and ciphertext.
- The authenticated adjacent peer necessarily links retries through the local transmission identifier.
- The identifier and ACK state terminate at the relay and never enter the forwarded M2 message.
- Fixed scheduling hides slot class only within a pre-existing non-overflowing schedule epoch.
- Schedule origin, end, rate, direction, topology, congestion changes, and global cross-link timing remain observable.
- No global traffic-flow unlinkability claim is made.

## Validation

The added tests cover:

- equal-size DATA, ACK, and CHAFF records;
- fresh retry padding and ciphertext;
- invalid ACK bitmap rejection;
- a deterministic loss case repaired by T1;
- bounded retry exhaustion under total loss;
- deep fragmented candidate recovery;
- fixed-schedule equivalence for active and empty traffic.

All transport and route state is reclaimed in the tracked experiments. The complete deterministic suite contains 99 tests.
