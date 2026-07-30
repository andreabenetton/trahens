# Roadmap

| Milestone | Purpose | Gate | State |
|---|---|---|---|
| M0 Baseline | Preserve and classify the concept | current and historical material are separated | Complete |
| M1 Core semantics | Make bounded discovery unambiguous | independent implementation is possible in principle | Complete baseline |
| M2 Resource safety | Bound abuse and amplification | work, state, bytes, and time are finite | Active |
| M3 Structural unlinkability | Remove stable cross-hop handles | U1 mechanism and claim scope are explicit | Complete research design |
| M4 Event lifecycle | Complete setup and cleanup | races have deterministic bounded outcomes | Complete model |
| M5 Retained crypto baseline | Make reply and authentication operations executable | independent review of retained composition | Review open |
| M6 Message/cell separation | Preserve variable semantics and equal cells | canonical parsing and bounded reassembly | Complete research baseline |
| M7 Active-eligibility audit | Test endpoint-specific cryptographic candidates | failing constructions remain reproducible and disabled | Complete research audit |
| M8 R1 rendezvous profile | Remove unresolved eligibility primitive from active discovery | endpoint capability is absent from DISCOVER and redeemable once after READY | Active baseline complete |
| M9 Private descriptor profile | Hide and authenticate descriptor distribution | lookup and replication have explicit privacy and abuse properties | Planned |
| M10 Reliability profile | Bound multi-cell loss recovery | delivery improves without stable cross-hop handles | Active baseline complete |
| M11 Overlay prototype | Prove interoperability | two implementations agree under faults and churn | Planned |
| M12 Traffic privacy | Measure metadata resistance | every scheduling claim is profile-specific and measured | T1 link-local baseline active |

## Current milestone

Core v1.1 adds T1 hop-local selective recovery and scheduled cells to the R1/M2/W2 route-discovery core. ACK, retry, and CHAFF classes are encrypted inside the same 1,052-byte record. Retries use new sequences, padding, and ciphertexts; transmission identifiers remain adjacent-link-local and are replaced at every relay. The fixed-schedule model produces identical per-direction public slot counts and zero inter-arrival variation for active and empty traffic, while reporting the substantial CHAFF bandwidth cost.

## Next increment

1. Define a private descriptor-distribution profile, including authentication, query privacy, replication, enumeration resistance, rotation, and revocation.
2. Add congestion-aware schedule negotiation and a formally specified response when fixed-rate capacity is exceeded.
3. Evaluate Poisson or randomized release profiles against the deterministic fixed-slot baseline.
4. Add forward-error-correction or limited redundancy as an alternative to retransmission for high-loss links.
5. Build an independent M2/W2/T1 implementation and differential-fuzz both codecs and state machines.
6. Obtain independent review of the additive reply-key chain, custom reply KEM, candidate transcript, gateway capability store, and T1 privacy boundary.
7. Keep the C2 author query and exhaustive checker available; reopen an endpoint-specific suite only after a corrected, reviewed construction passes all active-tag and composition tests.
