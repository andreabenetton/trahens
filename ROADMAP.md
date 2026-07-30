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
| M10 Reliability profile | Bound multi-cell loss recovery | delivery improves without stable cross-hop handles | Planned |
| M11 Overlay prototype | Prove interoperability | two implementations agree under faults and churn | Planned |
| M12 Traffic privacy | Measure metadata resistance | every scheduling claim is profile-specific and measured | Planned |

## Current milestone

Core v1.0 adopts R1 as the active eligibility provider. Discovery selects generic rendezvous gateways using a non-semantic per-hop nonce. Endpoint-specific capability material appears only after an authenticated route reaches READY. C1, symbolic C2, and the concrete C2 k=2 transcription remain research controls and are not network enabled.

## Next increment

1. Define a private descriptor-distribution profile, including authentication, query privacy, replication, enumeration resistance, rotation, and revocation.
2. Add bounded hop-by-hop reliability for fragmented W2 messages with fresh encryption on every retransmission.
3. Specify a scheduler for fragment interleaving, release delay, count padding, chaff, and congestion behavior.
4. Build an independent M2/W2 implementation and differential-fuzz both codecs.
5. Obtain independent review of the additive reply-key chain, custom reply KEM, candidate transcript, and gateway capability store.
6. Keep the C2 author query and exhaustive checker available; reopen an endpoint-specific suite only after a corrected, reviewed construction passes all active-tag and composition tests.
