<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.4.1 invariants

- Status: Active research design

## Route and privacy invariants

1. No complete route is transmitted as one object.
2. DISCOVER contains no endpoint capability, endpoint key, endpoint address, deterministic endpoint selector, or gateway pseudonym.
3. Every honest relay replaces branch token, R1 nonce, outgoing labels, M2 representation, T1 transmission identifier, padding, and adjacent-link ciphertext, and multiplicatively blinds the reply public key with an independently sampled non-zero scalar.
4. A T1 transmission identifier is scoped to one directed adjacent-link epoch and one M2 message.
5. A T1 identifier, ACK bitmap, retry count, fragment schedule, or RTT sample never appears in the forwarded M2 message.
6. Application data and RENDEZVOUS_OPEN are forbidden before authenticated READY.
7. R1 capability redemption succeeds at most once and only before its half-open expiry.
8. If `X_i=x_i B` and `b_i` is non-zero, reply-key evolution is `X_(i+1)=b_i X_i` and `x_(i+1)=b_i x_i mod q`.
9. For fixed non-identity `X_i`, uniform `b_i` makes `X_(i+1)` exactly uniform over non-identity group elements. This invariant does not by itself establish key privacy of the encrypted reply layer.
10. Core alone makes no complete-system endpoint-anonymity claim without an implemented private-directory profile.

## Encoding and reliability invariants

11. Every active T1/T2 record is exactly 1,052 bytes.
12. Every M2 message has one canonical fragment count `ceil(L/992)`, with at most 17 fragments.
13. T1 ACK bits outside the declared fragment count are zero.
14. A complete ACK bitmap has exactly the lowest `q` bits set.
15. Exact duplicate fragments are idempotent; conflicting duplicates invalidate the context.
16. A retransmission preserves only the same-link transmission identifier, fragment index, and canonical fragment bytes.
17. Every retry uses a new link sequence, fresh padding, and a new AEAD ciphertext.
18. A relay assigns a new transmission identifier on every outgoing link.
19. Unauthenticated input never advances replay state.
20. T1 completion is required before M2 decoding and route-state allocation.
21. Sender, receiver, ACK, timer, retry, and completion-cache state all have finite limits and deadlines.
22. Retry exhaustion fails closed and cannot create unbounded repair traffic.

## Scheduling invariants

23. Fixed-schedule mode emits one complete record per declared directed slot during the epoch.
24. An otherwise idle fixed slot carries CHAFF.
25. Frame class is encrypted and not present in the public link header.
26. Queue selection order is due ACK, bounded SCHEDULE control, due retransmission, weighted-DRR new DATA, then CHAFF.
27. Under no-overflow assumptions, active and empty traffic use the same public slot timestamps and record lengths within the same fixed epoch.
28. Work-conserving mode makes no constant-trace claim.
29. Schedule establishment, termination, rate, direction, topology, and congestion changes remain outside the schedule-shape invariant.

## Resource and failure invariants

30. Every transmitted DATA, ACK, SCHEDULE, retransmission, and CHAFF record is charged as one physical cell.
31. The first fragment reserves the complete declared logical length against reassembly capacity.
32. Recovery state cannot outlive the associated route operation's deadline.
33. Failures before authentication, T1 validation, complete reassembly, or M2 validation allocate no route state.
34. Detailed failure causes are not reflected in amplified network responses.
35. Disabled cryptographic providers remain fail closed and cannot be selected by active network configuration.


## T2 congestion and scheduling invariants

36. `c_e` belongs to the configured finite rate menu for every epoch.
37. A cadence transition takes effect only at an epoch boundary and changes by at most one class.
38. An invalid, stale, conflicting, or incomplete negotiation cannot increase the class.
39. The current epoch's slot count is unaffected by queue changes inside that epoch.
40. Fixed mode emits exactly the declared slots or explicitly records a profile break.
41. Adaptive mode makes no claim that the public class sequence is independent of traffic.
42. Queued cells, queue residence, schedule controls, DRR classes, deficits, CHAFF, and negotiation state are finite.
43. Link-local schedule identifiers and weights never enter an outgoing M2 object.
44. At maximum class, overload is handled by bounded rejection or expiry, not hidden cadence growth.
45. Weighted service cannot starve a continuously backlogged positive-weight class while slots remain after bounded control service.

## T3 traffic-analysis invariants

- Every compared profile exposes the same exact number of complete cells per observed link and super-epoch.
- The fixed reference trace is route-label independent.
- Test-set data is not used to standardize features or construct class centroids.
- Route classification, active probing, boundary alignment, and cross-link correlation are reported separately.
- Hybrid decoy choices do not depend on the route label.
- Analysis metadata never appears in network messages.
- A classifier result is not promoted to a global anonymity claim.

## T4 packet-evaluation invariants

1. T4 releases exactly the declared public-cell budget for every compared profile.
2. Every public record remains exactly 1,052 bytes.
3. One access or shared-bottleneck serializer never serves two cells simultaneously.
4. Per-link observer clocks transform observations only and never protocol event order.
5. Target and route labels terminate at each modelled relay and are never encoded.
6. Open-world unknown calibration routes and unknown testing routes are disjoint.
7. Training-only statistics determine feature standardization and rejection threshold.
8. Unobserved links are omitted from the adversary trace rather than represented by privileged zero observations.
9. Route churn affects only target traffic generated after the declared churn epoch.
10. Selective delay is finite, link-scoped, pattern-scoped, and reported.
11. Queue drops, expiry, budget mismatch, delivery failure, and cleanup failure are never suppressed.
12. T4 results remain scoped to the declared model and detector.
