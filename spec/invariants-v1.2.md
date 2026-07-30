# Trahens Core v1.2 invariants

- Status: Active research design

## Route and privacy invariants

1. No complete route is transmitted as one object.
2. DISCOVER contains no endpoint capability, endpoint key, endpoint address, deterministic endpoint selector, or gateway pseudonym.
3. Every honest relay replaces branch token, R1 nonce, outgoing labels, M2 representation, T1 transmission identifier, padding, and adjacent-link ciphertext.
4. A T1 transmission identifier is scoped to one directed adjacent-link epoch and one M2 message.
5. A T1 identifier, ACK bitmap, retry count, fragment schedule, or RTT sample never appears in the forwarded M2 message.
6. Application data and RENDEZVOUS_OPEN are forbidden before authenticated READY.
7. R1 capability redemption succeeds at most once and only before its half-open expiry.

## Encoding and reliability invariants

8. Every active T1/T2 record is exactly 1,052 bytes.
9. Every M2 message has one canonical fragment count `ceil(L/992)`, with at most 17 fragments.
10. T1 ACK bits outside the declared fragment count are zero.
11. A complete ACK bitmap has exactly the lowest `q` bits set.
12. Exact duplicate fragments are idempotent; conflicting duplicates invalidate the context.
13. A retransmission preserves only the same-link transmission identifier, fragment index, and canonical fragment bytes.
14. Every retry uses a new link sequence, fresh padding, and a new AEAD ciphertext.
15. A relay assigns a new transmission identifier on every outgoing link.
16. Unauthenticated input never advances replay state.
17. T1 completion is required before M2 decoding and route-state allocation.
18. Sender, receiver, ACK, timer, retry, and completion-cache state all have finite limits and deadlines.
19. Retry exhaustion fails closed and cannot create unbounded repair traffic.

## Scheduling invariants

20. Fixed-schedule mode emits one complete record per declared directed slot during the epoch.
21. An otherwise idle fixed slot carries CHAFF.
22. Frame class is encrypted and not present in the public link header.
23. Queue selection order is due ACK, bounded SCHEDULE control, due retransmission, weighted-DRR new DATA, then CHAFF.
24. Under no-overflow assumptions, active and empty traffic use the same public slot timestamps and record lengths within the same fixed epoch.
25. Work-conserving mode makes no constant-trace claim.
26. Schedule establishment, termination, rate, direction, topology, and congestion changes remain outside the schedule-shape invariant.

## Resource and failure invariants

27. Every transmitted DATA, ACK, SCHEDULE, retransmission, and CHAFF record is charged as one physical cell.
28. The first fragment reserves the complete declared logical length against reassembly capacity.
29. Recovery state cannot outlive the associated route operation's deadline.
30. Failures before authentication, T1 validation, complete reassembly, or M2 validation allocate no route state.
31. Detailed failure causes are not reflected in amplified network responses.
32. Disabled cryptographic providers remain fail closed and cannot be selected by active network configuration.


## T2 congestion and scheduling invariants

33. `c_e` belongs to the configured finite rate menu for every epoch.
34. A cadence transition takes effect only at an epoch boundary and changes by at most one class.
35. An invalid, stale, conflicting, or incomplete negotiation cannot increase the class.
36. The current epoch's slot count is unaffected by queue changes inside that epoch.
37. Fixed mode emits exactly the declared slots or explicitly records a profile break.
38. Adaptive mode makes no claim that the public class sequence is independent of traffic.
39. Queued cells, queue residence, schedule controls, DRR classes, deficits, CHAFF, and negotiation state are finite.
40. Link-local schedule identifiers and weights never enter an outgoing M2 object.
41. At maximum class, overload is handled by bounded rejection or expiry, not hidden cadence growth.
42. Weighted service cannot starve a continuously backlogged positive-weight class while slots remain after bounded control service.
