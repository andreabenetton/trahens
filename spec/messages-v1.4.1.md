<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens Core v1.4.1 messages and T1/T2 adjacent-link frames

- Status: Active research design
- Applies to: U1, E1, R1, M2, W2, T1, and T2; D1 is a non-normative external dependency

## 1. Layering

Trahens uses four representations:

1. protocol object: DISCOVER, CANDIDATE, COMMIT, READY, RENDEZVOUS_OPEN, CANCEL, ABORT, or CLOSE;
2. canonical variable-length M2 message;
3. canonical W2 fragment set of at most 17 fragments;
4. T1/T2 fixed-size encrypted DATA, ACK, SCHEDULE, or CHAFF record on one adjacent link.

A relay terminates T1, T2, and M2. It MUST NOT forward an incoming T1 transmission identifier, ACK bitmap, fragment body, retry count, padding, or ciphertext unchanged.

## 2. T1/T2 frame classes

### DATA

Carries one canonical M2 fragment. Encrypted fields include suite, link-local transmission identifier, fragment index, fragment count, fragment length, total logical length, and payload.

### ACK

Carries the same link-local transmission identifier, declared fragment count, bounded receiver ACK delay, and a cumulative 32-bit selective bitmap. It is authenticated and encrypted in the reverse adjacent-link direction. It is not an M2 message and does not cross a relay.

### CHAFF

Carries a fresh random link-local identifier, zero control fields, and random padding. It receives no ACK and allocates no protocol state.

### SCHEDULE

Carries a link-local negotiation identifier, future effective epoch, current/requested/maximum rate class, and OFFER/ACCEPT/REJECT action. It is adjacent-link-only, receives no routed acknowledgement, and is never copied into M2.

All four classes produce the same 1,052-byte complete record.

## 3. Common receive order

A receiver SHOULD:

1. enforce exact record length and physical-link budgets;
2. parse epoch and sequence and perform a non-mutating replay precheck;
3. authenticate and decrypt;
4. commit replay admission;
5. parse and validate the T1/T2 frame;
6. process CHAFF without semantic state or update bounded SCHEDULE negotiation state;
7. update ACK or DATA transmission state when applicable;
8. for DATA, enforce reassembly capacity and accept one canonical fragment;
9. enqueue a cumulative ACK within the configured delay;
10. after complete reassembly, decode M2 and validate the protocol object;
11. allocate or transition route state only after all earlier checks;
12. construct a new M2 message and a new T1 transmission for every outgoing link.

## 4. Routed M2 objects

The logical fields, multiplicative reply-key blinding, and U1 transformations of DISCOVER, CANDIDATE, COMMIT, READY, RENDEZVOUS_OPEN, CANCEL, ABORT, and CLOSE are defined by the bound R1 and E1 profiles. Active DISCOVER uses R1 suite `0x0101` and contains a 32-byte non-semantic service-query nonce, not an endpoint capability or selector. The private descriptor that authorizes a gateway pseudonym is obtained outside Core; D1 describes one non-normative strawman and is not serialized into M2.

## 5. Reliability semantics

A sender reserves all canonical fragments before emission. It records an ACK bitmap and retransmits only missing fragments after timeout. A duplicate authenticated fragment with identical bytes is idempotent and causes the receiver's current bitmap to be acknowledged again. A conflicting duplicate invalidates the receive context.

A complete ACK releases sender state. Receiver completion state is retained only for a finite cache interval so a lost complete ACK can be regenerated when a retry arrives.

## 6. Retry privacy rule

Within one adjacent-link transmission, retry linkage is visible to the authenticated peer because the transmission identifier and fragment index must be stable. Every retry nevertheless uses a fresh public sequence, fresh padding, and fresh AEAD ciphertext. A relay creates a new transmission identifier before sending the transformed M2 message on another link.

## 7. Scheduler semantics

Fixed and adaptive T2 modes emit exactly the configured number of records per directed epoch. Selection order is:

1. due ACK within reserve;
2. due SCHEDULE control within reserve;
3. missing-fragment retransmission within reserve;
4. weighted-DRR new DATA;
5. CHAFF.

Work-conserving mode uses the same ordering but leaves empty slots silent. Queue overflow, class change, epoch termination, and fixed-profile break have explicit finite behavior. Implementations MUST NOT extend a schedule or accelerate beyond the negotiated maximum in response to one message.


## 8. T2 SCHEDULE frame

T2 adds an encrypted adjacent-link-only SCHEDULE frame with wire profile `0x04`. Its fixed header contains a non-zero negotiation identifier, future effective epoch, current class, requested class, peer maximum class, and OFFER/ACCEPT/REJECT action. The remainder is random padding.

SCHEDULE has the same complete 1,052-byte length as DATA, ACK, and CHAFF. It does not enter M2, receives no routed acknowledgement, and is never copied across a relay. A rate transition is valid only after a matching authenticated exchange; otherwise the current class remains in force.

## T3 analysis records

T3 adds no network message or adjacent-link frame. Route labels, classifier features, transition phases, active-probe labels, and super-epoch summaries are offline analysis records and MUST NOT be serialized into M2 or T1/T2 cells.

## T4 analysis note

T4 introduces no wire message or frame class. The packet-event emulator consumes only the public timing and fixed-length record outputs of T2. Route labels, target/background/CHAFF token kinds, observer-clock parameters, churn state, classifier labels, and selective-delay experiment controls are analysis-only values and MUST NOT appear in M2, W2, T1, or T2 encodings.
