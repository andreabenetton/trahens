<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Trahens v1.7 typed state machines

- Status: Normative P1 lifecycle
- Executable model: `implementation/rust/crates/state-machine/`
- Bounded exploration: `tools/check_state_models.py`
- Formal models: `formal/R1Capability.tla`, `formal/E1Lifecycle.tla`

## Route phases

```text
Discovering
  --CandidateAccepted--> Candidate
  --CancelAccepted/Timeout--> Reclaimed

Candidate
  --CommitAccepted--> Committed
  --CancelAccepted/Timeout--> Reclaimed

Committed
  --ReadyAccepted--> Ready
  --CancelAccepted/Timeout--> Reclaimed

Ready
  --CapabilityAccepted--> Open
  --CancelAccepted/Timeout--> Reclaimed

Open
  --DataAccepted--> Open
  --CloseAccepted/CancelAccepted/Timeout--> Reclaimed
```

Any other event is a state violation and MUST NOT mutate state.

## Endpoint

The endpoint allocates one bounded discovery entry after locally constructing a canonical DISCOVER. It accepts only a CANDIDATE whose outer token matches, layer count is bounded, nested layers open canonically, nonce transitions form one chain beginning at its original nonce, and the gateway offer is signed, unexpired, and bound to the final nonce. A candidate counts once per authenticated gateway offer: a repeated offer is rejected without being held, counted toward the candidate threshold, or changing route phase, however it was transmitted. It sends COMMIT, authenticates READY, then presents the R1 capability. DATA starts only after a successful RENDEZVOUS_RESULT.

## Relay

A relay allocates route state only after W2 authentication, replay commitment, complete T1 reassembly, and canonical M2 decode. A fresh DISCOVER creates one parent-to-child mapping and reverse mapping. Candidate return changes Discovering to Candidate. A child-facing candidate label is consumed on admission: a later CANDIDATE naming a consumed label is rejected before nested wrapping, and allocates no offer label, forwards nothing upstream, and renews no deadline. Response-quota accounting precedes nested wrapping. Adjacent-link replay state does not supply this property, because a duplicate carried in a fresh T1 transmission is new link traffic. COMMIT, READY, successful result, DATA, and teardown follow the route phase machine. Labels are replaced at each boundary. Timeout or peer loss removes both maps atomically.

## Gateway

A gateway creates a candidate entry after a valid bounded DISCOVER. COMMIT proof success moves it to Committed and causes READY. Capability redemption is permitted only in Ready and only when the pseudonym, gateway, capability commitment, and expiry match. Atomic success consumes the capability before returning success and moves the route to Open.

## T1 sender

A sender reserves a complete first-send fragment set before admission. Each fragment is Pending, Sent, or Acknowledged. Timeout may enqueue only currently missing fragments. Each retry increments bounded counters and produces a fresh W2 sequence/ciphertext. Complete ACK or retry exhaustion releases all sender state.

## T1 receiver

The first authenticated canonical fragment may allocate a bounded context. Duplicate equal fragments do not allocate. Conflicting duplicates invalidate and release the context. Complete reassembly validates exact total length and M2 canonicality before protocol state allocation. Context timeout and completion-cache expiry are authoritative.

## R1 capability

A capability record is Live, Redeemed, or Expired. Redemption is one atomic compare-and-consume operation. Only Live with matching gateway and unexpired time can become Redeemed. Redeemed and Expired never return to Live.
