# Trahens simulator

The simulator is deterministic. It is a protocol-research model, not a packet-level performance benchmark.

## Models

- `model.py` - identifier-based bounded discovery, expanding-ring policy, and U1 branch-local discovery.
- `event_model.py` - integrated E1 lifecycle with C1 transformations, M1 messages, W2 fragmentation and reassembly, nested CANDIDATE, COMMIT/READY authentication, expiry, cancellation, loss, duplication, tampering, and active tagging.
- `fragmentation_compare.py` - M1 logical-size, W2 cell-count, route-depth, and cell-loss comparison.
- `unlinkability_compare.py` - resource comparison between identifier-based and U1 branch-local discovery.
- `lifecycle_compare.py` - clean, impaired-transport, and fresh-branch-attack lifecycle comparison.
- `tagging_compare.py` - deterministic link tampering and persistent-ratio-tag comparison.
- `trahens_codec/m1w2.py` - canonical M1 messages, exact W2 cells, link protection, and bounded reassembly.
- `trahens_codec/c1.py` - superseded W1 reference retained for historical regression tests.
- `trahens_crypto/candidate.py` - nested authenticated candidate construction and opening.
- `trahens_crypto/tagging.py` - research-only active-tag fault injection and observation.

The event model retains full paths and legitimate/malicious classification only for measurement. Those values are not protocol-visible fields.

## Commands

```bash
make test
make fragmentation-compare
make unlinkability-compare
make lifecycle-compare
make tagging-compare
```

A direct fragmentation comparison can be run with:

```bash
PYTHONPATH=simulator python -m trahens_sim.fragmentation_compare \
  --capacity-output reports/message-cell-capacity.csv \
  --lifecycle-output reports/lifecycle-fragmentation.csv
```

Timed rings use `hop:fanout:window_ms` or `hop:initial_fanout:relay_fanout:window_ms`.

## E1 event semantics

State is valid on `[created, expiry)`. At the same timestamp, expiry precedes cancellation, route control, candidate, discovery, and candidate-window closure. Thus a candidate at the exact window deadline is eligible, while a message at the exact state expiry is rejected.

## Integrated behavior

The event model performs actual URE rerandomization, reply-key tweaks, nested candidate encryption, responder signature verification, COMMIT and READY proof checks, canonical M1 encoding, fixed-size W2 encryption, out-of-order reassembly, and adjacent-link authentication. It records logical messages, cells, complete wire bytes, reassembly pressure, and cryptographic failure classes.

## Limitations

The model uses abstract event delays rather than a real transport or mixing scheduler. It is not a throughput benchmark. W2 equalizes cell length but does not hide fragment count or cell timing. The active ratio-tag experiment is a counterexample demonstrating a missing security property; it is not a protocol feature.
