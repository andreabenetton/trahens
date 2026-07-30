# Trahens simulator

The simulator is deterministic and uses only the Python standard library. It is a protocol-research model, not a packet-level benchmark.

## Models

- `model.py` - identifier-based bounded discovery, expanding-ring policy, and U1 branch-local discovery.
- `event_model.py` - integrated E1 lifecycle with actual C1 transformations, W1 records, nested CANDIDATE, COMMIT/READY authentication, expiry, cancellation, loss, duplication, tampering, and active tagging.
- `unlinkability_compare.py` - resource comparison between identifier-based and U1 branch-local discovery.
- `lifecycle_compare.py` - clean, impaired-transport, and fresh-branch-attack lifecycle comparison.
- `tagging_compare.py` - deterministic W1 tampering and persistent-ratio-tag comparison.
- `trahens_codec/c1.py` - exact W1 fixed-size encoder and adjacent-link protection.
- `trahens_crypto/candidate.py` - nested authenticated candidate construction and opening.
- `trahens_crypto/tagging.py` - research-only active-tag fault injection and observation.

The event model retains full paths and legitimate/malicious classification only for measurement. Those values are not protocol-visible fields.

## Commands

```bash
make test
make unlinkability-compare
make lifecycle-compare
make tagging-compare
```

A direct lifecycle comparison can be run with:

```bash
PYTHONPATH=simulator python -m trahens_sim.lifecycle_compare \
  --nodes 500 \
  --average-degree 8 \
  --runs 100 \
  --rings 2:2:18,3:2:24,4:3:32 \
  --responder-fraction 0.02 \
  --output reports/lifecycle.csv
```

Timed rings use `hop:fanout:window_ms` or `hop:initial_fanout:relay_fanout:window_ms`.

## E1 event semantics

State is valid on `[created, expiry)`. At the same timestamp, expiry precedes cancellation, route control, candidate, discovery, and candidate-window closure. Thus a candidate at the exact window deadline is eligible, while a message at the exact state expiry is rejected.

## Integrated behavior

The event model performs actual URE rerandomization, reply-key tweaks, nested candidate encryption, responder signature verification, COMMIT and READY proof checks, W1 encoding, and adjacent-link authentication. It records complete wire bytes and cryptographic failure classes.

## Limitations

The model is deterministic and uses abstract event delays rather than a real transport or mixing scheduler. It is not a throughput benchmark. The active ratio-tag experiment is a counterexample demonstrating a missing security property; it is not a protocol feature.
