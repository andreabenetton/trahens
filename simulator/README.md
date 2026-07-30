# Trahens simulator

The simulator is deterministic and uses only the Python standard library. It is a protocol-research model, not a packet-level benchmark.

## Models

- `model.py` - identifier-based bounded discovery, expanding-ring policy, and U1 branch-local discovery.
- `event_model.py` - E1 discrete-event lifecycle with candidate windows, reverse tentative state, COMMIT/READY, expiry, cancellation, loss, exact duplication, and fresh-branch attack generation.
- `unlinkability_compare.py` - resource comparison between identifier-based and U1 branch-local discovery.
- `lifecycle_compare.py` - clean, impaired-transport, and fresh-branch-attack lifecycle comparison.

The event model retains full paths and legitimate/malicious classification only for measurement. Those values are not protocol-visible fields.

## Commands

```bash
make test
make unlinkability-compare
make lifecycle-compare
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

## Limitations

The simulator does not execute URE, KEM, signatures, packet codecs, or a real mixing scheduler. Delay, loss, duplication, attack classification, and token buckets are abstract controls. Results are comparative model outputs rather than network throughput or anonymity measurements.
