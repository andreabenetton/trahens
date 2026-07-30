# Simulator

The simulator is the first executable artifact. It currently provides three related models:

1. identifier-based bounded discovery with first-parent duplicate suppression;
2. expanding-ring policy with fresh attempt contexts;
3. U1 branch-local discovery without attempt-wide duplicate suppression.

The U1 model treats every accepted ingress as independent branch state, excludes only immediate backtracking, and enforces hard transmission, global-state, per-node-context, candidate-response, and candidate-count limits. Complete paths are retained internally only to measure hidden loop re-entry; they are not protocol-visible state.

The simulator measures:

- discovery transmissions and candidate success;
- state allocations and unique relays;
- repeated branch contexts at one physical relay;
- hidden loop re-entry;
- context amplification;
- per-node and global budget exhaustion;
- expanding-ring work and cross-attempt overlap.

It does not yet model event time, reverse candidate capsules, COMMIT/READY, expiry, cryptographic distributions, packet loss, churn, or malicious behavior.

## Fixed identifier-based attempt

```bash
PYTHONPATH=simulator python -m trahens_sim.cli \
  --nodes 100 \
  --average-degree 4 \
  --hop-limit 4 \
  --relay-fanout 3 \
  --seed 1
```

## Expanding rings

```bash
PYTHONPATH=simulator python -m trahens_sim.expanding_cli \
  --nodes 500 \
  --average-degree 8 \
  --rings 2:2,3:2,4:3,5:4 \
  --responder-fraction 0.02 \
  --seed 1
```

A two-field ring is `hop_limit:fanout`. A three-field ring is `hop_limit:initial_fanout:relay_fanout`.

## U1 comparison

```bash
make unlinkability-compare
```

This writes `reports/iteration-0004-unlinkability-comparison.csv` and compares the identifier-based baseline with branch-local U1 discovery across hop/fan-out settings.

## Test and reproduce

```bash
make test
make reproduce
```

## Next simulator increment

The next model introduces an event queue, candidate windows, delayed candidates, reverse candidate propagation, tentative state, COMMIT/READY, expiration, cancellation, and malicious branch generation.
