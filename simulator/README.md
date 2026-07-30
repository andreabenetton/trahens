# Simulator

The simulator is the first executable artifact. It models outward Core discovery and policy selection:

- connected undirected graph generation;
- bounded hop count;
- separate origin and relay fan-out limits;
- first-parent duplicate suppression;
- deterministic responder sets;
- candidate limits and cross-attempt candidate deduplication;
- hard transmission and state-allocation budgets;
- expanding-ring schedules with fresh attempt contexts;
- cumulative cost and cross-attempt relay-overlap metrics;
- deterministic seeds and JSON/CSV output.

It does not yet model message sizes, event time, candidate reverse propagation, commitment, route expiration, churn, cryptography, or malicious behavior.

## Fixed attempt

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

## Test

```bash
make test
```

## Experiments

```bash
make experiments
make sweep
make policy-compare
```

The policy comparison writes `reports/iteration-0003-policy-comparison.csv` and compares success, transmissions, duplicates, state allocations, attempts, and relay overlap.

## Next simulator increments

1. Event time and candidate windows.
2. Candidate reverse propagation and tentative state.
3. Commit/ready bidirectional state installation.
4. Expiration, packet loss, duplication, and reordering.
5. Churn and route teardown.
6. Malicious fresh-attempt floods, candidate spam, replay, selective forwarding, and state exhaustion.
7. Padding and correlation experiments for named privacy profiles.
