# Simulator

The simulator is the first executable artifact. It models the Core v0.1 outward discovery only:

- connected undirected graph generation;
- bounded hop count;
- separate origin and relay fan-out limits;
- first-parent duplicate suppression;
- responder sampling and candidate limits;
- discovery-state and replay-cache growth;
- deterministic seeds and JSON output.

It does not yet model message sizes, timers, cryptography, candidate reverse propagation, commitment, route expiration, churn, or malicious behavior.

## Run

```bash
PYTHONPATH=simulator python -m trahens_sim.cli \
  --nodes 100 \
  --average-degree 4 \
  --hop-limit 4 \
  --relay-fanout 3 \
  --seed 1
```

Or run a stored experiment:

```bash
PYTHONPATH=simulator python -m trahens_sim.cli \
  --config simulator/experiments/baseline.json \
  --output reports/baseline.json
```

## Test

```bash
PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v
```

## Next simulator increments

1. Candidate reverse propagation and tentative state.
2. Commit/ready bidirectional state installation.
3. Event time, expiration, packet loss, duplication, and reordering.
4. Churn and route teardown.
5. Malicious fan-out, replay, selective forwarding, and state exhaustion.
6. Padding and correlation experiments for named privacy profiles.
