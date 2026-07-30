# Reports

Generated experiment outputs are kept when they support a recorded design decision.

- `iteration-0002-sweep.csv` - fixed discovery hop/fan-out sweep.
- `iteration-0003-policy-comparison.csv` - fixed broad flood versus expanding-ring policy across responder densities.
- `baseline.json`, `conservative.json`, `dense.json` - deterministic single-run examples.

Reproduce with:

```bash
make experiments
make sweep
make policy-compare
```
