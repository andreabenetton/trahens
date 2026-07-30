# Reports

Generated experiment outputs are retained when they support a recorded design decision.

- `iteration-0002-sweep.csv` - fixed discovery hop/fan-out sweep.
- `iteration-0003-policy-comparison.csv` - fixed broad flood versus expanding-ring policy across responder densities.
- `iteration-0004-unlinkability-comparison.csv` - identifier-based duplicate suppression versus U1 branch-local contexts.
- `baseline.json`, `conservative.json`, `dense.json` - deterministic single-run examples.

Reproduce with:

```bash
make experiments
make sweep
make policy-compare
make unlinkability-compare
```

The outputs are model results. They are not measurements of a network implementation and do not establish a cryptographic privacy property.
