# Formal working paper

`main.tex` is the formal Core v0.4 paper. It restores the structured language, notation, definitions, algorithms, conditional security statements, and normative requirements of the legacy draft while replacing its incomplete or unsafe mechanisms.

The paper is not the normative implementation specification. Normative behavior remains in `spec/`. Quantitative statements trace to `reports/iteration-0004-unlinkability-comparison.csv` and `docs/review-log/iteration-0004.md`.

Build and verify with:

```bash
make paper
```
