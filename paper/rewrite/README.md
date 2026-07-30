# Formal working paper

`main.tex` is the formal Core v0.5 paper. It restores the formal language of the legacy manuscript while replacing incomplete or unsafe mechanisms with explicit definitions, notation, algorithms, propositions, claim boundaries, state rules, measured results, and implementation gates.

The document uses line numbers every five lines and contains no background watermark. It is a research paper, not the sole normative implementation specification; normative behavior remains in `spec/`.

Quantitative statements trace to the tracked reports, while C1 values trace to `spec/crypto-test-vectors-c1.json` and the executable reference implementation.

Build with:

```bash
make paper
```

The PDF must be rendered and visually reviewed after material changes.
