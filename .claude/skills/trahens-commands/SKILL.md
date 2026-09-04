---
name: trahens-commands
description: Build, test, and vector-regeneration commands for the Trahens Python simulator and Rust implementation — use when running tests, regenerating vectors, building the paper, or running the Rust interop harness.
---

### Python simulator and tests

```bash
# Run the full test suite
make test
# Equivalent: PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

# Run a single test file
PYTHONPATH=simulator python -m unittest simulator/tests/test_t1_model.py -v

# Full repo integrity check (regenerates all vectors, compares, runs tests, checks paper)
make check

# Regenerate specific test vectors
make crypto-vectors
make r1-vectors
make t1-vectors  make t2-vectors  make t3-vectors  make t4-vectors

# Comparison/analysis runs
make t1-compare  make t2-compare  make t3-compare  make t4-compare
make r1-compare  make c2-compare  make fragmentation-compare
make unlinkability-compare  make lifecycle-compare

# Regenerate the protocol registry (Python, Rust, and Markdown outputs simultaneously)
make registry     # python tools/generate_protocol_registry.py

# Build the LaTeX paper
make paper
```

### Rust implementation

Requirements: Rust ≥1.82, `libsodium-dev`.

```bash
# Build and test all crates
cargo test --manifest-path implementation/rust/Cargo.toml --all-targets
cargo build --release --manifest-path implementation/rust/Cargo.toml

# Linux namespace interoperability harness (requires root, ip, tc, tcpdump)
sudo implementation/harness/netns-p1.sh --relays 2 --loss 5
sudo implementation/harness/netns-p1.sh --relays 12 --loss 0
sudo implementation/harness/netns-fanout.sh          # fan-out and off-route cancellation

# Selectable experimental profiles, each with its own CI gate. Neither may be
# cited as evidence for a mandatory gate line.
sudo implementation/harness/netns-p1.sh --relays 2 --schedule-profile adaptive
sudo implementation/harness/netns-p1.sh --relays 2 --eligibility-suite c1
sudo implementation/harness/netns-p1.sh --relays 2 --scenario c1-not-eligible

# A third-party initiator against our relays and gateway
sudo implementation/harness/netns-p1.sh --relays 2 --external-endpoint "<command>"

# A foreign M2 decoder against the published corpus, before it can speak
python3 tools/check_external_codec.py "<decoder command>"

# One node per host over ssh; --runner replaces ssh for local testing
sudo implementation/harness/multihost-p1.sh --relays 1 --node 0=a --node 1=b --node 2=c

# Cost measurement, not a derived artifact: excluded from check_repo
sudo tools/run_p1_load_sweep.sh
```

### Full reproducibility

```bash
make reproduce   # regenerates all vectors, runs all comparisons, builds paper
```
