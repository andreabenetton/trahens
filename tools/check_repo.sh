#!/bin/sh
set -eu

required_files="
README.md
ROADMAP.md
docs/strategy.md
docs/threat-model.md
docs/adr/0008-branch-local-unlinkable-contexts.md
docs/adr/0009-blinded-reply-key-chain.md
docs/adr/0010-rerandomizable-eligibility-capsule.md
docs/adr/0011-explicit-event-time.md
docs/adr/0012-ready-gated-route-activation.md
docs/adr/0013-ingress-peer-token-buckets.md
spec/core-v0.4.md
spec/unlinkability-profile-u1.md
spec/event-lifecycle-profile-e1.md
spec/crypto-transcript-v0.1.md
spec/messages-v0.4.md
spec/state-machines-v0.4.md
spec/invariants-v0.4.md
spec/resource-accounting-v0.4.md
paper/legacy/trahens-2020.tex
paper/legacy/trahens-2020.pdf
paper/rewrite/main.tex
reports/iteration-0004-unlinkability-comparison.csv
reports/iteration-0005-lifecycle-comparison.csv
"

for path in $required_files; do
    if [ ! -f "$path" ]; then
        echo "missing required file: $path" >&2
        exit 1
    fi
done

python -m compileall -q simulator
PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v
./tools/run_experiments.sh

PYTHONPATH=simulator python -m trahens_sim.expanding_cli \
    --nodes 50 \
    --average-degree 4 \
    --rings 1:1,3:2 \
    --responder-fraction 0.1 \
    --transmission-budget 100 \
    --state-budget 100 \
    --seed 17 \
    --output /tmp/trahens-expanding-smoke.json

test -s /tmp/trahens-expanding-smoke.json
rm -f /tmp/trahens-expanding-smoke.json

PYTHONPATH=simulator python -m trahens_sim.unlinkability_compare \
    --nodes 40 \
    --average-degree 4 \
    --runs 2 \
    --hop-limits 2 \
    --fanouts 2 \
    --responder-fractions 0.1 \
    --transmission-budget 100 \
    --state-budget 100 \
    --per-node-context-limit 4 \
    --output /tmp/trahens-u1-smoke.csv

test -s /tmp/trahens-u1-smoke.csv
rm -f /tmp/trahens-u1-smoke.csv

PYTHONPATH=simulator python -m trahens_sim.lifecycle_compare \
    --nodes 40 \
    --average-degree 4 \
    --runs 2 \
    --rings 2:2:10 \
    --responder-fraction 0.1 \
    --seed-base 41 \
    --output /tmp/trahens-e1-smoke.csv

test -s /tmp/trahens-e1-smoke.csv
rm -f /tmp/trahens-e1-smoke.csv

echo "repository checks passed"
