#!/bin/sh
set -eu

required_files="
README.md
ROADMAP.md
docs/strategy.md
docs/threat-model.md
docs/adr/0006-expanding-ring-discovery.md
docs/adr/0007-fresh-attempt-contexts.md
spec/core-v0.2.md
spec/messages-v0.2.md
spec/state-machines-v0.2.md
spec/invariants-v0.2.md
spec/resource-accounting-v0.2.md
paper/legacy/trahens-2020.tex
paper/legacy/trahens-2020.pdf
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

echo "repository checks passed"
