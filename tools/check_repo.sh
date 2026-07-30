#!/bin/sh
set -eu

required_files="
README.md
ROADMAP.md
docs/strategy.md
docs/threat-model.md
spec/core-v0.1.md
spec/messages-v0.1.md
spec/state-machines-v0.1.md
spec/invariants.md
paper/legacy/trahens-2020.tex
paper/legacy/trahens-2020.pdf
"

for path in $required_files; do
    if [ ! -f "$path" ]; then
        echo "missing required file: $path" >&2
        exit 1
    fi
done

PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v
./tools/run_experiments.sh

echo "repository checks passed"
