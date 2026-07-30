#!/bin/sh
set -eu

mkdir -p reports
for config in simulator/experiments/*.json; do
    name=$(basename "$config" .json)
    PYTHONPATH=simulator python -m trahens_sim.cli \
        --config "$config" \
        --output "reports/$name.json"
done
