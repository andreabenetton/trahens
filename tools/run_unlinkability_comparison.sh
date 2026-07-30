#!/bin/sh
set -eu

PYTHONPATH=simulator python -m trahens_sim.unlinkability_compare \
    --nodes 500 \
    --average-degree 8 \
    --runs 100 \
    --hop-limits 3,4,5 \
    --fanouts 2,3,4 \
    --responder-fractions 0.02 \
    --candidate-limit 8 \
    --candidate-response-limit 24 \
    --transmission-budget 1200 \
    --state-budget 1200 \
    --per-node-context-limit 8 \
    --seed-base 5000 \
    --output reports/iteration-0004-unlinkability-comparison.csv
