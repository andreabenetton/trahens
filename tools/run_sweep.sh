#!/bin/sh
set -eu

PYTHONPATH=simulator python -m trahens_sim.sweep \
    --nodes 500 \
    --average-degree 8 \
    --hop-limits 3,4,5 \
    --relay-fanouts 2,3,4 \
    --runs 20 \
    --candidate-limit 8 \
    --responder-fraction 0.02 \
    --seed-base 1000 \
    --output reports/iteration-0002-sweep.csv
