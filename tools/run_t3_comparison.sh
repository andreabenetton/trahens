#!/bin/sh
set -eu
PYTHONPATH=simulator python -m trahens_sim.t3_compare \
  --classification-output reports/iteration-0014-t3-route-classification.csv \
  --probe-output reports/iteration-0014-t3-active-probing.csv \
  --budget-output reports/iteration-0014-t3-equal-budget.csv
