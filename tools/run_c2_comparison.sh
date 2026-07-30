#!/usr/bin/env sh
set -eu
PYTHONPATH=simulator python -m trahens_sim.c2_compare \
  --runs 100 \
  --output reports/iteration-0009-c2-active-security.csv
