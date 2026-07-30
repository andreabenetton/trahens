#!/usr/bin/env bash
set -euo pipefail
PYTHONPATH=simulator python -m trahens_sim.r1_compare --runs 100 --output reports/iteration-0011-r1-gate-b.csv
