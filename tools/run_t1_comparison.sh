#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
PYTHONPATH=simulator python -m trahens_sim.t1_compare \
  --runs 30 \
  --output reports/iteration-0012-t1-reliability.csv \
  --trace-output reports/iteration-0012-t1-trace-equivalence.csv
